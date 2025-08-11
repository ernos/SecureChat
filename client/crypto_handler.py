
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

class CryptoHandler:
    def __init__(self, client):
        self.client = client

    def initialize_keys(self):
        if self.client.config["encryption"]["store_keys"] == False:
            return
        RSA_KEYS_PATH = "keys/"
        private_rsa_keyfile = Path(RSA_KEYS_PATH + f"{self.client.username}_private.pem")
        public_rsa_keyfile = Path(RSA_KEYS_PATH + f"{self.client.username}_public.pem")
        print(f"private key file: {private_rsa_keyfile}")
        print(f"public key file: {public_rsa_keyfile}")
        if (private_rsa_keyfile.exists() and public_rsa_keyfile.exists()):
            try:
                with open(private_rsa_keyfile, 'rb') as f:
                    self.client.private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                with open(public_rsa_keyfile, 'rb') as f:
                    self.client.public_key = serialization.load_pem_public_key(
                        f.read(), backend=default_backend()
                    )
                print(f"✓ Loaded existing keys for {self.client.username}")
            except Exception as e:
                print(f"❌ Error loading keys: {e}")
                print("Generating new keys...")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        print(f"🔑 Generating new RSA keys (size: {self.client.config['encryption']['key_size']})...")
        self.client.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.client.config["encryption"]["key_size"],
            backend=default_backend()
        )
        self.client.public_key = self.client.private_key.public_key()
        if self.client.config["encryption"]["store_keys"]:
            self.save_keys()
        print("✓ Keys generated successfully")

    def save_keys(self):
        if self.client.private_key is None or self.client.public_key is None:
            print(f"Failed to save keys: keys not initialized")
            raise ValueError("Keys not initialized")
        CLIENT_KEYS_PATH = Path(self.client.config["encryption"]["keys_directory"])
        CLIENT_KEYS_PATH.mkdir(exist_ok=True)
        private_key_file = CLIENT_KEYS_PATH / f"{self.client.username}_private.pem"
        public_key_file = CLIENT_KEYS_PATH / f"{self.client.username}_public.pem"
        private_pem = self.client.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        public_pem = self.client.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        print(f"✓ Keys saved to {CLIENT_KEYS_PATH}")

    def ensure_private_key(self):
        if self.client.private_key is None:
            raise ValueError("Private key not initialized")
