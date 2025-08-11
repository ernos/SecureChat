"""
Cryptographic utilities for the secure chat server
"""

import base64
import secrets
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class CryptoUtils:
    """Utility class for cryptographic operations"""
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
        """Serialize public key to PEM format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> str:
        """Serialize private key to PEM format"""
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')
    
    @staticmethod
    def load_public_key(pem_data: str) -> rsa.RSAPublicKey:
        """Load public key from PEM format"""
        return serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )
    
    @staticmethod
    def load_private_key(pem_data: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
        """Load private key from PEM format"""
        return serialization.load_pem_private_key(
            pem_data.encode(),
            password=password,
            backend=default_backend()
        )
    
    @staticmethod
    def encrypt_rsa(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt message using RSA public key"""
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def decrypt_rsa(encrypted_message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt message using RSA private key"""
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    @staticmethod
    def sign_message(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Sign message using RSA private key"""
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    @staticmethod
    def verify_signature(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """Verify message signature using RSA public key"""
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate random AES-256 key"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_aes(message: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt message using AES-256-GCM"""
        iv = secrets.token_bytes(12)  # GCM recommended IV size
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return ciphertext + encryptor.tag, iv
    
    @staticmethod
    def decrypt_aes(ciphertext_with_tag: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt message using AES-256-GCM"""
        ciphertext = ciphertext_with_tag[:-16]  # Remove 16-byte tag
        tag = ciphertext_with_tag[-16:]  # Last 16 bytes are the tag
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Hash password using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def verify_password(password: str, hash_value: bytes, salt: bytes) -> bool:
        """Verify password against hash"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            kdf.verify(password.encode(), hash_value)
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_session_token() -> str:
        """Generate secure session token"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """Generate SHA-256 hash of data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def encode_base64(data: bytes) -> str:
        """Encode data to base64 string"""
        return base64.b64encode(data).decode()
    
    @staticmethod
    def decode_base64(data: str) -> bytes:
        """Decode base64 string to bytes"""
        return base64.b64decode(data.encode())
