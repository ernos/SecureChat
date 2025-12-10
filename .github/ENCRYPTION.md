# Encryption in SafeMessenger

 This document describes the encryption mechanisms used in SafeMessenger, including the cryptographic functions, their usage, and integration points in the client and server codebases.

---

 ## 1.Overview
  SafeMessenger uses a combination of RSA (asymmetric) and AES (symmetric) encryption to ensure end-to-end security for all communications between clients and the server.

---

 ## 2.Key Concepts
  - **RSA:** Used for public key exchange and encrypting the AES session key during handshake.
  - **AES:** Used for encrypting all message payloads after the handshake.
  - **HMAC/RSA Signatures:** Used to sign messages for integrity and authentication.

---

 ## 3.Functions & Usage
 ### 3.1Client-Side (`client/crypto_utils.py`)
  - `generate_rsa_keypair()`: Generates a new RSA public/private key pair for the user.
  - `encrypt_rsa(data: bytes, public_key: str) -> bytes`: Encrypts data using the recipient's RSA public key.
  - `decrypt_rsa(ciphertext: bytes, private_key: str) -> bytes`: Decrypts data using the user's RSA private key.
  - `generate_aes_key() -> bytes`: Generates a new AES session key.
  - `encrypt_aes(data: bytes, key: bytes) -> bytes`: Encrypts data using AES (CBC or GCM mode).
  - `decrypt_aes(ciphertext: bytes, key: bytes) -> bytes`: Decrypts AES-encrypted data.
  - `sign_message(message: bytes, private_key: str) -> str`: Signs a message using the user's RSA private key.
  - `verify_signature(message: bytes, signature: str, public_key: str) -> bool`: Verifies a message signature.

 #### 3.1.1Usage Example (Client):
 1. On registration, generate RSA keypair and send public key to server.
 2. On connection, receive server public key, generate AES session key, encrypt with server's public key, and send.
 3. For each message, encrypt payload with AES session key, sign with private key.

 ---

 ### 4.Server-Side (`server/crypto_utils.py`)
  - `generate_rsa_keypair()`: Generates server RSA keypair.
  - `encrypt_rsa(data: bytes, public_key: str) -> bytes`: Encrypts data for a client.
  - `decrypt_rsa(ciphertext: bytes, private_key: str) -> bytes`: Decrypts data sent by a client.
  - `generate_aes_key() -> bytes`: Generates AES session key for each client session.
  - `encrypt_aes(data: bytes, key: bytes) -> bytes`: Encrypts payloads for clients.
  - `decrypt_aes(ciphertext: bytes, key: bytes) -> bytes`: Decrypts client payloads.
  - `sign_message(message: bytes, private_key: str) -> str`: Signs server messages.
  - `verify_signature(message: bytes, signature: str, public_key: str) -> bool`: Verifies client signatures.
 #### 4.1Usage Example (Server):
 1. On client connect, send server public key.
 2. Receive AES session key from client, decrypt with server private key.
 3. For each message, decrypt payload with AES session key, verify signature.

---

 ## 5.Integration Points
  - All message payloads are encrypted and signed before being sent over the network.
  - Handshake and key exchange occur before any sensitive data is transmitted.
  - See `client/crypto_utils.py` and `server/crypto_utils.py` for implementation details.

---

 ## 6.References
  - [PyCryptodome Documentation](https://www.pycryptodome.org/)
  - [RSA Encryption (Wikipedia)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
  - [AES Encryption (Wikipedia)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
