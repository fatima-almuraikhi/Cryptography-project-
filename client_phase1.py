import os, json, base64, requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = "http://127.0.0.1:11000"
PUBLIC_FILE = "public_key.pem"
ENCRYPTED_FILE = "encrypted_key.json"

class CoreClient:
    def __init__(self):
        print("--- Phase 1: Crypto & Registration Client ---")

    # --- STUDENT 1: CRYPTOGRAPHY WORK ---
    def derive_key(self, pin: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
        return kdf.derive(pin.encode())

    def init_keys(self, pin):
        """Generates RSA keys and encrypts the private key to disk."""
        print("[Crypto] Generating RSA Keypair...")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Save Public Key
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(PUBLIC_FILE, "wb") as f: f.write(pub_pem)

        # Encrypt Private Key (Student 1's logic)
        print("[Crypto] Encrypting Private Key with PIN...")
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        salt = os.urandom(16)
        aes_key = self.derive_key(pin, salt)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, priv_pem, associated_data=None)

        blob = {
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        with open(ENCRYPTED_FILE, "w") as f: json.dump(blob, f)
        print("[Success] Keys generated and saved.")
