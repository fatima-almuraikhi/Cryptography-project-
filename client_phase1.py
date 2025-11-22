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

    # --- STUDENT 1: CRYPTOGRAPHY WORK --- (fatima)
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


    # NETWORK REGISTRATION TASK --- (moudi)
    def register(self, username, device_id):
        """Reads the public key and sends it to the server."""
        if not os.path.exists(PUBLIC_FILE):
            print("[Error] No keys found. Run init first.")
            return

        with open(PUBLIC_FILE, "rb") as f:
            pub_pem = f.read().decode()

        payload = {
            "username": username,
            "device_id": device_id,
            "public_key_pem": pub_pem,
            "meta": {"client_version": "v1.0_terminal"}
        }
        print(f"[Network] Connecting to {SERVER_URL}/register...")
        try:
            r = requests.post(f"{SERVER_URL}/register", json=payload)
            print(f"[Server Response {r.status_code}]: {r.text}")
        except Exception as e:
            print(f"[Network Error] {e}")

if __name__ == "__main__":
    client = CoreClient()
    action = input("Select Action (1: Init Keys, 2: Register): ")
    if action == "1":
        p = input("Set a PIN: ")
        client.init_keys(p)
    elif action == "2":
        u = input("Username: ")
        d = input("Device ID: ")
        client.register(u, d)
