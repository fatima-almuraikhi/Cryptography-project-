# client_phase2.py
import os, json, base64, requests
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Importing Phase 1 logic (simulated by inheritance/copying for standalone submission)

SERVER_URL = "http://127.0.0.1:11000"
ENCRYPTED_FILE = "encrypted_key.json"

class LogicClient:
    # Reusing basic crypto helpers from Phase 1...
    def derive_key(self, pin, salt):
        return PBKDF2HMAC(hashes.SHA256(), 32, salt, 200000).derive(pin.encode())

    # AUTHENTICATION LOGIC ---
    def decrypt_private_key(self, pin):
        """Decrypts the private key from disk using the PIN."""
        with open(ENCRYPTED_FILE, "r") as f: data = json.load(f)
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        
        aes_key = self.derive_key(pin, salt)
        aesgcm = AESGCM(aes_key)
        try:
            priv_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            return serialization.load_pem_private_key(priv_pem, password=None)
        except:
            print("[Auth Error] Incorrect PIN or corrupted key.")
            return None

    def login(self, username, device_id, pin):
        """Performs the Challenge-Response Authentication."""
        print(f"[Auth] Requesting challenge for {username}...")
        # 1. Get Challenge
        r = requests.post(f"{SERVER_URL}/get_challenge", json={"username": username, "device_id": device_id})
        if r.status_code != 200: 
            print(f"[Error] {r.text}"); return
        
        nonce = r.json()["challenge"]
        print(f"[Auth] Challenge received: {nonce}")

        # 2. Sign Challenge (Student 3's Core Contribution)
        priv_key = self.decrypt_private_key(pin)
        if not priv_key: return

        signature = priv_key.sign(
            nonce.encode(),
            asympadding.PSS(mgf=asympadding.MGF1(hashes.SHA256()), salt_length=asympadding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Verification code
        payload = {
            "username": username, "device_id": device_id,
            "signature": base64.b64encode(signature).decode(), "nonce": nonce
        }
        r_ver = requests.post(f"{SERVER_URL}/verify", json=payload)
        print(f"[Server Login Result]: {r_ver.json()}")

        

