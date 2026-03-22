import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type


class SecureStorage:
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self.master_key = None

    def setup(self, password: str):
        salt_path = os.path.join(self.storage_dir, "salt")

        if os.path.exists(salt_path):
            with open(salt_path, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(salt_path, "wb") as f:
                f.write(salt)

        self.master_key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )

    def encrypt_data(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        cipher = AESGCM(self.master_key)
        ciphertext = cipher.encrypt(nonce, plaintext, b"")
        return nonce + ciphertext

    def decrypt_data(self, blob: bytes) -> bytes:
        nonce = blob[:12]
        ciphertext = blob[12:]
        cipher = AESGCM(self.master_key)
        return cipher.decrypt(nonce, ciphertext, b"")

    def save(self, name: str, data: bytes):
        blob = self.encrypt_data(data)
        path = os.path.join(self.storage_dir, name)
        with open(path, "wb") as f:
            f.write(blob)

    def load(self, name: str):
        path = os.path.join(self.storage_dir, name)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            blob = f.read()
        return self.decrypt_data(blob)
