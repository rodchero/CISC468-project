import os
import struct
import time
from src.generated.p2pfileshare_pb2 import FileMetadata
from src.crypto_utils import sha256, sign, get_public_key_bytes


def compute_file_id(filename: str, file_hash: bytes, file_size: int) -> bytes:
    """file_id = SHA-256(filename_utf8 || file_hash_32 || file_size_8byte_BE)"""
    return sha256(
        filename.encode("utf-8") + file_hash + struct.pack(">Q", file_size)
    )


class FileManager:
    def __init__(self, shared_dir, identity_private_key, identity_public_key):
        self.shared_dir = shared_dir
        self.identity_priv = identity_private_key
        self.identity_pub = identity_public_key
        self.identity_pub_bytes = get_public_key_bytes(identity_public_key)
        self.files = {}  # file_id bytes -> (filepath, FileMetadata)

    def create_file_metadata(self, filepath) -> FileMetadata:
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            raw = f.read()

        file_hash = sha256(raw)
        file_size = len(raw)
        file_id = compute_file_id(filename, file_hash, file_size)
        owner_fp = sha256(self.identity_pub_bytes)
        ts = int(time.time())

        # Canonical bytes for signing — Rust side must match this exact order:
        # owner_fingerprint(32) || file_id(32) || filename_utf8 || file_size(8B BE) || file_hash(32) || timestamp(8B BE)
        canonical = (
            owner_fp
            + file_id
            + filename.encode("utf-8")
            + struct.pack(">Q", file_size)
            + file_hash
            + struct.pack(">Q", ts)
        )
        sig = sign(self.identity_priv, canonical)

        meta = FileMetadata()
        meta.owner_fingerprint = owner_fp
        meta.file_id = file_id
        meta.filename = filename
        meta.file_size = file_size
        meta.file_hash = file_hash
        meta.timestamp = ts
        meta.owner_signature = sig
        return meta

    def scan_files(self):
        self.files.clear()
        for name in os.listdir(self.shared_dir):
            path = os.path.join(self.shared_dir, name)
            if os.path.isfile(path):
                meta = self.create_file_metadata(path)
                self.files[meta.file_id] = (path, meta)

    def get_file_list(self):
        return [meta for _, meta in self.files.values()]

    def get_file_path(self, file_id):
        entry = self.files.get(file_id)
        return entry[0] if entry else None
