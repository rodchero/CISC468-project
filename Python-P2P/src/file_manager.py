import os
import struct
import time
from src.generated.p2pfileshare_pb2 import FileMetadata
from src.crypto_utils import sha256, sign, verify, get_public_key_bytes


def compute_file_id(filename: str, file_hash: bytes, file_size: int) -> bytes:
    """file_id = SHA-256(filename_utf8 || file_hash_32 || file_size_8byte_BE)"""
    return sha256(
        filename.encode("utf-8") + file_hash + struct.pack(">Q", file_size)
    )


def build_canonical_metadata_bytes(metadata) -> bytes:
    # Canonical byte order for signing/verifying — Rust side must match exactly:
    # owner_fingerprint(32) || file_id(32) || filename_utf8 || file_size(8B BE) || file_hash(32) || timestamp(8B BE)
    return (
        metadata.owner_fingerprint
        + metadata.file_id
        + metadata.filename.encode("utf-8")
        + struct.pack(">Q", metadata.file_size)
        + metadata.file_hash
        + struct.pack(">Q", metadata.timestamp)
    )


def verify_file_metadata(metadata, owner_pubkey_bytes: bytes) -> bool:
    canonical = build_canonical_metadata_bytes(metadata)
    return verify(owner_pubkey_bytes, metadata.owner_signature, canonical)


def verify_file_integrity(filepath, metadata) -> bool:
    with open(filepath, "rb") as f:
        data = f.read()
    return sha256(data) == metadata.file_hash


def verify_file_id(metadata) -> bool:
    expected = compute_file_id(metadata.filename, metadata.file_hash, metadata.file_size)
    return metadata.file_id == expected


class FileManager:
    def __init__(self, shared_dir, identity_private_key, identity_public_key, storage=None):
        self.shared_dir = shared_dir
        self.identity_priv = identity_private_key
        self.identity_pub = identity_public_key
        self.identity_pub_bytes = get_public_key_bytes(identity_public_key)
        self.storage = storage
        self.files = {}  # file_id bytes -> (filepath, FileMetadata)
        self.third_party = {}  # file_id bytes -> FileMetadata (original owner's)

    def _read_file(self, filepath):
        """Read a file, decrypting if encrypted. Returns plaintext bytes."""
        with open(filepath, "rb") as f:
            raw = f.read()
        if self.storage is None:
            return raw
        try:
            return self.storage.decrypt_data(raw)
        except Exception:
            return raw

    def _write_file(self, filepath, plaintext):
        """Write encrypted file to disk."""
        if self.storage is None:
            with open(filepath, "wb") as f:
                f.write(plaintext)
            return
        blob = self.storage.encrypt_data(plaintext)
        with open(filepath, "wb") as f:
            f.write(blob)

    def _encrypt_if_plaintext(self, filepath):
        """If file is plaintext, encrypt it in place. Returns plaintext either way."""
        with open(filepath, "rb") as f:
            raw = f.read()
        if self.storage is None:
            return raw
        try:
            return self.storage.decrypt_data(raw)
        except Exception:
            self._write_file(filepath, raw)
            return raw

    def create_file_metadata(self, filepath) -> FileMetadata:
        filename = os.path.basename(filepath)
        raw = self._read_file(filepath)

        file_hash = sha256(raw)
        file_size = len(raw)
        file_id = compute_file_id(filename, file_hash, file_size)
        owner_fp = sha256(self.identity_pub_bytes)
        ts = int(time.time())

        meta = FileMetadata()
        meta.owner_fingerprint = owner_fp
        meta.file_id = file_id
        meta.filename = filename
        meta.file_size = file_size
        meta.file_hash = file_hash
        meta.timestamp = ts

        canonical = build_canonical_metadata_bytes(meta)
        meta.owner_signature = sign(self.identity_priv, canonical)
        return meta

    def scan_files(self):
        self.files.clear()
        # Restore third-party files first (preserve original owner's metadata)
        for file_id, meta in self.third_party.items():
            filepath = os.path.join(self.shared_dir, meta.filename)
            if os.path.isfile(filepath):
                self.files[file_id] = (filepath, meta)
        # Scan our own files, encrypt any plaintext files in place
        for name in os.listdir(self.shared_dir):
            path = os.path.join(self.shared_dir, name)
            if os.path.isfile(path):
                self._encrypt_if_plaintext(path)
                meta = self.create_file_metadata(path)
                if meta.file_id not in self.third_party:
                    self.files[meta.file_id] = (path, meta)

    def get_file_list(self):
        return [meta for _, meta in self.files.values()]

    def get_file_path(self, file_id):
        entry = self.files.get(file_id)
        return entry[0] if entry else None

    def store_third_party_metadata(self, metadata):
        """Store received file's metadata with original owner's signature for re-sharing."""
        file_id = metadata.file_id
        self.third_party[file_id] = metadata
        filepath = os.path.join(self.shared_dir, metadata.filename)
        self.files[file_id] = (filepath, metadata)

    def export_third_party(self):
        """Serialize third-party metadata for encrypted storage."""
        result = {}
        for file_id, meta in self.third_party.items():
            result[file_id.hex()] = meta.SerializeToString().hex()
        return result

    def import_third_party(self, data):
        """Restore third-party metadata from storage."""
        for file_id_hex, meta_hex in data.items():
            file_id = bytes.fromhex(file_id_hex)
            meta = FileMetadata()
            meta.ParseFromString(bytes.fromhex(meta_hex))
            self.third_party[file_id] = meta
