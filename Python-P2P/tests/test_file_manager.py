import os
import struct
import tempfile
from src.file_manager import (
    FileManager, compute_file_id,
    verify_file_metadata, verify_file_integrity, verify_file_id,
)
from src.crypto_utils import generate_identity_keypair, get_public_key_bytes, sha256


def test_create_file_metadata():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "hello.txt")
        with open(path, "wb") as f:
            f.write(b"hello world")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)

        assert meta.filename == "hello.txt"
        assert meta.file_size == 11
        assert len(meta.file_id) == 32
        assert len(meta.file_hash) == 32
        assert len(meta.owner_signature) == 64
        assert len(meta.owner_fingerprint) == 32


def test_compute_file_id_manual():
    filename = "test.bin"
    file_hash = b'\xaa' * 32
    file_size = 256

    expected = sha256(
        filename.encode("utf-8") + file_hash + struct.pack(">Q", file_size)
    )
    result = compute_file_id(filename, file_hash, file_size)
    assert result == expected


def test_scan_files():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        for name in ["a.txt", "b.txt", "c.txt"]:
            with open(os.path.join(tmpdir, name), "wb") as f:
                f.write(f"contents of {name}".encode())

        fm = FileManager(tmpdir, priv, pub)
        fm.scan_files()

        assert len(fm.get_file_list()) == 3
        filenames = {m.filename for m in fm.get_file_list()}
        assert filenames == {"a.txt", "b.txt", "c.txt"}


# --- Day 13: verification ---

def test_verify_metadata_correct_key():
    priv, pub = generate_identity_keypair()
    pub_bytes = get_public_key_bytes(pub)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "doc.txt")
        with open(path, "wb") as f:
            f.write(b"some content")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)
        assert verify_file_metadata(meta, pub_bytes)


def test_verify_metadata_wrong_key():
    priv, pub = generate_identity_keypair()
    priv2, pub2 = generate_identity_keypair()
    wrong_bytes = get_public_key_bytes(pub2)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "doc.txt")
        with open(path, "wb") as f:
            f.write(b"some content")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)
        assert not verify_file_metadata(meta, wrong_bytes)


def test_verify_file_integrity_ok():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "data.bin")
        with open(path, "wb") as f:
            f.write(b"original bytes")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)
        assert verify_file_integrity(path, meta)


def test_verify_file_integrity_tampered():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "data.bin")
        with open(path, "wb") as f:
            f.write(b"original bytes")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)

        # Tamper with the file
        with open(path, "ab") as f:
            f.write(b"extra")
        assert not verify_file_integrity(path, meta)


def test_verify_file_id_valid():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.txt")
        with open(path, "wb") as f:
            f.write(b"test data")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)
        assert verify_file_id(meta)


def test_verify_file_id_wrong_filename():
    priv, pub = generate_identity_keypair()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.txt")
        with open(path, "wb") as f:
            f.write(b"test data")

        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)
        meta.filename = "renamed.txt"
        assert not verify_file_id(meta)
