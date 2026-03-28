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


# --- Third-party file support ---

def test_store_third_party_preserves_metadata():
    """Storing third-party metadata should preserve original owner's signature."""
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()
    pub_a_bytes = get_public_key_bytes(pub_a)

    with tempfile.TemporaryDirectory() as alice_dir, \
         tempfile.TemporaryDirectory() as bob_dir:
        # Alice creates and signs a file
        path = os.path.join(alice_dir, "shared.txt")
        with open(path, "wb") as f:
            f.write(b"alice's data")
        fm_alice = FileManager(alice_dir, priv_a, pub_a)
        meta = fm_alice.create_file_metadata(path)

        # Bob receives the file and stores third-party metadata
        bob_path = os.path.join(bob_dir, "shared.txt")
        with open(bob_path, "wb") as f:
            f.write(b"alice's data")
        fm_bob = FileManager(bob_dir, priv_b, pub_b)
        fm_bob.store_third_party_metadata(meta)

        # Bob's file list should include alice's file with alice's signature
        files = fm_bob.get_file_list()
        assert len(files) == 1
        assert files[0].owner_signature == meta.owner_signature
        assert verify_file_metadata(files[0], pub_a_bytes)


def test_scan_skips_third_party_files():
    """scan_files should not re-sign files tracked as third-party."""
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    with tempfile.TemporaryDirectory() as alice_dir, \
         tempfile.TemporaryDirectory() as bob_dir:
        # Alice creates a file
        path = os.path.join(alice_dir, "doc.txt")
        with open(path, "wb") as f:
            f.write(b"original")
        fm_alice = FileManager(alice_dir, priv_a, pub_a)
        meta = fm_alice.create_file_metadata(path)

        # Bob stores the file and metadata
        with open(os.path.join(bob_dir, "doc.txt"), "wb") as f:
            f.write(b"original")
        fm_bob = FileManager(bob_dir, priv_b, pub_b)
        fm_bob.store_third_party_metadata(meta)
        fm_bob.scan_files()

        # Should still have alice's signature, not bob's
        files = fm_bob.get_file_list()
        found = [f for f in files if f.filename == "doc.txt"]
        assert len(found) == 1
        assert found[0].owner_signature == meta.owner_signature


def test_export_import_third_party():
    """Third-party metadata should survive export/import cycle."""
    priv, pub = generate_identity_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.bin")
        with open(path, "wb") as f:
            f.write(b"data")
        fm = FileManager(tmpdir, priv, pub)
        meta = fm.create_file_metadata(path)

        # Store as third-party and export
        fm.store_third_party_metadata(meta)
        exported = fm.export_third_party()

        # Import into a fresh FileManager
        priv2, pub2 = generate_identity_keypair()
        fm2 = FileManager(tmpdir, priv2, pub2)
        fm2.import_third_party(exported)

        assert meta.file_id in fm2.third_party
        restored = fm2.third_party[meta.file_id]
        assert restored.filename == meta.filename
        assert restored.owner_signature == meta.owner_signature
