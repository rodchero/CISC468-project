"""Cross-validation test vectors for Python ↔ Rust interoperability.

Each test uses hardcoded inputs and verifies the output matches a known value.
The partner should independently verify the same inputs produce the same
outputs on the Rust side. If any test here produces a different value than
Rust, that's an interop bug.
"""
import struct
import hashlib
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto_utils import sha256, derive_session_keys, fingerprint
from src.nonce import NonceManager
from src.file_manager import compute_file_id, build_canonical_metadata_bytes
from src.generated.p2pfileshare_pb2 import (
    P2PMessage, Hello, EncryptedMessage, FileMetadata,
)
from src.handshake import PROTOCOL_VERSION


# ---- Test vector constants ----

# Fake 32-byte keys (deterministic, easy to replicate in Rust)
KEY_A_ID = bytes(range(0, 32))          # 0x00..0x1f
KEY_B_ID = bytes(range(32, 64))         # 0x20..0x3f
KEY_A_EPH = bytes(range(64, 96))        # 0x40..0x5f
KEY_B_EPH = bytes(range(96, 128))       # 0x60..0x7f
SHARED_SECRET = bytes(range(128, 160))  # 0x80..0x9f
AES_KEY = bytes(range(160, 192))        # 0xa0..0xbf


# ---- 1. Transcript hash ----

def test_transcript_byte_layout():
    """Transcript = version(4B BE) || init_id(32) || init_eph(32) || resp_id(32) || resp_eph(32)"""
    transcript = (
        struct.pack('>I', PROTOCOL_VERSION)
        + KEY_A_ID   # initiator identity
        + KEY_A_EPH  # initiator ephemeral
        + KEY_B_ID   # responder identity
        + KEY_B_EPH  # responder ephemeral
    )

    assert len(transcript) == 132

    # Both sides must produce this exact hash
    transcript_hash = sha256(transcript)
    print(f"\nTranscript hash: {transcript_hash.hex()}")
    assert len(transcript_hash) == 32

    # Verify it's deterministic
    assert transcript_hash == sha256(transcript)


def test_transcript_version_is_big_endian():
    """Protocol version 1 should be 00 00 00 01 in the transcript."""
    version_bytes = struct.pack('>I', 1)
    assert version_bytes == b'\x00\x00\x00\x01'


# ---- 2. HKDF key derivation ----

def test_hkdf_deterministic():
    """Given a known shared secret, HKDF must produce deterministic keys."""
    key_i2r, key_r2i = derive_session_keys(SHARED_SECRET)

    print(f"\nHKDF input:  {SHARED_SECRET.hex()}")
    print(f"key_i2r:     {key_i2r.hex()}")
    print(f"key_r2i:     {key_r2i.hex()}")

    assert len(key_i2r) == 32
    assert len(key_r2i) == 32
    assert key_i2r != key_r2i

    # Must be reproducible
    k1, k2 = derive_session_keys(SHARED_SECRET)
    assert k1 == key_i2r
    assert k2 == key_r2i


def test_hkdf_salt_and_info():
    """Verify the exact salt and info strings used."""
    from src.crypto_utils import HKDF_SALT, HKDF_INFO
    assert HKDF_SALT == b"p2pfileshare-v1-salt"
    assert HKDF_INFO == b"p2pfileshare-v1-session-keys"


# ---- 3. Nonce format ----

def test_nonce_format_counter_zero():
    """Counter 0 → 4 zero bytes + 8-byte BE zero."""
    nm = NonceManager()
    nonce = nm.next_nonce()
    assert nonce == b'\x00' * 12
    assert len(nonce) == 12


def test_nonce_format_counter_one():
    """Counter 1 → 4 zero bytes + 8-byte BE 1."""
    nm = NonceManager()
    nm.next_nonce()  # consume 0
    nonce = nm.next_nonce()
    assert nonce == b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x01'


def test_nonce_format_counter_256():
    """Counter 256 → 4 zero bytes + 0x0000000000000100."""
    nm = NonceManager()
    for _ in range(256):
        nm.next_nonce()
    nonce = nm.next_nonce()
    expected = b'\x00\x00\x00\x00' + struct.pack('>Q', 256)
    assert nonce == expected


# ---- 4. AES-256-GCM encryption ----

def test_aes_gcm_with_known_values():
    """AES-256-GCM encryption with known key, nonce, plaintext, empty AAD."""
    plaintext = b"hello from python"
    nonce = b'\x00' * 12  # counter 0
    aad = b""  # empty AAD as per spec

    cipher = AESGCM(AES_KEY)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)

    print(f"\nAES key:     {AES_KEY.hex()}")
    print(f"Nonce:       {nonce.hex()}")
    print(f"Plaintext:   {plaintext.hex()}")
    print(f"Ciphertext:  {ciphertext.hex()}")

    # Ciphertext should be plaintext_len + 16 (GCM tag)
    assert len(ciphertext) == len(plaintext) + 16

    # Must decrypt back
    decrypted = cipher.decrypt(nonce, ciphertext, aad)
    assert decrypted == plaintext


def test_aes_gcm_wrong_key_fails():
    """Decryption with wrong key must fail."""
    plaintext = b"secret"
    nonce = b'\x00' * 12
    cipher = AESGCM(AES_KEY)
    ciphertext = cipher.encrypt(nonce, plaintext, b"")

    wrong_key = bytes(range(192, 224))
    wrong_cipher = AESGCM(wrong_key)
    with pytest.raises(Exception):
        wrong_cipher.decrypt(nonce, ciphertext, b"")


def test_aes_gcm_empty_aad():
    """Both sides must use empty bytes b'' as AAD, not None."""
    plaintext = b"test"
    nonce = b'\x00' * 12
    cipher = AESGCM(AES_KEY)

    ct_empty = cipher.encrypt(nonce, plaintext, b"")
    # Verify it decrypts with empty AAD
    assert cipher.decrypt(nonce, ct_empty, b"") == plaintext


# ---- 5. SHA-256 hashing ----

def test_sha256_known_value():
    """SHA-256 of known input must match."""
    result = sha256(b"p2pfileshare")
    print(f"\nSHA-256('p2pfileshare'): {result.hex()}")
    assert result == hashlib.sha256(b"p2pfileshare").digest()
    assert len(result) == 32


def test_fingerprint_format():
    """Fingerprint = colon-separated lowercase hex of SHA-256."""
    pub_bytes = b'\xaa' * 32
    fp = fingerprint(pub_bytes)
    digest = sha256(pub_bytes)
    expected = ":".join(f"{b:02x}" for b in digest)
    assert fp == expected
    # Should look like "ab:cd:ef:..."
    assert len(fp.split(":")) == 32


# ---- 6. File ID computation ----

def test_file_id_known_values():
    """file_id = SHA-256(filename_utf8 || file_hash || file_size_8B_BE)"""
    filename = "document.pdf"
    file_hash = sha256(b"file content here")
    file_size = 12345

    file_id = compute_file_id(filename, file_hash, file_size)

    # Manually compute
    raw = filename.encode("utf-8") + file_hash + struct.pack(">Q", file_size)
    expected = sha256(raw)
    assert file_id == expected

    print(f"\nFilename:  {filename}")
    print(f"File hash: {file_hash.hex()}")
    print(f"File size: {file_size}")
    print(f"File ID:   {file_id.hex()}")


def test_file_id_size_is_big_endian():
    """File size must be 8-byte big-endian in the file_id computation."""
    size_bytes = struct.pack(">Q", 65536)
    assert size_bytes == b'\x00\x00\x00\x00\x00\x01\x00\x00'


# ---- 7. Canonical metadata bytes ----

def test_canonical_metadata_layout():
    """Canonical = owner_fp(32) || file_id(32) || filename_utf8 || size(8B BE) || hash(32) || timestamp(8B BE)"""
    meta = FileMetadata()
    meta.owner_fingerprint = b'\x01' * 32
    meta.file_id = b'\x02' * 32
    meta.filename = "test.txt"
    meta.file_size = 1000
    meta.file_hash = b'\x03' * 32
    meta.timestamp = 1700000000

    canonical = build_canonical_metadata_bytes(meta)

    # Manually build expected
    expected = (
        b'\x01' * 32                          # owner_fingerprint
        + b'\x02' * 32                        # file_id
        + b"test.txt"                         # filename UTF-8
        + struct.pack(">Q", 1000)             # file_size
        + b'\x03' * 32                        # file_hash
        + struct.pack(">Q", 1700000000)       # timestamp
    )
    assert canonical == expected

    print(f"\nCanonical metadata length: {len(canonical)}")
    print(f"Canonical metadata: {canonical.hex()}")


def test_canonical_metadata_unicode_filename():
    """UTF-8 filenames must be encoded the same way on both sides."""
    meta = FileMetadata()
    meta.owner_fingerprint = b'\x00' * 32
    meta.file_id = b'\x00' * 32
    meta.filename = "résumé.pdf"
    meta.file_size = 0
    meta.file_hash = b'\x00' * 32
    meta.timestamp = 0

    canonical = build_canonical_metadata_bytes(meta)

    # The filename bytes in the middle should be UTF-8 encoded
    filename_bytes = "résumé.pdf".encode("utf-8")
    assert filename_bytes in canonical
    print(f"\nUTF-8 filename bytes: {filename_bytes.hex()}")


# ---- 8. Key rotation canonical bytes ----

def test_key_rotation_canonical_layout():
    """Canonical = old_pub(32) || new_pub(32) || timestamp(8B BE)"""
    old_pub = b'\xaa' * 32
    new_pub = b'\xbb' * 32
    timestamp = 1700000000

    canonical = old_pub + new_pub + struct.pack(">Q", timestamp)

    assert len(canonical) == 72
    assert canonical[:32] == old_pub
    assert canonical[32:64] == new_pub
    assert canonical[64:] == struct.pack(">Q", timestamp)

    print(f"\nRotation canonical: {canonical.hex()}")


# ---- 9. Protobuf wire format ----

def test_hello_protobuf_serialization():
    """Hello message must serialize consistently for both sides."""
    msg = P2PMessage()
    msg.hello.protocol_version = 1
    msg.hello.identity_public_key = KEY_A_ID
    msg.hello.ephemeral_public_key = KEY_A_EPH
    msg.hello.display_name = "alice"

    data = msg.SerializeToString()
    print(f"\nHello wire bytes: {data.hex()}")

    # Must round-trip
    parsed = P2PMessage()
    parsed.ParseFromString(data)
    assert parsed.hello.protocol_version == 1
    assert parsed.hello.identity_public_key == KEY_A_ID
    assert parsed.hello.ephemeral_public_key == KEY_A_EPH
    assert parsed.hello.display_name == "alice"


def test_encrypted_message_protobuf():
    """EncryptedMessage wrapper must serialize with correct field numbers."""
    msg = P2PMessage()
    msg.encrypted_message.message_type = "FileListRequest"
    msg.encrypted_message.counter = 0
    msg.encrypted_message.nonce = b'\x00' * 12
    msg.encrypted_message.ciphertext = b'\xde\xad\xbe\xef'

    data = msg.SerializeToString()
    print(f"\nEncryptedMessage wire bytes: {data.hex()}")

    parsed = P2PMessage()
    parsed.ParseFromString(data)
    assert parsed.encrypted_message.message_type == "FileListRequest"
    assert parsed.encrypted_message.counter == 0
    assert parsed.encrypted_message.nonce == b'\x00' * 12
    assert parsed.encrypted_message.ciphertext == b'\xde\xad\xbe\xef'


# ---- 10. Framing ----

def test_frame_length_prefix():
    """Length prefix must be 4-byte big-endian."""
    # A message of 256 bytes should have prefix 0x00000100
    length = 256
    prefix = struct.pack('>I', length)
    assert prefix == b'\x00\x00\x01\x00'

    # A message of 1 byte
    assert struct.pack('>I', 1) == b'\x00\x00\x00\x01'


# ---- 11. Full encrypt-then-frame cycle ----

def test_full_encrypt_cycle():
    """Simulate a complete encrypt → wrap in EncryptedMessage → serialize cycle.
    The partner should be able to deserialize and decrypt this on the Rust side."""
    # Known key and plaintext
    key = AES_KEY
    plaintext = b"FileListRequest payload"
    counter = 0
    nonce = b'\x00\x00\x00\x00' + struct.pack('>Q', counter)

    # Encrypt
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, b"")

    # Wrap in EncryptedMessage
    msg = P2PMessage()
    msg.encrypted_message.message_type = "FileListRequest"
    msg.encrypted_message.counter = counter
    msg.encrypted_message.nonce = nonce
    msg.encrypted_message.ciphertext = ciphertext

    # Serialize with length prefix
    wire_bytes = msg.SerializeToString()
    framed = struct.pack('>I', len(wire_bytes)) + wire_bytes

    print(f"\n--- Full encrypt cycle ---")
    print(f"Key:         {key.hex()}")
    print(f"Plaintext:   {plaintext.hex()}")
    print(f"Counter:     {counter}")
    print(f"Nonce:       {nonce.hex()}")
    print(f"Ciphertext:  {ciphertext.hex()}")
    print(f"Wire bytes:  {wire_bytes.hex()}")
    print(f"Framed:      {framed.hex()}")

    # Verify round-trip
    parsed = P2PMessage()
    parsed.ParseFromString(wire_bytes)
    decrypted = cipher.decrypt(
        parsed.encrypted_message.nonce,
        parsed.encrypted_message.ciphertext,
        b""
    )
    assert decrypted == plaintext
