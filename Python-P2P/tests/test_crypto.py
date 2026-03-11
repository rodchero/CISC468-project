from src.crypto_utils import (
    generate_identity_keypair, get_public_key_bytes,
    sign, verify, private_key_to_seed, seed_to_private_key,
    sha256, fingerprint,
)


def test_sign_and_verify():
    priv, pub = generate_identity_keypair()
    pub_bytes = get_public_key_bytes(pub)

    data = b"hello world"
    sig = sign(priv, data)

    assert len(sig) == 64
    assert verify(pub_bytes, sig, data)


def test_verify_rejects_tampered_data():
    priv, pub = generate_identity_keypair()
    pub_bytes = get_public_key_bytes(pub)

    sig = sign(priv, b"original")
    assert not verify(pub_bytes, sig, b"tampered")


def test_seed_roundtrip():
    priv, pub = generate_identity_keypair()
    seed = private_key_to_seed(priv)
    assert len(seed) == 32

    priv2 = seed_to_private_key(seed)
    data = b"test message"
    sig1 = sign(priv, data)
    sig2 = sign(priv2, data)
    assert sig1 == sig2


def test_fingerprint_deterministic():
    _, pub = generate_identity_keypair()
    pub_bytes = get_public_key_bytes(pub)

    fp1 = fingerprint(pub_bytes)
    fp2 = fingerprint(pub_bytes)
    assert fp1 == fp2
    # Should be colon-separated hex, 32 bytes = 95 chars (32*2 + 31 colons)
    assert len(fp1) == 95
    assert fp1.count(":") == 31
