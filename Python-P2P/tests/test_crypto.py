from src.crypto_utils import (
    generate_identity_keypair, get_public_key_bytes,
    sign, verify, private_key_to_seed, seed_to_private_key,
    sha256, fingerprint,
    generate_ephemeral_keypair, get_ephemeral_public_bytes,
    compute_shared_secret, derive_session_keys,
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


# --- X25519 tests ---

def test_x25519_shared_secret():
    priv_a, pub_a = generate_ephemeral_keypair()
    priv_b, pub_b = generate_ephemeral_keypair()

    pub_a_bytes = get_ephemeral_public_bytes(pub_a)
    pub_b_bytes = get_ephemeral_public_bytes(pub_b)

    secret_a = compute_shared_secret(priv_a, pub_b_bytes)
    secret_b = compute_shared_secret(priv_b, pub_a_bytes)
    assert secret_a == secret_b
    assert len(secret_a) == 32


def test_derive_session_keys():
    priv_a, pub_a = generate_ephemeral_keypair()
    priv_b, pub_b = generate_ephemeral_keypair()
    shared = compute_shared_secret(priv_a, get_ephemeral_public_bytes(pub_b))

    key_i2r, key_r2i = derive_session_keys(shared)
    assert len(key_i2r) == 32
    assert len(key_r2i) == 32
    assert key_i2r != key_r2i


def test_different_secrets_give_different_keys():
    priv_a, _ = generate_ephemeral_keypair()
    _, pub_b = generate_ephemeral_keypair()
    _, pub_c = generate_ephemeral_keypair()

    secret1 = compute_shared_secret(priv_a, get_ephemeral_public_bytes(pub_b))
    secret2 = compute_shared_secret(priv_a, get_ephemeral_public_bytes(pub_c))

    keys1 = derive_session_keys(secret1)
    keys2 = derive_session_keys(secret2)
    assert keys1 != keys2
