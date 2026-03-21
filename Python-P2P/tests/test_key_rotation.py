import pytest
from src.crypto_utils import generate_identity_keypair, get_public_key_bytes
from src.key_rotation import create_rotation_notice, verify_rotation_notice
from src.trust import TrustStore
from src.protocol import handle_key_rotation
from src.errors import P2PError, KEY_ROTATION_INVALID


def _make_keypair_bytes():
    priv, pub = generate_identity_keypair()
    return priv, pub, get_public_key_bytes(pub)


def test_create_and_verify():
    old_priv, old_pub, old_bytes = _make_keypair_bytes()
    new_priv, new_pub, new_bytes = _make_keypair_bytes()

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    assert verify_rotation_notice(notice, old_bytes)


def test_verify_wrong_stored_key():
    old_priv, old_pub, _ = _make_keypair_bytes()
    new_priv, new_pub, _ = _make_keypair_bytes()
    _, _, wrong_bytes = _make_keypair_bytes()

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    assert not verify_rotation_notice(notice, wrong_bytes)


def test_verify_tampered_old_signature():
    old_priv, old_pub, old_bytes = _make_keypair_bytes()
    new_priv, new_pub, _ = _make_keypair_bytes()

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    notice.old_signature = b'\x00' * 64
    assert not verify_rotation_notice(notice, old_bytes)


def test_verify_tampered_new_signature():
    old_priv, old_pub, old_bytes = _make_keypair_bytes()
    new_priv, new_pub, _ = _make_keypair_bytes()

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    notice.new_signature = b'\x00' * 64
    assert not verify_rotation_notice(notice, old_bytes)


@pytest.mark.asyncio
async def test_handle_rotation_marks_untrusted():
    old_priv, old_pub, old_bytes = _make_keypair_bytes()
    new_priv, new_pub, new_bytes = _make_keypair_bytes()

    store = TrustStore()
    store.add_contact(old_bytes, "alice", trusted=True)
    assert store.is_trusted(old_bytes)

    notice = create_rotation_notice(old_priv, old_pub, new_priv, new_pub)
    await handle_key_rotation(None, store, notice)

    # Old key should be gone, new key should exist but untrusted
    assert not store.is_known(old_bytes)
    assert store.is_known(new_bytes)
    assert not store.is_trusted(new_bytes)
