from src.trust import TrustStore
from src.crypto_utils import generate_identity_keypair, get_public_key_bytes


def _make_pubkey():
    _, pub = generate_identity_keypair()
    return get_public_key_bytes(pub)


def test_add_and_is_known():
    store = TrustStore()
    pk = _make_pubkey()
    assert not store.is_known(pk)
    store.add_contact(pk, "alice")
    assert store.is_known(pk)


def test_trusted_after_mark():
    store = TrustStore()
    pk = _make_pubkey()
    store.add_contact(pk, "alice")
    assert not store.is_trusted(pk)
    store.mark_trusted(pk)
    assert store.is_trusted(pk)


def test_key_changed_different_key():
    store = TrustStore()
    pk1 = _make_pubkey()
    pk2 = _make_pubkey()
    store.add_contact(pk1, "alice")
    assert store.check_key_changed("alice", pk2)


def test_key_changed_same_key():
    store = TrustStore()
    pk = _make_pubkey()
    store.add_contact(pk, "alice")
    assert not store.check_key_changed("alice", pk)


def test_to_dict_from_dict_roundtrip():
    store = TrustStore()
    pk = _make_pubkey()
    store.add_contact(pk, "bob", trusted=True)

    data = store.to_dict()
    store2 = TrustStore.from_dict(data)

    assert store2.is_known(pk)
    assert store2.is_trusted(pk)
