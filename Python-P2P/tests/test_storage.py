import pytest
from src.storage import SecureStorage


def test_save_and_load(tmp_path):
    store = SecureStorage(str(tmp_path / "vault"))
    store.setup("mypassword")

    store.save("secret.dat", b"hello world")
    result = store.load("secret.dat")
    assert result == b"hello world"


def test_wrong_password_fails(tmp_path):
    vault_dir = str(tmp_path / "vault")

    store1 = SecureStorage(vault_dir)
    store1.setup("correct-password")
    store1.save("secret.dat", b"sensitive data")

    store2 = SecureStorage(vault_dir)
    store2.setup("wrong-password")
    with pytest.raises(Exception):
        store2.load("secret.dat")


def test_multiple_keys(tmp_path):
    store = SecureStorage(str(tmp_path / "vault"))
    store.setup("pass123")

    store.save("key_a", b"value_a")
    store.save("key_b", b"value_b")

    assert store.load("key_a") == b"value_a"
    assert store.load("key_b") == b"value_b"


def test_load_nonexistent(tmp_path):
    store = SecureStorage(str(tmp_path / "vault"))
    store.setup("pass")

    assert store.load("nope") is None
