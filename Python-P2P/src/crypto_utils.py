import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.exceptions import InvalidSignature


def generate_identity_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def get_public_key_bytes(public_key) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data)


def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def private_key_to_seed(private_key) -> bytes:
    # Raw private key bytes for Ed25519 = the 32-byte seed
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return raw


def seed_to_private_key(seed: bytes):
    return Ed25519PrivateKey.from_private_bytes(seed)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def fingerprint(public_key_bytes: bytes) -> str:
    digest = sha256(public_key_bytes)
    return ":".join(f"{b:02x}" for b in digest)
