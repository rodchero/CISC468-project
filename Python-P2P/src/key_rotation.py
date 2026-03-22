import struct
import time
from src.generated.p2pfileshare_pb2 import KeyRotationNotice
from src.crypto_utils import get_public_key_bytes, sign, verify


def create_rotation_notice(old_priv, old_pub, new_priv, new_pub) -> KeyRotationNotice:
    ts = int(time.time())
    old_pub_bytes = get_public_key_bytes(old_pub)
    new_pub_bytes = get_public_key_bytes(new_pub)

    # Canonical bytes — Rust must match this exact order:
    # old_pubkey(32) || new_pubkey(32) || timestamp(8-byte BE)
    canonical = old_pub_bytes + new_pub_bytes + struct.pack(">Q", ts)

    old_sig = sign(old_priv, canonical)
    new_sig = sign(new_priv, canonical)

    notice = KeyRotationNotice()
    notice.old_public_key = old_pub_bytes
    notice.new_public_key = new_pub_bytes
    notice.timestamp = ts
    notice.old_signature = old_sig
    notice.new_signature = new_sig
    return notice


def verify_rotation_notice(notice, stored_old_pubkey_bytes) -> bool:
    canonical = (
        notice.old_public_key
        + notice.new_public_key
        + struct.pack(">Q", notice.timestamp)
    )

    if not verify(stored_old_pubkey_bytes, notice.old_signature, canonical):
        return False
    if not verify(notice.new_public_key, notice.new_signature, canonical):
        return False

    return True
