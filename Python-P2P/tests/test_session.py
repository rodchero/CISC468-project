import os
import pytest
from src.session import Session
from src.errors import P2PError, DECRYPTION_FAILED


def _make_session_pair():
    """Create an initiator and responder session with matching keys."""
    send_key = os.urandom(32)
    recv_key = os.urandom(32)
    # Initiator sends with send_key, responder receives with send_key
    initiator = Session(send_key, recv_key, b'\x00' * 32, "bob", True)
    responder = Session(recv_key, send_key, b'\x00' * 32, "alice", False)
    return initiator, responder


def test_encrypt_decrypt_roundtrip():
    initiator, responder = _make_session_pair()

    msg = initiator.encrypt("FileListRequest", b"hello")
    msg_type, plaintext = responder.decrypt(msg)

    assert msg_type == "FileListRequest"
    assert plaintext == b"hello"


def test_decrypt_wrong_key():
    initiator, _ = _make_session_pair()
    # Make a responder with wrong keys
    wrong = Session(os.urandom(32), os.urandom(32), b'\x00' * 32, "eve", False)

    msg = initiator.encrypt("FileListRequest", b"secret")
    with pytest.raises(P2PError) as exc_info:
        wrong.decrypt(msg)
    assert exc_info.value.error_code == DECRYPTION_FAILED


def test_replayed_counter_rejected():
    initiator, responder = _make_session_pair()

    msg = initiator.encrypt("FileListRequest", b"first")
    responder.decrypt(msg)  # counter 0, should work

    # Try to decrypt the same message again (counter 0 replayed)
    with pytest.raises(P2PError) as exc_info:
        responder.decrypt(msg)
    assert exc_info.value.error_code == DECRYPTION_FAILED


def test_skipped_counter_rejected():
    initiator, responder = _make_session_pair()

    initiator.encrypt("FileListRequest", b"first")   # counter 0, not sent to responder
    msg2 = initiator.encrypt("FileListRequest", b"second")  # counter 1

    # Responder expects 0 but gets 1
    with pytest.raises(P2PError) as exc_info:
        responder.decrypt(msg2)
    assert exc_info.value.error_code == DECRYPTION_FAILED


def test_three_messages_sequential():
    initiator, responder = _make_session_pair()

    for i in range(3):
        msg = initiator.encrypt("FileChunk", f"chunk-{i}".encode())
        msg_type, plaintext = responder.decrypt(msg)
        assert msg_type == "FileChunk"
        assert plaintext == f"chunk-{i}".encode()
