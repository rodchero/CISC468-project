import pytest
from src.crypto_utils import generate_identity_keypair
from src.handshake import Handshake
from src.errors import P2PError, UNSUPPORTED_PROTOCOL_VERSION
from src.generated.p2pfileshare_pb2 import P2PMessage


def test_create_hello_fields():
    priv, pub = generate_identity_keypair()
    hs = Handshake(priv, pub, "alice", is_initiator=True)

    msg = hs.create_hello()
    hello = msg.hello
    assert hello.protocol_version == 1
    assert len(hello.identity_public_key) == 32
    assert len(hello.ephemeral_public_key) == 32
    assert hello.display_name == "alice"


def test_process_hello_bad_version():
    priv, pub = generate_identity_keypair()
    hs = Handshake(priv, pub, "alice", is_initiator=True)

    msg = P2PMessage()
    msg.hello.protocol_version = 99
    msg.hello.identity_public_key = b'\x00' * 32
    msg.hello.ephemeral_public_key = b'\x00' * 32
    msg.hello.display_name = "evil"

    with pytest.raises(P2PError) as exc_info:
        hs.process_hello(msg)
    assert exc_info.value.error_code == UNSUPPORTED_PROTOCOL_VERSION


def test_transcript_matches_both_sides():
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    initiator = Handshake(priv_a, pub_a, "alice", is_initiator=True)
    responder = Handshake(priv_b, pub_b, "bob", is_initiator=False)

    # Exchange Hellos
    hello_a = initiator.create_hello()
    hello_b = responder.create_hello()
    initiator.process_hello(hello_b)
    responder.process_hello(hello_a)

    t_init = initiator.build_transcript()
    t_resp = responder.build_transcript()
    assert t_init == t_resp


def test_transcript_length():
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    initiator = Handshake(priv_a, pub_a, "alice", is_initiator=True)
    responder = Handshake(priv_b, pub_b, "bob", is_initiator=False)

    hello_a = initiator.create_hello()
    hello_b = responder.create_hello()
    initiator.process_hello(hello_b)
    responder.process_hello(hello_a)

    # 4 (version) + 32*4 (four pubkeys) = 132
    assert len(initiator.build_transcript()) == 132


def test_transcript_hash_matches():
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    initiator = Handshake(priv_a, pub_a, "alice", is_initiator=True)
    responder = Handshake(priv_b, pub_b, "bob", is_initiator=False)

    hello_a = initiator.create_hello()
    hello_b = responder.create_hello()
    initiator.process_hello(hello_b)
    responder.process_hello(hello_a)

    hash_a = initiator.compute_transcript_hash()
    hash_b = responder.compute_transcript_hash()
    assert hash_a == hash_b
    assert len(hash_a) == 32


# --- Day 7: signing, verification, key derivation ---

def _do_hello_exchange():
    """Helper: create two Handshake instances and exchange Hellos."""
    priv_a, pub_a = generate_identity_keypair()
    priv_b, pub_b = generate_identity_keypair()

    initiator = Handshake(priv_a, pub_a, "alice", is_initiator=True)
    responder = Handshake(priv_b, pub_b, "bob", is_initiator=False)

    initiator.process_hello(responder.create_hello())
    responder.process_hello(initiator.create_hello())

    initiator.compute_transcript_hash()
    responder.compute_transcript_hash()

    return initiator, responder


def test_sign_and_verify_both_sides():
    initiator, responder = _do_hello_exchange()

    auth_a = initiator.create_auth_message()
    auth_b = responder.create_auth_message()

    assert responder.verify_peer_signature(auth_a)
    assert initiator.verify_peer_signature(auth_b)


def test_verify_fails_wrong_key():
    initiator, responder = _do_hello_exchange()

    auth_a = initiator.create_auth_message()

    # Make a third party and try to pass off initiator's sig
    priv_c, pub_c = generate_identity_keypair()
    imposter = Handshake(priv_c, pub_c, "charlie", is_initiator=False)
    imposter.process_hello(initiator.create_hello())
    imposter.compute_transcript_hash()

    # Responder should reject because sig was made by initiator, not imposter
    # But let's check: imposter tries to verify initiator's auth with wrong peer key
    imposter.peer_identity_pub_bytes = responder.identity_pub_bytes  # wrong key
    assert not imposter.verify_peer_signature(auth_a)


def test_verify_fails_tampered_hash():
    initiator, responder = _do_hello_exchange()

    auth_a = initiator.create_auth_message()

    # Tamper with responder's transcript hash
    responder.transcript_hash = b'\x00' * 32
    assert not responder.verify_peer_signature(auth_a)


def test_session_keys_cross_match():
    initiator, responder = _do_hello_exchange()

    initiator.compute_shared_secret()
    responder.compute_shared_secret()

    i_send, i_recv = initiator.derive_session_keys()
    r_send, r_recv = responder.derive_session_keys()

    assert i_send == r_recv  # initiator's send = responder's recv
    assert i_recv == r_send  # initiator's recv = responder's send
    assert len(i_send) == 32
