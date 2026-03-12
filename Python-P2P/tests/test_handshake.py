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
