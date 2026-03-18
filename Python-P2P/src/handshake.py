import struct
from src.generated.p2pfileshare_pb2 import P2PMessage
from src.crypto_utils import (
    get_public_key_bytes, get_ephemeral_public_bytes,
    generate_ephemeral_keypair, sha256, sign, verify,
    compute_shared_secret as x25519_shared_secret,
    derive_session_keys as hkdf_derive,
)
from src.errors import P2PError, UNSUPPORTED_PROTOCOL_VERSION, AUTH_FAILED
from src.framing import send_message, recv_message
from src.session import Session

PROTOCOL_VERSION = 1


class Handshake:
    def __init__(self, identity_private_key, identity_public_key, display_name, is_initiator):
        self.identity_priv = identity_private_key
        self.identity_pub = identity_public_key
        self.identity_pub_bytes = get_public_key_bytes(identity_public_key)
        self.display_name = display_name
        self.is_initiator = is_initiator

        # Fresh ephemeral keypair for this session
        self.ephemeral_priv, self.ephemeral_pub = generate_ephemeral_keypair()
        self.ephemeral_pub_bytes = get_ephemeral_public_bytes(self.ephemeral_pub)

        # Filled in when we process the peer's Hello
        self.peer_identity_pub_bytes = None
        self.peer_ephemeral_pub_bytes = None
        self.peer_display_name = None

        self.transcript_hash = None
        self.shared_secret = None
        self.send_key = None
        self.recv_key = None

    def create_hello(self) -> P2PMessage:
        msg = P2PMessage()
        msg.hello.protocol_version = PROTOCOL_VERSION
        msg.hello.identity_public_key = self.identity_pub_bytes
        msg.hello.ephemeral_public_key = self.ephemeral_pub_bytes
        msg.hello.display_name = self.display_name
        return msg

    def process_hello(self, msg: P2PMessage):
        hello = msg.hello
        if hello.protocol_version != PROTOCOL_VERSION:
            raise P2PError(
                UNSUPPORTED_PROTOCOL_VERSION,
                f"Expected {PROTOCOL_VERSION}, got {hello.protocol_version}",
            )
        self.peer_identity_pub_bytes = hello.identity_public_key
        self.peer_ephemeral_pub_bytes = hello.ephemeral_public_key
        self.peer_display_name = hello.display_name

    def build_transcript(self) -> bytes:
        if self.is_initiator:
            init_id = self.identity_pub_bytes
            init_eph = self.ephemeral_pub_bytes
            resp_id = self.peer_identity_pub_bytes
            resp_eph = self.peer_ephemeral_pub_bytes
        else:
            init_id = self.peer_identity_pub_bytes
            init_eph = self.peer_ephemeral_pub_bytes
            resp_id = self.identity_pub_bytes
            resp_eph = self.ephemeral_pub_bytes

        transcript = struct.pack('>I', PROTOCOL_VERSION) + init_id + init_eph + resp_id + resp_eph
        return transcript

    def compute_transcript_hash(self) -> bytes:
        transcript = self.build_transcript()
        self.transcript_hash = sha256(transcript)
        return self.transcript_hash

    def sign_transcript(self) -> bytes:
        return sign(self.identity_priv, self.transcript_hash)

    def create_auth_message(self) -> P2PMessage:
        sig = self.sign_transcript()
        msg = P2PMessage()
        msg.auth_signature.signature = sig
        return msg

    def verify_peer_signature(self, msg: P2PMessage) -> bool:
        sig = msg.auth_signature.signature
        return verify(self.peer_identity_pub_bytes, sig, self.transcript_hash)

    def compute_shared_secret(self):
        self.shared_secret = x25519_shared_secret(
            self.ephemeral_priv, self.peer_ephemeral_pub_bytes
        )
        return self.shared_secret

    def derive_session_keys(self):
        key_i2r, key_r2i = hkdf_derive(self.shared_secret)
        if self.is_initiator:
            self.send_key = key_i2r
            self.recv_key = key_r2i
        else:
            self.send_key = key_r2i
            self.recv_key = key_i2r
        return self.send_key, self.recv_key


async def perform_handshake_initiator(reader, writer, identity_priv, identity_pub, display_name) -> Session:
    hs = Handshake(identity_priv, identity_pub, display_name, is_initiator=True)

    # 1. Send our Hello, then receive peer's Hello
    await send_message(writer, hs.create_hello())
    peer_hello = await recv_message(reader)
    hs.process_hello(peer_hello)

    # 2. Compute shared secret and transcript
    hs.compute_shared_secret()
    hs.compute_transcript_hash()

    # 3. Send our AuthSignature, then receive peer's
    await send_message(writer, hs.create_auth_message())
    peer_auth = await recv_message(reader)
    if not hs.verify_peer_signature(peer_auth):
        raise P2PError(AUTH_FAILED, "Peer signature verification failed")

    # 4. Derive keys and return session
    send_key, recv_key = hs.derive_session_keys()
    return Session(send_key, recv_key, hs.peer_identity_pub_bytes, hs.peer_display_name, True)


async def perform_handshake_responder(reader, writer, identity_priv, identity_pub, display_name) -> Session:
    hs = Handshake(identity_priv, identity_pub, display_name, is_initiator=False)

    # 1. Receive peer's Hello, then send ours
    peer_hello = await recv_message(reader)
    hs.process_hello(peer_hello)
    await send_message(writer, hs.create_hello())

    # 2. Compute shared secret and transcript
    hs.compute_shared_secret()
    hs.compute_transcript_hash()

    # 3. Receive peer's AuthSignature, verify, then send ours
    peer_auth = await recv_message(reader)
    if not hs.verify_peer_signature(peer_auth):
        raise P2PError(AUTH_FAILED, "Peer signature verification failed")
    await send_message(writer, hs.create_auth_message())

    # 4. Derive keys and return session
    send_key, recv_key = hs.derive_session_keys()
    return Session(send_key, recv_key, hs.peer_identity_pub_bytes, hs.peer_display_name, False)
