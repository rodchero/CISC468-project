import struct
from src.generated.p2pfileshare_pb2 import P2PMessage
from src.crypto_utils import (
    get_public_key_bytes, get_ephemeral_public_bytes,
    generate_ephemeral_keypair, sha256,
)
from src.errors import P2PError, UNSUPPORTED_PROTOCOL_VERSION

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
