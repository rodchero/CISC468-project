from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.generated.p2pfileshare_pb2 import P2PMessage
from src.nonce import NonceManager, CounterValidator
from src.framing import send_message, recv_message
from src.errors import P2PError, DECRYPTION_FAILED


class Session:
    def __init__(self, send_key, recv_key, peer_identity_pubkey, peer_display_name, is_initiator):
        self.send_key = send_key
        self.recv_key = recv_key
        self.peer_identity_pubkey = peer_identity_pubkey
        self.peer_display_name = peer_display_name
        self.is_initiator = is_initiator

        self.send_nonce = NonceManager()
        self.recv_validator = CounterValidator()
        self.send_cipher = AESGCM(send_key)
        self.recv_cipher = AESGCM(recv_key)

    def encrypt(self, message_type: str, plaintext: bytes) -> P2PMessage:
        nonce = self.send_nonce.next_nonce()
        ciphertext = self.send_cipher.encrypt(nonce, plaintext, b"")

        msg = P2PMessage()
        msg.encrypted_message.message_type = message_type
        msg.encrypted_message.counter = self.send_nonce.counter - 1
        msg.encrypted_message.nonce = nonce
        msg.encrypted_message.ciphertext = ciphertext
        return msg

    def decrypt(self, msg: P2PMessage):
        enc = msg.encrypted_message
        if not self.recv_validator.validate(enc.counter):
            raise P2PError(DECRYPTION_FAILED, "Invalid counter")

        try:
            plaintext = self.recv_cipher.decrypt(enc.nonce, enc.ciphertext, b"")
        except Exception:
            raise P2PError(DECRYPTION_FAILED, "Decryption failed")

        return enc.message_type, plaintext

    async def send_encrypted(self, writer, message_type: str, inner_message):
        plaintext = inner_message.SerializeToString()
        msg = self.encrypt(message_type, plaintext)
        await send_message(writer, msg)

    async def recv_encrypted(self, reader):
        msg = await recv_message(reader)
        return self.decrypt(msg)
