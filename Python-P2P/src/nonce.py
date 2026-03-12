import struct


class NonceManager:
    def __init__(self):
        self.counter = 0

    def next_nonce(self) -> bytes:
        # 4 zero bytes + 8-byte big-endian counter
        nonce = b'\x00\x00\x00\x00' + struct.pack('>Q', self.counter)
        self.counter += 1
        return nonce


class CounterValidator:
    def __init__(self):
        self.expected = 0

    def validate(self, received_counter: int) -> bool:
        if received_counter != self.expected:
            return False
        self.expected += 1
        return True
