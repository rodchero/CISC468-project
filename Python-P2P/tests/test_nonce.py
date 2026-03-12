from src.nonce import NonceManager, CounterValidator


def test_first_nonce_is_zeros():
    nm = NonceManager()
    nonce = nm.next_nonce()
    assert nonce == b'\x00' * 12
    assert len(nonce) == 12


def test_second_nonce_has_counter_one():
    nm = NonceManager()
    nm.next_nonce()  # counter 0
    nonce = nm.next_nonce()  # counter 1
    assert nonce == b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00\x00\x01'


def test_counter_validator_sequential():
    cv = CounterValidator()
    assert cv.validate(0)
    assert cv.validate(1)
    assert cv.validate(2)


def test_counter_validator_rejects_repeat():
    cv = CounterValidator()
    assert cv.validate(0)
    assert not cv.validate(0)  # repeated


def test_counter_validator_rejects_skip():
    cv = CounterValidator()
    assert cv.validate(0)
    assert not cv.validate(2)  # skipped 1
