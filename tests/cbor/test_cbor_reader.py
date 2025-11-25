import pytest

from biglup.cometa.cbor import CborReader


def test_read_uint_from_hex():
    # CBOR encoding for unsigned integer 42 is 0x18 0x2a
    reader = CborReader.from_hex("182a")

    value = reader.read_uint()
    assert value == 42

    # After reading, no bytes should remain
    remaining = reader.get_bytes_remaining()
    assert remaining == 0


def test_read_int_negative_and_positive():
    # 0x01  -> positive 1
    # 0x20  -> -1  (CBOR: major type 1, value 0 => -1)
    reader = CborReader.from_hex("0120")

    v1 = reader.read_int()
    v2 = reader.read_int()

    assert v1 == 1
    assert v2 == -1

    assert reader.get_bytes_remaining() == 0


def test_read_bool_and_null():
    # CBOR: true (0xf5), false (0xf4), null (0xf6)
    reader = CborReader.from_hex("f5f4f6")

    b1 = reader.read_bool()
    b2 = reader.read_bool()
    reader.read_null()

    assert b1 is True
    assert b2 is False
    assert reader.get_bytes_remaining() == 0


def test_cbor_reader_clone_and_refcount():
    # small definite sequence: uint 1 then uint 2
    reader = CborReader.from_hex("0102")

    # refcount should be >= 1
    rc_before = reader.refcount()
    assert rc_before >= 1

    clone = reader.clone()
    rc_after = reader.refcount()
    # some implementations increment refcount by 1
    assert rc_after >= rc_before

    # readers operate independently but share underlying data position
    v1 = reader.read_uint()
    v2 = clone.read_uint()

    assert v1 == 1
    assert v2 == 1  # clone starts from same initial state

    # We don't assert refcount after destruction; just ensure no exceptions.
