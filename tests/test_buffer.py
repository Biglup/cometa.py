import pytest
import math
from biglup.cometa.buffer import Buffer
from biglup.cometa.common.byte_order import ByteOrder

def test_buffer_new():
    buf = Buffer.new(10)
    assert buf.capacity >= 10
    assert len(buf) == 0
    assert not buf  # Test __bool__ for empty


def test_buffer_from_bytes():
    data = b"hello world"
    buf = Buffer.from_bytes(data)
    assert len(buf) == 11
    assert buf.to_bytes() == data
    assert buf


def test_buffer_from_hex():
    hex_str = "deadbeef"
    buf = Buffer.from_hex(hex_str)
    assert len(buf) == 4
    assert buf.to_hex() == hex_str
    assert buf.to_bytes() == b"\xde\xad\xbe\xef"


def test_buffer_indexing():
    buf = Buffer.from_bytes(b"\x01\x02\x03\x04")

    # Positive indices
    assert buf[0] == 1
    assert buf[3] == 4

    # Negative indices
    assert buf[-1] == 4
    assert buf[-4] == 1

    # Out of bounds
    with pytest.raises(IndexError):
        _ = buf[4]
    with pytest.raises(IndexError):
        _ = buf[-5]


def test_buffer_slicing():
    buf = Buffer.from_bytes(b"\x01\x02\x03\x04\x05")

    # Normal slice
    slice1 = buf[1:4]
    assert isinstance(slice1, Buffer)
    assert slice1.to_bytes() == b"\x02\x03\x04"

    # Open ended
    slice2 = buf[2:]
    assert slice2.to_bytes() == b"\x03\x04\x05"

    # Negative slice
    slice3 = buf[:-1]
    assert slice3.to_bytes() == b"\x01\x02\x03\x04"

    # Slice with stride (not supported)
    with pytest.raises(ValueError):
        _ = buf[::2]


def test_buffer_assignment():
    buf = Buffer.from_bytes(b"\x00\x00\x00")
    buf[0] = 0xFF
    buf[1] = 128
    buf[-1] = 1

    assert buf.to_bytes() == b"\xff\x80\x01"

    with pytest.raises(IndexError):
        buf[10] = 1

    with pytest.raises(ValueError):
        buf[0] = 256  # Byte out of range


def test_buffer_iteration():
    data = b"\x01\x02\x03"
    buf = Buffer.from_bytes(data)
    assert list(buf) == [1, 2, 3]


def test_buffer_equality():
    b1 = Buffer.from_bytes(b"abc")
    b2 = Buffer.from_bytes(b"abc")
    b3 = Buffer.from_bytes(b"abd")

    assert b1 == b2
    assert b1 != b3
    assert b1 != "abc"  # Type mismatch


def test_buffer_comparison():
    b1 = Buffer.from_bytes(b"\x01")
    b2 = Buffer.from_bytes(b"\x02")
    b3 = Buffer.from_bytes(b"\x01")

    assert b1 < b2
    assert b2 > b1
    assert b1 <= b3
    assert b1 >= b3
    assert b1.compare(b2) < 0
    assert b2.compare(b1) > 0
    assert b1.compare(b3) == 0


def test_buffer_concatenation():
    b1 = Buffer.from_bytes(b"hello ")
    b2 = Buffer.from_bytes(b"world")
    b3 = b1 + b2

    assert len(b3) == 11
    assert b3.to_bytes() == b"hello world"
    # Ensure originals are untouched
    assert len(b1) == 6


def test_buffer_clone():
    b1 = Buffer.from_bytes(b"data")
    b2 = b1.clone()
    assert b1 == b2

    # Modify clone, check original
    b2[0] = 0xFF
    assert b1 != b2
    assert b1[0] == ord('d')


def test_buffer_strings():
    text = "Cardano"
    buf = Buffer.new(len(text) + 1)
    buf.write(text.encode("utf-8"))
    # Null terminator usually handled by to_str internals or data layout,
    # but strictly from_bytes/write just puts raw bytes.
    # to_str expects valid UTF8.

    # Let's use a safer test for to_str if the C lib expects a null terminator or length
    # Based on bindings, to_str reads `size` bytes and decodes.

    buf2 = Buffer.from_bytes(text.encode("utf-8"))
    assert buf2.to_str() == text


def test_buffer_raw_io():
    buf = Buffer.new(10)
    buf.write(b"1234")
    assert len(buf) == 4

    buf.seek(0)
    read_data = buf.read(2)
    assert read_data == b"12"

    read_rest = buf.read(2)
    assert read_rest == b"34"


def test_buffer_set_size_and_memzero():
    buf = Buffer.from_bytes(b"secret")
    assert len(buf) == 6

    # Expand size (logical only, assumes capacity exists)
    current_cap = buf.capacity
    if current_cap > 6:
        buf.set_size(7)
        assert len(buf) == 7

    # Wipe
    buf.memzero()
    assert buf[0] == 0
    assert buf[1] == 0


def test_context_manager():
    with Buffer.new(10) as buf:
        buf.write(b"test")
        assert len(buf) == 4
    # No explicit check for free possible in python easily,
    # but ensures no exceptions.


# ------------------------------------------------------------------------------
# Typed Read/Write Tests
# ------------------------------------------------------------------------------

def test_rw_uint16():
    buf = Buffer.new(2)
    val = 0x1234

    # Little Endian
    buf.write_uint16(val, ByteOrder.LITTLE_ENDIAN)
    assert buf.to_hex() == "3412"
    buf.seek(0)
    assert buf.read_uint16(ByteOrder.LITTLE_ENDIAN) == val

    # Big Endian
    buf.set_size(0)
    buf.seek(0)
    buf.write_uint16(val, ByteOrder.BIG_ENDIAN)
    assert buf.to_hex() == "1234"
    buf.seek(0)
    assert buf.read_uint16(ByteOrder.BIG_ENDIAN) == val


def test_rw_uint32():
    buf = Buffer.new(4)
    val = 0x12345678

    buf.write_uint32(val, ByteOrder.LITTLE_ENDIAN)
    assert buf.to_hex() == "78563412"
    buf.seek(0)
    assert buf.read_uint32(ByteOrder.LITTLE_ENDIAN) == val


def test_rw_uint64():
    buf = Buffer.new(8)
    val = 0x123456789ABCDEF0

    buf.write_uint64(val, ByteOrder.BIG_ENDIAN)
    assert buf.to_hex() == "123456789abcdef0"
    buf.seek(0)
    assert buf.read_uint64(ByteOrder.BIG_ENDIAN) == val


def test_rw_int_signed():
    buf = Buffer.new(8)
    val = -12345

    buf.write_int16(val, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int16(ByteOrder.LITTLE_ENDIAN) == val

    buf.set_size(0)
    buf.seek(0)
    val32 = -12345678
    buf.write_int32(val32, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int32(ByteOrder.LITTLE_ENDIAN) == val32


def test_rw_float():
    buf = Buffer.new(4)
    val = 3.14159

    buf.write_float(val, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    read_val = buf.read_float(ByteOrder.LITTLE_ENDIAN)
    assert math.isclose(val, read_val, rel_tol=1e-5)


def test_rw_double():
    buf = Buffer.new(8)
    val = 3.1415926535

    buf.write_double(val, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    read_val = buf.read_double(ByteOrder.LITTLE_ENDIAN)
    assert math.isclose(val, read_val, rel_tol=1e-9)


def test_error_handling():
    buf = Buffer.new(10)
    msg = "Custom Error"
    buf.set_last_error(msg)
    assert buf.get_last_error() == msg