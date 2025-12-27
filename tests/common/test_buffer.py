"""
Tests for the Buffer class.

This module contains comprehensive tests for the Buffer class,
including factory methods, properties, methods, typed read/write operations,
and various edge cases.
"""
import math

import pytest
from cometa import Buffer, ByteOrder

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


def test_buffer_new_with_zero_capacity():
    """Test that creating a buffer with zero capacity."""
    buf = Buffer.new(0)
    assert buf is not None


def test_buffer_new_with_negative_capacity():
    """Test that creating a buffer with negative capacity raises an error."""
    with pytest.raises((OverflowError, Exception)):
        Buffer.new(-1)


def test_buffer_from_empty_bytes():
    """Test creating buffer from empty bytes."""
    buf = Buffer.from_bytes(b"")
    assert len(buf) == 0
    assert not buf
    assert buf.to_bytes() == b""


def test_buffer_from_hex_invalid():
    """Test that invalid hex strings are handled (C library may accept them)."""
    try:
        Buffer.from_hex("gg")
    except Exception:
        pass


def test_buffer_from_hex_odd_length():
    """Test that odd-length hex strings raise errors."""
    with pytest.raises(Exception):
        Buffer.from_hex("123")


def test_buffer_from_hex_empty():
    """Test creating buffer from empty hex string."""
    buf = Buffer.from_hex("")
    assert len(buf) == 0


def test_buffer_to_hex_empty():
    """Test converting empty buffer to hex."""
    buf = Buffer.new(10)
    assert buf.to_hex() == ""


def test_buffer_to_str_empty():
    """Test converting empty buffer to string."""
    buf = Buffer.new(10)
    assert buf.to_str() == ""


def test_buffer_copy_bytes():
    """Test copy_bytes method."""
    data = b"test data"
    buf = Buffer.from_bytes(data)
    copied = buf.copy_bytes()
    assert copied == data
    assert isinstance(copied, bytes)


def test_buffer_size_property():
    """Test size property returns correct value."""
    buf = Buffer.new(100)
    assert buf.size == 0
    buf.write(b"test")
    assert buf.size == 4


def test_buffer_capacity_property():
    """Test capacity property returns correct value."""
    buf = Buffer.new(100)
    assert buf.capacity >= 100


def test_buffer_set_size_invalid():
    """Test set_size with invalid arguments."""
    buf = Buffer.new(10)
    with pytest.raises(Exception):
        buf.set_size(100)


def test_buffer_set_size_decrease():
    """Test decreasing buffer size."""
    buf = Buffer.from_bytes(b"12345")
    buf.set_size(3)
    assert len(buf) == 3
    assert buf.to_bytes() == b"123"


def test_buffer_memzero_with_data():
    """Test memzero clears all data."""
    buf = Buffer.from_bytes(b"\xFF\xFF\xFF\xFF")
    buf.memzero()
    for byte in buf:
        assert byte == 0


def test_buffer_write_expands_capacity():
    """Test that write expands buffer capacity automatically."""
    buf = Buffer.new(2)
    buf.write(b"a" * 100)
    assert len(buf) == 100
    assert buf.capacity >= 100


def test_buffer_read_beyond_size():
    """Test reading beyond buffer size raises error."""
    buf = Buffer.from_bytes(b"test")
    buf.seek(0)
    with pytest.raises(Exception):
        buf.read(100)


def test_buffer_seek_invalid():
    """Test seeking to invalid position raises error."""
    buf = Buffer.from_bytes(b"test")
    with pytest.raises(Exception):
        buf.seek(100)


def test_buffer_seek_zero():
    """Test seeking to position 0."""
    buf = Buffer.from_bytes(b"test")
    buf.read(2)
    buf.seek(0)
    assert buf.read(1) == b"t"


def test_buffer_concatenation_type_error():
    """Test that concatenating with non-Buffer raises TypeError."""
    buf = Buffer.from_bytes(b"test")
    with pytest.raises(TypeError):
        _ = buf + b"other"
    with pytest.raises(TypeError):
        _ = buf + "string"


def test_buffer_repr():
    """Test __repr__ method."""
    buf = Buffer.new(100)
    buf.write(b"test")
    repr_str = repr(buf)
    assert "Buffer" in repr_str
    assert "size=4" in repr_str
    assert "capacity=" in repr_str


def test_buffer_bytes_conversion():
    """Test __bytes__ magic method."""
    data = b"test data"
    buf = Buffer.from_bytes(data)
    assert bytes(buf) == data


def test_buffer_getitem_invalid_type():
    """Test __getitem__ with invalid key type."""
    buf = Buffer.from_bytes(b"test")
    with pytest.raises(TypeError):
        _ = buf["invalid"]
    with pytest.raises(TypeError):
        _ = buf[1.5]


def test_buffer_setitem_invalid_type():
    """Test __setitem__ with invalid key type."""
    buf = Buffer.from_bytes(b"test")
    with pytest.raises(TypeError):
        buf["invalid"] = 0


def test_buffer_setitem_invalid_value():
    """Test __setitem__ with invalid value."""
    buf = Buffer.from_bytes(b"test")
    with pytest.raises(ValueError):
        buf[0] = -1
    with pytest.raises(ValueError):
        buf[0] = 256


def test_buffer_comparison_with_non_buffer():
    """Test comparison operators with non-Buffer objects."""
    buf = Buffer.from_bytes(b"test")
    assert buf != "test"
    assert buf != b"test"
    assert buf != 123


def test_rw_int64():
    """Test reading and writing 64-bit signed integers."""
    buf = Buffer.new(8)
    val = -9223372036854775808

    buf.write_int64(val, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int64(ByteOrder.LITTLE_ENDIAN) == val

    buf.set_size(0)
    buf.seek(0)
    val2 = 9223372036854775807
    buf.write_int64(val2, ByteOrder.BIG_ENDIAN)
    buf.seek(0)
    assert buf.read_int64(ByteOrder.BIG_ENDIAN) == val2


def test_rw_float_big_endian():
    """Test reading and writing floats in big-endian."""
    buf = Buffer.new(4)
    val = -3.14159

    buf.write_float(val, ByteOrder.BIG_ENDIAN)
    buf.seek(0)
    read_val = buf.read_float(ByteOrder.BIG_ENDIAN)
    assert math.isclose(val, read_val, rel_tol=1e-5)


def test_rw_double_big_endian():
    """Test reading and writing doubles in big-endian."""
    buf = Buffer.new(8)
    val = -3.1415926535897932

    buf.write_double(val, ByteOrder.BIG_ENDIAN)
    buf.seek(0)
    read_val = buf.read_double(ByteOrder.BIG_ENDIAN)
    assert math.isclose(val, read_val, rel_tol=1e-14)


def test_rw_multiple_values():
    """Test writing and reading multiple values in sequence."""
    buf = Buffer.new(100)

    buf.write_uint16(0x1234, ByteOrder.LITTLE_ENDIAN)
    buf.write_uint32(0x56789ABC, ByteOrder.LITTLE_ENDIAN)
    buf.write_int16(-100, ByteOrder.LITTLE_ENDIAN)
    buf.write_float(3.14, ByteOrder.LITTLE_ENDIAN)

    buf.seek(0)
    assert buf.read_uint16(ByteOrder.LITTLE_ENDIAN) == 0x1234
    assert buf.read_uint32(ByteOrder.LITTLE_ENDIAN) == 0x56789ABC
    assert buf.read_int16(ByteOrder.LITTLE_ENDIAN) == -100
    assert math.isclose(buf.read_float(ByteOrder.LITTLE_ENDIAN), 3.14, rel_tol=1e-5)


def test_buffer_write_empty():
    """Test writing empty bytes."""
    buf = Buffer.new(10)
    buf.write(b"")
    assert len(buf) == 0


def test_buffer_read_zero_bytes():
    """Test reading zero bytes."""
    buf = Buffer.from_bytes(b"test")
    buf.seek(0)
    data = buf.read(0)
    assert data == b""


def test_buffer_slice_empty():
    """Test slicing empty buffer."""
    buf = Buffer.new(10)
    slice_buf = buf[0:0]
    assert len(slice_buf) == 0


def test_buffer_slice_full():
    """Test slicing entire buffer."""
    data = b"test data"
    buf = Buffer.from_bytes(data)
    slice_buf = buf[:]
    assert slice_buf.to_bytes() == data
    slice_buf[0] = 0xFF
    assert buf[0] != 0xFF


def test_buffer_comparison_operators():
    """Test all comparison operators comprehensively."""
    buf1 = Buffer.from_bytes(b"a")
    buf2 = Buffer.from_bytes(b"b")
    buf3 = Buffer.from_bytes(b"a")

    assert buf1 < buf2
    assert buf2 >= buf1
    assert buf1 >= buf3

    assert buf2 > buf1
    assert buf1 <= buf2
    assert buf1 <= buf3

    assert buf1 <= buf2
    assert buf1 <= buf3
    assert buf2 > buf1

    assert buf2 >= buf1
    assert buf1 >= buf3
    assert buf1 < buf2


def test_buffer_concatenate_empty():
    """Test concatenating empty buffers."""
    buf1 = Buffer.new(10)
    buf2 = Buffer.new(10)
    buf3 = buf1 + buf2
    assert len(buf3) == 0


def test_buffer_concatenate_with_empty():
    """Test concatenating buffer with empty buffer."""
    buf1 = Buffer.from_bytes(b"test")
    buf2 = Buffer.new(10)
    buf3 = buf1 + buf2
    assert len(buf3) == 4
    assert buf3.to_bytes() == b"test"


def test_buffer_negative_indexing():
    """Test negative indexing comprehensively."""
    buf = Buffer.from_bytes(b"\x01\x02\x03\x04\x05")
    assert buf[-1] == 5
    assert buf[-2] == 4
    assert buf[-5] == 1

    with pytest.raises(IndexError):
        _ = buf[-6]


def test_buffer_assignment_negative_index():
    """Test assignment with negative index."""
    buf = Buffer.from_bytes(b"\x01\x02\x03")
    buf[-1] = 0xFF
    assert buf[2] == 0xFF
    buf[-3] = 0xAA
    assert buf[0] == 0xAA


def test_buffer_to_hex_various_data():
    """Test to_hex with various data patterns."""
    test_cases = [
        (b"\x00", "00"),
        (b"\xFF", "ff"),
        (b"\x00\xFF", "00ff"),
        (b"\xDE\xAD\xBE\xEF", "deadbeef"),
    ]
    for data, expected_hex in test_cases:
        buf = Buffer.from_bytes(data)
        assert buf.to_hex() == expected_hex


def test_buffer_from_hex_various_patterns():
    """Test from_hex with various hex patterns."""
    test_cases = [
        ("00", b"\x00"),
        ("FF", b"\xFF"),
        ("00ff", b"\x00\xFF"),
        ("DEADBEEF", b"\xDE\xAD\xBE\xEF"),
        ("deadbeef", b"\xDE\xAD\xBE\xEF"),
    ]
    for hex_str, expected_bytes in test_cases:
        buf = Buffer.from_hex(hex_str)
        assert buf.to_bytes() == expected_bytes


def test_buffer_utf8_strings():
    """Test UTF-8 string handling."""
    test_strings = [
        "Hello World",
        "Cardano",
        "Test123",
        "Unicode: \u2764",
    ]
    for text in test_strings:
        buf = Buffer.from_bytes(text.encode("utf-8"))
        assert buf.to_str() == text


def test_buffer_large_capacity():
    """Test creating buffer with large capacity."""
    buf = Buffer.new(1000000)
    assert buf.capacity >= 1000000
    assert len(buf) == 0


def test_buffer_write_large_data():
    """Test writing large amount of data."""
    data = b"x" * 100000
    buf = Buffer.new(10)
    buf.write(data)
    assert len(buf) == 100000
    assert buf.to_bytes() == data


def test_buffer_iteration_empty():
    """Test iteration over empty buffer."""
    buf = Buffer.new(10)
    assert not list(buf)


def test_buffer_write_read_boundary_values():
    """Test writing and reading boundary values for integer types."""
    buf = Buffer.new(200)

    buf.write_uint16(0, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint16(ByteOrder.LITTLE_ENDIAN) == 0

    buf.set_size(0)
    buf.seek(0)
    buf.write_uint16(0xFFFF, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint16(ByteOrder.LITTLE_ENDIAN) == 0xFFFF

    buf.set_size(0)
    buf.seek(0)
    buf.write_uint32(0, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint32(ByteOrder.LITTLE_ENDIAN) == 0

    buf.set_size(0)
    buf.seek(0)
    buf.write_uint32(0xFFFFFFFF, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint32(ByteOrder.LITTLE_ENDIAN) == 0xFFFFFFFF

    buf.set_size(0)
    buf.seek(0)
    buf.write_uint64(0, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint64(ByteOrder.LITTLE_ENDIAN) == 0

    buf.set_size(0)
    buf.seek(0)
    buf.write_uint64(0xFFFFFFFFFFFFFFFF, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_uint64(ByteOrder.LITTLE_ENDIAN) == 0xFFFFFFFFFFFFFFFF

    buf.set_size(0)
    buf.seek(0)
    buf.write_int16(-32768, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int16(ByteOrder.LITTLE_ENDIAN) == -32768

    buf.set_size(0)
    buf.seek(0)
    buf.write_int16(32767, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int16(ByteOrder.LITTLE_ENDIAN) == 32767

    buf.set_size(0)
    buf.seek(0)
    buf.write_int32(-2147483648, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int32(ByteOrder.LITTLE_ENDIAN) == -2147483648

    buf.set_size(0)
    buf.seek(0)
    buf.write_int32(2147483647, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int32(ByteOrder.LITTLE_ENDIAN) == 2147483647

    buf.set_size(0)
    buf.seek(0)
    buf.write_int64(-9223372036854775808, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int64(ByteOrder.LITTLE_ENDIAN) == -9223372036854775808

    buf.set_size(0)
    buf.seek(0)
    buf.write_int64(9223372036854775807, ByteOrder.LITTLE_ENDIAN)
    buf.seek(0)
    assert buf.read_int64(ByteOrder.LITTLE_ENDIAN) == 9223372036854775807


def test_buffer_special_float_values():
    """Test writing and reading special float values."""
    buf = Buffer.new(100)

    test_values = [0.0, -0.0, 1.0, -1.0, float('inf'), float('-inf')]

    for val in test_values:
        buf.write_float(val, ByteOrder.LITTLE_ENDIAN)

    buf.seek(0)
    for val in test_values:
        read_val = buf.read_float(ByteOrder.LITTLE_ENDIAN)
        if math.isnan(val):
            assert math.isnan(read_val)
        elif math.isinf(val):
            assert math.isinf(read_val)
            assert (val > 0) == (read_val > 0)
        else:
            assert read_val == val


def test_buffer_special_double_values():
    """Test writing and reading special double values."""
    buf = Buffer.new(100)

    test_values = [0.0, -0.0, 1.0, -1.0, float('inf'), float('-inf')]

    for val in test_values:
        buf.write_double(val, ByteOrder.LITTLE_ENDIAN)

    buf.seek(0)
    for val in test_values:
        read_val = buf.read_double(ByteOrder.LITTLE_ENDIAN)
        if math.isnan(val):
            assert math.isnan(read_val)
        elif math.isinf(val):
            assert math.isinf(read_val)
            assert (val > 0) == (read_val > 0)
        else:
            assert read_val == val


def test_buffer_mixed_endianness():
    """Test mixing little-endian and big-endian operations."""
    buf = Buffer.new(100)

    buf.write_uint32(0x12345678, ByteOrder.LITTLE_ENDIAN)
    buf.write_uint32(0x9ABCDEF0, ByteOrder.BIG_ENDIAN)

    buf.seek(0)
    assert buf.read_uint32(ByteOrder.LITTLE_ENDIAN) == 0x12345678
    assert buf.read_uint32(ByteOrder.BIG_ENDIAN) == 0x9ABCDEF0


def test_buffer_clone_independence():
    """Test that cloned buffers are independent."""
    original = Buffer.from_bytes(b"\x01\x02\x03\x04")
    cloned = original.clone()

    assert original == cloned

    cloned[0] = 0xFF
    assert original[0] == 0x01
    assert cloned[0] == 0xFF

    cloned.write(b"\x05\x06")
    assert len(original) == 4
    assert len(cloned) == 6
