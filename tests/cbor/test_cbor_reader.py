import math
from cometa import CborReader
from cometa import CborReaderState
from cometa import CborTag
from cometa import CborSimpleValue

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def verify_int(hex_str: str, expected_val: int, expected_state: CborReaderState):
    reader = CborReader.from_hex(hex_str)
    assert reader.peek_state() == expected_state

    if expected_state == CborReaderState.UNSIGNED_INTEGER:
        assert reader.read_uint() == expected_val
    else:
        assert reader.read_int() == expected_val

    assert reader.peek_state() == CborReaderState.FINISHED


def verify_float(hex_str: str, expected_val: float, expected_state: CborReaderState):
    reader = CborReader.from_hex(hex_str)
    assert reader.peek_state() == expected_state
    val = reader.read_float()

    if math.isnan(expected_val):
        assert math.isnan(val)
    elif math.isinf(expected_val):
        assert val == expected_val
    else:
        # Use isclose for float precision
        assert math.isclose(val, expected_val, rel_tol=1e-9)

    assert reader.peek_state() == CborReaderState.FINISHED


def verify_text(hex_str: str, expected_val: str, expected_state: CborReaderState):
    reader = CborReader.from_hex(hex_str)
    assert reader.peek_state() == expected_state
    assert reader.read_str() == expected_val
    assert reader.peek_state() == CborReaderState.FINISHED


def get_val(reader: CborReader):
    state = reader.peek_state()

    if state == CborReaderState.BYTESTRING:
        return bytes(reader.read_bytes())

    elif state == CborReaderState.TEXTSTRING:
        return reader.read_str()

    elif state == CborReaderState.NEGATIVE_INTEGER:
        return reader.read_int()

    elif state == CborReaderState.UNSIGNED_INTEGER:
        return reader.read_uint()

    elif state == CborReaderState.START_MAP:
        length = reader.read_map_len()
        data = {}

        if length is None:
            while reader.peek_state() != CborReaderState.END_MAP:
                k = get_val(reader)
                v = get_val(reader)
                data[k] = v
        else:
            for _ in range(length):
                k = get_val(reader)
                v = get_val(reader)
                data[k] = v

        reader.read_map_end()
        return data

    elif state == CborReaderState.START_ARRAY:
        length = reader.read_array_len()
        data = []

        if length is None:
            while reader.peek_state() != CborReaderState.END_ARRAY:
                data.append(get_val(reader))
        else:
            for _ in range(length):
                data.append(get_val(reader))

        reader.read_array_end()
        return data

    return None


# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

class TestArray:
    def test_empty_fixed_size_array(self):
        reader = CborReader.from_hex('80')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        length = reader.read_array_len()
        assert length == 0
        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_with_unsigned(self):
        reader = CborReader.from_hex('81182a')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 1

        assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
        assert reader.read_uint() == 42

        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_many_unsigned(self):
        reader = CborReader.from_hex('98190102030405060708090a0b0c0d0e0f101112131415161718181819')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        length = reader.read_array_len()
        assert length == 25

        for i in range(length):
            assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
            assert reader.read_uint() == i + 1

        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_64bit_unsigned(self):
        reader = CborReader.from_hex('831bcd2fb6b45d4cf7b01bcd2fb6b45d4cf7b11bcd2fb6b45d4cf7b2')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        length = reader.read_array_len()
        assert length == 3

        base = 14_785_236_987_456_321_456
        for i in range(length):
            assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
            assert reader.read_uint() == base + i

        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_mixed_types(self):
        reader = CborReader.from_hex('840120604107')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 4

        assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
        assert reader.read_uint() == 1

        assert reader.peek_state() == CborReaderState.NEGATIVE_INTEGER
        assert reader.read_int() == -1

        assert reader.peek_state() == CborReaderState.TEXTSTRING
        assert reader.read_str() == ""

        assert reader.peek_state() == CborReaderState.BYTESTRING
        assert bytes(reader.read_bytes()) == b"\x07"

        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_strings(self):
        reader = CborReader.from_hex('83656c6f72656d65697073756d65646f6c6f72')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 3

        assert reader.read_str() == "lorem"
        assert reader.read_str() == "ipsum"
        assert reader.read_str() == "dolor"

        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_simple_values(self):
        reader = CborReader.from_hex('84f4f6faffc00000fb7ff0000000000000')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 4

        assert reader.peek_state() == CborReaderState.BOOLEAN
        assert reader.read_bool() is False

        assert reader.peek_state() == CborReaderState.NULL
        reader.read_null()

        assert reader.peek_state() == CborReaderState.SINGLE_PRECISION_FLOAT
        assert math.isnan(reader.read_float())

        assert reader.peek_state() == CborReaderState.DOUBLE_PRECISION_FLOAT
        assert reader.read_float() == float("inf")

        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_size_array_nested(self):
        reader = CborReader.from_hex('8301820203820405')

        # Outer array
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 3
        assert reader.read_int() == 1

        # Nested 1
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 2
        assert reader.read_int() == 2
        assert reader.read_int() == 3
        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()

        # Nested 2
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() == 2
        assert reader.read_int() == 4
        assert reader.read_int() == 5
        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()

        # Close Outer
        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_indefinite_length_array_empty(self):
        reader = CborReader.from_hex('9fff')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() is None
        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_indefinite_length_array_with_unsigned(self):
        reader = CborReader.from_hex('9f182aff')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() is None

        assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
        assert reader.read_uint() == 42

        assert reader.peek_state() == CborReaderState.END_ARRAY
        reader.read_array_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_indefinite_length_array_many_unsigned(self):
        reader = CborReader.from_hex('9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff')
        assert reader.peek_state() == CborReaderState.START_ARRAY
        assert reader.read_array_len() is None

        count = 0
        while reader.peek_state() != CborReaderState.END_ARRAY:
            count += 1
            assert reader.peek_state() == CborReaderState.UNSIGNED_INTEGER
            assert reader.read_uint() == count

        reader.read_array_end()
        assert count == 25
        assert reader.peek_state() == CborReaderState.FINISHED


class TestByteString:
    def test_empty_fixed_bytestring(self):
        reader = CborReader.from_hex('40')
        assert reader.peek_state() == CborReaderState.BYTESTRING
        assert len(reader.read_bytes()) == 0
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_non_empty_fixed_bytestring(self):
        # Short
        reader = CborReader.from_hex('4401020304')
        assert reader.peek_state() == CborReaderState.BYTESTRING
        data = reader.read_bytes()
        assert len(data) == 4
        assert bytes(data) == b"\x01\x02\x03\x04"

        # Long
        reader = CborReader.from_hex('4effffffffffffffffffffffffffff')
        assert reader.peek_state() == CborReaderState.BYTESTRING
        data = reader.read_bytes()
        assert len(data) == 14
        assert bytes(data) == b"\xff" * 14
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_empty_indefinite_bytestring(self):
        # Empty chunks
        reader = CborReader.from_hex('5fff')
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        assert len(reader.read_bytes()) == 0
        assert reader.peek_state() == CborReaderState.FINISHED

        # Chunked explicit empty
        reader = CborReader.from_hex('5f40ff')
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        assert len(reader.read_bytes()) == 0
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_non_empty_indefinite_bytestring(self):
        # Single Chunk
        reader = CborReader.from_hex('5f41ab40ff')
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        data = reader.read_bytes()
        assert len(data) == 1
        assert bytes(data) == b"\xab"
        assert reader.peek_state() == CborReaderState.FINISHED

        # Two Chunks
        reader = CborReader.from_hex('5f41ab41bc40ff')
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        data = reader.read_bytes()
        assert len(data) == 2
        assert bytes(data) == b"\xab\xbc"
        assert reader.peek_state() == CborReaderState.FINISHED

        # Large Indefinite (Chunked 64 bytes x 4)
        chunk = "64676273786767746f6768646a7074657476746b636f6376796669647171676775726a687268716169697370717275656c687679707178656577707279667677"
        hex_data = '5f' + ('5840' + chunk) * 4 + 'ff'
        reader = CborReader.from_hex(hex_data)
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        data = reader.read_bytes()
        assert len(data) == 256
        assert data.hex() == chunk * 4
        assert reader.peek_state() == CborReaderState.FINISHED


class TestInteger:
    def test_read_unsigned_integers(self):
        cases = [
            ('00', 0), ('01', 1), ('0a', 10), ('17', 23),
            ('1818', 24), ('1819', 25), ('1864', 100),
            ('1903e8', 1000), ('1a000f4240', 1_000_000),
            ('1b000000e8d4a51000', 1_000_000_000_000),
            ('18ff', 255), ('190100', 256),
            ('1affffffff', 4_294_967_295),
            ('1b7fffffffffffffff', 9_223_372_036_854_775_807),
            ('1b0000000100000000', 4_294_967_296),
            ('19ffff', 65_535), ('1a00010000', 65_536)
        ]
        for hex_s, val in cases:
            verify_int(hex_s, val, CborReaderState.UNSIGNED_INTEGER)

    def test_read_negative_integers(self):
        cases = [
            ('20', -1), ('29', -10), ('37', -24),
            ('3863', -100), ('3903e7', -1000), ('38ff', -256),
            ('390100', -257), ('39ffff', -65_536),
            ('3a00010000', -65_537), ('3affffffff', -4_294_967_296),
            ('3b0000000100000000', -4_294_967_297),
            ('3b7fffffffffffffff', -9_223_372_036_854_775_808)
        ]
        for hex_s, val in cases:
            verify_int(hex_s, val, CborReaderState.NEGATIVE_INTEGER)


class TestSimple:
    def test_half_precision(self):
        # Note: Python floats are doubles. C library handles conversion.
        verify_float('f90000', 0, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f93c00', 1, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f93e00', 1.5, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f98000', -0.0, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f97bff', 65504, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f90001', 5.960464477539063e-8, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f9c400', -4, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f97c00', math.inf, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f97e00', math.nan, CborReaderState.HALF_PRECISION_FLOAT)
        verify_float('f9fc00', -math.inf, CborReaderState.HALF_PRECISION_FLOAT)

    def test_single_precision(self):
        verify_float('fa47c35000', 100_000, CborReaderState.SINGLE_PRECISION_FLOAT)
        verify_float('fa7f7fffff', 3.4028234663852886e+38, CborReaderState.SINGLE_PRECISION_FLOAT)
        verify_float('fa7f800000', math.inf, CborReaderState.SINGLE_PRECISION_FLOAT)
        verify_float('fa7fc00000', math.nan, CborReaderState.SINGLE_PRECISION_FLOAT)
        verify_float('faff800000', -math.inf, CborReaderState.SINGLE_PRECISION_FLOAT)

    def test_double_precision(self):
        verify_float('fb3ff199999999999a', 1.1, CborReaderState.DOUBLE_PRECISION_FLOAT)
        verify_float('fb7e37e43c8800759c', 1e300, CborReaderState.DOUBLE_PRECISION_FLOAT)
        verify_float('fbc010666666666666', -4.1, CborReaderState.DOUBLE_PRECISION_FLOAT)
        verify_float('fb7ff0000000000000', math.inf, CborReaderState.DOUBLE_PRECISION_FLOAT)
        verify_float('fb7ff8000000000000', math.nan, CborReaderState.DOUBLE_PRECISION_FLOAT)
        verify_float('fbfff0000000000000', -math.inf, CborReaderState.DOUBLE_PRECISION_FLOAT)

    def test_null(self):
        reader = CborReader.from_hex('f6')
        assert reader.peek_state() == CborReaderState.NULL
        reader.read_null()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_boolean(self):
        reader = CborReader.from_hex('f4')
        assert reader.peek_state() == CborReaderState.BOOLEAN
        assert reader.read_bool() is False
        assert reader.peek_state() == CborReaderState.FINISHED

        reader = CborReader.from_hex('f5')
        assert reader.peek_state() == CborReaderState.BOOLEAN
        assert reader.read_bool() is True
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_simple_values(self):
        reader = CborReader.from_hex('e0f4f5f6f7f820f8ff')

        assert reader.read_simple_value() == 0  # e0
        assert reader.read_simple_value() == CborSimpleValue.FALSE  # f4
        assert reader.read_simple_value() == CborSimpleValue.TRUE  # f5

        # f6 (null), f7 (undefined) are technically simple values too
        assert reader.read_simple_value() == CborSimpleValue.NULL
        assert reader.read_simple_value() == CborSimpleValue.UNDEFINED

        assert reader.read_simple_value() == 32  # f820
        assert reader.read_simple_value() == 255  # f8ff
        assert reader.peek_state() == CborReaderState.FINISHED


class TestSkip:
    def test_skip_value(self):
        reader = CborReader.from_hex('83656c6f72656d65697073756d65646f6c6f72')  # ["lorem", "ipsum", "dolor"]
        reader.read_array_len()
        reader.skip_value()  # Skip "lorem"
        reader.skip_value()  # Skip "ipsum"
        assert reader.read_str() == "dolor"
        reader.read_array_end()

    def test_read_encoded_value(self):
        # "lorem" encoded is 65 6c 6f 72 65 6d
        reader = CborReader.from_hex('83656c6f72656d65697073756d65646f6c6f72')
        reader.read_array_len()
        reader.skip_value()
        reader.skip_value()

        # 65 = TextString(5), 646F6C6F72 = "dolor"
        encoded = reader.read_encoded_value()
        assert bytes(encoded) == b"\x65\x64\x6f\x6c\x6f\x72"
        reader.read_array_end()


class TestTag:
    def test_tagged_datetime(self):
        reader = CborReader.from_hex('c074323031332d30332d32315432303a30343a30305a')
        assert reader.peek_state() == CborReaderState.TAG
        assert reader.read_tag() == CborTag.DATE_TIME_STRING
        assert reader.peek_state() == CborReaderState.TEXTSTRING
        assert reader.read_str() == "2013-03-21T20:04:00Z"
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_tagged_unix_time(self):
        reader = CborReader.from_hex('c11a514b67b0')
        assert reader.peek_state() == CborReaderState.TAG
        assert reader.read_tag() == CborTag.UNIX_TIME_SECONDS
        assert reader.read_uint() == 1_363_896_240

    def test_tagged_bignum(self):
        reader = CborReader.from_hex('c202')
        assert reader.peek_state() == CborReaderState.TAG
        assert reader.read_tag() == CborTag.UNSIGNED_BIG_NUM
        assert reader.read_int() == 2

    def test_tagged_uri(self):
        reader = CborReader.from_hex('d82076687474703a2f2f7777772e6578616d706c652e636f6d')
        assert reader.peek_state() == CborReaderState.TAG
        assert reader.read_tag() == 32
        assert reader.read_str() == "http://www.example.com"

    def test_nested_tags(self):
        reader = CborReader.from_hex('c0c0c074323031332d30332d32315432303a30343a30305a')
        assert reader.read_tag() == CborTag.DATE_TIME_STRING
        assert reader.read_tag() == CborTag.DATE_TIME_STRING
        assert reader.read_tag() == CborTag.DATE_TIME_STRING
        assert reader.read_str() == "2013-03-21T20:04:00Z"


class TestTextString:
    def test_fixed_length(self):
        verify_text('60', '', CborReaderState.TEXTSTRING)
        verify_text('6161', 'a', CborReaderState.TEXTSTRING)
        verify_text('6449455446', 'IETF', CborReaderState.TEXTSTRING)
        verify_text('62225c', '"\\', CborReaderState.TEXTSTRING)
        verify_text('62c3bc', '\u00FC', CborReaderState.TEXTSTRING)
        verify_text('63e6b0b4', '\u6C34', CborReaderState.TEXTSTRING)

    def test_indefinite_length(self):
        # Note: read_str() automatically handles indefinite length strings by concatenating chunks
        # if the underlying C lib supports it (cardano-c usually does).
        # However, peek_state will show START_INDEFINITE...

        reader = CborReader.from_hex('7fff')
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_TEXTSTRING
        assert reader.read_str() == ""

        reader = CborReader.from_hex('7f62616262626360ff')  # "ab" + "bc"
        assert reader.peek_state() == CborReaderState.START_INDEFINITE_LENGTH_TEXTSTRING
        assert reader.read_str() == "abbc"


class TestMap:
    def test_empty_map(self):
        reader = CborReader.from_hex('a0')
        assert reader.peek_state() == CborReaderState.START_MAP
        assert reader.read_map_len() == 0
        assert reader.peek_state() == CborReaderState.END_MAP
        reader.read_map_end()
        assert reader.peek_state() == CborReaderState.FINISHED

    def test_fixed_map_numbers(self):
        reader = CborReader.from_hex('a201020304')  # {1: 2, 3: 4}
        data = get_val(reader)
        assert data == {1: 2, 3: 4}

    def test_fixed_map_strings(self):
        reader = CborReader.from_hex('a56161614161626142616361436164614461656145')
        data = get_val(reader)
        assert data == {
            "a": "A", "b": "B", "c": "C", "d": "D", "e": "E"
        }

    def test_fixed_map_mixed(self):
        reader = CborReader.from_hex('a3616161412002404101')
        # {'a': 'A', -1: 2, b'': b'\x01'}
        data = get_val(reader)
        assert data['a'] == 'A'
        assert data[-1] == 2
        assert data[b''] == b'\x01'

    def test_nested_maps(self):
        # {'a': {2: 3}, 'b': {'x': -1, 'y': {'z': 0}}}
        reader = CborReader.from_hex('a26161a102036162a26178206179a1617a00')
        data = get_val(reader)
        assert data['a'] == {2: 3}
        assert data['b'] == {'x': -1, 'y': {'z': 0}}

    def test_indefinite_map(self):
        reader = CborReader.from_hex('bf6161614161626142616361436164614461656145ff')
        assert reader.peek_state() == CborReaderState.START_MAP
        data = get_val(reader)
        assert data == {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}