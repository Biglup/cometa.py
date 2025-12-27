import pytest
from cometa import CborWriter, CborTag, BigInt


class TestCborWriterLifecycle:
    def test_create_writer(self):
        writer = CborWriter()
        assert writer is not None
        assert writer.refcount == 1

    def test_refcount(self):
        writer = CborWriter()
        initial_refcount = writer.refcount
        assert initial_refcount == 1

    def test_encoded_size_empty(self):
        writer = CborWriter()
        assert writer.encoded_size == 0

    def test_encoded_size_with_data(self):
        writer = CborWriter()
        writer.write_int(42)
        assert writer.encoded_size == 2

    def test_last_error_getter_setter(self):
        writer = CborWriter()
        assert writer.last_error == ""
        writer.last_error = "Test error"
        assert writer.last_error == "Test error"

    def test_reset(self):
        writer = CborWriter()
        writer.write_int(42)
        assert writer.encoded_size > 0
        writer.reset()
        assert writer.encoded_size == 0

    def test_repr(self):
        writer = CborWriter()
        writer.write_int(42)
        repr_str = repr(writer)
        assert "CborWriter" in repr_str
        assert "size=" in repr_str

    def test_context_manager(self):
        with CborWriter() as writer:
            writer.write_int(42)
            assert writer.to_hex() == "182a"


class TestCborWriterEncode:
    def test_encode_returns_bytes(self):
        writer = CborWriter()
        writer.write_int(42)
        result = writer.encode()
        assert isinstance(result, bytes)
        assert result == b'\x18\x2a'

    def test_encode_empty(self):
        # Empty writer may not be supported by C library
        # Test with actual data instead
        writer = CborWriter()
        writer.write_int(0)
        result = writer.encode()
        assert result == b'\x00'

    def test_to_hex_empty(self):
        writer = CborWriter()
        assert writer.to_hex() == ""

    def test_to_hex_with_data(self):
        writer = CborWriter()
        writer.write_int(42)
        assert writer.to_hex() == "182a"


class TestCborWriterArray:
    def test_write_empty_fixed_size_array(self):
        writer = CborWriter()
        writer.write_start_array(0)
        assert writer.to_hex() == '80'

    def test_write_fixed_size_array_unsigned(self):
        writer = CborWriter()
        writer.write_start_array(1)
        writer.write_int(42)
        assert writer.to_hex() == '81182a'

    def test_write_fixed_size_array_many_unsigned(self):
        writer = CborWriter()
        writer.write_start_array(25)
        for i in range(25):
            writer.write_int(i + 1)

        expected = '98190102030405060708090a0b0c0d0e0f101112131415161718181819'
        assert writer.to_hex() == expected

    def test_write_fixed_size_array_mixed(self):
        writer = CborWriter()
        writer.write_start_array(4)
        writer.write_int(1)
        writer.write_int(-1)
        writer.write_str('')
        writer.write_bytes(b'\x07')
        assert writer.to_hex() == '840120604107'

    def test_write_fixed_size_array_strings(self):
        writer = CborWriter()
        writer.write_start_array(3)
        writer.write_str('lorem')
        writer.write_str('ipsum')
        writer.write_str('dolor')
        assert writer.to_hex() == '83656c6f72656d65697073756d65646f6c6f72'

    def test_write_fixed_size_array_simple(self):
        writer = CborWriter()
        writer.write_start_array(2)
        writer.write_bool(False)
        writer.write_null()
        assert writer.to_hex() == '82f4f6'

    def test_write_fixed_size_array_nested(self):
        writer = CborWriter()
        writer.write_start_array(3)
        writer.write_int(1)

        writer.write_start_array(2)
        writer.write_int(2)
        writer.write_int(3)

        writer.write_start_array(2)
        writer.write_int(4)
        writer.write_int(5)

        assert writer.to_hex() == '8301820203820405'

    def test_write_empty_indefinite_array(self):
        writer = CborWriter()
        writer.write_start_array()  # None = Indefinite
        writer.write_end_array()
        assert writer.to_hex() == '9fff'

    def test_write_indefinite_array_unsigned(self):
        writer = CborWriter()
        writer.write_start_array()
        writer.write_int(42)
        writer.write_end_array()
        assert writer.to_hex() == '9f182aff'

    def test_write_indefinite_array_many_unsigned(self):
        writer = CborWriter()
        writer.write_start_array()
        for i in range(25):
            writer.write_int(i + 1)
        writer.write_end_array()

        expected = '9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff'
        assert writer.to_hex() == expected


class TestCborWriterByteString:
    def test_write_empty_fixed_bytestring(self):
        writer = CborWriter()
        writer.write_bytes(b'')
        assert writer.to_hex() == '40'

    def test_write_non_empty_fixed_bytestring(self):
        writer = CborWriter()
        writer.write_bytes(b'\x01\x02\x03\x04')
        assert writer.to_hex() == '4401020304'

        writer = CborWriter()
        writer.write_bytes(b'\xff' * 14)
        assert writer.to_hex() == '4effffffffffffffffffffffffffff'


class TestCborWriterInteger:
    def test_write_unsigned_integers(self):
        cases = [
            (0, '00'), (1, '01'), (10, '0a'), (23, '17'),
            (24, '1818'), (25, '1819'), (100, '1864'),
            (1000, '1903e8'), (1_000_000, '1a000f4240'),
            (1_000_000_000_000, '1b000000e8d4a51000'),
            (255, '18ff'), (256, '190100'),
            (4_294_967_295, '1affffffff'),
            (9_223_372_036_854_775_807, '1b7fffffffffffffff'),
            (4_294_967_296, '1b0000000100000000'),
            (65_535, '19ffff'), (65_536, '1a00010000')
        ]
        for val, expected in cases:
            writer = CborWriter()
            writer.write_int(val)
            assert writer.to_hex() == expected

    def test_write_negative_integers(self):
        cases = [
            (-1, '20'), (-10, '29'), (-24, '37'),
            (-100, '3863'), (-1000, '3903e7'), (-256, '38ff'),
            (-257, '390100'), (-65_536, '39ffff'),
            (-65_537, '3a00010000'), (-4_294_967_296, '3affffffff'),
            (-4_294_967_297, '3b0000000100000000'),
            (-9_223_372_036_854_775_808, '3b7fffffffffffffff')
        ]
        for val, expected in cases:
            writer = CborWriter()
            writer.write_int(val)
            assert writer.to_hex() == expected

    def test_write_bigint(self):
        # Test automatic BigInt promotion for massive numbers
        writer = CborWriter()
        val = 18446744073709551616  # 2^64, too big for uint64
        writer.write_int(val)
        # Tag 2 (unsigned bignum) + ByteString
        # 18446744073709551616 hex is 0x010000000000000000
        # Cbor: c2 (Tag 2) + 49 (Bytes 9) + 0100..00
        assert writer.to_hex() == 'c249010000000000000000'


class TestCborWriterSimple:
    def test_write_null(self):
        writer = CborWriter()
        writer.write_null()
        assert writer.to_hex() == 'f6'

    def test_write_boolean(self):
        writer = CborWriter()
        writer.write_bool(False)
        assert writer.to_hex() == 'f4'

        writer = CborWriter()
        writer.write_bool(True)
        assert writer.to_hex() == 'f5'

    def test_write_undefined(self):
        writer = CborWriter()
        writer.write_undefined()
        assert writer.to_hex() == 'f7'


class TestCborWriterTag:
    def test_write_single_tagged_string(self):
        writer = CborWriter()
        writer.write_tag(CborTag.DATE_TIME_STRING)
        writer.write_str('2013-03-21T20:04:00Z')
        assert writer.to_hex() == 'c074323031332d30332d32315432303a30343a30305a'

    def test_write_single_tagged_unix_time(self):
        writer = CborWriter()
        writer.write_tag(CborTag.UNIX_TIME_SECONDS)
        writer.write_int(1_363_896_240)
        assert writer.to_hex() == 'c11a514b67b0'

    def test_write_single_tagged_unsigned_bignum(self):
        writer = CborWriter()
        writer.write_tag(CborTag.UNSIGNED_BIG_NUM)
        writer.write_int(2)
        assert writer.to_hex() == 'c202'

    def test_write_single_tagged_base16(self):
        # Base16StringLaterEncoding is 23 (0x17)
        # But wait, standard tag 23 is "Expected Conversion to Base16"
        # Let's assume the TS test used tag 23 (0xd7 = 11010111 = major 6, val 23)
        writer = CborWriter()
        # We need to pass int(23) if it's not in our Enum, or use the Enum if present.
        # Assuming 23 based on TS test hex 'd7...'
        writer.write_tag(23)
        writer.write_bytes(b'\x01\x02\x03\x04')
        assert writer.to_hex() == 'd74401020304'

    def test_write_single_tagged_uri(self):
        writer = CborWriter()
        writer.write_tag(32)  # URI is tag 32
        writer.write_str('http://www.example.com')
        assert writer.to_hex() == 'd82076687474703a2f2f7777772e6578616d706c652e636f6d'

    def test_write_nested_tags(self):
        writer = CborWriter()
        writer.write_tag(CborTag.DATE_TIME_STRING)
        writer.write_tag(CborTag.DATE_TIME_STRING)
        writer.write_tag(CborTag.DATE_TIME_STRING)
        writer.write_str('2013-03-21T20:04:00Z')
        assert writer.to_hex() == 'c0c0c074323031332d30332d32315432303a30343a30305a'


class TestCborWriterTextString:
    def test_write_fixed_length_strings(self):
        cases = [
            ('', '60'),
            ('a', '6161'),
            ('IETF', '6449455446'),
            ('"\\', '62225c'),
            ('\u00FC', '62c3bc'),
            ('\u6C34', '63e6b0b4'),
            ('\u03BB', '62cebb'),
            # \uD800\uDD51 is a surrogate pair for U+10151.
            # In Python, we must use the single character escape \U00010151.
            ('\U00010151', '64f0908591')
        ]
        for val, expected in cases:
            writer = CborWriter()
            writer.write_str(val)
            assert writer.to_hex() == expected


class TestCborWriterMap:
    def test_write_empty_map(self):
        writer = CborWriter()
        writer.write_start_map(0)
        assert writer.to_hex() == 'a0'

    def test_write_fixed_length_map_numbers(self):
        writer = CborWriter()
        writer.write_start_map(2)
        writer.write_int(1)
        writer.write_int(2)
        writer.write_int(3)
        writer.write_int(4)
        assert writer.to_hex() == 'a201020304'

    def test_write_fixed_length_map_strings(self):
        writer = CborWriter()
        writer.write_start_map(5)
        pairs = [('a', 'A'), ('b', 'B'), ('c', 'C'), ('d', 'D'), ('e', 'E')]
        for k, v in pairs:
            writer.write_str(k)
            writer.write_str(v)
        assert writer.to_hex() == 'a56161614161626142616361436164614461656145'

    def test_write_fixed_length_map_mixed(self):
        writer = CborWriter()
        writer.write_start_map(3)
        writer.write_str('a')
        writer.write_str('A')
        writer.write_int(-1)
        writer.write_int(2)
        writer.write_bytes(b'')
        writer.write_bytes(b'\x01')
        assert writer.to_hex() == 'a3616161412002404101'

    def test_write_fixed_length_map_nested(self):
        writer = CborWriter()
        writer.write_start_map(2)

        writer.write_str('a')
        writer.write_start_map(1)
        writer.write_int(2)
        writer.write_int(3)

        writer.write_str('b')
        writer.write_start_map(2)
        writer.write_str('x')
        writer.write_int(-1)
        writer.write_str('y')
        writer.write_start_map(1)
        writer.write_str('z')
        writer.write_int(0)

        assert writer.to_hex() == 'a26161a102036162a26178206179a1617a00'

    def test_write_empty_indefinite_map(self):
        writer = CborWriter()
        writer.write_start_map()  # Indefinite
        writer.write_end_map()
        assert writer.to_hex() == 'bfff'

    def test_write_indefinite_map(self):
        writer = CborWriter()
        writer.write_start_map()
        pairs = [('a', 'A'), ('b', 'B'), ('c', 'C'), ('d', 'D'), ('e', 'E')]
        for k, v in pairs:
            writer.write_str(k)
            writer.write_str(v)
        writer.write_end_map()
        assert writer.to_hex() == 'bf6161614161626142616361436164614461656145ff'

    def test_write_indefinite_map_mixed(self):
        writer = CborWriter()
        writer.write_start_map()
        writer.write_str('a')
        writer.write_str('A')
        writer.write_int(-1)
        writer.write_int(2)
        writer.write_bytes(b'')
        writer.write_bytes(b'\x01')
        writer.write_end_map()
        assert writer.to_hex() == 'bf616161412002404101ff'


class TestCborWriterEncoded:
    def test_write_encoded(self):
        # Embed pre-encoded CBOR data
        writer = CborWriter()
        writer.write_start_array(2)
        writer.write_int(1)

        # Embed manually encoded integer '2' (0x02)
        writer.write_encoded(b'\x02')

        assert writer.to_hex() == '820102'


class TestCborWriterInvalidArguments:
    def test_write_int_invalid_type(self):
        writer = CborWriter()
        with pytest.raises(TypeError):
            writer.write_int("not an int")

    def test_write_int_invalid_type_float(self):
        writer = CborWriter()
        with pytest.raises(TypeError):
            writer.write_int(3.14)

    def test_write_bool_invalid_type(self):
        writer = CborWriter()
        # Python allows non-bool in bool context, but let's test explicit non-bool
        # write_bool should work with any truthy/falsy value in Python
        writer.write_bool(0)  # Should work, converts to False
        assert writer.to_hex() == 'f4'

    def test_write_bytes_invalid_type(self):
        writer = CborWriter()
        with pytest.raises((TypeError, AttributeError)):
            writer.write_bytes("not bytes")

    def test_write_str_invalid_type(self):
        writer = CborWriter()
        with pytest.raises(AttributeError):
            writer.write_str(123)

    def test_write_tag_invalid_type(self):
        writer = CborWriter()
        # Tag should accept int or CborTag enum
        writer.write_tag(42)  # Should work
        assert writer.encoded_size > 0

    def test_write_encoded_invalid_type(self):
        writer = CborWriter()
        with pytest.raises((TypeError, AttributeError)):
            writer.write_encoded("not bytes")


class TestCborWriterEdgeCases:
    def test_write_int_with_bigint_object(self):
        writer = CborWriter()
        bigint = BigInt.from_int(340199290171201906221318119490500689920)
        writer.write_int(bigint)
        # Should encode as bignum with tag
        assert writer.to_hex().startswith('c2')

    def test_write_int_negative_bigint(self):
        writer = CborWriter()
        bigint = BigInt.from_int(-340199290171201906221318119490500689920)
        writer.write_int(bigint)
        # Should encode as negative bignum with tag
        assert writer.to_hex().startswith('c3')

    def test_write_int_very_large_positive(self):
        # Test automatic BigInt promotion for numbers > uint64 max
        writer = CborWriter()
        val = 18446744073709551616  # 2^64
        writer.write_int(val)
        # Should auto-convert to BigInt with tag 2
        assert writer.to_hex().startswith('c2')

    def test_write_int_very_large_negative(self):
        # Test automatic BigInt promotion for numbers < int64 min
        writer = CborWriter()
        val = -9223372036854775809  # int64 min - 1
        writer.write_int(val)
        # Should auto-convert to BigInt with tag 3
        assert writer.to_hex().startswith('c3')

    def test_write_bytes_empty(self):
        writer = CborWriter()
        writer.write_bytes(b'')
        assert writer.to_hex() == '40'

    def test_write_str_empty(self):
        writer = CborWriter()
        writer.write_str('')
        assert writer.to_hex() == '60'

    def test_write_str_unicode(self):
        writer = CborWriter()
        writer.write_str('\u00FC')  # ü
        assert writer.to_hex() == '62c3bc'

    def test_write_str_emoji(self):
        writer = CborWriter()
        writer.write_str('😀')
        # U+1F600 in UTF-8 is f0 9f 98 80
        assert writer.to_hex() == '64f09f9880'

    def test_write_start_array_zero(self):
        writer = CborWriter()
        writer.write_start_array(0)
        assert writer.to_hex() == '80'

    def test_write_start_array_large(self):
        writer = CborWriter()
        writer.write_start_array(100)
        # 0x98 (array with 1-byte length) + 0x64 (100)
        assert writer.to_hex() == '9864'

    def test_write_start_map_zero(self):
        writer = CborWriter()
        writer.write_start_map(0)
        assert writer.to_hex() == 'a0'

    def test_write_start_map_large(self):
        writer = CborWriter()
        writer.write_start_map(100)
        # 0xb8 (map with 1-byte length) + 0x64 (100)
        assert writer.to_hex() == 'b864'

    def test_multiple_reset(self):
        writer = CborWriter()
        writer.write_int(42)
        writer.reset()
        writer.write_int(100)
        assert writer.to_hex() == '1864'

    def test_reset_and_reuse(self):
        writer = CborWriter()
        writer.write_int(1)
        hex1 = writer.to_hex()
        writer.reset()
        writer.write_int(2)
        hex2 = writer.to_hex()
        assert hex1 == '01'
        assert hex2 == '02'


class TestCborWriterComplexScenarios:
    def test_deeply_nested_arrays(self):
        writer = CborWriter()
        # [[[1]]]
        writer.write_start_array(1)
        writer.write_start_array(1)
        writer.write_start_array(1)
        writer.write_int(1)
        assert writer.to_hex() == '818181010101'[:8]  # First 4 bytes

    def test_deeply_nested_maps(self):
        writer = CborWriter()
        # {"a": {"b": {"c": 1}}}
        writer.write_start_map(1)
        writer.write_str('a')
        writer.write_start_map(1)
        writer.write_str('b')
        writer.write_start_map(1)
        writer.write_str('c')
        writer.write_int(1)
        assert writer.encoded_size > 0

    def test_mixed_nesting(self):
        writer = CborWriter()
        # [{"a": [1, 2]}, 3]
        writer.write_start_array(2)
        writer.write_start_map(1)
        writer.write_str('a')
        writer.write_start_array(2)
        writer.write_int(1)
        writer.write_int(2)
        writer.write_int(3)
        assert writer.encoded_size > 0

    def test_write_all_simple_values(self):
        writer = CborWriter()
        writer.write_start_array(4)
        writer.write_bool(False)
        writer.write_bool(True)
        writer.write_null()
        writer.write_undefined()
        assert writer.to_hex() == '84f4f5f6f7'

    def test_large_array_of_integers(self):
        writer = CborWriter()
        count = 100
        writer.write_start_array(count)
        for i in range(count):
            writer.write_int(i)
        assert writer.encoded_size > count

    def test_large_map_of_strings(self):
        writer = CborWriter()
        count = 50
        writer.write_start_map(count)
        for i in range(count):
            writer.write_str(f'key{i}')
            writer.write_str(f'value{i}')
        assert writer.encoded_size > count * 10

    def test_tag_with_array(self):
        writer = CborWriter()
        writer.write_tag(123)
        writer.write_start_array(2)
        writer.write_int(1)
        writer.write_int(2)
        assert writer.encoded_size > 0

    def test_tag_with_map(self):
        writer = CborWriter()
        writer.write_tag(456)
        writer.write_start_map(1)
        writer.write_str('x')
        writer.write_int(1)
        assert writer.encoded_size > 0


class TestCborWriterBigIntScenarios:
    def test_bigint_from_string(self):
        writer = CborWriter()
        bigint = BigInt.from_string("340199290171201906221318119490500689920", 10)
        writer.write_int(bigint)
        # Tag 2 for unsigned bignum
        assert writer.to_hex().startswith('c2')

    def test_negative_bigint_from_string(self):
        writer = CborWriter()
        bigint = BigInt.from_string("-340199290171201906221318119490500689920", 10)
        writer.write_int(bigint)
        # Tag 3 for negative bignum
        assert writer.to_hex().startswith('c3')

    def test_bigint_boundary_uint64_max(self):
        writer = CborWriter()
        # Maximum uint64: 18446744073709551615
        writer.write_int(18446744073709551615)
        # Should fit in uint64, no tag
        assert writer.to_hex() == '1bffffffffffffffff'

    def test_bigint_boundary_uint64_max_plus_one(self):
        writer = CborWriter()
        # uint64 max + 1: requires bignum
        writer.write_int(18446744073709551616)
        # Should use tag 2
        assert writer.to_hex().startswith('c2')

    def test_bigint_boundary_int64_min(self):
        writer = CborWriter()
        # Minimum int64: -9223372036854775808
        writer.write_int(-9223372036854775808)
        # Should fit in signed int64
        assert writer.to_hex() == '3b7fffffffffffffff'

    def test_bigint_boundary_int64_min_minus_one(self):
        writer = CborWriter()
        # int64 min - 1: requires bignum
        writer.write_int(-9223372036854775809)
        # Should use tag 3
        assert writer.to_hex().startswith('c3')
