from biglup.cometa.cbor.cbor_writer import CborWriter
from biglup.cometa.cbor.cbor_tag import CborTag

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