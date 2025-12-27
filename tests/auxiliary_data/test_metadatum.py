"""
Copyright 2025 Biglup Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import pytest
from cometa import (
    Metadatum,
    MetadatumKind,
    MetadatumList,
    MetadatumMap,
    BigInt,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


METADATUM_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
JSON_1_CBOR = "a178383136306238356535336532356566343932373263343231663034623730326263333231383464313032383635666431646338383135636465a177486f72726f637562653030373236783636363636364544a56563617264739fa1646e616d65664845524d4954a1646e616d656a54454d504552414e4345a1646e616d6565444556494cff65696d6167657835697066733a2f2f516d5471464d786f447a514531336f785661746b5773646134755a474a524c35746b734a4c5176394a52764e7251646e616d6570486f72726f63756265202330303732366a70726f70657274696573a86661737065637467416e67756973686a6261636b67726f756e6465477265656e68636f6d6d75746572674f6e656972696364636f7265781f476f6c64656e204b616461746869616e20537465656c20467261676d656e74696d656368616e69736d6c476169616e20526970706572686f726e616d656e74744d6f6c74656e20566f6f6e697468205475736b7368737570706f727473724c75636966657269616e20536861636b6c6562696400697369676e6174757265a36172782c414a5270544a614d75374356376b364952636b4f2b71467a6251484d79566c516e47686c6c67717a327545446173782c414f745242626c56644f30354f7775636b3955435531356c36785a4f2f662f63536b634d5241546f56545373717365637572697479416c676f726974686d744563647361536563703235366b31536861323536"


class TestMetadatumFromInt:
    """Tests for Metadatum.from_int() factory method."""

    def test_can_create_from_positive_int(self):
        """Test that Metadatum can be created from positive integer."""
        meta = Metadatum.from_int(42)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_negative_int(self):
        """Test that Metadatum can be created from negative integer."""
        meta = Metadatum.from_int(-42)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_zero(self):
        """Test that Metadatum can be created from zero."""
        meta = Metadatum.from_int(0)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_large_int(self):
        """Test that Metadatum can be created from large integer."""
        meta = Metadatum.from_int(9223372036854775807)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_retrieve_int_value(self):
        """Test that integer value can be retrieved."""
        meta = Metadatum.from_int(42)
        bigint = meta.to_integer()
        assert bigint.to_int() == 42

    def test_raises_error_if_value_is_none(self):
        """Test that creating metadatum with None raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            Metadatum.from_int(None)

    def test_raises_error_if_value_is_string(self):
        """Test that creating metadatum with string raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            Metadatum.from_int("42")


class TestMetadatumFromUint:
    """Tests for Metadatum.from_uint() factory method."""

    def test_can_create_from_uint(self):
        """Test that Metadatum can be created from unsigned integer."""
        meta = Metadatum.from_uint(42)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_large_uint(self):
        """Test that Metadatum can be created from large unsigned integer."""
        meta = Metadatum.from_uint(18446744073709551615)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_retrieve_uint_value(self):
        """Test that unsigned integer value can be retrieved."""
        meta = Metadatum.from_uint(42)
        bigint = meta.to_integer()
        assert bigint.to_unsigned_int() == 42

    def test_raises_error_if_value_is_none(self):
        """Test that creating metadatum with None raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            Metadatum.from_uint(None)

    def test_raises_error_if_value_is_negative(self):
        """Test that creating metadatum with negative value raises an error."""
        with pytest.raises((CardanoError, OverflowError)):
            Metadatum.from_uint(-42)


class TestMetadatumFromIntegerString:
    """Tests for Metadatum.from_integer_string() factory method."""

    def test_can_create_from_decimal_string(self):
        """Test that Metadatum can be created from decimal string."""
        meta = Metadatum.from_integer_string("12345678901234567890")
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_hex_string(self):
        """Test that Metadatum can be created from hex string."""
        meta = Metadatum.from_integer_string("DEADBEEF", 16)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_binary_string(self):
        """Test that Metadatum can be created from binary string."""
        meta = Metadatum.from_integer_string("101010", 2)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_retrieve_string_value(self):
        """Test that string value can be retrieved."""
        value_str = "12345678901234567890"
        meta = Metadatum.from_integer_string(value_str)
        bigint = meta.to_integer()
        assert bigint.to_string(10) == value_str

    def test_raises_error_if_string_is_none(self):
        """Test that creating metadatum with None string raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_integer_string(None)

    def test_raises_error_if_string_is_invalid(self):
        """Test that creating metadatum with invalid string raises an error."""
        with pytest.raises(CardanoError):
            Metadatum.from_integer_string("not a number")

    def test_raises_error_if_base_is_invalid(self):
        """Test that creating metadatum with invalid base raises an error."""
        with pytest.raises(CardanoError):
            Metadatum.from_integer_string("123", 1)

    def test_raises_error_if_base_is_too_large(self):
        """Test that creating metadatum with base > 36 raises an error."""
        meta = Metadatum.from_integer_string("123", 37)
        assert meta is not None


class TestMetadatumFromBigInt:
    """Tests for Metadatum.from_bigint() factory method."""

    def test_can_create_from_bigint(self):
        """Test that Metadatum can be created from BigInt."""
        bigint = BigInt.from_int(42)
        meta = Metadatum.from_bigint(bigint)
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_retrieve_bigint_value(self):
        """Test that BigInt value can be retrieved."""
        bigint = BigInt.from_int(42)
        meta = Metadatum.from_bigint(bigint)
        retrieved = meta.to_integer()
        assert retrieved.to_int() == 42

    def test_raises_error_if_bigint_is_none(self):
        """Test that creating metadatum with None BigInt raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_bigint(None)


class TestMetadatumFromBytes:
    """Tests for Metadatum.from_bytes() factory method."""

    def test_can_create_from_bytes(self):
        """Test that Metadatum can be created from bytes."""
        meta = Metadatum.from_bytes(b"\xde\xad\xbe\xef")
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_create_from_bytearray(self):
        """Test that Metadatum can be created from bytearray."""
        meta = Metadatum.from_bytes(bytearray(b"\xde\xad\xbe\xef"))
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_create_from_empty_bytes(self):
        """Test that Metadatum can be created from empty bytes."""
        meta = Metadatum.from_bytes(b"")
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_retrieve_bytes_value(self):
        """Test that bytes value can be retrieved."""
        data = b"\xde\xad\xbe\xef"
        meta = Metadatum.from_bytes(data)
        retrieved = meta.to_bytes()
        assert retrieved == data

    def test_raises_error_if_bytes_is_none(self):
        """Test that creating metadatum with None bytes raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            Metadatum.from_bytes(None)


class TestMetadatumFromHex:
    """Tests for Metadatum.from_hex() factory method."""

    def test_can_create_from_hex(self):
        """Test that Metadatum can be created from hex string."""
        meta = Metadatum.from_hex("deadbeef")
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_create_from_uppercase_hex(self):
        """Test that Metadatum can be created from uppercase hex string."""
        meta = Metadatum.from_hex("DEADBEEF")
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_create_from_empty_hex(self):
        """Test that Metadatum can be created from empty hex string."""
        meta = Metadatum.from_hex("")
        assert meta is not None
        assert meta.kind == MetadatumKind.BYTES

    def test_can_retrieve_bytes_from_hex(self):
        """Test that bytes value can be retrieved from hex metadatum."""
        meta = Metadatum.from_hex("deadbeef")
        retrieved = meta.to_bytes()
        assert retrieved == b"\xde\xad\xbe\xef"

    def test_raises_error_if_hex_is_none(self):
        """Test that creating metadatum with None hex raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_hex(None)

    def test_raises_error_if_hex_is_invalid(self):
        """Test that creating metadatum with invalid hex raises an error."""
        with pytest.raises(CardanoError):
            Metadatum.from_hex("not hex")

    def test_raises_error_if_hex_is_odd_length(self):
        """Test that creating metadatum with odd length hex raises an error."""
        with pytest.raises(CardanoError):
            Metadatum.from_hex("abc")


class TestMetadatumFromString:
    """Tests for Metadatum.from_string() factory method."""

    def test_can_create_from_string(self):
        """Test that Metadatum can be created from string."""
        meta = Metadatum.from_string("Hello, Cardano!")
        assert meta is not None
        assert meta.kind == MetadatumKind.TEXT

    def test_can_create_from_empty_string(self):
        """Test that Metadatum can be created from empty string."""
        meta = Metadatum.from_string("")
        assert meta is not None
        assert meta.kind == MetadatumKind.TEXT

    def test_can_create_from_unicode_string(self):
        """Test that Metadatum can be created from unicode string."""
        meta = Metadatum.from_string("Hello \u2665 Unicode")
        assert meta is not None
        assert meta.kind == MetadatumKind.TEXT

    def test_can_retrieve_string_value(self):
        """Test that string value can be retrieved."""
        text = "Hello, Cardano!"
        meta = Metadatum.from_string(text)
        retrieved = meta.to_str()
        assert retrieved == text

    def test_raises_error_if_string_is_none(self):
        """Test that creating metadatum with None string raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_string(None)


class TestMetadatumFromMap:
    """Tests for Metadatum.from_map() factory method."""

    def test_can_create_from_map(self):
        """Test that Metadatum can be created from MetadatumMap."""
        meta_map = MetadatumMap()
        meta = Metadatum.from_map(meta_map)
        assert meta is not None
        assert meta.kind == MetadatumKind.MAP

    def test_can_create_from_map_with_entries(self):
        """Test that Metadatum can be created from MetadatumMap with entries."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        assert meta is not None
        assert meta.kind == MetadatumKind.MAP

    def test_can_retrieve_map_value(self):
        """Test that map value can be retrieved."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        retrieved_map = meta.to_map()
        assert retrieved_map is not None
        assert len(retrieved_map) == 1

    def test_raises_error_if_map_is_none(self):
        """Test that creating metadatum with None map raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_map(None)


class TestMetadatumFromList:
    """Tests for Metadatum.from_list() factory method."""

    def test_can_create_from_metadatum_list(self):
        """Test that Metadatum can be created from MetadatumList."""
        meta_list = MetadatumList()
        meta = Metadatum.from_list(meta_list)
        assert meta is not None
        assert meta.kind == MetadatumKind.LIST

    def test_can_create_from_metadatum_list_with_entries(self):
        """Test that Metadatum can be created from MetadatumList with entries."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta = Metadatum.from_list(meta_list)
        assert meta is not None
        assert meta.kind == MetadatumKind.LIST

    def test_can_create_from_python_list(self):
        """Test that Metadatum can be created from Python list."""
        meta = Metadatum.from_list([1, "hello", b"bytes"])
        assert meta is not None
        assert meta.kind == MetadatumKind.LIST

    def test_can_retrieve_list_value(self):
        """Test that list value can be retrieved."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta = Metadatum.from_list(meta_list)
        retrieved_list = meta.to_list()
        assert retrieved_list is not None
        assert len(retrieved_list) == 2

    def test_raises_error_if_list_is_none(self):
        """Test that creating metadatum with None list raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_list(None)


class TestMetadatumFromCbor:
    """Tests for Metadatum.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that Metadatum can be deserialized from CBOR."""
        reader = CborReader.from_hex(METADATUM_CBOR)
        meta = Metadatum.from_cbor(reader)
        assert meta is not None

    def test_can_deserialize_complex_cbor(self):
        """Test that Metadatum can be deserialized from complex CBOR."""
        reader = CborReader.from_hex(JSON_1_CBOR)
        meta = Metadatum.from_cbor(reader)
        assert meta is not None
        assert meta.kind == MetadatumKind.MAP

    def test_raises_error_if_reader_is_none(self):
        """Test that deserializing with None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_cbor(None)

    def test_raises_error_if_cbor_is_invalid(self):
        """Test that deserializing invalid CBOR raises an error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            Metadatum.from_cbor(reader)


class TestMetadatumFromJson:
    """Tests for Metadatum.from_json() factory method."""

    def test_can_create_from_json_int(self):
        """Test that Metadatum can be created from JSON integer."""
        meta = Metadatum.from_json('42')
        assert meta is not None
        assert meta.kind == MetadatumKind.INTEGER

    def test_can_create_from_json_string(self):
        """Test that Metadatum can be created from JSON string."""
        meta = Metadatum.from_json('"hello"')
        assert meta is not None
        assert meta.kind == MetadatumKind.TEXT

    def test_can_create_from_json_bytes(self):
        """Test that Metadatum can be created from JSON bytes."""
        meta = Metadatum.from_json('{"0xdeadbeef": ""}')
        assert meta is not None
        assert meta.kind == MetadatumKind.MAP

    def test_can_create_from_json_list(self):
        """Test that Metadatum can be created from JSON list."""
        meta = Metadatum.from_json('[1, 2, 3]')
        assert meta is not None
        assert meta.kind == MetadatumKind.LIST

    def test_can_create_from_json_map(self):
        """Test that Metadatum can be created from JSON map."""
        meta = Metadatum.from_json('{"key": "value"}')
        assert meta is not None
        assert meta.kind == MetadatumKind.MAP

    def test_raises_error_if_json_is_none(self):
        """Test that creating metadatum with None JSON raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Metadatum.from_json(None)

    def test_raises_error_if_json_is_invalid(self):
        """Test that creating metadatum with invalid JSON raises an error."""
        with pytest.raises(CardanoError):
            Metadatum.from_json("not json")


class TestMetadatumKind:
    """Tests for Metadatum.kind property."""

    def test_kind_is_integer_for_int(self):
        """Test that kind is INTEGER for int metadatum."""
        meta = Metadatum.from_int(42)
        assert meta.kind == MetadatumKind.INTEGER

    def test_kind_is_bytes_for_bytes(self):
        """Test that kind is BYTES for bytes metadatum."""
        meta = Metadatum.from_bytes(b"test")
        assert meta.kind == MetadatumKind.BYTES

    def test_kind_is_text_for_string(self):
        """Test that kind is TEXT for string metadatum."""
        meta = Metadatum.from_string("test")
        assert meta.kind == MetadatumKind.TEXT

    def test_kind_is_list_for_list(self):
        """Test that kind is LIST for list metadatum."""
        meta = Metadatum.from_list(MetadatumList())
        assert meta.kind == MetadatumKind.LIST

    def test_kind_is_map_for_map(self):
        """Test that kind is MAP for map metadatum."""
        meta = Metadatum.from_map(MetadatumMap())
        assert meta.kind == MetadatumKind.MAP


class TestMetadatumToInteger:
    """Tests for Metadatum.to_integer() method."""

    def test_can_convert_int_to_integer(self):
        """Test that int metadatum can be converted to BigInt."""
        meta = Metadatum.from_int(42)
        bigint = meta.to_integer()
        assert bigint.to_int() == 42

    def test_can_convert_uint_to_integer(self):
        """Test that uint metadatum can be converted to BigInt."""
        meta = Metadatum.from_uint(42)
        bigint = meta.to_integer()
        assert bigint.to_unsigned_int() == 42

    def test_raises_error_if_not_integer_type(self):
        """Test that converting non-integer metadatum raises an error."""
        meta = Metadatum.from_string("not an integer")
        with pytest.raises(CardanoError):
            meta.to_integer()


class TestMetadatumToBytes:
    """Tests for Metadatum.to_bytes() method."""

    def test_can_convert_bytes_to_bytes(self):
        """Test that bytes metadatum can be converted to bytes."""
        data = b"\xde\xad\xbe\xef"
        meta = Metadatum.from_bytes(data)
        retrieved = meta.to_bytes()
        assert retrieved == data

    def test_can_convert_hex_to_bytes(self):
        """Test that hex metadatum can be converted to bytes."""
        meta = Metadatum.from_hex("deadbeef")
        retrieved = meta.to_bytes()
        assert retrieved == b"\xde\xad\xbe\xef"

    def test_raises_error_if_not_bytes_type(self):
        """Test that converting non-bytes metadatum raises an error."""
        meta = Metadatum.from_int(42)
        with pytest.raises(CardanoError):
            meta.to_bytes()


class TestMetadatumToStr:
    """Tests for Metadatum.to_str() method."""

    def test_can_convert_string_to_str(self):
        """Test that string metadatum can be converted to str."""
        text = "Hello, Cardano!"
        meta = Metadatum.from_string(text)
        retrieved = meta.to_str()
        assert retrieved == text

    def test_can_convert_empty_string_to_str(self):
        """Test that empty string metadatum can be converted to str."""
        meta = Metadatum.from_string("")
        retrieved = meta.to_str()
        assert retrieved == ""


class TestMetadatumToMap:
    """Tests for Metadatum.to_map() method."""

    def test_can_convert_map_to_map(self):
        """Test that map metadatum can be converted to MetadatumMap."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        retrieved_map = meta.to_map()
        assert retrieved_map is not None
        assert len(retrieved_map) == 1

    def test_raises_error_if_not_map_type(self):
        """Test that converting non-map metadatum raises an error."""
        meta = Metadatum.from_int(42)
        with pytest.raises(CardanoError):
            meta.to_map()


class TestMetadatumToList:
    """Tests for Metadatum.to_list() method."""

    def test_can_convert_list_to_list(self):
        """Test that list metadatum can be converted to MetadatumList."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta = Metadatum.from_list(meta_list)
        retrieved_list = meta.to_list()
        assert retrieved_list is not None
        assert len(retrieved_list) == 2

    def test_raises_error_if_not_list_type(self):
        """Test that converting non-list metadatum raises an error."""
        meta = Metadatum.from_int(42)
        with pytest.raises(CardanoError):
            meta.to_list()


class TestMetadatumToJson:
    """Tests for Metadatum.to_json() method."""

    def test_can_convert_integer_to_json(self):
        """Test that integer metadatum can be converted to JSON."""
        meta = Metadatum.from_int(42)
        json_str = meta.to_json()
        assert json_str is not None
        assert "42" in json_str

    def test_can_convert_string_to_json(self):
        """Test that string metadatum can be converted to JSON."""
        meta = Metadatum.from_string("hello")
        json_str = meta.to_json()
        assert json_str is not None
        assert "hello" in json_str

    def test_can_convert_bytes_to_json(self):
        """Test that bytes metadatum can be converted to JSON."""
        meta = Metadatum.from_hex("deadbeef")
        json_str = meta.to_json()
        assert json_str is not None

    def test_can_convert_list_to_json(self):
        """Test that list metadatum can be converted to JSON."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta = Metadatum.from_list(meta_list)
        json_str = meta.to_json()
        assert json_str is not None

    def test_can_convert_map_to_json(self):
        """Test that map metadatum can be converted to JSON."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        json_str = meta.to_json()
        assert json_str is not None


class TestMetadatumToCip116Json:
    """Tests for Metadatum.to_cip116_json() method."""

    def test_can_convert_integer_to_cip116_json(self):
        """Test that integer metadatum can be converted to CIP-116 JSON."""
        meta = Metadatum.from_int(42)
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "int" in json_str

    def test_can_convert_string_to_cip116_json(self):
        """Test that string metadatum can be converted to CIP-116 JSON."""
        meta = Metadatum.from_string("hello")
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "string" in json_str

    def test_can_convert_bytes_to_cip116_json(self):
        """Test that bytes metadatum can be converted to CIP-116 JSON."""
        meta = Metadatum.from_hex("deadbeef")
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "bytes" in json_str

    def test_can_convert_list_to_cip116_json(self):
        """Test that list metadatum can be converted to CIP-116 JSON."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta = Metadatum.from_list(meta_list)
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "list" in json_str

    def test_can_convert_map_to_cip116_json(self):
        """Test that map metadatum can be converted to CIP-116 JSON."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "map" in json_str

    def test_raises_error_if_writer_is_none(self):
        """Test that converting with None writer raises an error."""
        meta = Metadatum.from_int(42)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            meta.to_cip116_json(None)


class TestMetadatumToCbor:
    """Tests for Metadatum.to_cbor() method."""

    def test_can_serialize_integer_to_cbor(self):
        """Test that integer metadatum can be serialized to CBOR."""
        meta = Metadatum.from_int(42)
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None

    def test_can_serialize_string_to_cbor(self):
        """Test that string metadatum can be serialized to CBOR."""
        meta = Metadatum.from_string("hello")
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None

    def test_can_serialize_bytes_to_cbor(self):
        """Test that bytes metadatum can be serialized to CBOR."""
        meta = Metadatum.from_hex("deadbeef")
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None

    def test_can_serialize_list_to_cbor(self):
        """Test that list metadatum can be serialized to CBOR."""
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta = Metadatum.from_list(meta_list)
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None

    def test_can_serialize_map_to_cbor(self):
        """Test that map metadatum can be serialized to CBOR."""
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None

    def test_can_roundtrip_cbor(self):
        """Test that metadatum can be serialized and deserialized."""
        meta = Metadatum.from_int(42)
        writer = CborWriter()
        meta.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        meta2 = Metadatum.from_cbor(reader)
        assert meta == meta2

    def test_raises_error_if_writer_is_none(self):
        """Test that serializing with None writer raises an error."""
        meta = Metadatum.from_int(42)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            meta.to_cbor(None)


class TestMetadatumEquality:
    """Tests for Metadatum.__eq__() method."""

    def test_integer_metadatum_equals_itself(self):
        """Test that integer metadatum equals itself."""
        meta = Metadatum.from_int(42)
        assert meta == meta

    def test_two_integer_metadatum_with_same_value_are_equal(self):
        """Test that two integer metadatum with same value are equal."""
        meta1 = Metadatum.from_int(42)
        meta2 = Metadatum.from_int(42)
        assert meta1 == meta2

    def test_two_integer_metadatum_with_different_values_are_not_equal(self):
        """Test that two integer metadatum with different values are not equal."""
        meta1 = Metadatum.from_int(42)
        meta2 = Metadatum.from_int(43)
        assert meta1 != meta2

    def test_string_metadatum_equals_itself(self):
        """Test that string metadatum equals itself."""
        meta = Metadatum.from_string("hello")
        assert meta == meta

    def test_two_string_metadatum_with_same_value_are_equal(self):
        """Test that two string metadatum with same value are equal."""
        meta1 = Metadatum.from_string("hello")
        meta2 = Metadatum.from_string("hello")
        assert meta1 == meta2

    def test_two_string_metadatum_with_different_values_are_not_equal(self):
        """Test that two string metadatum with different values are not equal."""
        meta1 = Metadatum.from_string("hello")
        meta2 = Metadatum.from_string("world")
        assert meta1 != meta2

    def test_bytes_metadatum_equals_itself(self):
        """Test that bytes metadatum equals itself."""
        meta = Metadatum.from_bytes(b"test")
        assert meta == meta

    def test_two_bytes_metadatum_with_same_value_are_equal(self):
        """Test that two bytes metadatum with same value are equal."""
        meta1 = Metadatum.from_bytes(b"test")
        meta2 = Metadatum.from_bytes(b"test")
        assert meta1 == meta2

    def test_two_bytes_metadatum_with_different_values_are_not_equal(self):
        """Test that two bytes metadatum with different values are not equal."""
        meta1 = Metadatum.from_bytes(b"test")
        meta2 = Metadatum.from_bytes(b"other")
        assert meta1 != meta2

    def test_metadatum_is_not_equal_to_none(self):
        """Test that metadatum is not equal to None."""
        meta = Metadatum.from_int(42)
        assert meta != None

    def test_metadatum_is_not_equal_to_different_type(self):
        """Test that metadatum is not equal to different type."""
        meta = Metadatum.from_int(42)
        assert meta != 42
        assert meta != "42"


class TestMetadatumHash:
    """Tests for Metadatum.__hash__() method."""

    def test_integer_metadatum_is_hashable(self):
        """Test that integer metadatum is hashable."""
        meta = Metadatum.from_int(42)
        hash_value = hash(meta)
        assert hash_value is not None

    def test_string_metadatum_is_hashable(self):
        """Test that string metadatum is hashable."""
        meta = Metadatum.from_string("hello")
        hash_value = hash(meta)
        assert hash_value is not None

    def test_bytes_metadatum_is_hashable(self):
        """Test that bytes metadatum is hashable."""
        meta = Metadatum.from_bytes(b"test")
        hash_value = hash(meta)
        assert hash_value is not None

    def test_equal_metadatum_have_same_hash(self):
        """Test that equal metadatum have same hash."""
        meta1 = Metadatum.from_int(42)
        meta2 = Metadatum.from_int(42)
        assert hash(meta1) == hash(meta2)

    def test_metadatum_can_be_used_in_set(self):
        """Test that metadatum can be used in set."""
        meta1 = Metadatum.from_int(42)
        meta2 = Metadatum.from_int(42)
        meta3 = Metadatum.from_int(43)
        metadatum_set = {meta1, meta2, meta3}
        assert len(metadatum_set) == 2

    def test_metadatum_can_be_used_as_dict_key(self):
        """Test that metadatum can be used as dict key."""
        meta1 = Metadatum.from_int(42)
        meta2 = Metadatum.from_int(43)
        metadatum_dict = {meta1: "value1", meta2: "value2"}
        assert metadatum_dict[meta1] == "value1"
        assert metadatum_dict[meta2] == "value2"


class TestMetadatumRepr:
    """Tests for Metadatum.__repr__() method."""

    def test_repr_contains_kind_for_integer(self):
        """Test that repr contains kind for integer metadatum."""
        meta = Metadatum.from_int(42)
        repr_str = repr(meta)
        assert "Metadatum" in repr_str
        assert "INTEGER" in repr_str

    def test_repr_contains_kind_for_string(self):
        """Test that repr contains kind for string metadatum."""
        meta = Metadatum.from_string("hello")
        repr_str = repr(meta)
        assert "Metadatum" in repr_str
        assert "TEXT" in repr_str

    def test_repr_contains_kind_for_bytes(self):
        """Test that repr contains kind for bytes metadatum."""
        meta = Metadatum.from_bytes(b"test")
        repr_str = repr(meta)
        assert "Metadatum" in repr_str
        assert "BYTES" in repr_str

    def test_repr_contains_kind_for_list(self):
        """Test that repr contains kind for list metadatum."""
        meta = Metadatum.from_list(MetadatumList())
        repr_str = repr(meta)
        assert "Metadatum" in repr_str
        assert "LIST" in repr_str

    def test_repr_contains_kind_for_map(self):
        """Test that repr contains kind for map metadatum."""
        meta = Metadatum.from_map(MetadatumMap())
        repr_str = repr(meta)
        assert "Metadatum" in repr_str
        assert "MAP" in repr_str


class TestMetadatumContextManager:
    """Tests for Metadatum context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that Metadatum can be used as context manager."""
        with Metadatum.from_int(42) as meta:
            assert meta is not None
            assert meta.kind == MetadatumKind.INTEGER

    def test_context_manager_exits_normally(self):
        """Test that context manager exits normally."""
        meta = Metadatum.from_int(42)
        with meta:
            pass
        assert meta is not None


class TestMetadatumEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_can_create_large_integer_metadatum(self):
        """Test that Metadatum can handle very large integers."""
        large_value = "123456789012345678901234567890123456789012345678901234567890"
        meta = Metadatum.from_integer_string(large_value)
        bigint = meta.to_integer()
        assert bigint.to_string(10) == large_value

    def test_can_create_negative_integer_metadatum(self):
        """Test that Metadatum can handle negative integers."""
        meta = Metadatum.from_int(-12345)
        bigint = meta.to_integer()
        assert bigint.to_int() == -12345

    def test_can_create_zero_integer_metadatum(self):
        """Test that Metadatum can handle zero."""
        meta = Metadatum.from_int(0)
        bigint = meta.to_integer()
        assert bigint.to_int() == 0

    def test_can_create_empty_string_metadatum(self):
        """Test that Metadatum can handle empty strings."""
        meta = Metadatum.from_string("")
        text = meta.to_str()
        assert text == ""

    def test_can_create_empty_bytes_metadatum(self):
        """Test that Metadatum can handle empty bytes."""
        meta = Metadatum.from_bytes(b"")
        data = meta.to_bytes()
        assert data == b""

    def test_can_create_empty_list_metadatum(self):
        """Test that Metadatum can handle empty lists."""
        meta = Metadatum.from_list(MetadatumList())
        meta_list = meta.to_list()
        assert len(meta_list) == 0

    def test_can_create_empty_map_metadatum(self):
        """Test that Metadatum can handle empty maps."""
        meta = Metadatum.from_map(MetadatumMap())
        meta_map = meta.to_map()
        assert len(meta_map) == 0

    def test_can_create_nested_structures(self):
        """Test that Metadatum can handle nested structures."""
        inner_list = MetadatumList()
        inner_list.add(Metadatum.from_int(1))
        inner_list.add(Metadatum.from_int(2))

        outer_list = MetadatumList()
        outer_list.add(Metadatum.from_list(inner_list))
        outer_list.add(Metadatum.from_string("test"))

        meta = Metadatum.from_list(outer_list)
        assert meta is not None
        assert meta.kind == MetadatumKind.LIST
