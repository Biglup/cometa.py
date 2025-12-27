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
from cometa import AssetName, CborReader, CborWriter, JsonWriter, CardanoError


ASSET_NAME_HEX = "736b7977616c6b6572"
ASSET_NAME_BYTES = bytes([
    0x73, 0x6b, 0x79, 0x77, 0x61, 0x6c, 0x6b, 0x65, 0x72
])
ASSET_NAME_STRING = "skywalker"
ASSET_NAME_CBOR = "49736b7977616c6b6572"
EMPTY_ASSET_NAME_CBOR = "40"


class TestAssetNameFromBytes:
    """Tests for AssetName.from_bytes() factory method."""

    def test_can_create_from_bytes(self):
        """Test that AssetName can be created from bytes."""
        asset_name = AssetName.from_bytes(ASSET_NAME_BYTES)
        assert asset_name is not None
        assert asset_name.to_bytes() == ASSET_NAME_BYTES

    def test_can_create_from_bytearray(self):
        """Test that AssetName can be created from bytearray."""
        asset_name = AssetName.from_bytes(bytearray(ASSET_NAME_BYTES))
        assert asset_name is not None
        assert asset_name.to_bytes() == ASSET_NAME_BYTES

    def test_can_create_empty_asset_name(self):
        """Test that AssetName can be created with empty bytes."""
        asset_name = AssetName.from_bytes(b"")
        assert asset_name is not None
        assert len(asset_name) == 0
        assert asset_name.to_bytes() == b""

    def test_can_create_with_max_length(self):
        """Test that AssetName can be created with maximum 32 bytes."""
        max_bytes = b"a" * 32
        asset_name = AssetName.from_bytes(max_bytes)
        assert asset_name is not None
        assert len(asset_name) == 32

    def test_can_create_with_binary_data(self):
        """Test that AssetName can contain arbitrary binary data."""
        binary_data = bytes([0x00, 0xff, 0x80, 0x7f])
        asset_name = AssetName.from_bytes(binary_data)
        assert asset_name is not None
        assert asset_name.to_bytes() == binary_data

    def test_raises_error_for_none_data(self):
        """Test that None data raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetName.from_bytes(None)

    def test_raises_error_for_invalid_type(self):
        """Test that invalid data type raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetName.from_bytes("not bytes")

    def test_raises_error_for_too_long(self):
        """Test that bytes longer than 32 raise an error."""
        too_long = b"a" * 33
        with pytest.raises(CardanoError):
            AssetName.from_bytes(too_long)


class TestAssetNameFromHex:
    """Tests for AssetName.from_hex() factory method."""

    def test_can_create_from_hex(self):
        """Test that AssetName can be created from hex string."""
        asset_name = AssetName.from_hex(ASSET_NAME_HEX)
        assert asset_name is not None
        assert asset_name.to_hex() == ASSET_NAME_HEX

    def test_can_create_from_uppercase_hex(self):
        """Test that AssetName can be created from uppercase hex."""
        asset_name = AssetName.from_hex(ASSET_NAME_HEX.upper())
        assert asset_name is not None
        assert asset_name.to_hex().lower() == ASSET_NAME_HEX.lower()

    def test_can_create_empty_asset_name_from_hex(self):
        """Test that AssetName can be created from empty hex string."""
        asset_name = AssetName.from_hex("")
        assert asset_name is not None
        assert len(asset_name) == 0

    def test_can_create_with_max_length_hex(self):
        """Test that AssetName can be created from 64-char hex (32 bytes)."""
        max_hex = "ab" * 32
        asset_name = AssetName.from_hex(max_hex)
        assert asset_name is not None
        assert len(asset_name) == 32

    def test_raises_error_for_none_hex(self):
        """Test that None hex string raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_hex(None)

    def test_raises_error_for_invalid_hex_characters(self):
        """Test that invalid hex characters raise an error."""
        with pytest.raises(CardanoError):
            AssetName.from_hex("zz")

    def test_raises_error_for_odd_length_hex(self):
        """Test that odd-length hex string raises an error."""
        with pytest.raises(CardanoError):
            AssetName.from_hex("abc")

    def test_raises_error_for_too_long_hex(self):
        """Test that hex longer than 64 characters (32 bytes) raises an error."""
        too_long_hex = "ab" * 33
        with pytest.raises(CardanoError):
            AssetName.from_hex(too_long_hex)

    def test_raises_error_for_invalid_type(self):
        """Test that invalid type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_hex(123)


class TestAssetNameFromString:
    """Tests for AssetName.from_string() factory method."""

    def test_can_create_from_string(self):
        """Test that AssetName can be created from string."""
        asset_name = AssetName.from_string(ASSET_NAME_STRING)
        assert asset_name is not None
        assert asset_name.to_string() == ASSET_NAME_STRING

    def test_can_create_empty_asset_name_from_string(self):
        """Test that AssetName can be created from empty string."""
        asset_name = AssetName.from_string("")
        assert asset_name is not None
        assert len(asset_name) == 0

    def test_can_create_with_unicode_characters(self):
        """Test that AssetName can contain unicode characters."""
        unicode_name = "MyToken🎉"
        asset_name = AssetName.from_string(unicode_name)
        assert asset_name is not None
        assert asset_name.to_string() == unicode_name

    def test_can_create_with_special_characters(self):
        """Test that AssetName can contain special characters."""
        special_name = "Token_123-ABC.xyz"
        asset_name = AssetName.from_string(special_name)
        assert asset_name is not None
        assert asset_name.to_string() == special_name

    def test_raises_error_for_none_string(self):
        """Test that None string raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_string(None)

    def test_raises_error_for_invalid_type(self):
        """Test that invalid type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_string(123)

    def test_raises_error_for_too_long_string(self):
        """Test that string longer than 32 bytes raises an error."""
        too_long = "a" * 33
        with pytest.raises(CardanoError):
            AssetName.from_string(too_long)


class TestAssetNameFromCbor:
    """Tests for AssetName.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that AssetName can be deserialized from CBOR."""
        reader = CborReader.from_hex(ASSET_NAME_CBOR)
        asset_name = AssetName.from_cbor(reader)
        assert asset_name is not None
        assert asset_name.to_bytes() == ASSET_NAME_BYTES

    def test_can_deserialize_empty_asset_name(self):
        """Test that empty AssetName can be deserialized from CBOR."""
        reader = CborReader.from_hex(EMPTY_ASSET_NAME_CBOR)
        asset_name = AssetName.from_cbor(reader)
        assert asset_name is not None
        assert len(asset_name) == 0

    def test_raises_error_for_none_reader(self):
        """Test that None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_cbor(None)

    def test_raises_error_for_invalid_cbor_data(self):
        """Test that invalid CBOR data raises an error."""
        reader = CborReader.from_hex("ef")
        with pytest.raises(CardanoError):
            AssetName.from_cbor(reader)

    def test_raises_error_for_invalid_type(self):
        """Test that invalid type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetName.from_cbor("not a reader")


class TestAssetNameToBytes:
    """Tests for AssetName.to_bytes() method."""

    def test_returns_correct_bytes(self):
        """Test that to_bytes returns the correct bytes."""
        asset_name = AssetName.from_hex(ASSET_NAME_HEX)
        assert asset_name.to_bytes() == ASSET_NAME_BYTES

    def test_returns_empty_bytes_for_empty_asset_name(self):
        """Test that to_bytes returns empty bytes for empty asset name."""
        asset_name = AssetName.from_bytes(b"")
        assert asset_name.to_bytes() == b""

    def test_returns_bytes_for_binary_data(self):
        """Test that to_bytes works with binary data."""
        binary_data = bytes([0x00, 0xff, 0x80])
        asset_name = AssetName.from_bytes(binary_data)
        assert asset_name.to_bytes() == binary_data


class TestAssetNameToHex:
    """Tests for AssetName.to_hex() method."""

    def test_returns_correct_hex(self):
        """Test that to_hex returns the correct hex string."""
        asset_name = AssetName.from_bytes(ASSET_NAME_BYTES)
        assert asset_name.to_hex() == ASSET_NAME_HEX

    def test_returns_empty_string_for_empty_asset_name(self):
        """Test that to_hex returns empty string for empty asset name."""
        asset_name = AssetName.from_bytes(b"")
        assert asset_name.to_hex() == ""

    def test_returns_lowercase_hex(self):
        """Test that to_hex returns lowercase hex."""
        asset_name = AssetName.from_string("ABC")
        hex_result = asset_name.to_hex()
        assert hex_result == hex_result.lower()


class TestAssetNameToString:
    """Tests for AssetName.to_string() method."""

    def test_returns_correct_string(self):
        """Test that to_string returns the correct string."""
        asset_name = AssetName.from_string(ASSET_NAME_STRING)
        assert asset_name.to_string() == ASSET_NAME_STRING

    def test_returns_empty_string_for_empty_asset_name(self):
        """Test that to_string returns empty string for empty asset name."""
        asset_name = AssetName.from_bytes(b"")
        assert asset_name.to_string() == ""

    def test_returns_string_with_unicode(self):
        """Test that to_string works with unicode characters."""
        unicode_name = "Token🎉"
        asset_name = AssetName.from_string(unicode_name)
        assert asset_name.to_string() == unicode_name

    def test_may_return_garbled_for_binary_data(self):
        """Test that to_string handles non-UTF-8 data gracefully."""
        binary_data = bytes([0xff, 0xfe])
        asset_name = AssetName.from_bytes(binary_data)
        result = asset_name.to_string()
        assert isinstance(result, str)


class TestAssetNameToCbor:
    """Tests for AssetName.to_cbor() method."""

    def test_can_serialize_to_cbor(self):
        """Test that AssetName can be serialized to CBOR."""
        asset_name = AssetName.from_bytes(ASSET_NAME_BYTES)
        writer = CborWriter()
        asset_name.to_cbor(writer)
        result = writer.to_hex()
        assert result == ASSET_NAME_CBOR

    def test_can_serialize_empty_asset_name(self):
        """Test that empty AssetName can be serialized to CBOR."""
        asset_name = AssetName.from_bytes(b"")
        writer = CborWriter()
        asset_name.to_cbor(writer)
        result = writer.to_hex()
        assert result == EMPTY_ASSET_NAME_CBOR

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        original = AssetName.from_string(ASSET_NAME_STRING)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        deserialized = AssetName.from_cbor(reader)

        assert deserialized == original

    def test_raises_error_for_none_writer(self):
        """Test that None writer raises an error."""
        asset_name = AssetName.from_string("Token")
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_name.to_cbor(None)

    def test_raises_error_for_invalid_writer(self):
        """Test that invalid writer raises an error."""
        asset_name = AssetName.from_string("Token")
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_name.to_cbor("not a writer")


class TestAssetNameToCip116Json:
    """Tests for AssetName.to_cip116_json() method."""

    def test_can_serialize_to_cip116_json(self):
        """Test that AssetName can be serialized to CIP-116 JSON."""
        data = bytes([0x4D, 0x79, 0x41, 0x73, 0x73, 0x65, 0x74])
        asset_name = AssetName.from_bytes(data)
        writer = JsonWriter()
        asset_name.to_cip116_json(writer)
        result = writer.encode()
        assert result == '"4d794173736574"'

    def test_can_serialize_empty_asset_name_to_cip116_json(self):
        """Test that empty AssetName can be serialized to CIP-116 JSON."""
        asset_name = AssetName.from_bytes(b"")
        writer = JsonWriter()
        asset_name.to_cip116_json(writer)
        result = writer.encode()
        assert result == '""'

    def test_raises_error_for_none_writer(self):
        """Test that None writer raises an error."""
        asset_name = AssetName.from_string("Token")
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_name.to_cip116_json(None)

    def test_raises_error_for_invalid_writer(self):
        """Test that invalid writer raises an error."""
        asset_name = AssetName.from_string("Token")
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_name.to_cip116_json("not a writer")


class TestAssetNameMagicMethods:
    """Tests for AssetName magic methods."""

    def test_len_returns_byte_size(self):
        """Test that __len__ returns the byte size."""
        asset_name = AssetName.from_string("Test")
        assert len(asset_name) == 4

    def test_len_returns_zero_for_empty(self):
        """Test that __len__ returns 0 for empty asset name."""
        asset_name = AssetName.from_bytes(b"")
        assert len(asset_name) == 0

    def test_equality_with_same_content(self):
        """Test that two AssetNames with same content are equal."""
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        assert name1 == name2

    def test_inequality_with_different_content(self):
        """Test that two AssetNames with different content are not equal."""
        name1 = AssetName.from_string("Token1")
        name2 = AssetName.from_string("Token2")
        assert name1 != name2

    def test_equality_with_non_asset_name(self):
        """Test that AssetName is not equal to non-AssetName objects."""
        name = AssetName.from_string("Token")
        assert name != "Token"
        assert name != b"Token"
        assert name != None
        assert name != 123

    def test_hash_same_for_equal_objects(self):
        """Test that hash is the same for equal objects."""
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        assert hash(name1) == hash(name2)

    def test_hash_different_for_different_objects(self):
        """Test that hash is different for different objects."""
        name1 = AssetName.from_string("Token1")
        name2 = AssetName.from_string("Token2")
        assert hash(name1) != hash(name2)

    def test_can_use_in_set(self):
        """Test that AssetName can be used in a set."""
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        name3 = AssetName.from_string("Other")
        asset_set = {name1, name2, name3}
        assert len(asset_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that AssetName can be used as a dict key."""
        name = AssetName.from_string("Token")
        asset_dict = {name: 100}
        assert asset_dict[name] == 100

    def test_str_returns_string_representation(self):
        """Test that __str__ returns string representation."""
        asset_name = AssetName.from_string("Token")
        assert str(asset_name) == "Token"

    def test_str_returns_hex_for_binary_data(self):
        """Test that __str__ returns hex for non-UTF-8 data."""
        binary_data = bytes([0xff, 0xfe])
        asset_name = AssetName.from_bytes(binary_data)
        result = str(asset_name)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_repr_contains_string_name(self):
        """Test that __repr__ contains the string name."""
        asset_name = AssetName.from_string("Token")
        repr_str = repr(asset_name)
        assert "Token" in repr_str
        assert "AssetName" in repr_str

    def test_repr_contains_representation_for_binary_data(self):
        """Test that __repr__ contains a representation for binary data."""
        binary_data = bytes([0xff, 0xfe])
        asset_name = AssetName.from_bytes(binary_data)
        repr_str = repr(asset_name)
        assert "AssetName" in repr_str
        assert len(repr_str) > len("AssetName()")


class TestAssetNameContextManager:
    """Tests for AssetName context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that AssetName can be used as a context manager."""
        with AssetName.from_string("Token") as asset_name:
            assert asset_name is not None
            assert asset_name.to_string() == "Token"

    def test_object_accessible_after_context(self):
        """Test that object is still accessible after context (Python manages refs)."""
        with AssetName.from_string("Token") as asset_name:
            assert asset_name is not None
        assert asset_name.to_string() == "Token"


class TestAssetNameEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_asset_name_equals_another_empty(self):
        """Test that empty asset names are equal."""
        name1 = AssetName.from_bytes(b"")
        name2 = AssetName.from_string("")
        assert name1 == name2

    def test_asset_name_with_null_bytes(self):
        """Test that AssetName can contain null bytes."""
        data_with_nulls = b"Token\x00\x00"
        asset_name = AssetName.from_bytes(data_with_nulls)
        assert asset_name.to_bytes() == data_with_nulls

    def test_asset_name_with_all_zeros(self):
        """Test that AssetName can be all zeros."""
        all_zeros = b"\x00" * 10
        asset_name = AssetName.from_bytes(all_zeros)
        assert len(asset_name) == 10
        assert asset_name.to_bytes() == all_zeros

    def test_asset_name_with_all_ones(self):
        """Test that AssetName can be all 0xFF bytes."""
        all_ones = b"\xff" * 10
        asset_name = AssetName.from_bytes(all_ones)
        assert len(asset_name) == 10
        assert asset_name.to_bytes() == all_ones

    def test_single_byte_asset_name(self):
        """Test that AssetName can be a single byte."""
        asset_name = AssetName.from_bytes(b"X")
        assert len(asset_name) == 1
        assert asset_name.to_string() == "X"

    def test_multibyte_unicode_character(self):
        """Test that multibyte unicode characters are handled correctly."""
        emoji_name = "🎉"
        asset_name = AssetName.from_string(emoji_name)
        assert asset_name.to_string() == emoji_name
        assert len(asset_name) == len(emoji_name.encode("utf-8"))


class TestAssetNameTestVectorsFromC:
    """Tests using test vectors from the C test file."""

    def test_skywalker_test_vector(self):
        """Test the 'skywalker' test vector from C tests."""
        asset_name = AssetName.from_hex(ASSET_NAME_HEX)
        assert asset_name.to_string() == ASSET_NAME_STRING
        assert asset_name.to_bytes() == ASSET_NAME_BYTES
        assert asset_name.to_hex() == ASSET_NAME_HEX

    def test_cbor_encoding_skywalker(self):
        """Test CBOR encoding of 'skywalker' matches C test."""
        asset_name = AssetName.from_hex(ASSET_NAME_HEX)
        writer = CborWriter()
        asset_name.to_cbor(writer)
        assert writer.to_hex() == ASSET_NAME_CBOR

    def test_cbor_decoding_skywalker(self):
        """Test CBOR decoding of 'skywalker' matches C test."""
        reader = CborReader.from_hex(ASSET_NAME_CBOR)
        asset_name = AssetName.from_cbor(reader)
        assert asset_name.to_bytes() == ASSET_NAME_BYTES
        assert asset_name.to_string() == ASSET_NAME_STRING

    def test_empty_asset_name_cbor_encoding(self):
        """Test empty asset name CBOR encoding matches C test."""
        asset_name = AssetName.from_bytes(b"")
        writer = CborWriter()
        asset_name.to_cbor(writer)
        assert writer.to_hex() == EMPTY_ASSET_NAME_CBOR

    def test_empty_asset_name_cbor_decoding(self):
        """Test empty asset name CBOR decoding matches C test."""
        reader = CborReader.from_hex(EMPTY_ASSET_NAME_CBOR)
        asset_name = AssetName.from_cbor(reader)
        assert len(asset_name) == 0
        assert asset_name.to_bytes() == b""
