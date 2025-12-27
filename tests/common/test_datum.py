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
    Datum,
    DatumType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
    PlutusData
)


INLINE_DATUM_CBOR = "8201d81849d8799f0102030405ff"
DATUM_HASH_CBOR = "820058200000000000000000000000000000000000000000000000000000000000000000"
HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
PLUTUS_DATA_CBOR = "d8799f0102030405ff"


class TestDatumFromDataHash:
    """Tests for Datum.from_data_hash() factory method."""

    def test_can_create_datum_from_hash(self):
        """Test that Datum can be created from a Blake2bHash."""
        hash_val = Blake2bHash.from_hex(HASH_HEX)
        datum = Datum.from_data_hash(hash_val)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_datum_hash_is_retrievable(self):
        """Test that the hash can be retrieved from the datum."""
        hash_val = Blake2bHash.from_hex(HASH_HEX)
        datum = Datum.from_data_hash(hash_val)
        retrieved_hash = datum.data_hash
        assert retrieved_hash is not None
        assert retrieved_hash.to_hex() == HASH_HEX

    def test_raises_error_if_hash_is_none(self):
        """Test that creating datum with None hash raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_data_hash(None)

    def test_raises_error_if_hash_is_invalid_type(self):
        """Test that creating datum with invalid hash type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_data_hash("not a hash")

    def test_raises_error_if_hash_is_wrong_size(self):
        """Test that creating datum with wrong size hash raises an error."""
        invalid_hash_hex = "82005821000000000000000000000000000000000000000000000000000000000000000000"
        with pytest.raises(CardanoError):
            hash_val = Blake2bHash.from_hex(invalid_hash_hex)
            Datum.from_data_hash(hash_val)


class TestDatumFromDataHashHex:
    """Tests for Datum.from_data_hash_hex() factory method."""

    def test_can_create_datum_from_hex_string(self):
        """Test that Datum can be created from hexadecimal hash string."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_hex_string_is_retrievable(self):
        """Test that the hex string can be retrieved from the datum."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        assert datum.data_hash_hex == HASH_HEX

    def test_can_create_datum_with_various_hex_lengths(self):
        """Test that Datum can be created with valid 64-character hex strings."""
        hex_string = "abcd1234" * 8
        datum = Datum.from_data_hash_hex(hex_string)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_raises_error_if_hex_is_none(self):
        """Test that creating datum with None hex raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_data_hash_hex(None)

    def test_raises_error_if_hex_is_invalid_length(self):
        """Test that creating datum with invalid hex length raises an error."""
        with pytest.raises(CardanoError):
            Datum.from_data_hash_hex("abcd")


class TestDatumFromDataHashBytes:
    """Tests for Datum.from_data_hash_bytes() factory method."""

    def test_can_create_datum_from_bytes(self):
        """Test that Datum can be created from raw hash bytes."""
        hash_bytes = bytes(32)
        datum = Datum.from_data_hash_bytes(hash_bytes)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_can_create_datum_from_bytearray(self):
        """Test that Datum can be created from bytearray."""
        hash_bytes = bytearray(32)
        datum = Datum.from_data_hash_bytes(hash_bytes)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_bytes_are_retrievable(self):
        """Test that bytes can be retrieved from the datum."""
        hash_bytes = bytes(32)
        datum = Datum.from_data_hash_bytes(hash_bytes)
        retrieved_bytes = datum.data_hash_bytes
        assert retrieved_bytes == hash_bytes

    def test_raises_error_if_bytes_are_none(self):
        """Test that creating datum with None bytes raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_data_hash_bytes(None)

    def test_raises_error_if_bytes_are_wrong_size(self):
        """Test that creating datum with wrong size bytes raises an error."""
        with pytest.raises(CardanoError):
            Datum.from_data_hash_bytes(bytes(31))

    def test_raises_error_if_bytes_are_too_large(self):
        """Test that creating datum with too large bytes raises an error."""
        with pytest.raises(CardanoError):
            Datum.from_data_hash_bytes(bytes(33))


class TestDatumFromInlineData:
    """Tests for Datum.from_inline_data() factory method."""

    def test_can_create_datum_from_plutus_data(self):
        """Test that Datum can be created from PlutusData."""
        plutus_data = PlutusData.from_int(42)
        datum = Datum.from_inline_data(plutus_data)
        assert datum is not None
        assert datum.datum_type == DatumType.INLINE_DATA

    def test_can_retrieve_inline_data(self):
        """Test that inline data can be retrieved from the datum."""
        plutus_data = PlutusData.from_int(42)
        datum = Datum.from_inline_data(plutus_data)
        retrieved_data = datum.get_inline_data()
        assert retrieved_data is not None

    def test_raises_error_if_data_is_none(self):
        """Test that creating datum with None data raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_inline_data(None)

    def test_raises_error_if_data_is_invalid_type(self):
        """Test that creating datum with invalid data type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_inline_data("not plutus data")


class TestDatumFromCbor:
    """Tests for CBOR deserialization."""

    def test_can_deserialize_inline_datum_from_cbor(self):
        """Test that inline Datum can be deserialized from CBOR."""
        reader = CborReader.from_hex(INLINE_DATUM_CBOR)
        datum = Datum.from_cbor(reader)
        assert datum is not None
        assert datum.datum_type == DatumType.INLINE_DATA

    def test_can_deserialize_data_hash_from_cbor(self):
        """Test that data hash Datum can be deserialized from CBOR."""
        reader = CborReader.from_hex(DATUM_HASH_CBOR)
        datum = Datum.from_cbor(reader)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_raises_error_if_reader_is_none(self):
        """Test that deserializing with None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Datum.from_cbor(None)

    def test_raises_error_with_invalid_array_size(self):
        """Test that deserializing with invalid array size raises an error."""
        invalid_cbor = "8100581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Datum.from_cbor(reader)

    def test_raises_error_with_invalid_datum_type(self):
        """Test that deserializing with invalid datum type raises an error."""
        invalid_cbor = "8203581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Datum.from_cbor(reader)

    def test_raises_error_with_invalid_byte_string_size(self):
        """Test that deserializing with invalid byte string size raises an error."""
        invalid_cbor = "8200581b0000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Datum.from_cbor(reader)

    def test_raises_error_with_invalid_tag(self):
        """Test that deserializing with invalid tag raises an error."""
        invalid_cbor = "8201ef1849d8799f0102030405ff"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Datum.from_cbor(reader)

    def test_raises_error_with_invalid_tag_value(self):
        """Test that deserializing with invalid tag value raises an error."""
        invalid_cbor = "8201d81949d8799f0102030405ff"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Datum.from_cbor(reader)


class TestDatumToCbor:
    """Tests for CBOR serialization."""

    def test_can_serialize_inline_datum_to_cbor(self):
        """Test that inline Datum can be serialized to CBOR."""
        reader = CborReader.from_hex(INLINE_DATUM_CBOR)
        datum = Datum.from_cbor(reader)
        writer = CborWriter()
        datum.to_cbor(writer)
        result = writer.to_hex()
        assert result == INLINE_DATUM_CBOR

    def test_can_serialize_data_hash_to_cbor(self):
        """Test that data hash Datum can be serialized to CBOR."""
        reader = CborReader.from_hex(DATUM_HASH_CBOR)
        datum = Datum.from_cbor(reader)
        writer = CborWriter()
        datum.to_cbor(writer)
        result = writer.to_hex()
        assert result == DATUM_HASH_CBOR

    def test_roundtrip_cbor_serialization_inline(self):
        """Test that CBOR serialization/deserialization roundtrip works for inline datum."""
        original = Datum.from_data_hash_hex(HASH_HEX)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = Datum.from_cbor(reader)

        assert deserialized.datum_type == original.datum_type

    def test_raises_error_if_writer_is_none(self):
        """Test that serializing with None writer raises an error."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            datum.to_cbor(None)


class TestDatumProperties:
    """Tests for Datum properties."""

    def test_get_datum_type_for_data_hash(self):
        """Test that datum_type returns DATA_HASH for hash-based datum."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        assert datum.datum_type == DatumType.DATA_HASH

    def test_get_datum_type_for_inline_data(self):
        """Test that datum_type returns INLINE_DATA for inline datum."""
        plutus_data = PlutusData.from_int(42)
        datum = Datum.from_inline_data(plutus_data)
        assert datum.datum_type == DatumType.INLINE_DATA

    def test_get_data_hash_returns_hash(self):
        """Test that data_hash property returns Blake2bHash."""
        hash_val = Blake2bHash.from_hex(HASH_HEX)
        datum = Datum.from_data_hash(hash_val)
        retrieved_hash = datum.data_hash
        assert retrieved_hash is not None
        assert isinstance(retrieved_hash, Blake2bHash)

    def test_get_data_hash_hex_returns_string(self):
        """Test that data_hash_hex property returns hex string."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hex_str = datum.data_hash_hex
        assert isinstance(hex_str, str)
        assert hex_str == HASH_HEX

    def test_get_data_hash_bytes_returns_bytes(self):
        """Test that data_hash_bytes property returns bytes."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hash_bytes = datum.data_hash_bytes
        assert isinstance(hash_bytes, bytes)
        assert len(hash_bytes) == 32

    def test_set_data_hash_updates_hash(self):
        """Test that data_hash setter updates the hash."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        new_hash_hex = "abcd1234" * 8
        new_hash = Blake2bHash.from_hex(new_hash_hex)
        datum.data_hash = new_hash
        assert datum.data_hash_hex == new_hash_hex

    def test_set_data_hash_raises_error_with_none(self):
        """Test that setting data_hash to None raises an error."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            datum.data_hash = None

    def test_set_data_hash_raises_error_with_wrong_size(self):
        """Test that setting data_hash with wrong size raises an error."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        invalid_hash_hex = "82005821000000000000000000000000000000000000000000000000000000000000000000"
        with pytest.raises(CardanoError):
            invalid_hash = Blake2bHash.from_hex(invalid_hash_hex)
            datum.data_hash = invalid_hash


class TestDatumGetInlineData:
    """Tests for get_inline_data() method."""

    def test_get_inline_data_returns_plutus_data(self):
        """Test that get_inline_data returns PlutusData for inline datum."""
        plutus_data = PlutusData.from_int(42)
        datum = Datum.from_inline_data(plutus_data)
        retrieved_data = datum.get_inline_data()
        assert retrieved_data is not None

    def test_get_inline_data_returns_none_for_hash_datum(self):
        """Test that get_inline_data returns None for hash-based datum."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        retrieved_data = datum.get_inline_data()
        assert retrieved_data is None


class TestDatumToCip116Json:
    """Tests for CIP-116 JSON serialization."""

    def test_can_convert_data_hash_to_cip116_json(self):
        """Test that data hash Datum can be converted to CIP-116 JSON."""
        hash_val = Blake2bHash.from_hex(HASH_HEX)
        datum = Datum.from_data_hash(hash_val)
        writer = JsonWriter()
        datum.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"datum_hash"' in json_str
        assert f'"value":"{HASH_HEX}"' in json_str

    def test_can_convert_inline_data_to_cip116_json(self):
        """Test that inline Datum can be converted to CIP-116 JSON."""
        plutus_data = PlutusData.from_int(10)
        datum = Datum.from_inline_data(plutus_data)
        writer = JsonWriter()
        datum.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"datum"' in json_str
        assert '"value"' in json_str

    def test_raises_error_if_writer_is_none(self):
        """Test that converting to CIP-116 JSON with None writer raises an error."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        with pytest.raises((CardanoError, TypeError)):
            datum.to_cip116_json(None)

    def test_raises_error_if_writer_is_wrong_type(self):
        """Test that converting to CIP-116 JSON with wrong writer type raises an error."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        with pytest.raises((CardanoError, TypeError)):
            datum.to_cip116_json("not a writer")


class TestDatumMagicMethods:
    """Tests for magic methods (__eq__, __hash__, __repr__, __str__)."""

    def test_equality_with_same_hash(self):
        """Test that two Datums with same hash are equal."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        datum2 = Datum.from_data_hash_hex(HASH_HEX)
        assert datum1 == datum2

    def test_equality_with_same_inline_data(self):
        """Test that two Datums with same inline data are equal."""
        reader1 = CborReader.from_hex(INLINE_DATUM_CBOR)
        datum1 = Datum.from_cbor(reader1)
        reader2 = CborReader.from_hex(INLINE_DATUM_CBOR)
        datum2 = Datum.from_cbor(reader2)
        assert datum1 == datum2

    def test_inequality_with_different_hash(self):
        """Test that Datums with different hashes are not equal."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        datum2 = Datum.from_data_hash_hex("abcd1234" * 8)
        assert datum1 != datum2

    def test_inequality_with_different_types(self):
        """Test that Datums with different types are not equal."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        plutus_data = PlutusData.from_int(42)
        datum2 = Datum.from_inline_data(plutus_data)
        assert datum1 != datum2

    def test_inequality_with_non_datum_object(self):
        """Test that Datum is not equal to non-Datum objects."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        assert datum != "not a datum"
        assert datum != 123
        assert datum != None

    def test_hash_consistency(self):
        """Test that hash is consistent for the same object."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hash1 = hash(datum)
        hash2 = hash(datum)
        assert hash1 == hash2

    def test_hash_equality_for_equal_objects(self):
        """Test that equal Datums have the same hash."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        datum2 = Datum.from_data_hash_hex(HASH_HEX)
        assert hash(datum1) == hash(datum2)

    def test_can_use_in_set(self):
        """Test that Datum can be used in a set."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        datum2 = Datum.from_data_hash_hex(HASH_HEX)
        datum3 = Datum.from_data_hash_hex("abcd1234" * 8)

        datum_set = {datum1, datum2, datum3}
        assert len(datum_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that Datum can be used as a dictionary key."""
        datum1 = Datum.from_data_hash_hex(HASH_HEX)
        datum2 = Datum.from_data_hash_hex(HASH_HEX)

        datum_dict = {datum1: "value1"}
        datum_dict[datum2] = "value2"

        assert len(datum_dict) == 1
        assert datum_dict[datum1] == "value2"

    def test_repr_contains_datum_type(self):
        """Test that __repr__ contains datum type."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        repr_str = repr(datum)
        assert "Datum" in repr_str
        assert "DATA_HASH" in repr_str

    def test_str_contains_type_info_for_hash(self):
        """Test that __str__ contains type info for hash datum."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        str_repr = str(datum)
        assert "DatumHash" in str_repr or "DATA_HASH" in str_repr

    def test_str_contains_type_info_for_inline(self):
        """Test that __str__ contains type info for inline datum."""
        plutus_data = PlutusData.from_int(42)
        datum = Datum.from_inline_data(plutus_data)
        str_repr = str(datum)
        assert "InlineDatum" in str_repr or "INLINE_DATA" in str_repr


class TestDatumContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that Datum can be used as a context manager."""
        with Datum.from_data_hash_hex(HASH_HEX) as datum:
            assert datum is not None
            assert datum.datum_type == DatumType.DATA_HASH

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        with datum:
            pass


class TestDatumEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_create_modify_serialize_deserialize(self):
        """Test complete workflow: create, modify, serialize, deserialize."""
        original = Datum.from_data_hash_hex(HASH_HEX)
        new_hash = Blake2bHash.from_hex("abcd1234" * 8)
        original.data_hash = new_hash

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = Datum.from_cbor(reader)

        assert deserialized.data_hash_hex == "abcd1234" * 8

    def test_json_and_cbor_serialization_consistency(self):
        """Test that both JSON and CBOR serialization work on same object."""
        datum = Datum.from_data_hash_hex(HASH_HEX)

        cbor_writer = CborWriter()
        datum.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        datum.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert '"tag":"datum_hash"' in json_str

    def test_multiple_hash_updates(self):
        """Test that multiple hash updates work correctly."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hash1 = Blake2bHash.from_hex("abcd1234" * 8)
        hash2 = Blake2bHash.from_hex("ef012345" * 8)

        datum.data_hash = hash1
        assert datum.data_hash_hex == "abcd1234" * 8

        datum.data_hash = hash2
        assert datum.data_hash_hex == "ef012345" * 8

    def test_data_hash_bytes_size_is_32(self):
        """Test that data_hash_bytes always returns 32 bytes."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hash_bytes = datum.data_hash_bytes
        assert len(hash_bytes) == 32

    def test_data_hash_hex_contains_only_hex_chars(self):
        """Test that data_hash_hex contains only hexadecimal characters."""
        datum = Datum.from_data_hash_hex(HASH_HEX)
        hex_str = datum.data_hash_hex
        assert all(c in "0123456789abcdef" for c in hex_str.lower())

    def test_can_create_datum_from_all_zeros_hash(self):
        """Test that Datum can be created with all zeros hash."""
        datum = Datum.from_data_hash_hex("00" * 32)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH

    def test_can_create_datum_from_all_ones_hash(self):
        """Test that Datum can be created with all ones hash."""
        datum = Datum.from_data_hash_hex("ff" * 32)
        assert datum is not None
        assert datum.datum_type == DatumType.DATA_HASH
