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
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


KEY_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
KEY_HASH_HEX_2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
INVALID_KEY_HASH_HEX = "000000000000000000000000000000000000000000000000"
GOVERNANCE_ACTION_ID_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
CIP129_HEX_1 = "000000000000000000000000000000000000000000000000000000000000000011"
CIP129_BECH32_1 = "gov_action1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpzklpgpf"
CIP129_HEX_2 = "111111111111111111111111111111111111111111111111111111111111111100"
CIP129_BECH32_2 = "gov_action1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsq6dmejn"
INVALID_CIP129_BECH32 = "gov_action1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyp6q4j5"
INVALID_CIP129_BECH32_2 = "gox_action1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsqqjxekw"


class TestGovernanceActionIdNew:
    """Tests for GovernanceActionId.new() factory method."""

    def test_can_create_with_hash_and_index(self):
        """Test that GovernanceActionId can be created with hash and index."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 0)
        assert gov_id is not None
        assert gov_id.index == 0
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_can_create_with_different_index(self):
        """Test that GovernanceActionId can be created with different index values."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 42)
        assert gov_id is not None
        assert gov_id.index == 42

    def test_can_create_with_max_index(self):
        """Test that GovernanceActionId can be created with maximum index value."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 2**64 - 1)
        assert gov_id is not None
        assert gov_id.index == 2**64 - 1

    def test_raises_error_if_hash_is_none(self):
        """Test that creating with None hash raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            GovernanceActionId.new(None, 0)

    def test_raises_error_if_hash_is_invalid_size(self):
        """Test that creating with invalid hash size raises an error."""
        invalid_hash = Blake2bHash.from_hex(INVALID_KEY_HASH_HEX)
        with pytest.raises(CardanoError):
            GovernanceActionId.new(invalid_hash, 0)


class TestGovernanceActionIdFromBech32:
    """Tests for GovernanceActionId.from_bech32() factory method."""

    def test_can_create_from_bech32(self):
        """Test that GovernanceActionId can be created from CIP-129 Bech32 string."""
        gov_id = GovernanceActionId.from_bech32(CIP129_BECH32_1)
        assert gov_id is not None
        assert gov_id.index == 17
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_can_create_from_bech32_different_values(self):
        """Test that different Bech32 strings produce different governance action IDs."""
        gov_id = GovernanceActionId.from_bech32(CIP129_BECH32_2)
        assert gov_id is not None
        assert gov_id.index == 0

    def test_roundtrip_bech32(self):
        """Test that Bech32 parsing and serialization roundtrip works."""
        original = GovernanceActionId.from_bech32(CIP129_BECH32_1)
        bech32_str = original.to_bech32()
        assert bech32_str == CIP129_BECH32_1

    def test_raises_error_for_empty_string(self):
        """Test that empty Bech32 string raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_bech32("")

    def test_raises_error_for_invalid_bech32(self):
        """Test that invalid Bech32 string raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_bech32(INVALID_CIP129_BECH32)

    def test_raises_error_for_invalid_prefix(self):
        """Test that Bech32 with invalid prefix raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_bech32(INVALID_CIP129_BECH32_2)

    def test_raises_error_for_none(self):
        """Test that None input raises an error."""
        with pytest.raises(AttributeError):
            GovernanceActionId.from_bech32(None)


class TestGovernanceActionIdFromHashHex:
    """Tests for GovernanceActionId.from_hash_hex() factory method."""

    def test_can_create_from_hash_hex(self):
        """Test that GovernanceActionId can be created from hex string."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        assert gov_id is not None
        assert gov_id.index == 3
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_can_create_with_zero_index(self):
        """Test that GovernanceActionId can be created with index 0."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        assert gov_id is not None
        assert gov_id.index == 0

    def test_can_create_with_different_hash(self):
        """Test that different hex hashes produce different governance action IDs."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX_2, 1)
        assert gov_id is not None
        assert gov_id.hash_hex == KEY_HASH_HEX_2

    def test_raises_error_for_invalid_hex_size(self):
        """Test that invalid hex size raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_hash_hex(INVALID_KEY_HASH_HEX, 0)

    def test_raises_error_for_none_hex(self):
        """Test that None hex string raises an error."""
        with pytest.raises(AttributeError):
            GovernanceActionId.from_hash_hex(None, 0)

    def test_raises_error_for_empty_hex(self):
        """Test that empty hex string raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_hash_hex("", 0)


class TestGovernanceActionIdFromHashBytes:
    """Tests for GovernanceActionId.from_hash_bytes() factory method."""

    def test_can_create_from_hash_bytes(self):
        """Test that GovernanceActionId can be created from raw bytes."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.from_hash_bytes(hash_bytes, 0)
        assert gov_id is not None
        assert gov_id.index == 0
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_can_create_from_bytearray(self):
        """Test that GovernanceActionId can be created from bytearray."""
        hash_bytes = bytearray.fromhex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.from_hash_bytes(hash_bytes, 5)
        assert gov_id is not None
        assert gov_id.index == 5

    def test_hash_bytes_property_matches_input(self):
        """Test that hash_bytes property returns the same bytes as input."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.from_hash_bytes(hash_bytes, 0)
        assert gov_id.hash_bytes == hash_bytes

    def test_raises_error_for_invalid_bytes_size(self):
        """Test that invalid bytes size raises an error."""
        invalid_bytes = bytes.fromhex(INVALID_KEY_HASH_HEX)
        with pytest.raises(CardanoError):
            GovernanceActionId.from_hash_bytes(invalid_bytes, 0)

    def test_raises_error_for_none_bytes(self):
        """Test that None bytes raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            GovernanceActionId.from_hash_bytes(None, 0)

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raises an error."""
        with pytest.raises(CardanoError):
            GovernanceActionId.from_hash_bytes(b"", 0)


class TestGovernanceActionIdFromCbor:
    """Tests for CBOR deserialization."""

    def test_can_deserialize_from_cbor(self):
        """Test that GovernanceActionId can be deserialized from CBOR."""
        reader = CborReader.from_hex(GOVERNANCE_ACTION_ID_CBOR)
        gov_id = GovernanceActionId.from_cbor(reader)
        assert gov_id is not None
        assert gov_id.index == 3
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_roundtrip_cbor_serialization(self):
        """Test CBOR serialization/deserialization roundtrip."""
        original = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = GovernanceActionId.from_cbor(reader)

        assert deserialized.index == original.index
        assert deserialized.hash_hex == original.hash_hex

    def test_raises_error_with_invalid_reader(self):
        """Test that invalid reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            GovernanceActionId.from_cbor(None)

    def test_raises_error_with_invalid_cbor_array_size(self):
        """Test that invalid CBOR array size raises an error."""
        invalid_cbor = "8100581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            GovernanceActionId.from_cbor(reader)

    def test_raises_error_with_invalid_index(self):
        """Test that invalid index in CBOR raises an error."""
        invalid_cbor = "8258200000000000000000000000000000000000000000000000000000000000000000ff"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            GovernanceActionId.from_cbor(reader)

    def test_raises_error_with_invalid_hash_size(self):
        """Test that invalid hash size in CBOR raises an error."""
        invalid_cbor = "8200581b0000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            GovernanceActionId.from_cbor(reader)


class TestGovernanceActionIdToCbor:
    """Tests for CBOR serialization."""

    def test_can_serialize_to_cbor(self):
        """Test that GovernanceActionId can be serialized to CBOR."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        writer = CborWriter()
        gov_id.to_cbor(writer)
        result = writer.to_hex()
        assert result == GOVERNANCE_ACTION_ID_CBOR

    def test_can_serialize_with_different_values(self):
        """Test that different values produce different CBOR."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 1)

        writer1 = CborWriter()
        gov_id1.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        gov_id2.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 != cbor2

    def test_raises_error_with_invalid_writer(self):
        """Test that invalid writer raises an error."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            gov_id.to_cbor(None)


class TestGovernanceActionIdToCip116Json:
    """Tests for CIP-116 JSON serialization."""

    def test_can_convert_to_cip116_json(self):
        """Test that GovernanceActionId can be converted to CIP-116 JSON."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 1)
        writer = JsonWriter()
        gov_id.to_cip116_json(writer)
        json_str = writer.encode()
        assert "transaction_id" in json_str
        assert "gov_action_index" in json_str
        assert KEY_HASH_HEX in json_str
        assert "1" in json_str

    def test_raises_error_with_invalid_writer(self):
        """Test that invalid writer raises an error."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        with pytest.raises((CardanoError, TypeError)):
            gov_id.to_cip116_json(None)

    def test_raises_error_with_wrong_writer_type(self):
        """Test that wrong writer type raises an error."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        with pytest.raises((CardanoError, TypeError)):
            gov_id.to_cip116_json("not a writer")


class TestGovernanceActionIdProperties:
    """Tests for GovernanceActionId properties."""

    def test_get_transaction_hash(self):
        """Test that transaction_hash property returns the correct hash."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 0)
        retrieved_hash = gov_id.transaction_hash
        assert retrieved_hash is not None
        assert retrieved_hash.to_hex() == KEY_HASH_HEX

    def test_set_transaction_hash(self):
        """Test that transaction_hash property can be set."""
        tx_hash1 = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash1, 0)

        tx_hash2 = Blake2bHash.from_hex(KEY_HASH_HEX_2)
        gov_id.transaction_hash = tx_hash2

        retrieved_hash = gov_id.transaction_hash
        assert retrieved_hash.to_hex() == KEY_HASH_HEX_2

    def test_set_transaction_hash_raises_error_for_none(self):
        """Test that setting transaction_hash to None raises an error."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            gov_id.transaction_hash = None

    def test_set_transaction_hash_raises_error_for_invalid_size(self):
        """Test that setting invalid hash size raises an error."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        invalid_hash = Blake2bHash.from_hex(INVALID_KEY_HASH_HEX)
        with pytest.raises(CardanoError):
            gov_id.transaction_hash = invalid_hash

    def test_get_index(self):
        """Test that index property returns the correct value."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 42)
        assert gov_id.index == 42

    def test_set_index(self):
        """Test that index property can be set."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id.index = 9
        assert gov_id.index == 9

    def test_set_index_to_zero(self):
        """Test that index can be set to zero."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 5)
        gov_id.index = 0
        assert gov_id.index == 0

    def test_set_index_to_max_value(self):
        """Test that index can be set to maximum value."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        gov_id.index = 2**64 - 1
        assert gov_id.index == 2**64 - 1

    def test_get_hash_hex(self):
        """Test that hash_hex property returns hex string."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        assert gov_id.hash_hex == KEY_HASH_HEX

    def test_get_hash_bytes(self):
        """Test that hash_bytes property returns bytes."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.from_hash_bytes(hash_bytes, 0)
        assert gov_id.hash_bytes == hash_bytes


class TestGovernanceActionIdToBech32:
    """Tests for Bech32 serialization."""

    def test_can_convert_to_bech32(self):
        """Test that GovernanceActionId can be converted to Bech32."""
        gov_id = GovernanceActionId.from_bech32(CIP129_BECH32_1)
        bech32_str = gov_id.to_bech32()
        assert bech32_str == CIP129_BECH32_1

    def test_bech32_roundtrip(self):
        """Test that Bech32 roundtrip preserves values."""
        original = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 17)
        bech32_str = original.to_bech32()
        restored = GovernanceActionId.from_bech32(bech32_str)
        assert restored.index == original.index
        assert restored.hash_hex == original.hash_hex


class TestGovernanceActionIdMagicMethods:
    """Tests for magic methods (__eq__, __hash__, __repr__, __str__)."""

    def test_equality_for_same_values(self):
        """Test that two GovernanceActionIds with same values are equal."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        assert gov_id1 == gov_id2

    def test_inequality_for_different_hashes(self):
        """Test that different hashes produce inequality."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX_2, 3)
        assert gov_id1 != gov_id2

    def test_inequality_for_different_indexes(self):
        """Test that different indexes produce inequality."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 4)
        assert gov_id1 != gov_id2

    def test_inequality_with_non_governance_action_id(self):
        """Test that GovernanceActionId is not equal to non-GovernanceActionId objects."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        assert gov_id != "not a governance action id"
        assert gov_id != 123
        assert gov_id != None

    def test_hash_consistency(self):
        """Test that hash is consistent for the same object."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        hash1 = hash(gov_id)
        hash2 = hash(gov_id)
        assert hash1 == hash2

    def test_hash_equality_for_equal_objects(self):
        """Test that equal GovernanceActionIds have the same hash."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        assert hash(gov_id1) == hash(gov_id2)

    def test_can_use_in_set(self):
        """Test that GovernanceActionIds can be used in a set."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        gov_id3 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 1)

        gov_set = {gov_id1, gov_id2, gov_id3}
        assert len(gov_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that GovernanceActionIds can be used as dictionary keys."""
        gov_id1 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)

        gov_dict = {gov_id1: "value1"}
        gov_dict[gov_id2] = "value2"

        assert len(gov_dict) == 1
        assert gov_dict[gov_id1] == "value2"

    def test_repr_contains_index(self):
        """Test that __repr__ contains the index."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 42)
        repr_str = repr(gov_id)
        assert "GovernanceActionId" in repr_str
        assert "42" in repr_str

    def test_str_returns_bech32(self):
        """Test that __str__ returns Bech32 string."""
        gov_id = GovernanceActionId.from_bech32(CIP129_BECH32_1)
        assert str(gov_id) == CIP129_BECH32_1


class TestGovernanceActionIdContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that GovernanceActionId can be used as a context manager."""
        with GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0) as gov_id:
            assert gov_id is not None
            assert gov_id.index == 0

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        with gov_id:
            pass


class TestGovernanceActionIdEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_property_updates(self):
        """Test that multiple property updates work correctly."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)

        gov_id.index = 5
        assert gov_id.index == 5

        gov_id.index = 10
        assert gov_id.index == 10

        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX_2)
        gov_id.transaction_hash = tx_hash
        assert gov_id.hash_hex == KEY_HASH_HEX_2

    def test_create_modify_serialize_deserialize(self):
        """Test complete workflow: create, modify, serialize, deserialize."""
        original = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        original.index = 9

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = GovernanceActionId.from_cbor(reader)

        assert deserialized.index == 9
        assert deserialized.hash_hex == KEY_HASH_HEX

    def test_json_and_cbor_serialization_consistency(self):
        """Test that both JSON and CBOR serialization work on same object."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        gov_id = GovernanceActionId.new(tx_hash, 1)

        cbor_writer = CborWriter()
        gov_id.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        gov_id.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert "transaction_id" in json_str
        assert KEY_HASH_HEX in json_str

    def test_hex_to_bytes_consistency(self):
        """Test that hash_hex and hash_bytes are consistent."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        hex_from_property = gov_id.hash_hex
        bytes_from_property = gov_id.hash_bytes
        hex_from_bytes = bytes_from_property.hex()
        assert hex_from_property == hex_from_bytes

    def test_bech32_with_zero_index(self):
        """Test Bech32 encoding/decoding with zero index."""
        gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 0)
        bech32_str = gov_id.to_bech32()
        restored = GovernanceActionId.from_bech32(bech32_str)
        assert restored.index == 0
        assert restored.hash_hex == KEY_HASH_HEX

    def test_all_factory_methods_produce_equal_objects(self):
        """Test that all factory methods can produce equal objects."""
        tx_hash = Blake2bHash.from_hex(KEY_HASH_HEX)
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)

        gov_id1 = GovernanceActionId.new(tx_hash, 3)
        gov_id2 = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, 3)
        gov_id3 = GovernanceActionId.from_hash_bytes(hash_bytes, 3)

        assert gov_id1 == gov_id2
        assert gov_id2 == gov_id3
        assert gov_id1 == gov_id3

    def test_large_index_values(self):
        """Test that large index values work correctly."""
        large_indices = [1000, 10000, 100000, 2**32, 2**48, 2**63]
        for idx in large_indices:
            gov_id = GovernanceActionId.from_hash_hex(KEY_HASH_HEX, idx)
            assert gov_id.index == idx

            writer = CborWriter()
            gov_id.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            deserialized = GovernanceActionId.from_cbor(reader)
            assert deserialized.index == idx
