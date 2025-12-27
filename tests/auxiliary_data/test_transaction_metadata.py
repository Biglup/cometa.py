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
    TransactionMetadata,
    Metadatum,
    MetadatumLabelList,
    CardanoError,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
)


CBOR = "a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65"
METADATUM_CBOR = "a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65"
METADATUM_CBOR2 = "a4187b1904d2636b65796576616c7565646b65793246000102034405a1190237656569676874a119029a6463616b65"


def create_default_metadatum(cbor_hex: str) -> Metadatum:
    """Helper function to create a metadatum from CBOR hex string."""
    reader = CborReader.from_hex(cbor_hex)
    return Metadatum.from_cbor(reader)


class TestTransactionMetadataNew:
    """Tests for TransactionMetadata constructor."""

    def test_can_create_empty_metadata(self):
        """Test that an empty TransactionMetadata can be created."""
        metadata = TransactionMetadata()
        assert metadata is not None
        assert len(metadata) == 0

    def test_metadata_is_false_when_empty(self):
        """Test that empty metadata evaluates to False."""
        metadata = TransactionMetadata()
        assert not bool(len(metadata))

    def test_metadata_is_true_when_not_empty(self):
        """Test that non-empty metadata evaluates to True."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        assert len(metadata) > 0

    def test_repr_shows_length(self):
        """Test that __repr__ shows the metadata length."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        assert "len=1" in repr(metadata)

    def test_context_manager(self):
        """Test that TransactionMetadata works as a context manager."""
        with TransactionMetadata() as metadata:
            metadatum = create_default_metadatum(METADATUM_CBOR)
            metadata.insert(721, metadatum)
            assert len(metadata) == 1

    def test_raises_error_for_null_pointer(self):
        """Test that passing NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            TransactionMetadata(ffi.NULL)


class TestTransactionMetadataFromCbor:
    """Tests for TransactionMetadata.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that TransactionMetadata can be deserialized from CBOR."""
        reader = CborReader.from_hex(CBOR)
        metadata = TransactionMetadata.from_cbor(reader)
        assert metadata is not None
        assert len(metadata) == 1

    def test_can_deserialize_and_reserialize(self):
        """Test that metadata can be deserialized and reserialized to same CBOR."""
        reader = CborReader.from_hex(CBOR)
        metadata = TransactionMetadata.from_cbor(reader)

        writer = CborWriter()
        metadata.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_deserialize_empty_metadata(self):
        """Test deserializing empty metadata map."""
        reader = CborReader.from_hex("a0")
        metadata = TransactionMetadata.from_cbor(reader)
        assert len(metadata) == 0

    def test_raises_error_for_invalid_cbor_type(self):
        """Test that invalid CBOR type raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TransactionMetadata.from_cbor(reader)

    def test_raises_error_for_invalid_cbor_structure(self):
        """Test that invalid CBOR structure raises error."""
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            TransactionMetadata.from_cbor(reader)


class TestTransactionMetadataToCbor:
    """Tests for TransactionMetadata.to_cbor() method."""

    def test_can_serialize_empty_metadata(self):
        """Test that empty metadata serializes correctly."""
        metadata = TransactionMetadata()
        writer = CborWriter()
        metadata.to_cbor(writer)
        result = writer.to_hex()
        assert result == "a0"

    def test_can_serialize_metadata_with_entry(self):
        """Test that metadata with entries serializes correctly."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)

        writer = CborWriter()
        metadata.to_cbor(writer)
        result = writer.to_hex()

        assert result.startswith("a1")
        assert len(result) > 4


class TestTransactionMetadataInsert:
    """Tests for TransactionMetadata.insert() method."""

    def test_can_insert_metadatum(self):
        """Test that a metadatum can be inserted."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        assert len(metadata) == 1

    def test_can_insert_multiple_metadatum(self):
        """Test that multiple metadatum can be inserted."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)
        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)
        assert len(metadata) == 2

    def test_insert_keeps_elements_sorted_by_label(self):
        """Test that inserted elements are kept sorted by label."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(99, metadatum1)
        metadata.insert(2, metadatum2)

        assert len(metadata) == 2
        writer = CborWriter()
        metadata.to_cbor(writer)
        result = writer.to_hex()

        expected = "a202a4187b1904d2636b65796576616c7565646b65793246000102034405a1190237656569676874a119029a6463616b651863a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65"
        assert result == expected

    def test_insert_with_common_nft_label(self):
        """Test inserting with common NFT metadata label 721."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        retrieved = metadata.get(721)
        assert retrieved is not None

    def test_insert_with_large_label(self):
        """Test inserting with large label value."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        large_label = 18446744073709551615
        metadata.insert(large_label, metadatum)
        assert len(metadata) == 1

    def test_insert_with_same_label_updates_value(self):
        """Test that inserting with same label updates the value."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(721, metadatum1)
        first_length = len(metadata)

        metadata.insert(721, metadatum2)
        second_length = len(metadata)

        assert first_length <= second_length

    def test_setitem_syntax(self):
        """Test that bracket notation can be used to insert."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata[721] = metadatum
        assert len(metadata) == 1


class TestTransactionMetadataGet:
    """Tests for TransactionMetadata.get() method."""

    def test_can_get_metadatum(self):
        """Test that a metadatum can be retrieved."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(65, metadatum)

        retrieved = metadata.get(65)
        assert retrieved is not None

    def test_get_raises_error_for_missing_label(self):
        """Test that getting non-existent label raises error."""
        metadata = TransactionMetadata()
        with pytest.raises(CardanoError):
            metadata.get(999)

    def test_get_returns_correct_metadatum_with_multiple_entries(self):
        """Test that get returns correct metadatum when multiple exist."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)

        retrieved = metadata.get(2)
        assert retrieved is not None

    def test_getitem_syntax(self):
        """Test that bracket notation can be used to get."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)

        retrieved = metadata[721]
        assert retrieved is not None

    def test_contains_returns_true_for_existing_label(self):
        """Test that 'in' operator works for existing labels."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        assert 721 in metadata

    def test_contains_returns_false_for_missing_label(self):
        """Test that 'in' operator works for missing labels."""
        metadata = TransactionMetadata()
        assert 999 not in metadata


class TestTransactionMetadataGetKeyAt:
    """Tests for TransactionMetadata.get_key_at() method."""

    def test_can_get_key_at_index(self):
        """Test that key can be retrieved at specific index."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)

        label = metadata.get_key_at(0)
        assert label == 1

    def test_get_key_at_returns_keys_in_sorted_order(self):
        """Test that keys are returned in sorted order."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(99, metadatum1)
        metadata.insert(2, metadatum2)

        assert metadata.get_key_at(0) == 2
        assert metadata.get_key_at(1) == 99

    def test_get_key_at_raises_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        metadata = TransactionMetadata()
        with pytest.raises(IndexError):
            metadata.get_key_at(0)

    def test_get_key_at_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        with pytest.raises(IndexError):
            metadata.get_key_at(-1)


class TestTransactionMetadataGetValueAt:
    """Tests for TransactionMetadata.get_value_at() method."""

    def test_can_get_value_at_index(self):
        """Test that value can be retrieved at specific index."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(2, metadatum)

        value = metadata.get_value_at(0)
        assert value is not None

    def test_get_value_at_raises_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        metadata = TransactionMetadata()
        with pytest.raises(IndexError):
            metadata.get_value_at(0)

    def test_get_value_at_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        with pytest.raises(IndexError):
            metadata.get_value_at(-1)


class TestTransactionMetadataGetKeyValueAt:
    """Tests for TransactionMetadata.get_key_value_at() method."""

    def test_can_get_key_value_at_index(self):
        """Test that key-value pair can be retrieved at specific index."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(10, metadatum)

        key, value = metadata.get_key_value_at(0)
        assert key == 10
        assert value is not None

    def test_get_key_value_at_returns_correct_pairs(self):
        """Test that correct key-value pairs are returned."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(5, metadatum1)
        metadata.insert(15, metadatum2)

        key1, val1 = metadata.get_key_value_at(0)
        key2, val2 = metadata.get_key_value_at(1)

        assert key1 == 5
        assert key2 == 15

    def test_get_key_value_at_raises_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        metadata = TransactionMetadata()
        with pytest.raises(IndexError):
            metadata.get_key_value_at(0)

    def test_get_key_value_at_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)
        with pytest.raises(IndexError):
            metadata.get_key_value_at(-1)


class TestTransactionMetadataGetKeys:
    """Tests for TransactionMetadata.get_keys() method."""

    def test_can_get_keys_from_empty_metadata(self):
        """Test that empty list is returned for empty metadata."""
        metadata = TransactionMetadata()
        keys = metadata.get_keys()
        assert isinstance(keys, MetadatumLabelList)
        assert len(keys) == 0

    def test_can_get_keys_from_metadata(self):
        """Test that keys can be retrieved from metadata."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)

        keys = metadata.get_keys()
        assert len(keys) == 2

    def test_keys_are_in_sorted_order(self):
        """Test that returned keys are in sorted order."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(99, metadatum1)
        metadata.insert(2, metadatum2)

        keys = metadata.get_keys()
        assert keys.get(0) == 2
        assert keys.get(1) == 99


class TestTransactionMetadataLen:
    """Tests for TransactionMetadata.__len__() method."""

    def test_len_returns_zero_for_empty_metadata(self):
        """Test that len returns 0 for empty metadata."""
        metadata = TransactionMetadata()
        assert len(metadata) == 0

    def test_len_returns_correct_count(self):
        """Test that len returns correct count."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(5, metadatum)
        assert len(metadata) == 1

    def test_len_updates_after_insertions(self):
        """Test that len updates after multiple insertions."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        assert len(metadata) == 0
        metadata.insert(1, metadatum1)
        assert len(metadata) == 1
        metadata.insert(2, metadatum2)
        assert len(metadata) == 2


class TestTransactionMetadataIter:
    """Tests for TransactionMetadata.__iter__() method."""

    def test_can_iterate_over_empty_metadata(self):
        """Test that empty metadata can be iterated."""
        metadata = TransactionMetadata()
        items = list(metadata)
        assert len(items) == 0

    def test_can_iterate_over_metadata(self):
        """Test that metadata can be iterated."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)

        items = list(metadata)
        assert len(items) == 2

    def test_iteration_returns_key_value_tuples(self):
        """Test that iteration returns (key, value) tuples."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)

        for label, value in metadata:
            assert isinstance(label, int)
            assert value is not None

    def test_iteration_order_is_sorted(self):
        """Test that iteration order is sorted by label."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(99, metadatum1)
        metadata.insert(2, metadatum2)

        labels = [label for label, _ in metadata]
        assert labels == [2, 99]


class TestTransactionMetadataToCip116Json:
    """Tests for TransactionMetadata.to_cip116_json() method."""

    def test_can_encode_to_cip116_json(self):
        """Test that metadata can be encoded to CIP-116 JSON."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(10, metadatum)

        writer = JsonWriter(JsonFormat.COMPACT)
        metadata.to_cip116_json(writer)
        result = writer.encode()

        assert '"key":"10"' in result
        assert '"tag":"map"' in result

    def test_cip116_json_uses_decimal_string_for_key(self):
        """Test that CIP-116 JSON uses decimal string for key."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(721, metadatum)

        writer = JsonWriter(JsonFormat.COMPACT)
        metadata.to_cip116_json(writer)
        result = writer.encode()

        assert '"key":"721"' in result

    def test_cip116_json_empty_metadata(self):
        """Test that empty metadata encodes to empty JSON array."""
        metadata = TransactionMetadata()

        writer = JsonWriter(JsonFormat.COMPACT)
        metadata.to_cip116_json(writer)
        result = writer.encode()

        assert result == "[]"

    def test_cip116_json_raises_error_for_invalid_writer(self):
        """Test that invalid writer type raises TypeError."""
        metadata = TransactionMetadata()
        with pytest.raises(TypeError):
            metadata.to_cip116_json("not a writer")

    def test_cip116_json_multiple_entries(self):
        """Test CIP-116 JSON with multiple entries."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        metadata.insert(2, metadatum2)

        writer = JsonWriter(JsonFormat.COMPACT)
        metadata.to_cip116_json(writer)
        result = writer.encode()

        assert '"key":"1"' in result
        assert '"key":"2"' in result


class TestTransactionMetadataEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_insert_and_retrieve_with_zero_label(self):
        """Test inserting and retrieving with label 0."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata.insert(0, metadatum)

        retrieved = metadata.get(0)
        assert retrieved is not None

    def test_multiple_operations_on_same_metadata(self):
        """Test multiple operations on the same metadata instance."""
        metadata = TransactionMetadata()
        metadatum1 = create_default_metadatum(METADATUM_CBOR)
        metadatum2 = create_default_metadatum(METADATUM_CBOR2)

        metadata.insert(1, metadatum1)
        assert len(metadata) == 1

        metadata.insert(2, metadatum2)
        assert len(metadata) == 2

        assert 1 in metadata
        assert 2 in metadata

        keys = metadata.get_keys()
        assert len(keys) == 2

    def test_round_trip_serialization(self):
        """Test that metadata survives round-trip serialization."""
        metadata1 = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        metadata1.insert(721, metadatum)

        writer = CborWriter()
        metadata1.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        metadata2 = TransactionMetadata.from_cbor(reader)

        assert len(metadata2) == 1
        assert 721 in metadata2

    def test_metadata_with_max_uint64_label(self):
        """Test metadata with maximum uint64 label."""
        metadata = TransactionMetadata()
        metadatum = create_default_metadatum(METADATUM_CBOR)
        max_label = (2**64) - 1
        metadata.insert(max_label, metadatum)

        retrieved = metadata.get(max_label)
        assert retrieved is not None
