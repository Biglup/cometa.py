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
    TransactionInput,
    TransactionInputSet,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "d90102848258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001021058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001022058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102305"
CBOR_WITHOUT_TAG = "848258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001021058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001022058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102305"
CBOR_EMPTY = "d9010280"
TRANSACTION_INPUT1_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102005"
TRANSACTION_INPUT2_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102105"
TRANSACTION_INPUT3_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102205"
TRANSACTION_INPUT4_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102305"

TRANSACTION_INPUT_CBORS = [
    TRANSACTION_INPUT1_CBOR,
    TRANSACTION_INPUT2_CBOR,
    TRANSACTION_INPUT3_CBOR,
    TRANSACTION_INPUT4_CBOR,
]


def create_transaction_input_from_cbor(cbor_hex: str) -> TransactionInput:
    """Helper function to create TransactionInput from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return TransactionInput.from_cbor(reader)


class TestTransactionInputSetInit:
    """Tests for TransactionInputSet initialization."""

    def test_new_creates_empty_set(self):
        """Test creating an empty transaction input set."""
        input_set = TransactionInputSet()

        assert input_set is not None
        assert len(input_set) == 0
        assert not bool(input_set)

    def test_new_with_null_ptr_raises_error(self):
        """Test that creating set with NULL pointer raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            TransactionInputSet(ffi.NULL)


class TestTransactionInputSetFromCbor:
    """Tests for TransactionInputSet CBOR deserialization."""

    def test_from_cbor_deserializes_tagged_set(self):
        """Test deserializing a tagged transaction input set from CBOR."""
        reader = CborReader.from_hex(CBOR)
        input_set = TransactionInputSet.from_cbor(reader)

        assert input_set is not None
        assert len(input_set) == 4
        assert input_set.is_tagged is True

    def test_from_cbor_deserializes_untagged_set(self):
        """Test deserializing an untagged transaction input set from CBOR."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        input_set = TransactionInputSet.from_cbor(reader)

        assert input_set is not None
        assert len(input_set) == 4
        assert input_set.is_tagged is False

    def test_from_cbor_deserializes_empty_set(self):
        """Test deserializing an empty transaction input set from CBOR."""
        reader = CborReader.from_hex(CBOR_EMPTY)
        input_set = TransactionInputSet.from_cbor(reader)

        assert input_set is not None
        assert len(input_set) == 0

    def test_from_cbor_preserves_input_order(self):
        """Test that CBOR deserialization preserves input order."""
        reader = CborReader.from_hex(CBOR)
        input_set = TransactionInputSet.from_cbor(reader)

        for i in range(4):
            tx_input = input_set.get(i)
            writer = CborWriter()
            tx_input.to_cbor(writer)
            assert writer.to_hex() == TRANSACTION_INPUT_CBORS[i]

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            TransactionInputSet.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TransactionInputSet.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test that invalid array elements raise error."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            TransactionInputSet.from_cbor(reader)

    def test_from_cbor_with_missing_end_array_raises_error(self):
        """Test that missing end array marker raises error."""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            TransactionInputSet.from_cbor(reader)


class TestTransactionInputSetToCbor:
    """Tests for TransactionInputSet CBOR serialization."""

    def test_to_cbor_serializes_empty_set(self):
        """Test serializing an empty transaction input set to CBOR."""
        input_set = TransactionInputSet()
        writer = CborWriter()
        input_set.to_cbor(writer)

        assert writer.to_hex() == CBOR_EMPTY

    def test_to_cbor_serializes_set_with_elements(self):
        """Test serializing a transaction input set with elements to CBOR."""
        input_set = TransactionInputSet()

        for cbor_hex in TRANSACTION_INPUT_CBORS:
            tx_input = create_transaction_input_from_cbor(cbor_hex)
            input_set.add(tx_input)

        writer = CborWriter()
        input_set.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_to_cbor_round_trip_tagged(self):
        """Test CBOR round-trip for tagged set."""
        reader = CborReader.from_hex(CBOR)
        input_set = TransactionInputSet.from_cbor(reader)

        writer = CborWriter()
        input_set.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_to_cbor_round_trip_untagged(self):
        """Test CBOR round-trip for untagged set (upgrades to tagged)."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        input_set = TransactionInputSet.from_cbor(reader)

        writer = CborWriter()
        input_set.to_cbor(writer)

        assert writer.to_hex() == CBOR


class TestTransactionInputSetFromList:
    """Tests for TransactionInputSet.from_list factory."""

    def test_from_list_creates_set_from_inputs(self):
        """Test creating set from list of transaction inputs."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        assert input_set is not None
        assert len(input_set) == 4

    def test_from_list_with_empty_list(self):
        """Test creating set from empty list."""
        input_set = TransactionInputSet.from_list([])

        assert input_set is not None
        assert len(input_set) == 0

    def test_from_list_preserves_order(self):
        """Test that from_list preserves input order."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        for i, expected_input in enumerate(inputs):
            actual_input = input_set.get(i)
            assert actual_input.transaction_id == expected_input.transaction_id
            assert actual_input.index == expected_input.index

    def test_from_list_with_generator(self):
        """Test creating set from generator."""
        inputs_gen = (create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS)
        input_set = TransactionInputSet.from_list(inputs_gen)

        assert input_set is not None
        assert len(input_set) == 4

    def test_from_list_with_tuple(self):
        """Test creating set from tuple."""
        inputs = tuple(create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS)
        input_set = TransactionInputSet.from_list(inputs)

        assert input_set is not None
        assert len(input_set) == 4


class TestTransactionInputSetAdd:
    """Tests for TransactionInputSet.add method."""

    def test_add_single_input(self):
        """Test adding a single transaction input."""
        input_set = TransactionInputSet()
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)

        input_set.add(tx_input)

        assert len(input_set) == 1
        assert input_set.get(0) == tx_input

    def test_add_multiple_inputs(self):
        """Test adding multiple transaction inputs."""
        input_set = TransactionInputSet()

        for cbor_hex in TRANSACTION_INPUT_CBORS:
            tx_input = create_transaction_input_from_cbor(cbor_hex)
            input_set.add(tx_input)

        assert len(input_set) == 4

    def test_add_preserves_order(self):
        """Test that add preserves insertion order."""
        input_set = TransactionInputSet()
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]

        for tx_input in inputs:
            input_set.add(tx_input)

        for i, expected_input in enumerate(inputs):
            actual_input = input_set.get(i)
            assert actual_input.transaction_id == expected_input.transaction_id


class TestTransactionInputSetGet:
    """Tests for TransactionInputSet.get method."""

    def test_get_retrieves_input_at_index(self):
        """Test retrieving input at specific index."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        for i, expected_input in enumerate(inputs):
            actual_input = input_set.get(i)
            assert actual_input.transaction_id == expected_input.transaction_id
            assert actual_input.index == expected_input.index

    def test_get_with_negative_index_raises_error(self):
        """Test that negative index raises IndexError."""
        input_set = TransactionInputSet.from_list([
            create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        ])

        with pytest.raises(IndexError):
            input_set.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self):
        """Test that out of bounds index raises IndexError."""
        input_set = TransactionInputSet()

        with pytest.raises(IndexError):
            input_set.get(0)

    def test_get_with_index_equal_to_length_raises_error(self):
        """Test that index equal to length raises IndexError."""
        input_set = TransactionInputSet.from_list([
            create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        ])

        with pytest.raises(IndexError):
            input_set.get(1)


class TestTransactionInputSetIsTagged:
    """Tests for TransactionInputSet.is_tagged property."""

    def test_is_tagged_returns_true_for_tagged_set(self):
        """Test is_tagged returns True for tagged set."""
        reader = CborReader.from_hex(CBOR)
        input_set = TransactionInputSet.from_cbor(reader)

        assert input_set.is_tagged is True

    def test_is_tagged_returns_false_for_untagged_set(self):
        """Test is_tagged returns False for untagged set."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        input_set = TransactionInputSet.from_cbor(reader)

        assert input_set.is_tagged is False

    def test_is_tagged_returns_true_for_new_set(self):
        """Test is_tagged returns True for newly created set."""
        input_set = TransactionInputSet()

        assert input_set.is_tagged is True


class TestTransactionInputSetToCip116Json:
    """Tests for TransactionInputSet.to_cip116_json method."""

    def test_to_cip116_json_converts_set(self):
        """Test converting set to CIP-116 JSON."""
        input_set = TransactionInputSet()

        tx_hash1 = "0000000000000000000000000000000000000000000000000000000000000000"
        tx_hash2 = "1111111111111111111111111111111111111111111111111111111111111111"

        input1 = TransactionInput.from_hex(tx_hash1, 0)
        input2 = TransactionInput.from_hex(tx_hash2, 1)

        input_set.add(input1)
        input_set.add(input2)

        writer = JsonWriter()
        input_set.to_cip116_json(writer)
        json_str = writer.encode()

        expected = f'[{{"transaction_id":"{tx_hash1}","index":0}},{{"transaction_id":"{tx_hash2}","index":1}}]'
        assert json_str == expected

    def test_to_cip116_json_converts_empty_set(self):
        """Test converting empty set to CIP-116 JSON."""
        input_set = TransactionInputSet()

        writer = JsonWriter()
        input_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == "[]"

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that passing invalid writer raises TypeError."""
        input_set = TransactionInputSet()

        with pytest.raises(TypeError):
            input_set.to_cip116_json("not a writer")


class TestTransactionInputSetLen:
    """Tests for TransactionInputSet length operations."""

    def test_len_returns_zero_for_empty_set(self):
        """Test __len__ returns 0 for empty set."""
        input_set = TransactionInputSet()

        assert len(input_set) == 0

    def test_len_returns_correct_count(self):
        """Test __len__ returns correct count after adding inputs."""
        input_set = TransactionInputSet()

        for i, cbor_hex in enumerate(TRANSACTION_INPUT_CBORS, start=1):
            tx_input = create_transaction_input_from_cbor(cbor_hex)
            input_set.add(tx_input)
            assert len(input_set) == i

    def test_len_after_from_list(self):
        """Test __len__ after from_list."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        assert len(input_set) == 4


class TestTransactionInputSetIter:
    """Tests for TransactionInputSet iteration."""

    def test_iter_iterates_over_all_inputs(self):
        """Test iterating over all inputs in set."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        count = 0
        for tx_input in input_set:
            assert tx_input is not None
            count += 1

        assert count == 4

    def test_iter_on_empty_set(self):
        """Test iterating over empty set."""
        input_set = TransactionInputSet()

        count = 0
        for _ in input_set:
            count += 1

        assert count == 0

    def test_iter_preserves_order(self):
        """Test that iteration preserves insertion order."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        for i, tx_input in enumerate(input_set):
            expected_input = inputs[i]
            assert tx_input.transaction_id == expected_input.transaction_id
            assert tx_input.index == expected_input.index


class TestTransactionInputSetGetItem:
    """Tests for TransactionInputSet bracket notation."""

    def test_getitem_retrieves_input_at_index(self):
        """Test bracket notation retrieves input at index."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        for i, expected_input in enumerate(inputs):
            actual_input = input_set[i]
            assert actual_input.transaction_id == expected_input.transaction_id

    def test_getitem_with_negative_index_raises_error(self):
        """Test bracket notation with negative index raises error."""
        input_set = TransactionInputSet.from_list([
            create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        ])

        with pytest.raises(IndexError):
            _ = input_set[-1]

    def test_getitem_with_out_of_bounds_index_raises_error(self):
        """Test bracket notation with out of bounds index raises error."""
        input_set = TransactionInputSet()

        with pytest.raises(IndexError):
            _ = input_set[0]


class TestTransactionInputSetBool:
    """Tests for TransactionInputSet boolean conversion."""

    def test_bool_returns_false_for_empty_set(self):
        """Test bool() returns False for empty set."""
        input_set = TransactionInputSet()

        assert not bool(input_set)
        assert not input_set

    def test_bool_returns_true_for_non_empty_set(self):
        """Test bool() returns True for non-empty set."""
        input_set = TransactionInputSet()
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set.add(tx_input)

        assert bool(input_set)
        assert input_set


class TestTransactionInputSetContains:
    """Tests for TransactionInputSet membership testing."""

    def test_contains_returns_true_for_present_input(self):
        """Test __contains__ returns True for present input."""
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set = TransactionInputSet.from_list([tx_input])

        assert tx_input in input_set

    def test_contains_returns_false_for_absent_input(self):
        """Test __contains__ returns False for absent input."""
        tx_input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        tx_input2 = create_transaction_input_from_cbor(TRANSACTION_INPUT2_CBOR)
        input_set = TransactionInputSet.from_list([tx_input1])

        assert tx_input2 not in input_set

    def test_contains_returns_false_for_empty_set(self):
        """Test __contains__ returns False for empty set."""
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set = TransactionInputSet()

        assert tx_input not in input_set

    def test_contains_with_equivalent_input(self):
        """Test __contains__ with equivalent but different input instance."""
        tx_input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        tx_input2 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set = TransactionInputSet.from_list([tx_input1])

        assert tx_input2 in input_set

    def test_contains_with_non_input_object(self):
        """Test __contains__ with non-TransactionInput object."""
        input_set = TransactionInputSet()

        assert "not an input" not in input_set
        assert 123 not in input_set
        assert None not in input_set


class TestTransactionInputSetIsDisjoint:
    """Tests for TransactionInputSet.isdisjoint method."""

    def test_isdisjoint_returns_true_for_disjoint_sets(self):
        """Test isdisjoint returns True for disjoint sets."""
        input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input2 = create_transaction_input_from_cbor(TRANSACTION_INPUT2_CBOR)

        set1 = TransactionInputSet.from_list([input1])
        set2 = [input2]

        assert set1.isdisjoint(set2)

    def test_isdisjoint_returns_false_for_overlapping_sets(self):
        """Test isdisjoint returns False for overlapping sets."""
        input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input2 = create_transaction_input_from_cbor(TRANSACTION_INPUT2_CBOR)

        set1 = TransactionInputSet.from_list([input1, input2])
        set2 = [input2]

        assert not set1.isdisjoint(set2)

    def test_isdisjoint_with_empty_set(self):
        """Test isdisjoint with empty set returns True."""
        input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        set1 = TransactionInputSet.from_list([input1])
        set2 = []

        assert set1.isdisjoint(set2)

    def test_isdisjoint_when_this_set_is_empty(self):
        """Test isdisjoint when this set is empty returns True."""
        input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        set1 = TransactionInputSet()
        set2 = [input1]

        assert set1.isdisjoint(set2)

    def test_isdisjoint_with_list(self):
        """Test isdisjoint works with list."""
        inputs1 = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS[:2]]
        inputs2 = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS[2:]]

        set1 = TransactionInputSet.from_list(inputs1)

        assert set1.isdisjoint(inputs2)

    def test_isdisjoint_with_generator(self):
        """Test isdisjoint works with generator."""
        input1 = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input2 = create_transaction_input_from_cbor(TRANSACTION_INPUT2_CBOR)

        set1 = TransactionInputSet.from_list([input1])
        gen = (x for x in [input2])

        assert set1.isdisjoint(gen)


class TestTransactionInputSetRepr:
    """Tests for TransactionInputSet string representation."""

    def test_repr_shows_length(self):
        """Test __repr__ shows set length."""
        input_set = TransactionInputSet()

        repr_str = repr(input_set)
        assert "TransactionInputSet" in repr_str
        assert "len=0" in repr_str

    def test_repr_with_non_empty_set(self):
        """Test __repr__ with non-empty set."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        repr_str = repr(input_set)
        assert "TransactionInputSet" in repr_str
        assert "len=4" in repr_str


class TestTransactionInputSetContextManager:
    """Tests for TransactionInputSet context manager."""

    def test_context_manager(self):
        """Test using set as context manager."""
        with TransactionInputSet() as input_set:
            assert input_set is not None
            tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
            input_set.add(tx_input)
            assert len(input_set) == 1

    def test_context_manager_with_from_cbor(self):
        """Test using set from CBOR as context manager."""
        reader = CborReader.from_hex(CBOR)
        with TransactionInputSet.from_cbor(reader) as input_set:
            assert len(input_set) == 4


class TestTransactionInputSetLifecycle:
    """Tests for TransactionInputSet lifecycle management."""

    def test_set_lifecycle(self):
        """Test set creation and cleanup."""
        input_set = TransactionInputSet()
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set.add(tx_input)
        length = len(input_set)
        del input_set

        new_set = TransactionInputSet()
        new_set.add(tx_input)
        assert len(new_set) == length

    def test_multiple_sets_same_inputs(self):
        """Test creating multiple sets with same inputs."""
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)

        set1 = TransactionInputSet.from_list([tx_input])
        set2 = TransactionInputSet.from_list([tx_input])

        assert len(set1) == len(set2)
        assert set1 is not set2


class TestTransactionInputSetEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_add_same_input_multiple_times(self):
        """Test adding same input multiple times (set behavior)."""
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set = TransactionInputSet()

        input_set.add(tx_input)
        input_set.add(tx_input)

        assert len(input_set) >= 1

    def test_serialization_consistency(self):
        """Test that multiple serializations produce same result."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        writer1 = CborWriter()
        input_set.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        input_set.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_json_serialization_consistency(self):
        """Test that multiple JSON serializations produce same result."""
        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        input_set = TransactionInputSet.from_list([tx_input])

        writer1 = JsonWriter()
        input_set.to_cip116_json(writer1)
        json1 = writer1.encode()

        writer2 = JsonWriter()
        input_set.to_cip116_json(writer2)
        json2 = writer2.encode()

        assert json1 == json2

    def test_iteration_after_cbor_round_trip(self):
        """Test iteration works correctly after CBOR round-trip."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        writer = CborWriter()
        input_set.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized_set = TransactionInputSet.from_cbor(reader)

        for i, tx_input in enumerate(deserialized_set):
            expected_input = inputs[i]
            assert tx_input.transaction_id == expected_input.transaction_id
            assert tx_input.index == expected_input.index

    def test_empty_set_operations(self):
        """Test various operations on empty set."""
        input_set = TransactionInputSet()

        assert len(input_set) == 0
        assert not bool(input_set)
        assert list(input_set) == []

        tx_input = create_transaction_input_from_cbor(TRANSACTION_INPUT1_CBOR)
        assert tx_input not in input_set

    def test_large_set(self):
        """Test set with many inputs."""
        tx_hash = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102"
        input_set = TransactionInputSet()

        for i in range(100):
            tx_input = TransactionInput.from_hex(tx_hash + "0", i)
            input_set.add(tx_input)

        assert len(input_set) == 100

        for i in range(100):
            retrieved_input = input_set[i]
            assert retrieved_input.index == i

    def test_cbor_round_trip_preserves_all_data(self):
        """Test that CBOR round-trip preserves all input data."""
        inputs = [create_transaction_input_from_cbor(cbor) for cbor in TRANSACTION_INPUT_CBORS]
        input_set = TransactionInputSet.from_list(inputs)

        writer = CborWriter()
        input_set.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized_set = TransactionInputSet.from_cbor(reader)

        assert len(deserialized_set) == len(input_set)

        for i in range(len(input_set)):
            original = input_set[i]
            deserialized = deserialized_set[i]

            assert original.transaction_id == deserialized.transaction_id
            assert original.index == deserialized.index
