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

from cometa.transaction_builder.balancing import InputToRedeemerMap
from cometa.transaction_body import TransactionInput
from cometa.witness_set import Redeemer
from cometa.cbor import CborReader
from cometa.errors import CardanoError


INPUT_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102005"
INPUT_CBOR2 = "8258201102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102005"
REDEEMER_CBOR = "840000d8799f0102030405ff821821182c"


@pytest.fixture(name="transaction_input")
def fixture_transaction_input():
    """
    Create a test transaction input from CBOR.
    """
    reader = CborReader.from_hex(INPUT_CBOR)
    return TransactionInput.from_cbor(reader)


@pytest.fixture(name="transaction_input2")
def fixture_transaction_input2():
    """
    Create a second test transaction input from CBOR.
    """
    reader = CborReader.from_hex(INPUT_CBOR2)
    return TransactionInput.from_cbor(reader)


@pytest.fixture(name="redeemer")
def fixture_redeemer():
    """
    Create a test redeemer from CBOR.
    """
    reader = CborReader.from_hex(REDEEMER_CBOR)
    return Redeemer.from_cbor(reader)


@pytest.fixture(name="redeemer2")
def fixture_redeemer2():
    """
    Create a second test redeemer from CBOR.
    """
    reader = CborReader.from_hex(REDEEMER_CBOR)
    return Redeemer.from_cbor(reader)


@pytest.fixture(name="input_map")
def fixture_input_map():
    """
    Create an empty InputToRedeemerMap.
    """
    return InputToRedeemerMap.new()


class TestInputToRedeemerMapCreation:
    """
    Tests for InputToRedeemerMap creation and initialization.
    """

    def test_new_creates_empty_map(self):
        """
        Test that new() creates an empty map.
        """
        input_map = InputToRedeemerMap.new()
        assert len(input_map) == 0

    def test_init_creates_empty_map(self):
        """
        Test that __init__() creates an empty map.
        """
        input_map = InputToRedeemerMap()
        assert len(input_map) == 0

    def test_init_with_null_ptr_raises_error(self):
        """
        Test that initializing with NULL pointer raises CardanoError.
        """
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            InputToRedeemerMap(ptr=ffi.NULL)

    def test_context_manager_support(self, input_map):
        """
        Test that InputToRedeemerMap can be used as a context manager.
        """
        with input_map as map_context:
            assert map_context is input_map
            assert len(map_context) == 0


class TestInputToRedeemerMapInsert:
    """
    Tests for the insert() method.
    """

    def test_insert_single_entry(self, input_map, transaction_input, redeemer):
        """
        Test inserting a single key-value pair.
        """
        input_map.insert(transaction_input, redeemer)
        assert len(input_map) == 1

    def test_insert_multiple_entries(self, input_map, transaction_input, transaction_input2,
                                     redeemer, redeemer2):
        """
        Test inserting multiple key-value pairs.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)
        assert len(input_map) == 2

    def test_insert_duplicate_key_creates_new_entry(self, input_map, transaction_input,
                                                     redeemer, redeemer2):
        """
        Test that inserting with duplicate key creates a new entry.
        """
        input_map.insert(transaction_input, redeemer)
        assert len(input_map) == 1

        input_map.insert(transaction_input, redeemer2)
        assert len(input_map) == 2


class TestInputToRedeemerMapGetItem:
    """
    Tests for __getitem__() method (dictionary-style access).
    """

    def test_getitem_existing_key(self, input_map, transaction_input, redeemer):
        """
        Test retrieving an existing key using dictionary-style access.
        """
        input_map.insert(transaction_input, redeemer)
        retrieved = input_map[transaction_input]
        assert retrieved._ptr == redeemer._ptr

    def test_getitem_nonexistent_key_raises_keyerror(self, input_map, transaction_input):
        """
        Test that accessing a non-existent key raises KeyError.
        """
        with pytest.raises(KeyError):
            _ = input_map[transaction_input]

    def test_getitem_returns_correct_value_with_multiple_entries(
            self, input_map, transaction_input, transaction_input2, redeemer, redeemer2):
        """
        Test retrieving correct values when multiple entries exist.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        retrieved1 = input_map[transaction_input]
        retrieved2 = input_map[transaction_input2]

        assert retrieved1._ptr == redeemer._ptr
        assert retrieved2._ptr == redeemer2._ptr


class TestInputToRedeemerMapGet:
    """
    Tests for the get() method.
    """

    def test_get_existing_key(self, input_map, transaction_input, redeemer):
        """
        Test retrieving an existing key with get().
        """
        input_map.insert(transaction_input, redeemer)
        retrieved = input_map.get(transaction_input)
        assert retrieved is not None
        assert retrieved._ptr == redeemer._ptr

    def test_get_nonexistent_key_returns_none(self, input_map, transaction_input):
        """
        Test that get() returns None for non-existent keys.
        """
        result = input_map.get(transaction_input)
        assert result is None

    def test_get_with_default_value(self, input_map, transaction_input, redeemer):
        """
        Test get() with a custom default value.
        """
        result = input_map.get(transaction_input, redeemer)
        assert result is redeemer

    def test_get_existing_key_ignores_default(self, input_map, transaction_input,
                                               redeemer, redeemer2):
        """
        Test that get() returns the actual value and ignores default when key exists.
        """
        input_map.insert(transaction_input, redeemer)
        result = input_map.get(transaction_input, redeemer2)
        assert result._ptr == redeemer._ptr


class TestInputToRedeemerMapGetKeyAt:
    """
    Tests for get_key_at() method.
    """

    def test_get_key_at_valid_index(self, input_map, transaction_input, redeemer):
        """
        Test retrieving a key at a valid index.
        """
        input_map.insert(transaction_input, redeemer)
        retrieved_key = input_map.get_key_at(0)
        assert retrieved_key._ptr == transaction_input._ptr

    def test_get_key_at_invalid_index_raises_error(self, input_map):
        """
        Test that accessing an invalid index raises CardanoError.
        """
        with pytest.raises(CardanoError):
            input_map.get_key_at(0)

    def test_get_key_at_negative_index_raises_error(self, input_map, transaction_input, redeemer):
        """
        Test that negative index raises OverflowError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(OverflowError):
            input_map.get_key_at(-1)

    def test_get_key_at_out_of_bounds_raises_error(self, input_map, transaction_input, redeemer):
        """
        Test that index beyond map size raises CardanoError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(CardanoError):
            input_map.get_key_at(1)

    def test_get_key_at_with_multiple_entries(self, input_map, transaction_input,
                                               transaction_input2, redeemer, redeemer2):
        """
        Test retrieving keys at different indices with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        key0 = input_map.get_key_at(0)
        key1 = input_map.get_key_at(1)

        assert key0._ptr == transaction_input._ptr
        assert key1._ptr == transaction_input2._ptr


class TestInputToRedeemerMapGetValueAt:
    """
    Tests for get_value_at() method.
    """

    def test_get_value_at_valid_index(self, input_map, transaction_input, redeemer):
        """
        Test retrieving a value at a valid index.
        """
        input_map.insert(transaction_input, redeemer)
        retrieved_value = input_map.get_value_at(0)
        assert retrieved_value._ptr == redeemer._ptr

    def test_get_value_at_invalid_index_raises_error(self, input_map):
        """
        Test that accessing an invalid index raises CardanoError.
        """
        with pytest.raises(CardanoError):
            input_map.get_value_at(0)

    def test_get_value_at_negative_index_raises_error(self, input_map, transaction_input, redeemer):
        """
        Test that negative index raises OverflowError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(OverflowError):
            input_map.get_value_at(-1)

    def test_get_value_at_out_of_bounds_raises_error(self, input_map, transaction_input, redeemer):
        """
        Test that index beyond map size raises CardanoError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(CardanoError):
            input_map.get_value_at(1)

    def test_get_value_at_with_multiple_entries(self, input_map, transaction_input,
                                                 transaction_input2, redeemer, redeemer2):
        """
        Test retrieving values at different indices with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        value0 = input_map.get_value_at(0)
        value1 = input_map.get_value_at(1)

        assert value0._ptr == redeemer._ptr
        assert value1._ptr == redeemer2._ptr


class TestInputToRedeemerMapGetKeyValueAt:
    """
    Tests for get_key_value_at() method.
    """

    def test_get_key_value_at_valid_index(self, input_map, transaction_input, redeemer):
        """
        Test retrieving both key and value at a valid index.
        """
        input_map.insert(transaction_input, redeemer)
        key, value = input_map.get_key_value_at(0)
        assert key._ptr == transaction_input._ptr
        assert value._ptr == redeemer._ptr

    def test_get_key_value_at_invalid_index_raises_error(self, input_map):
        """
        Test that accessing an invalid index raises CardanoError.
        """
        with pytest.raises(CardanoError):
            input_map.get_key_value_at(0)

    def test_get_key_value_at_negative_index_raises_error(self, input_map,
                                                           transaction_input, redeemer):
        """
        Test that negative index raises OverflowError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(OverflowError):
            input_map.get_key_value_at(-1)

    def test_get_key_value_at_out_of_bounds_raises_error(self, input_map,
                                                          transaction_input, redeemer):
        """
        Test that index beyond map size raises CardanoError.
        """
        input_map.insert(transaction_input, redeemer)
        with pytest.raises(CardanoError):
            input_map.get_key_value_at(1)

    def test_get_key_value_at_with_multiple_entries(self, input_map, transaction_input,
                                                     transaction_input2, redeemer, redeemer2):
        """
        Test retrieving key-value pairs at different indices.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        key0, value0 = input_map.get_key_value_at(0)
        key1, value1 = input_map.get_key_value_at(1)

        assert key0._ptr == transaction_input._ptr
        assert value0._ptr == redeemer._ptr
        assert key1._ptr == transaction_input2._ptr
        assert value1._ptr == redeemer2._ptr


class TestInputToRedeemerMapUpdateRedeemerIndex:
    """
    Tests for update_redeemer_index() method.
    """

    def test_update_redeemer_index_existing_key(self, input_map, transaction_input, redeemer):
        """
        Test updating the index of an existing redeemer.
        """
        input_map.insert(transaction_input, redeemer)
        original_index = redeemer.index

        new_index = 77
        input_map.update_redeemer_index(transaction_input, new_index)

        retrieved = input_map[transaction_input]
        assert retrieved.index == new_index
        assert retrieved.index != original_index

    def test_update_redeemer_index_nonexistent_key_does_not_error(
            self, input_map, transaction_input):
        """
        Test that updating a non-existent key does not raise an error.
        """
        input_map.update_redeemer_index(transaction_input, 99)

    def test_update_redeemer_index_multiple_entries(self, input_map, transaction_input,
                                                     transaction_input2, redeemer, redeemer2):
        """
        Test updating index in a map with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        input_map.update_redeemer_index(transaction_input2, 42)

        retrieved1 = input_map[transaction_input]
        retrieved2 = input_map[transaction_input2]

        assert retrieved2.index == 42
        assert retrieved1.index == 0

    def test_update_redeemer_index_with_zero(self, input_map, transaction_input, redeemer):
        """
        Test updating redeemer index to zero.
        """
        redeemer.index = 10
        input_map.insert(transaction_input, redeemer)

        input_map.update_redeemer_index(transaction_input, 0)

        retrieved = input_map[transaction_input]
        assert retrieved.index == 0

    def test_update_redeemer_index_with_large_value(self, input_map, transaction_input, redeemer):
        """
        Test updating redeemer index to a large value.
        """
        input_map.insert(transaction_input, redeemer)

        large_index = 999999
        input_map.update_redeemer_index(transaction_input, large_index)

        retrieved = input_map[transaction_input]
        assert retrieved.index == large_index


class TestInputToRedeemerMapLength:
    """
    Tests for __len__() method.
    """

    def test_length_empty_map(self, input_map):
        """
        Test that an empty map has length 0.
        """
        assert len(input_map) == 0

    def test_length_single_entry(self, input_map, transaction_input, redeemer):
        """
        Test length after inserting a single entry.
        """
        input_map.insert(transaction_input, redeemer)
        assert len(input_map) == 1

    def test_length_multiple_entries(self, input_map, transaction_input,
                                      transaction_input2, redeemer, redeemer2):
        """
        Test length with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)
        assert len(input_map) == 2

    def test_length_after_duplicate_insert(self, input_map, transaction_input,
                                            redeemer, redeemer2):
        """
        Test that length increases when inserting duplicate key.
        """
        input_map.insert(transaction_input, redeemer)
        assert len(input_map) == 1

        input_map.insert(transaction_input, redeemer2)
        assert len(input_map) == 2


class TestInputToRedeemerMapIteration:
    """
    Tests for iteration support.
    """

    def test_iter_empty_map(self, input_map):
        """
        Test iterating over an empty map.
        """
        keys = list(input_map)
        assert len(keys) == 0

    def test_iter_single_entry(self, input_map, transaction_input, redeemer):
        """
        Test iterating over a map with a single entry.
        """
        input_map.insert(transaction_input, redeemer)
        keys = list(input_map)
        assert len(keys) == 1
        assert keys[0]._ptr == transaction_input._ptr

    def test_iter_multiple_entries(self, input_map, transaction_input,
                                    transaction_input2, redeemer, redeemer2):
        """
        Test iterating over a map with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        keys = list(input_map)
        assert len(keys) == 2
        assert keys[0]._ptr == transaction_input._ptr
        assert keys[1]._ptr == transaction_input2._ptr

    def test_iter_keys_only(self, input_map, transaction_input,
                            transaction_input2, redeemer, redeemer2):
        """
        Test that iteration yields only keys.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        for key in input_map:
            assert isinstance(key, TransactionInput)


class TestInputToRedeemerMapRepr:
    """
    Tests for __repr__() method.
    """

    def test_repr_empty_map(self, input_map):
        """
        Test string representation of an empty map.
        """
        repr_str = repr(input_map)
        assert "InputToRedeemerMap" in repr_str
        assert "length=0" in repr_str

    def test_repr_with_entries(self, input_map, transaction_input, redeemer):
        """
        Test string representation of a map with entries.
        """
        input_map.insert(transaction_input, redeemer)
        repr_str = repr(input_map)
        assert "InputToRedeemerMap" in repr_str
        assert "length=1" in repr_str

    def test_repr_multiple_entries(self, input_map, transaction_input,
                                    transaction_input2, redeemer, redeemer2):
        """
        Test string representation with multiple entries.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)
        repr_str = repr(input_map)
        assert "InputToRedeemerMap" in repr_str
        assert "length=2" in repr_str


class TestInputToRedeemerMapGetLastError:
    """
    Tests for get_last_error() method.
    """

    def test_get_last_error_empty_on_new_map(self, input_map):
        """
        Test that a new map has no last error.
        """
        error_msg = input_map.get_last_error()
        assert error_msg == ""

    def test_get_last_error_after_operations(self, input_map, transaction_input, redeemer):
        """
        Test getting last error after successful operations.
        """
        input_map.insert(transaction_input, redeemer)
        _ = input_map[transaction_input]
        error_msg = input_map.get_last_error()
        assert isinstance(error_msg, str)


class TestInputToRedeemerMapMappingInterface:
    """
    Tests for Mapping interface compliance.
    """

    def test_mapping_contains_existing_key(self, input_map, transaction_input, redeemer):
        """
        Test that the map supports 'in' operator for existing keys.
        """
        input_map.insert(transaction_input, redeemer)
        keys = list(input_map)
        found = False
        for key in keys:
            if key._ptr == transaction_input._ptr:
                found = True
                break
        assert found

    def test_mapping_keys_iteration(self, input_map, transaction_input,
                                     transaction_input2, redeemer, redeemer2):
        """
        Test iteration over keys via mapping interface.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        keys = list(input_map)
        assert len(keys) == 2

    def test_mapping_len_function(self, input_map, transaction_input, redeemer):
        """
        Test that len() function works with the map.
        """
        assert len(input_map) == 0
        input_map.insert(transaction_input, redeemer)
        assert len(input_map) == 1


class TestInputToRedeemerMapMemoryManagement:
    """
    Tests for memory management and lifecycle.
    """

    def test_map_deletion(self, transaction_input, redeemer):
        """
        Test that map can be properly deleted.
        """
        input_map = InputToRedeemerMap.new()
        input_map.insert(transaction_input, redeemer)
        del input_map

    def test_multiple_maps_independent(self, transaction_input, redeemer):
        """
        Test that multiple maps are independent.
        """
        map1 = InputToRedeemerMap.new()
        map2 = InputToRedeemerMap.new()

        map1.insert(transaction_input, redeemer)

        assert len(map1) == 1
        assert len(map2) == 0

    def test_map_with_context_manager_cleanup(self, transaction_input, redeemer):
        """
        Test that context manager properly handles cleanup.
        """
        with InputToRedeemerMap.new() as input_map:
            input_map.insert(transaction_input, redeemer)
            assert len(input_map) == 1


class TestInputToRedeemerMapEdgeCases:
    """
    Tests for edge cases and boundary conditions.
    """

    def test_empty_map_iteration(self, input_map):
        """
        Test that iterating over an empty map works correctly.
        """
        count = 0
        for _ in input_map:
            count += 1
        assert count == 0

    def test_get_on_empty_map(self, input_map, transaction_input):
        """
        Test get() on an empty map returns None.
        """
        result = input_map.get(transaction_input)
        assert result is None

    def test_insert_and_retrieve_same_key_multiple_times(
            self, input_map, transaction_input, redeemer):
        """
        Test inserting and retrieving the same key multiple times.
        """
        input_map.insert(transaction_input, redeemer)

        for _ in range(5):
            retrieved = input_map[transaction_input]
            assert retrieved._ptr == redeemer._ptr

    def test_update_index_on_empty_map(self, input_map, transaction_input):
        """
        Test that updating index on empty map doesn't cause issues.
        """
        input_map.update_redeemer_index(transaction_input, 100)
        assert len(input_map) == 0


class TestInputToRedeemerMapIntegration:
    """
    Integration tests combining multiple operations.
    """

    def test_full_workflow(self, transaction_input, transaction_input2, redeemer, redeemer2):
        """
        Test a complete workflow of map operations.
        """
        input_map = InputToRedeemerMap.new()

        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)
        assert len(input_map) == 2

        retrieved1 = input_map.get(transaction_input)
        assert retrieved1 is not None
        assert retrieved1._ptr == redeemer._ptr

        input_map.update_redeemer_index(transaction_input, 55)
        updated = input_map[transaction_input]
        assert updated.index == 55

        key, value = input_map.get_key_value_at(0)
        assert key._ptr == transaction_input._ptr
        assert value.index == 55

    def test_map_consistency_after_operations(self, input_map, transaction_input,
                                               transaction_input2, redeemer, redeemer2):
        """
        Test that map remains consistent after various operations.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        keys_before = [input_map.get_key_at(i) for i in range(len(input_map))]

        input_map.update_redeemer_index(transaction_input, 100)

        keys_after = [input_map.get_key_at(i) for i in range(len(input_map))]

        assert len(keys_before) == len(keys_after)
        for kb, ka in zip(keys_before, keys_after):
            assert kb._ptr == ka._ptr

    def test_retrieve_all_entries_by_index(self, input_map, transaction_input,
                                            transaction_input2, redeemer, redeemer2):
        """
        Test retrieving all entries using index-based access.
        """
        input_map.insert(transaction_input, redeemer)
        input_map.insert(transaction_input2, redeemer2)

        for i in range(len(input_map)):
            key = input_map.get_key_at(i)
            value = input_map.get_value_at(i)
            assert key is not None
            assert value is not None

            key2, value2 = input_map.get_key_value_at(i)
            assert key._ptr == key2._ptr
            assert value._ptr == value2._ptr
