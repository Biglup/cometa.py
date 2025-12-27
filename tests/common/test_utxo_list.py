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
    Utxo,
    UtxoList,
    TransactionInput,
    TransactionOutput,
    Address,
    CborReader,
    CardanoError,
)


CBOR = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"
CBOR_DIFFERENT_INPUT = "82825820bb217abaca60fc0ca78c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"
CBOR_DIFFERENT_OUTPUT = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c420a"
CBOR_DIFFERENT_VAL1 = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c20a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c420a"
CBOR_DIFFERENT_VAL2 = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c420a"
CBOR_DIFFERENT_VAL3 = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c22a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c420a"
TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def create_utxo_from_cbor(cbor_hex: str) -> Utxo:
    """Helper to create a Utxo from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return Utxo.from_cbor(reader)


def create_test_input(index: int = 0) -> TransactionInput:
    """Helper to create a test TransactionInput."""
    return TransactionInput.from_hex(TX_ID_HASH, index)


def create_test_output(lovelace: int = 1000000) -> TransactionOutput:
    """Helper to create a test TransactionOutput."""
    address = Address.from_string(
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
    )
    return TransactionOutput.new(address, lovelace)


def create_default_utxo_list() -> UtxoList:
    """Helper to create a default UtxoList with two test UTxOs."""
    utxo_list = UtxoList()
    utxo1 = create_utxo_from_cbor(CBOR_DIFFERENT_INPUT)
    utxo2 = create_utxo_from_cbor(CBOR_DIFFERENT_OUTPUT)
    utxo_list.add(utxo1)
    utxo_list.add(utxo2)
    return utxo_list


def create_utxo_list_diff_vals() -> UtxoList:
    """Helper to create a UtxoList with different value UTxOs."""
    utxo_list = UtxoList()
    utxo1 = create_utxo_from_cbor(CBOR_DIFFERENT_VAL1)
    utxo2 = create_utxo_from_cbor(CBOR_DIFFERENT_VAL2)
    utxo3 = create_utxo_from_cbor(CBOR_DIFFERENT_VAL3)
    utxo_list.add(utxo2)
    utxo_list.add(utxo1)
    utxo_list.add(utxo3)
    return utxo_list


class TestUtxoListCreation:
    """Tests for UtxoList creation and initialization."""

    def test_utxo_list_new(self):
        """Test creating a new empty UtxoList."""
        utxo_list = UtxoList()
        assert utxo_list is not None
        assert len(utxo_list) == 0

    def test_utxo_list_new_with_null_ptr_raises(self):
        """Test that creating UtxoList with NULL ptr raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            UtxoList(ffi.NULL)

    def test_utxo_list_from_list(self):
        """Test creating UtxoList from a Python list."""
        utxos = [
            Utxo.new(create_test_input(0), create_test_output(1000000)),
            Utxo.new(create_test_input(1), create_test_output(2000000)),
            Utxo.new(create_test_input(2), create_test_output(3000000)),
        ]
        utxo_list = UtxoList.from_list(utxos)
        assert len(utxo_list) == 3
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 1
        assert utxo_list[2].input.index == 2

    def test_utxo_list_from_empty_list(self):
        """Test creating UtxoList from an empty Python list."""
        utxo_list = UtxoList.from_list([])
        assert len(utxo_list) == 0


class TestUtxoListLength:
    """Tests for UtxoList length operations."""

    def test_utxo_list_length_empty(self):
        """Test length of empty UtxoList."""
        utxo_list = UtxoList()
        assert len(utxo_list) == 0

    def test_utxo_list_length_after_add(self):
        """Test length after adding elements."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(0), create_test_output()))
        assert len(utxo_list) == 1
        utxo_list.add(Utxo.new(create_test_input(1), create_test_output()))
        assert len(utxo_list) == 2

    def test_utxo_list_bool_empty(self):
        """Test bool conversion for empty list."""
        utxo_list = UtxoList()
        assert not utxo_list
        assert bool(utxo_list) is False

    def test_utxo_list_bool_non_empty(self):
        """Test bool conversion for non-empty list."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
        assert utxo_list
        assert bool(utxo_list) is True


class TestUtxoListAdd:
    """Tests for adding elements to UtxoList."""

    def test_utxo_list_add_single(self):
        """Test adding a single UTxO to the list."""
        utxo_list = UtxoList()
        utxo = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo_list.add(utxo)
        assert len(utxo_list) == 1

    def test_utxo_list_add_multiple(self):
        """Test adding multiple UTxOs to the list."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output(1000000 * (i + 1)))
            utxo_list.add(utxo)
        assert len(utxo_list) == 5

    def test_utxo_list_add_duplicate(self):
        """Test adding duplicate UTxOs to the list."""
        utxo_list = UtxoList()
        utxo = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo_list.add(utxo)
        utxo_list.add(utxo)
        assert len(utxo_list) == 2


class TestUtxoListGet:
    """Tests for retrieving elements from UtxoList."""

    def test_utxo_list_get_valid_index(self):
        """Test getting a UTxO at a valid index."""
        utxo_list = create_default_utxo_list()
        utxo = utxo_list.get(0)
        assert utxo is not None

    def test_utxo_list_get_second_element(self):
        """Test getting the second element."""
        utxo_list = create_default_utxo_list()
        utxo = utxo_list.get(1)
        assert utxo is not None

    def test_utxo_list_get_out_of_bounds(self):
        """Test that getting out of bounds index raises IndexError."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(0), create_test_output()))
        with pytest.raises(IndexError):
            utxo_list.get(5)

    def test_utxo_list_get_negative_index(self):
        """Test that get with negative index raises IndexError."""
        utxo_list = create_default_utxo_list()
        with pytest.raises(IndexError):
            utxo_list.get(-1)

    def test_utxo_list_getitem_valid(self):
        """Test bracket notation for getting UTxOs."""
        utxo_list = create_default_utxo_list()
        utxo = utxo_list[0]
        assert utxo is not None

    def test_utxo_list_getitem_negative_index(self):
        """Test bracket notation with negative index."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        assert utxo_list[-1].input.index == 1
        assert utxo_list[-2].input.index == 0


class TestUtxoListIteration:
    """Tests for iterating over UtxoList."""

    def test_utxo_list_iteration(self):
        """Test iterating over UtxoList."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output(1000000 * (i + 1)))
            utxo_list.add(utxo)
        indices = [utxo.input.index for utxo in utxo_list]
        assert indices == [0, 1, 2, 3, 4]

    def test_utxo_list_iteration_empty(self):
        """Test iterating over empty UtxoList."""
        utxo_list = UtxoList()
        count = 0
        for _ in utxo_list:
            count += 1
        assert count == 0

    def test_utxo_list_reversed(self):
        """Test reversed iteration over UtxoList."""
        utxo_list = UtxoList()
        for i in range(3):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        indices = [utxo.input.index for utxo in reversed(utxo_list)]
        assert indices == [2, 1, 0]


class TestUtxoListRemove:
    """Tests for removing elements from UtxoList."""

    def test_utxo_list_remove_existing(self):
        """Test removing an existing UTxO from the list."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        assert len(utxo_list) == 2
        utxo_list.remove(utxo1)
        assert len(utxo_list) == 1
        assert utxo_list[0].input.index == 1

    def test_utxo_list_remove_last_element(self):
        """Test removing the last element."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output())
        utxo2 = Utxo.new(create_test_input(1), create_test_output())
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.remove(utxo2)
        assert len(utxo_list) == 1
        assert utxo_list[0].input.index == 0

    def test_utxo_list_remove_nonexistent(self):
        """Test that removing a non-existent UTxO does not change the list."""
        utxo_list = create_default_utxo_list()
        original_length = len(utxo_list)
        different_utxo = Utxo.new(create_test_input(99), create_test_output())
        utxo_list.remove(different_utxo)
        assert len(utxo_list) == original_length


class TestUtxoListClear:
    """Tests for clearing UtxoList."""

    def test_utxo_list_clear(self):
        """Test clearing the list."""
        utxo_list = create_default_utxo_list()
        assert len(utxo_list) == 2
        utxo_list.clear()
        assert len(utxo_list) == 0

    def test_utxo_list_clear_empty(self):
        """Test clearing an already empty list."""
        utxo_list = UtxoList()
        utxo_list.clear()
        assert len(utxo_list) == 0

    def test_utxo_list_clear_and_add(self):
        """Test adding elements after clearing."""
        utxo_list = create_default_utxo_list()
        utxo_list.clear()
        utxo = Utxo.new(create_test_input(10), create_test_output())
        utxo_list.add(utxo)
        assert len(utxo_list) == 1
        assert utxo_list[0].input.index == 10


class TestUtxoListClone:
    """Tests for cloning UtxoList."""

    def test_utxo_list_clone(self):
        """Test cloning a UtxoList."""
        utxo_list = create_default_utxo_list()
        cloned = utxo_list.clone()
        assert len(cloned) == 2

    def test_utxo_list_clone_empty(self):
        """Test cloning an empty UtxoList fails."""
        utxo_list = UtxoList()
        with pytest.raises(CardanoError, match="Failed to clone UtxoList"):
            utxo_list.clone()

    def test_utxo_list_clone_independence(self):
        """Test that cloned list is independent."""
        utxo_list = create_default_utxo_list()
        cloned = utxo_list.clone()
        utxo_list.clear()
        assert len(utxo_list) == 0
        assert len(cloned) == 2


class TestUtxoListConcat:
    """Tests for concatenating UtxoLists."""

    def test_utxo_list_concat(self):
        """Test concatenating two UtxoLists."""
        list1 = UtxoList()
        list1.add(Utxo.new(create_test_input(0), create_test_output()))
        list1.add(Utxo.new(create_test_input(1), create_test_output()))
        list2 = UtxoList()
        list2.add(Utxo.new(create_test_input(2), create_test_output()))
        list2.add(Utxo.new(create_test_input(3), create_test_output()))
        result = list1.concat(list2)
        assert len(result) == 4
        assert result[0].input.index == 0
        assert result[3].input.index == 3

    def test_utxo_list_concat_with_empty(self):
        """Test concatenating with empty list."""
        list1 = create_default_utxo_list()
        list2 = UtxoList()
        result = list1.concat(list2)
        assert len(result) == 2

    def test_utxo_list_concat_empty_with_nonempty(self):
        """Test concatenating empty list with non-empty list."""
        list1 = UtxoList()
        list2 = create_default_utxo_list()
        result = list1.concat(list2)
        assert len(result) == 2

    def test_utxo_list_concat_same_list(self):
        """Test concatenating a list with itself."""
        utxo_list = create_default_utxo_list()
        result = utxo_list.concat(utxo_list)
        assert len(result) == 4

    def test_utxo_list_add_operator(self):
        """Test + operator for concatenation."""
        list1 = UtxoList()
        list1.add(Utxo.new(create_test_input(0), create_test_output()))
        list2 = UtxoList()
        list2.add(Utxo.new(create_test_input(1), create_test_output()))
        result = list1 + list2
        assert len(result) == 2

    def test_utxo_list_add_operator_with_python_list(self):
        """Test + operator with Python list."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(0), create_test_output()))
        python_list = [
            Utxo.new(create_test_input(1), create_test_output()),
            Utxo.new(create_test_input(2), create_test_output()),
        ]
        result = utxo_list + python_list
        assert len(result) == 3


class TestUtxoListSlice:
    """Tests for slicing UtxoList."""

    def test_utxo_list_slice(self):
        """Test slicing a UtxoList."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        sliced = utxo_list.slice(1, 4)
        assert len(sliced) == 3
        assert sliced[0].input.index == 1
        assert sliced[2].input.index == 3

    def test_utxo_list_slice_from_start(self):
        """Test slicing from start."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        sliced = utxo_list.slice(0, 3)
        assert len(sliced) == 3
        assert sliced[0].input.index == 0
        assert sliced[2].input.index == 2

    def test_utxo_list_slice_to_end(self):
        """Test slicing to end."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        sliced = utxo_list.slice(2, 5)
        assert len(sliced) == 3
        assert sliced[0].input.index == 2
        assert sliced[2].input.index == 4

    def test_utxo_list_slice_single_element(self):
        """Test slicing a single element."""
        utxo_list = create_default_utxo_list()
        sliced = utxo_list.slice(0, 1)
        assert len(sliced) == 1


class TestUtxoListErase:
    """Tests for erasing elements from UtxoList."""

    def test_utxo_list_erase_single(self):
        """Test erasing a single element."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        removed = utxo_list.erase(2, 1)
        assert len(utxo_list) == 4
        assert len(removed) == 1
        assert removed[0].input.index == 2
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 1
        assert utxo_list[2].input.index == 3
        assert utxo_list[3].input.index == 4

    def test_utxo_list_erase_multiple(self):
        """Test erasing multiple elements."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        removed = utxo_list.erase(1, 2)
        assert len(utxo_list) == 3
        assert len(removed) == 2
        assert removed[0].input.index == 1
        assert removed[1].input.index == 2
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 3
        assert utxo_list[2].input.index == 4

    def test_utxo_list_erase_negative_index(self):
        """Test erasing with negative index."""
        utxo_list = UtxoList()
        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        removed = utxo_list.erase(-1, 1)
        assert len(utxo_list) == 4
        assert len(removed) == 1
        assert removed[0].input.index == 4

    def test_utxo_list_erase_default_count(self):
        """Test erasing with default delete_count (1 element)."""
        utxo_list = UtxoList()
        for i in range(3):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        removed = utxo_list.erase(1)
        assert len(utxo_list) == 2
        assert len(removed) == 1
        assert removed[0].input.index == 1

    def test_utxo_list_erase_from_start(self):
        """Test erasing from start."""
        utxo_list = create_default_utxo_list()
        removed = utxo_list.erase(0, 1)
        assert len(utxo_list) == 1
        assert len(removed) == 1


class TestUtxoListSequence:
    """Tests for Sequence interface methods."""

    def test_utxo_list_index(self):
        """Test finding index of a UTxO."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo3 = Utxo.new(create_test_input(2), create_test_output(3000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.add(utxo3)
        assert utxo_list.index(utxo2) == 1

    def test_utxo_list_index_with_start(self):
        """Test finding index with start parameter."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo3 = Utxo.new(create_test_input(2), create_test_output(3000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.add(utxo3)
        assert utxo_list.index(utxo3, 1) == 2

    def test_utxo_list_index_with_stop(self):
        """Test finding index with stop parameter."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo3 = Utxo.new(create_test_input(2), create_test_output(3000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.add(utxo3)
        assert utxo_list.index(utxo2, 0, 2) == 1

    def test_utxo_list_index_not_found(self):
        """Test index raises ValueError when element not found."""
        utxo_list = create_default_utxo_list()
        different_utxo = Utxo.new(create_test_input(99), create_test_output())
        with pytest.raises(ValueError):
            utxo_list.index(different_utxo)

    def test_utxo_list_count(self):
        """Test counting occurrences of a UTxO."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.add(utxo1)
        assert utxo_list.count(utxo1) == 2
        assert utxo_list.count(utxo2) == 1

    def test_utxo_list_count_not_present(self):
        """Test counting when element is not present."""
        utxo_list = create_default_utxo_list()
        different_utxo = Utxo.new(create_test_input(99), create_test_output())
        assert utxo_list.count(different_utxo) == 0


class TestUtxoListRepresentation:
    """Tests for string representation of UtxoList."""

    def test_utxo_list_repr(self):
        """Test string representation."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
        utxo_list.add(Utxo.new(create_test_input(1), create_test_output()))
        repr_str = repr(utxo_list)
        assert "UtxoList" in repr_str
        assert "2" in repr_str

    def test_utxo_list_repr_empty(self):
        """Test string representation of empty list."""
        utxo_list = UtxoList()
        repr_str = repr(utxo_list)
        assert "UtxoList" in repr_str
        assert "0" in repr_str


class TestUtxoListContextManager:
    """Tests for context manager protocol."""

    def test_utxo_list_context_manager(self):
        """Test UtxoList as context manager."""
        with UtxoList() as utxo_list:
            utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
            assert len(utxo_list) == 1

    def test_utxo_list_context_manager_exception(self):
        """Test context manager with exception."""
        try:
            with UtxoList() as utxo_list:
                utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
                raise ValueError("test exception")
        except ValueError:
            pass


class TestUtxoListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_utxo_list_empty_operations(self):
        """Test operations on empty list."""
        utxo_list = UtxoList()
        assert len(utxo_list) == 0
        assert not utxo_list
        assert list(utxo_list) == []

    def test_utxo_list_single_element(self):
        """Test list with single element."""
        utxo_list = UtxoList()
        utxo = Utxo.new(create_test_input(0), create_test_output())
        utxo_list.add(utxo)
        assert len(utxo_list) == 1
        assert utxo_list[0] == utxo
        assert utxo_list[-1] == utxo

    def test_utxo_list_large_list(self):
        """Test list with many elements."""
        utxo_list = UtxoList()
        for i in range(100):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)
        assert len(utxo_list) == 100
        assert utxo_list[0].input.index == 0
        assert utxo_list[99].input.index == 99

    def test_utxo_list_multiple_operations(self):
        """Test multiple operations in sequence."""
        utxo_list = UtxoList()
        utxo1 = Utxo.new(create_test_input(0), create_test_output())
        utxo2 = Utxo.new(create_test_input(1), create_test_output())
        utxo3 = Utxo.new(create_test_input(2), create_test_output())
        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        utxo_list.add(utxo3)
        cloned = utxo_list.clone()
        utxo_list.remove(utxo2)
        assert len(utxo_list) == 2
        assert len(cloned) == 3
        sliced = cloned.slice(0, 2)
        assert len(sliced) == 2
