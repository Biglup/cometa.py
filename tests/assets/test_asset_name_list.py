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
from cometa import AssetName, AssetNameList, CardanoError


ASSET_NAME_HEX_1 = "736b7977616c6b657241"
ASSET_NAME_HEX_2 = "736b7977616c6b657242"
ASSET_NAME_HEX_3 = "736b7977616c6b657243"
ASSET_NAME_HEX_4 = "736b7977616c6b657244"


def create_default_asset_name_list():
    """Creates a default asset name list with 4 elements for testing."""
    name_list = AssetNameList()
    name_list.add(AssetName.from_hex(ASSET_NAME_HEX_1))
    name_list.add(AssetName.from_hex(ASSET_NAME_HEX_2))
    name_list.add(AssetName.from_hex(ASSET_NAME_HEX_3))
    name_list.add(AssetName.from_hex(ASSET_NAME_HEX_4))
    return name_list


class TestAssetNameListInit:
    """Tests for AssetNameList.__init__() initialization."""

    def test_can_create_empty_list(self):
        """Test that an empty AssetNameList can be created."""
        name_list = AssetNameList()
        assert name_list is not None
        assert len(name_list) == 0

    def test_raises_error_for_null_ptr(self):
        """Test that NULL pointer raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            AssetNameList(ffi.NULL)

    def test_can_create_with_valid_ptr(self):
        """Test that AssetNameList can be created with valid FFI pointer."""
        name_list1 = AssetNameList()
        name_list1.add(AssetName.from_string("Token"))
        from cometa._ffi import lib
        lib.cardano_asset_name_list_ref(name_list1._ptr)
        name_list2 = AssetNameList(name_list1._ptr)
        assert len(name_list2) == 1


class TestAssetNameListFromList:
    """Tests for AssetNameList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that AssetNameList can be created from empty list."""
        name_list = AssetNameList.from_list([])
        assert name_list is not None
        assert len(name_list) == 0

    def test_can_create_from_list_of_names(self):
        """Test that AssetNameList can be created from list of AssetName objects."""
        names = [
            AssetName.from_string("Token1"),
            AssetName.from_string("Token2"),
            AssetName.from_string("Token3")
        ]
        name_list = AssetNameList.from_list(names)
        assert name_list is not None
        assert len(name_list) == 3
        assert name_list[0].to_string() == "Token1"
        assert name_list[1].to_string() == "Token2"
        assert name_list[2].to_string() == "Token3"

    def test_can_create_from_iterable(self):
        """Test that AssetNameList can be created from any iterable."""
        names = (AssetName.from_string(f"Token{i}") for i in range(3))
        name_list = AssetNameList.from_list(names)
        assert name_list is not None
        assert len(name_list) == 3

    def test_raises_error_for_invalid_element_type(self):
        """Test that invalid element type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetNameList.from_list(["not", "asset", "names"])

    def test_raises_error_for_none(self):
        """Test that None raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetNameList.from_list(None)


class TestAssetNameListAdd:
    """Tests for AssetNameList.add() method."""

    def test_can_add_to_empty_list(self):
        """Test that AssetName can be added to empty list."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        assert len(name_list) == 1
        assert name_list[0] == name

    def test_can_add_multiple_names(self):
        """Test that multiple AssetNames can be added."""
        name_list = AssetNameList()
        name1 = AssetName.from_string("Token1")
        name2 = AssetName.from_string("Token2")
        name_list.add(name1)
        name_list.add(name2)
        assert len(name_list) == 2
        assert name_list[0] == name1
        assert name_list[1] == name2

    def test_can_add_duplicate_names(self):
        """Test that duplicate AssetNames can be added."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(name)
        assert len(name_list) == 2
        assert name_list[0] == name_list[1]

    def test_raises_error_for_none(self):
        """Test that adding None raises an error."""
        name_list = AssetNameList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            name_list.add(None)

    def test_raises_error_for_invalid_type(self):
        """Test that adding invalid type raises an error."""
        name_list = AssetNameList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            name_list.add("not an asset name")


class TestAssetNameListGet:
    """Tests for AssetNameList.get() method."""

    def test_can_get_element_at_index(self):
        """Test that element can be retrieved by index."""
        name_list = create_default_asset_name_list()
        name = name_list.get(0)
        assert name is not None
        assert name.to_string() == "skywalkerA"

    def test_can_get_all_elements(self):
        """Test that all elements can be retrieved."""
        name_list = create_default_asset_name_list()
        assert name_list.get(0).to_string() == "skywalkerA"
        assert name_list.get(1).to_string() == "skywalkerB"
        assert name_list.get(2).to_string() == "skywalkerC"
        assert name_list.get(3).to_string() == "skywalkerD"

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        name_list = create_default_asset_name_list()
        with pytest.raises(IndexError):
            name_list.get(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises IndexError."""
        name_list = AssetNameList()
        with pytest.raises(IndexError):
            name_list.get(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises IndexError."""
        name_list = create_default_asset_name_list()
        with pytest.raises(IndexError):
            name_list.get(10)


class TestAssetNameListLen:
    """Tests for AssetNameList.__len__() method."""

    def test_returns_zero_for_empty_list(self):
        """Test that __len__ returns 0 for empty list."""
        name_list = AssetNameList()
        assert len(name_list) == 0

    def test_returns_correct_length(self):
        """Test that __len__ returns correct length."""
        name_list = create_default_asset_name_list()
        assert len(name_list) == 4

    def test_length_increases_when_adding(self):
        """Test that length increases when adding elements."""
        name_list = AssetNameList()
        assert len(name_list) == 0
        name_list.add(AssetName.from_string("Token"))
        assert len(name_list) == 1
        name_list.add(AssetName.from_string("Token2"))
        assert len(name_list) == 2


class TestAssetNameListIter:
    """Tests for AssetNameList.__iter__() method."""

    def test_can_iterate_over_empty_list(self):
        """Test that iteration over empty list works."""
        name_list = AssetNameList()
        items = list(name_list)
        assert items == []

    def test_can_iterate_over_list(self):
        """Test that iteration over list works."""
        name_list = create_default_asset_name_list()
        items = list(name_list)
        assert len(items) == 4
        assert items[0].to_string() == "skywalkerA"
        assert items[1].to_string() == "skywalkerB"
        assert items[2].to_string() == "skywalkerC"
        assert items[3].to_string() == "skywalkerD"

    def test_can_use_in_for_loop(self):
        """Test that list can be used in for loop."""
        name_list = create_default_asset_name_list()
        count = 0
        for name in name_list:
            assert name is not None
            count += 1
        assert count == 4

    def test_iteration_order_matches_insertion_order(self):
        """Test that iteration order matches insertion order."""
        name_list = AssetNameList()
        names = [AssetName.from_string(f"Token{i}") for i in range(5)]
        for name in names:
            name_list.add(name)
        for i, name in enumerate(name_list):
            assert name == names[i]


class TestAssetNameListGetItem:
    """Tests for AssetNameList.__getitem__() method."""

    def test_can_access_by_positive_index(self):
        """Test that elements can be accessed by positive index."""
        name_list = create_default_asset_name_list()
        assert name_list[0].to_string() == "skywalkerA"
        assert name_list[1].to_string() == "skywalkerB"
        assert name_list[2].to_string() == "skywalkerC"
        assert name_list[3].to_string() == "skywalkerD"

    def test_can_access_by_negative_index(self):
        """Test that elements can be accessed by negative index."""
        name_list = create_default_asset_name_list()
        assert name_list[-1].to_string() == "skywalkerD"
        assert name_list[-2].to_string() == "skywalkerC"
        assert name_list[-3].to_string() == "skywalkerB"
        assert name_list[-4].to_string() == "skywalkerA"

    def test_raises_error_for_out_of_bounds_positive_index(self):
        """Test that out of bounds positive index raises IndexError."""
        name_list = create_default_asset_name_list()
        with pytest.raises(IndexError):
            _ = name_list[10]

    def test_raises_error_for_out_of_bounds_negative_index(self):
        """Test that out of bounds negative index raises IndexError."""
        name_list = create_default_asset_name_list()
        with pytest.raises(IndexError):
            _ = name_list[-10]


class TestAssetNameListBool:
    """Tests for AssetNameList.__bool__() method."""

    def test_empty_list_is_falsy(self):
        """Test that empty list is falsy."""
        name_list = AssetNameList()
        assert not name_list
        assert bool(name_list) is False

    def test_non_empty_list_is_truthy(self):
        """Test that non-empty list is truthy."""
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("Token"))
        assert name_list
        assert bool(name_list) is True

    def test_can_use_in_if_statement(self):
        """Test that list can be used in if statement."""
        empty_list = AssetNameList()
        non_empty_list = create_default_asset_name_list()

        if empty_list:
            pytest.fail("Empty list should be falsy")

        if not non_empty_list:
            pytest.fail("Non-empty list should be truthy")


class TestAssetNameListContains:
    """Tests for AssetNameList.__contains__() method."""

    def test_returns_true_for_contained_element(self):
        """Test that __contains__ returns True for contained element."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert name in name_list

    def test_returns_false_for_non_contained_element(self):
        """Test that __contains__ returns False for non-contained element."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_string("NotInList")
        assert name not in name_list

    def test_returns_false_for_empty_list(self):
        """Test that __contains__ returns False for empty list."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        assert name not in name_list

    def test_finds_duplicate_elements(self):
        """Test that __contains__ finds duplicate elements."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(name)
        assert name in name_list


class TestAssetNameListAppend:
    """Tests for AssetNameList.append() method."""

    def test_can_append_to_list(self):
        """Test that element can be appended to list."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.append(name)
        assert len(name_list) == 1
        assert name_list[0] == name

    def test_append_is_alias_for_add(self):
        """Test that append behaves the same as add."""
        list1 = AssetNameList()
        list2 = AssetNameList()
        name = AssetName.from_string("Token")

        list1.add(name)
        list2.append(name)

        assert len(list1) == len(list2)
        assert list1[0] == list2[0]

    def test_raises_error_for_none(self):
        """Test that appending None raises an error."""
        name_list = AssetNameList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            name_list.append(None)


class TestAssetNameListIndex:
    """Tests for AssetNameList.index() method."""

    def test_returns_index_of_element(self):
        """Test that index returns the index of element."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_hex(ASSET_NAME_HEX_2)
        assert name_list.index(name) == 1

    def test_returns_first_occurrence_index(self):
        """Test that index returns first occurrence for duplicates."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(name)
        name_list.add(name)
        assert name_list.index(name) == 0

    def test_raises_error_for_non_existent_element(self):
        """Test that index raises ValueError for non-existent element."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_string("NotInList")
        with pytest.raises(ValueError):
            name_list.index(name)

    def test_can_specify_start_index(self):
        """Test that start parameter works correctly."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(AssetName.from_string("Other"))
        name_list.add(name)
        assert name_list.index(name, start=1) == 2

    def test_can_specify_stop_index(self):
        """Test that stop parameter works correctly."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(AssetName.from_string("Other"))
        name_list.add(name)
        with pytest.raises(ValueError):
            name_list.index(name, start=1, stop=2)

    def test_can_specify_start_and_stop(self):
        """Test that start and stop parameters work together."""
        name_list = AssetNameList()
        name1 = AssetName.from_string("Token1")
        name2 = AssetName.from_string("Token2")
        name_list.add(name1)
        name_list.add(name2)
        name_list.add(name1)
        name_list.add(name2)
        assert name_list.index(name1, start=1, stop=4) == 2


class TestAssetNameListCount:
    """Tests for AssetNameList.count() method."""

    def test_returns_zero_for_non_existent_element(self):
        """Test that count returns 0 for non-existent element."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_string("NotInList")
        assert name_list.count(name) == 0

    def test_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        name_list = create_default_asset_name_list()
        name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert name_list.count(name) == 1

    def test_returns_correct_count_for_duplicates(self):
        """Test that count returns correct count for duplicates."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        name_list.add(name)
        name_list.add(name)
        assert name_list.count(name) == 3

    def test_returns_zero_for_empty_list(self):
        """Test that count returns 0 for empty list."""
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        assert name_list.count(name) == 0


class TestAssetNameListReversed:
    """Tests for AssetNameList.__reversed__() method."""

    def test_can_reverse_empty_list(self):
        """Test that reversing empty list works."""
        name_list = AssetNameList()
        items = list(reversed(name_list))
        assert items == []

    def test_can_reverse_list(self):
        """Test that reversing list works."""
        name_list = create_default_asset_name_list()
        items = list(reversed(name_list))
        assert len(items) == 4
        assert items[0].to_string() == "skywalkerD"
        assert items[1].to_string() == "skywalkerC"
        assert items[2].to_string() == "skywalkerB"
        assert items[3].to_string() == "skywalkerA"

    def test_reversed_order_is_correct(self):
        """Test that reversed order is exactly opposite of normal order."""
        name_list = create_default_asset_name_list()
        forward = list(name_list)
        backward = list(reversed(name_list))
        assert len(forward) == len(backward)
        for i in range(len(forward)):
            assert forward[i] == backward[-(i + 1)]


class TestAssetNameListRepr:
    """Tests for AssetNameList.__repr__() method."""

    def test_repr_contains_length(self):
        """Test that __repr__ contains the length."""
        name_list = create_default_asset_name_list()
        repr_str = repr(name_list)
        assert "AssetNameList" in repr_str
        assert "4" in repr_str

    def test_repr_for_empty_list(self):
        """Test that __repr__ works for empty list."""
        name_list = AssetNameList()
        repr_str = repr(name_list)
        assert "AssetNameList" in repr_str
        assert "0" in repr_str


class TestAssetNameListContextManager:
    """Tests for AssetNameList context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that AssetNameList can be used as a context manager."""
        with AssetNameList() as name_list:
            assert name_list is not None
            name_list.add(AssetName.from_string("Token"))
            assert len(name_list) == 1

    def test_object_accessible_after_context(self):
        """Test that object is still accessible after context."""
        with AssetNameList() as name_list:
            name_list.add(AssetName.from_string("Token"))
        assert len(name_list) == 1


class TestAssetNameListSequenceProtocol:
    """Tests for AssetNameList as a Sequence."""

    def test_implements_sequence_protocol(self):
        """Test that AssetNameList implements Sequence protocol."""
        from collections.abc import Sequence
        name_list = AssetNameList()
        assert isinstance(name_list, Sequence)

    def test_can_get_slice_behavior_through_iteration(self):
        """Test that list-like behavior works through iteration."""
        name_list = create_default_asset_name_list()
        first_two = [name_list[0], name_list[1]]
        assert len(first_two) == 2
        assert first_two[0].to_string() == "skywalkerA"
        assert first_two[1].to_string() == "skywalkerB"

    def test_len_matches_iteration_count(self):
        """Test that __len__ matches iteration count."""
        name_list = create_default_asset_name_list()
        assert len(name_list) == sum(1 for _ in name_list)


class TestAssetNameListEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_can_create_large_list(self):
        """Test that large list can be created."""
        name_list = AssetNameList()
        for i in range(100):
            name_list.add(AssetName.from_string(f"Token{i}"))
        assert len(name_list) == 100

    def test_can_iterate_multiple_times(self):
        """Test that list can be iterated multiple times."""
        name_list = create_default_asset_name_list()
        first_pass = list(name_list)
        second_pass = list(name_list)
        assert first_pass == second_pass

    def test_list_with_empty_asset_names(self):
        """Test that list can contain empty asset names."""
        name_list = AssetNameList()
        name_list.add(AssetName.from_bytes(b""))
        name_list.add(AssetName.from_string("Token"))
        assert len(name_list) == 2
        assert len(name_list[0]) == 0
        assert name_list[1].to_string() == "Token"

    def test_equality_checks_work_correctly(self):
        """Test that equality checks work correctly."""
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        name3 = AssetName.from_string("Other")

        name_list = AssetNameList()
        name_list.add(name1)

        assert name2 in name_list
        assert name3 not in name_list


class TestAssetNameListTestVectorsFromC:
    """Tests using test vectors from the C test file."""

    def test_creates_list_successfully(self):
        """Test that list creation matches C test expectations."""
        name_list = AssetNameList()
        assert name_list is not None
        assert len(name_list) == 0

    def test_adds_elements_successfully(self):
        """Test that adding elements works as in C tests."""
        name_list = AssetNameList()
        name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        name3 = AssetName.from_hex(ASSET_NAME_HEX_3)
        name4 = AssetName.from_hex(ASSET_NAME_HEX_4)

        name_list.add(name1)
        name_list.add(name2)
        name_list.add(name3)
        name_list.add(name4)

        assert len(name_list) == 4

    def test_gets_elements_by_index(self):
        """Test that getting elements by index works as in C tests."""
        name_list = create_default_asset_name_list()
        name = name_list.get(0)
        assert name.to_string() == "skywalkerA"

    def test_skywalker_test_vectors(self):
        """Test using all skywalker test vectors from C tests."""
        name_list = AssetNameList()
        name_list.add(AssetName.from_hex(ASSET_NAME_HEX_1))
        name_list.add(AssetName.from_hex(ASSET_NAME_HEX_2))
        name_list.add(AssetName.from_hex(ASSET_NAME_HEX_3))
        name_list.add(AssetName.from_hex(ASSET_NAME_HEX_4))

        assert len(name_list) == 4
        assert name_list[0].to_string() == "skywalkerA"
        assert name_list[1].to_string() == "skywalkerB"
        assert name_list[2].to_string() == "skywalkerC"
        assert name_list[3].to_string() == "skywalkerD"
