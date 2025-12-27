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
from cometa import AssetId, AssetIdList, CardanoError


ASSET_ID_HEX_1 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657241"
ASSET_ID_HEX_2 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657242"
ASSET_ID_HEX_3 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657243"
ASSET_ID_HEX_4 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657244"


def create_default_asset_id_list():
    """Creates a default asset ID list with 4 elements for testing."""
    id_list = AssetIdList()
    id_list.add(AssetId.from_hex(ASSET_ID_HEX_1))
    id_list.add(AssetId.from_hex(ASSET_ID_HEX_2))
    id_list.add(AssetId.from_hex(ASSET_ID_HEX_3))
    id_list.add(AssetId.from_hex(ASSET_ID_HEX_4))
    return id_list


class TestAssetIdListInit:
    """Tests for AssetIdList.__init__() initialization."""

    def test_can_create_empty_list(self):
        """Test that an empty AssetIdList can be created."""
        id_list = AssetIdList()
        assert id_list is not None
        assert len(id_list) == 0

    def test_raises_error_for_null_ptr(self):
        """Test that NULL pointer raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            AssetIdList(ffi.NULL)

    def test_can_create_with_valid_ptr(self):
        """Test that AssetIdList can be created with valid FFI pointer."""
        id_list1 = AssetIdList()
        id_list1.add(AssetId.new_lovelace())
        from cometa._ffi import lib
        lib.cardano_asset_id_list_ref(id_list1._ptr)
        id_list2 = AssetIdList(id_list1._ptr)
        assert len(id_list2) == 1


class TestAssetIdListFromList:
    """Tests for AssetIdList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that AssetIdList can be created from empty list."""
        id_list = AssetIdList.from_list([])
        assert id_list is not None
        assert len(id_list) == 0

    def test_can_create_from_list_of_ids(self):
        """Test that AssetIdList can be created from list of AssetId objects."""
        ids = [
            AssetId.from_hex(ASSET_ID_HEX_1),
            AssetId.from_hex(ASSET_ID_HEX_2),
            AssetId.from_hex(ASSET_ID_HEX_3)
        ]
        id_list = AssetIdList.from_list(ids)
        assert id_list is not None
        assert len(id_list) == 3
        assert id_list[0] == ids[0]
        assert id_list[1] == ids[1]
        assert id_list[2] == ids[2]

    def test_can_create_from_iterable(self):
        """Test that AssetIdList can be created from any iterable."""
        ids = (AssetId.from_hex(ASSET_ID_HEX_1) for _ in range(3))
        id_list = AssetIdList.from_list(ids)
        assert id_list is not None
        assert len(id_list) == 3

    def test_raises_error_for_invalid_element_type(self):
        """Test that invalid element type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetIdList.from_list(["not", "asset", "ids"])

    def test_raises_error_for_none(self):
        """Test that None raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetIdList.from_list(None)


class TestAssetIdListAdd:
    """Tests for AssetIdList.add() method."""

    def test_can_add_to_empty_list(self):
        """Test that AssetId can be added to empty list."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        assert len(id_list) == 1
        assert id_list[0] == asset_id

    def test_can_add_multiple_ids(self):
        """Test that multiple AssetIds can be added."""
        id_list = AssetIdList()
        id1 = AssetId.from_hex(ASSET_ID_HEX_1)
        id2 = AssetId.from_hex(ASSET_ID_HEX_2)
        id_list.add(id1)
        id_list.add(id2)
        assert len(id_list) == 2
        assert id_list[0] == id1
        assert id_list[1] == id2

    def test_can_add_duplicate_ids(self):
        """Test that duplicate AssetIds can be added."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(asset_id)
        assert len(id_list) == 2
        assert id_list[0] == id_list[1]

    def test_raises_error_for_none(self):
        """Test that adding None raises an error."""
        id_list = AssetIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            id_list.add(None)

    def test_raises_error_for_invalid_type(self):
        """Test that adding invalid type raises an error."""
        id_list = AssetIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            id_list.add("not an asset id")


class TestAssetIdListGet:
    """Tests for AssetIdList.get() method."""

    def test_can_get_element_at_index(self):
        """Test that element can be retrieved by index."""
        id_list = create_default_asset_id_list()
        asset_id = id_list.get(0)
        assert asset_id is not None
        assert asset_id.asset_name.to_string() == "skywalkerA"

    def test_can_get_all_elements(self):
        """Test that all elements can be retrieved."""
        id_list = create_default_asset_id_list()
        assert id_list.get(0).asset_name.to_string() == "skywalkerA"
        assert id_list.get(1).asset_name.to_string() == "skywalkerB"
        assert id_list.get(2).asset_name.to_string() == "skywalkerC"
        assert id_list.get(3).asset_name.to_string() == "skywalkerD"

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        id_list = create_default_asset_id_list()
        with pytest.raises(IndexError):
            id_list.get(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises IndexError."""
        id_list = AssetIdList()
        with pytest.raises(IndexError):
            id_list.get(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises IndexError."""
        id_list = create_default_asset_id_list()
        with pytest.raises(IndexError):
            id_list.get(10)


class TestAssetIdListLen:
    """Tests for AssetIdList.__len__() method."""

    def test_returns_zero_for_empty_list(self):
        """Test that __len__ returns 0 for empty list."""
        id_list = AssetIdList()
        assert len(id_list) == 0

    def test_returns_correct_length(self):
        """Test that __len__ returns correct length."""
        id_list = create_default_asset_id_list()
        assert len(id_list) == 4

    def test_length_increases_when_adding(self):
        """Test that length increases when adding elements."""
        id_list = AssetIdList()
        assert len(id_list) == 0
        id_list.add(AssetId.new_lovelace())
        assert len(id_list) == 1
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_1))
        assert len(id_list) == 2


class TestAssetIdListIter:
    """Tests for AssetIdList.__iter__() method."""

    def test_can_iterate_over_empty_list(self):
        """Test that iteration over empty list works."""
        id_list = AssetIdList()
        items = list(id_list)
        assert items == []

    def test_can_iterate_over_list(self):
        """Test that iteration over list works."""
        id_list = create_default_asset_id_list()
        items = list(id_list)
        assert len(items) == 4
        assert items[0].asset_name.to_string() == "skywalkerA"
        assert items[1].asset_name.to_string() == "skywalkerB"
        assert items[2].asset_name.to_string() == "skywalkerC"
        assert items[3].asset_name.to_string() == "skywalkerD"

    def test_can_use_in_for_loop(self):
        """Test that list can be used in for loop."""
        id_list = create_default_asset_id_list()
        count = 0
        for asset_id in id_list:
            assert asset_id is not None
            count += 1
        assert count == 4

    def test_iteration_order_matches_insertion_order(self):
        """Test that iteration order matches insertion order."""
        id_list = AssetIdList()
        ids = [AssetId.from_hex(ASSET_ID_HEX_1), AssetId.from_hex(ASSET_ID_HEX_2)]
        for asset_id in ids:
            id_list.add(asset_id)
        for i, asset_id in enumerate(id_list):
            assert asset_id == ids[i]


class TestAssetIdListGetItem:
    """Tests for AssetIdList.__getitem__() method."""

    def test_can_access_by_positive_index(self):
        """Test that elements can be accessed by positive index."""
        id_list = create_default_asset_id_list()
        assert id_list[0].asset_name.to_string() == "skywalkerA"
        assert id_list[1].asset_name.to_string() == "skywalkerB"
        assert id_list[2].asset_name.to_string() == "skywalkerC"
        assert id_list[3].asset_name.to_string() == "skywalkerD"

    def test_can_access_by_negative_index(self):
        """Test that elements can be accessed by negative index."""
        id_list = create_default_asset_id_list()
        assert id_list[-1].asset_name.to_string() == "skywalkerD"
        assert id_list[-2].asset_name.to_string() == "skywalkerC"
        assert id_list[-3].asset_name.to_string() == "skywalkerB"
        assert id_list[-4].asset_name.to_string() == "skywalkerA"

    def test_raises_error_for_out_of_bounds_positive_index(self):
        """Test that out of bounds positive index raises IndexError."""
        id_list = create_default_asset_id_list()
        with pytest.raises(IndexError):
            _ = id_list[10]

    def test_raises_error_for_out_of_bounds_negative_index(self):
        """Test that out of bounds negative index raises IndexError."""
        id_list = create_default_asset_id_list()
        with pytest.raises(IndexError):
            _ = id_list[-10]


class TestAssetIdListBool:
    """Tests for AssetIdList.__bool__() method."""

    def test_empty_list_is_falsy(self):
        """Test that empty list is falsy."""
        id_list = AssetIdList()
        assert not id_list
        assert bool(id_list) is False

    def test_non_empty_list_is_truthy(self):
        """Test that non-empty list is truthy."""
        id_list = AssetIdList()
        id_list.add(AssetId.new_lovelace())
        assert id_list
        assert bool(id_list) is True

    def test_can_use_in_if_statement(self):
        """Test that list can be used in if statement."""
        empty_list = AssetIdList()
        non_empty_list = create_default_asset_id_list()

        if empty_list:
            pytest.fail("Empty list should be falsy")

        if not non_empty_list:
            pytest.fail("Non-empty list should be truthy")


class TestAssetIdListContains:
    """Tests for AssetIdList.__contains__() method."""

    def test_returns_true_for_contained_element(self):
        """Test that __contains__ returns True for contained element."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.from_hex(ASSET_ID_HEX_1)
        assert asset_id in id_list

    def test_returns_false_for_non_contained_element(self):
        """Test that __contains__ returns False for non-contained element."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.new_lovelace()
        assert asset_id not in id_list

    def test_returns_false_for_empty_list(self):
        """Test that __contains__ returns False for empty list."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        assert asset_id not in id_list

    def test_finds_duplicate_elements(self):
        """Test that __contains__ finds duplicate elements."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(asset_id)
        assert asset_id in id_list


class TestAssetIdListAppend:
    """Tests for AssetIdList.append() method."""

    def test_can_append_to_list(self):
        """Test that element can be appended to list."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.append(asset_id)
        assert len(id_list) == 1
        assert id_list[0] == asset_id

    def test_append_is_alias_for_add(self):
        """Test that append behaves the same as add."""
        list1 = AssetIdList()
        list2 = AssetIdList()
        asset_id = AssetId.new_lovelace()

        list1.add(asset_id)
        list2.append(asset_id)

        assert len(list1) == len(list2)
        assert list1[0] == list2[0]

    def test_raises_error_for_none(self):
        """Test that appending None raises an error."""
        id_list = AssetIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            id_list.append(None)


class TestAssetIdListIndex:
    """Tests for AssetIdList.index() method."""

    def test_returns_index_of_element(self):
        """Test that index returns the index of element."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.from_hex(ASSET_ID_HEX_2)
        assert id_list.index(asset_id) == 1

    def test_returns_first_occurrence_index(self):
        """Test that index returns first occurrence for duplicates."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(asset_id)
        id_list.add(asset_id)
        assert id_list.index(asset_id) == 0

    def test_raises_error_for_non_existent_element(self):
        """Test that index raises ValueError for non-existent element."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.new_lovelace()
        with pytest.raises(ValueError):
            id_list.index(asset_id)

    def test_can_specify_start_index(self):
        """Test that start parameter works correctly."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_1))
        id_list.add(asset_id)
        assert id_list.index(asset_id, start=1) == 2

    def test_can_specify_stop_index(self):
        """Test that stop parameter works correctly."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_1))
        id_list.add(asset_id)
        with pytest.raises(ValueError):
            id_list.index(asset_id, start=1, stop=2)

    def test_can_specify_start_and_stop(self):
        """Test that start and stop parameters work together."""
        id_list = AssetIdList()
        id1 = AssetId.from_hex(ASSET_ID_HEX_1)
        id2 = AssetId.from_hex(ASSET_ID_HEX_2)
        id_list.add(id1)
        id_list.add(id2)
        id_list.add(id1)
        id_list.add(id2)
        assert id_list.index(id1, start=1, stop=4) == 2


class TestAssetIdListCount:
    """Tests for AssetIdList.count() method."""

    def test_returns_zero_for_non_existent_element(self):
        """Test that count returns 0 for non-existent element."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.new_lovelace()
        assert id_list.count(asset_id) == 0

    def test_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        id_list = create_default_asset_id_list()
        asset_id = AssetId.from_hex(ASSET_ID_HEX_1)
        assert id_list.count(asset_id) == 1

    def test_returns_correct_count_for_duplicates(self):
        """Test that count returns correct count for duplicates."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        id_list.add(asset_id)
        id_list.add(asset_id)
        id_list.add(asset_id)
        assert id_list.count(asset_id) == 3

    def test_returns_zero_for_empty_list(self):
        """Test that count returns 0 for empty list."""
        id_list = AssetIdList()
        asset_id = AssetId.new_lovelace()
        assert id_list.count(asset_id) == 0


class TestAssetIdListReversed:
    """Tests for AssetIdList.__reversed__() method."""

    def test_can_reverse_empty_list(self):
        """Test that reversing empty list works."""
        id_list = AssetIdList()
        items = list(reversed(id_list))
        assert items == []

    def test_can_reverse_list(self):
        """Test that reversing list works."""
        id_list = create_default_asset_id_list()
        items = list(reversed(id_list))
        assert len(items) == 4
        assert items[0].asset_name.to_string() == "skywalkerD"
        assert items[1].asset_name.to_string() == "skywalkerC"
        assert items[2].asset_name.to_string() == "skywalkerB"
        assert items[3].asset_name.to_string() == "skywalkerA"

    def test_reversed_order_is_correct(self):
        """Test that reversed order is exactly opposite of normal order."""
        id_list = create_default_asset_id_list()
        forward = list(id_list)
        backward = list(reversed(id_list))
        assert len(forward) == len(backward)
        for i in range(len(forward)):
            assert forward[i] == backward[-(i + 1)]


class TestAssetIdListRepr:
    """Tests for AssetIdList.__repr__() method."""

    def test_repr_contains_length(self):
        """Test that __repr__ contains the length."""
        id_list = create_default_asset_id_list()
        repr_str = repr(id_list)
        assert "AssetIdList" in repr_str
        assert "4" in repr_str

    def test_repr_for_empty_list(self):
        """Test that __repr__ works for empty list."""
        id_list = AssetIdList()
        repr_str = repr(id_list)
        assert "AssetIdList" in repr_str
        assert "0" in repr_str


class TestAssetIdListContextManager:
    """Tests for AssetIdList context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that AssetIdList can be used as a context manager."""
        with AssetIdList() as id_list:
            assert id_list is not None
            id_list.add(AssetId.new_lovelace())
            assert len(id_list) == 1

    def test_object_accessible_after_context(self):
        """Test that object is still accessible after context."""
        with AssetIdList() as id_list:
            id_list.add(AssetId.new_lovelace())
        assert len(id_list) == 1


class TestAssetIdListSequenceProtocol:
    """Tests for AssetIdList as a Sequence."""

    def test_implements_sequence_protocol(self):
        """Test that AssetIdList implements Sequence protocol."""
        from collections.abc import Sequence
        id_list = AssetIdList()
        assert isinstance(id_list, Sequence)

    def test_can_get_slice_behavior_through_iteration(self):
        """Test that list-like behavior works through iteration."""
        id_list = create_default_asset_id_list()
        first_two = [id_list[0], id_list[1]]
        assert len(first_two) == 2
        assert first_two[0].asset_name.to_string() == "skywalkerA"
        assert first_two[1].asset_name.to_string() == "skywalkerB"

    def test_len_matches_iteration_count(self):
        """Test that __len__ matches iteration count."""
        id_list = create_default_asset_id_list()
        assert len(id_list) == sum(1 for _ in id_list)


class TestAssetIdListEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_can_create_large_list(self):
        """Test that large list can be created."""
        id_list = AssetIdList()
        for _ in range(100):
            id_list.add(AssetId.new_lovelace())
        assert len(id_list) == 100

    def test_can_iterate_multiple_times(self):
        """Test that list can be iterated multiple times."""
        id_list = create_default_asset_id_list()
        first_pass = list(id_list)
        second_pass = list(id_list)
        assert len(first_pass) == len(second_pass)
        for i in range(len(first_pass)):
            assert first_pass[i] == second_pass[i]

    def test_equality_checks_work_correctly(self):
        """Test that equality checks work correctly."""
        id1 = AssetId.from_hex(ASSET_ID_HEX_1)
        id2 = AssetId.from_hex(ASSET_ID_HEX_1)
        id3 = AssetId.from_hex(ASSET_ID_HEX_2)

        id_list = AssetIdList()
        id_list.add(id1)

        assert id2 in id_list
        assert id3 not in id_list


class TestAssetIdListTestVectorsFromC:
    """Tests using test vectors from the C test file."""

    def test_creates_list_successfully(self):
        """Test that list creation matches C test expectations."""
        id_list = AssetIdList()
        assert id_list is not None
        assert len(id_list) == 0

    def test_adds_elements_successfully(self):
        """Test that adding elements works as in C tests."""
        id_list = AssetIdList()
        id1 = AssetId.from_hex(ASSET_ID_HEX_1)
        id2 = AssetId.from_hex(ASSET_ID_HEX_2)
        id3 = AssetId.from_hex(ASSET_ID_HEX_3)
        id4 = AssetId.from_hex(ASSET_ID_HEX_4)

        id_list.add(id1)
        id_list.add(id2)
        id_list.add(id3)
        id_list.add(id4)

        assert len(id_list) == 4

    def test_gets_elements_by_index(self):
        """Test that getting elements by index works as in C tests."""
        id_list = create_default_asset_id_list()
        asset_id = id_list.get(0)
        assert asset_id.asset_name.to_string() == "skywalkerA"

    def test_skywalker_test_vectors(self):
        """Test using all skywalker test vectors from C tests."""
        id_list = AssetIdList()
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_1))
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_2))
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_3))
        id_list.add(AssetId.from_hex(ASSET_ID_HEX_4))

        assert len(id_list) == 4
        assert id_list[0].asset_name.to_string() == "skywalkerA"
        assert id_list[1].asset_name.to_string() == "skywalkerB"
        assert id_list[2].asset_name.to_string() == "skywalkerC"
        assert id_list[3].asset_name.to_string() == "skywalkerD"
