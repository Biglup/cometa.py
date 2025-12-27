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
from cometa import Blake2bHash, CardanoError
from cometa.assets.policy_id_list import PolicyIdList


POLICY_ID_HEX_1 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
POLICY_ID_HEX_2 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9b"
POLICY_ID_HEX_3 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9c"
POLICY_ID_HEX_4 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9d"


def create_default_policy_id_list():
    """Creates a default policy ID list with 4 elements for testing."""
    policy_list = PolicyIdList()
    policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
    policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_2))
    policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_3))
    policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_4))
    return policy_list


class TestPolicyIdListInit:
    """Tests for PolicyIdList.__init__() initialization."""

    def test_can_create_empty_list(self):
        """Test that an empty PolicyIdList can be created."""
        policy_list = PolicyIdList()
        assert policy_list is not None
        assert len(policy_list) == 0

    def test_raises_error_for_null_ptr(self):
        """Test that NULL pointer raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            PolicyIdList(ffi.NULL)

    def test_can_create_with_valid_ptr(self):
        """Test that PolicyIdList can be created with valid FFI pointer."""
        policy_list1 = PolicyIdList()
        policy_list1.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        from cometa._ffi import lib
        lib.cardano_blake2b_hash_set_ref(policy_list1._ptr)
        policy_list2 = PolicyIdList(policy_list1._ptr)
        assert len(policy_list2) == 1


class TestPolicyIdListFromList:
    """Tests for PolicyIdList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that PolicyIdList can be created from empty list."""
        policy_list = PolicyIdList.from_list([])
        assert policy_list is not None
        assert len(policy_list) == 0

    def test_can_create_from_list_of_policy_ids(self):
        """Test that PolicyIdList can be created from list of Blake2bHash objects."""
        policy_ids = [
            Blake2bHash.from_hex(POLICY_ID_HEX_1),
            Blake2bHash.from_hex(POLICY_ID_HEX_2),
            Blake2bHash.from_hex(POLICY_ID_HEX_3)
        ]
        policy_list = PolicyIdList.from_list(policy_ids)
        assert policy_list is not None
        assert len(policy_list) == 3
        assert policy_list[0] == policy_ids[0]
        assert policy_list[1] == policy_ids[1]
        assert policy_list[2] == policy_ids[2]

    def test_can_create_from_iterable(self):
        """Test that PolicyIdList can be created from any iterable."""
        policy_ids = (Blake2bHash.from_hex(POLICY_ID_HEX_1) for _ in range(3))
        policy_list = PolicyIdList.from_list(policy_ids)
        assert policy_list is not None
        assert len(policy_list) == 3

    def test_raises_error_for_invalid_element_type(self):
        """Test that invalid element type raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PolicyIdList.from_list(["not", "policy", "ids"])

    def test_raises_error_for_none(self):
        """Test that None raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            PolicyIdList.from_list(None)


class TestPolicyIdListAdd:
    """Tests for PolicyIdList.add() method."""

    def test_can_add_to_empty_list(self):
        """Test that policy ID can be added to empty list."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.add(policy_id)
        assert len(policy_list) == 1
        assert policy_list[0] == policy_id

    def test_can_add_multiple_policy_ids(self):
        """Test that multiple policy IDs can be added."""
        policy_list = PolicyIdList()
        policy_id1 = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_id2 = Blake2bHash.from_hex(POLICY_ID_HEX_2)
        policy_list.add(policy_id1)
        policy_list.add(policy_id2)
        assert len(policy_list) == 2
        assert policy_list[0] == policy_id1
        assert policy_list[1] == policy_id2

    def test_can_add_duplicate_policy_ids(self):
        """Test that duplicate policy IDs can be added."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.add(policy_id)
        policy_list.add(policy_id)
        assert len(policy_list) == 2
        assert policy_list[0] == policy_list[1]

    def test_raises_error_for_none(self):
        """Test that adding None raises an error."""
        policy_list = PolicyIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            policy_list.add(None)

    def test_raises_error_for_invalid_type(self):
        """Test that adding invalid type raises an error."""
        policy_list = PolicyIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            policy_list.add("not a policy id")


class TestPolicyIdListGet:
    """Tests for PolicyIdList.get() method."""

    def test_can_get_element_at_index(self):
        """Test that policy ID can be retrieved by index."""
        policy_list = create_default_policy_id_list()
        policy_id = policy_list.get(0)
        assert policy_id is not None
        assert policy_id.to_hex() == POLICY_ID_HEX_1

    def test_can_get_all_elements(self):
        """Test that all policy IDs can be retrieved."""
        policy_list = create_default_policy_id_list()
        assert policy_list.get(0).to_hex() == POLICY_ID_HEX_1
        assert policy_list.get(1).to_hex() == POLICY_ID_HEX_2
        assert policy_list.get(2).to_hex() == POLICY_ID_HEX_3
        assert policy_list.get(3).to_hex() == POLICY_ID_HEX_4

    def test_can_get_last_element(self):
        """Test that last policy ID can be retrieved."""
        policy_list = create_default_policy_id_list()
        policy_id = policy_list.get(3)
        assert policy_id.to_hex() == POLICY_ID_HEX_4

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        policy_list = create_default_policy_id_list()
        with pytest.raises(IndexError):
            policy_list.get(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises IndexError."""
        policy_list = create_default_policy_id_list()
        with pytest.raises(IndexError):
            policy_list.get(4)

    def test_raises_error_for_empty_list(self):
        """Test that getting from empty list raises IndexError."""
        policy_list = PolicyIdList()
        with pytest.raises(IndexError):
            policy_list.get(0)


class TestPolicyIdListLen:
    """Tests for PolicyIdList.__len__() method."""

    def test_returns_zero_for_empty_list(self):
        """Test that length is 0 for empty list."""
        policy_list = PolicyIdList()
        assert len(policy_list) == 0

    def test_returns_correct_length_for_non_empty_list(self):
        """Test that length is correct for non-empty list."""
        policy_list = create_default_policy_id_list()
        assert len(policy_list) == 4

    def test_length_increases_after_add(self):
        """Test that length increases after adding elements."""
        policy_list = PolicyIdList()
        assert len(policy_list) == 0
        policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        assert len(policy_list) == 1
        policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_2))
        assert len(policy_list) == 2


class TestPolicyIdListIter:
    """Tests for PolicyIdList.__iter__() method."""

    def test_can_iterate_over_empty_list(self):
        """Test that empty list can be iterated over."""
        policy_list = PolicyIdList()
        items = list(policy_list)
        assert not items

    def test_can_iterate_over_non_empty_list(self):
        """Test that non-empty list can be iterated over."""
        policy_list = create_default_policy_id_list()
        items = list(policy_list)
        assert len(items) == 4
        assert items[0].to_hex() == POLICY_ID_HEX_1
        assert items[1].to_hex() == POLICY_ID_HEX_2
        assert items[2].to_hex() == POLICY_ID_HEX_3
        assert items[3].to_hex() == POLICY_ID_HEX_4

    def test_can_use_for_loop(self):
        """Test that for loop works with PolicyIdList."""
        policy_list = create_default_policy_id_list()
        count = 0
        for policy_id in policy_list:
            assert policy_id is not None
            count += 1
        assert count == 4

    def test_iterator_yields_blake2b_hash_objects(self):
        """Test that iterator yields Blake2bHash objects."""
        policy_list = create_default_policy_id_list()
        for policy_id in policy_list:
            assert isinstance(policy_id, Blake2bHash)


class TestPolicyIdListGetItem:
    """Tests for PolicyIdList.__getitem__() method."""

    def test_can_access_by_positive_index(self):
        """Test that elements can be accessed by positive index."""
        policy_list = create_default_policy_id_list()
        assert policy_list[0].to_hex() == POLICY_ID_HEX_1
        assert policy_list[1].to_hex() == POLICY_ID_HEX_2
        assert policy_list[2].to_hex() == POLICY_ID_HEX_3
        assert policy_list[3].to_hex() == POLICY_ID_HEX_4

    def test_can_access_by_negative_index(self):
        """Test that elements can be accessed by negative index."""
        policy_list = create_default_policy_id_list()
        assert policy_list[-1].to_hex() == POLICY_ID_HEX_4
        assert policy_list[-2].to_hex() == POLICY_ID_HEX_3
        assert policy_list[-3].to_hex() == POLICY_ID_HEX_2
        assert policy_list[-4].to_hex() == POLICY_ID_HEX_1

    def test_can_access_first_element(self):
        """Test that first element can be accessed."""
        policy_list = create_default_policy_id_list()
        assert policy_list[0].to_hex() == POLICY_ID_HEX_1

    def test_can_access_last_element(self):
        """Test that last element can be accessed."""
        policy_list = create_default_policy_id_list()
        assert policy_list[-1].to_hex() == POLICY_ID_HEX_4

    def test_raises_error_for_out_of_bounds_positive_index(self):
        """Test that out of bounds positive index raises IndexError."""
        policy_list = create_default_policy_id_list()
        with pytest.raises(IndexError):
            _ = policy_list[4]

    def test_raises_error_for_out_of_bounds_negative_index(self):
        """Test that out of bounds negative index raises IndexError."""
        policy_list = create_default_policy_id_list()
        with pytest.raises(IndexError):
            _ = policy_list[-5]


class TestPolicyIdListContains:
    """Tests for PolicyIdList.__contains__() method."""

    def test_returns_true_for_existing_element(self):
        """Test that __contains__ returns True for existing element."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        assert policy_id in policy_list

    def test_returns_false_for_non_existing_element(self):
        """Test that __contains__ returns False for non-existing element."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex("00" * 28)
        assert policy_id not in policy_list

    def test_returns_false_for_empty_list(self):
        """Test that __contains__ returns False for empty list."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        assert policy_id not in policy_list

    def test_can_find_all_elements(self):
        """Test that all elements can be found."""
        policy_list = create_default_policy_id_list()
        assert Blake2bHash.from_hex(POLICY_ID_HEX_1) in policy_list
        assert Blake2bHash.from_hex(POLICY_ID_HEX_2) in policy_list
        assert Blake2bHash.from_hex(POLICY_ID_HEX_3) in policy_list
        assert Blake2bHash.from_hex(POLICY_ID_HEX_4) in policy_list


class TestPolicyIdListBool:
    """Tests for PolicyIdList.__bool__() method."""

    def test_returns_false_for_empty_list(self):
        """Test that empty list is falsy."""
        policy_list = PolicyIdList()
        assert not policy_list
        assert bool(policy_list) is False

    def test_returns_true_for_non_empty_list(self):
        """Test that non-empty list is truthy."""
        policy_list = PolicyIdList()
        policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        assert policy_list
        assert bool(policy_list) is True

    def test_can_use_in_if_statement(self):
        """Test that PolicyIdList can be used in if statement."""
        empty_list = PolicyIdList()
        non_empty_list = create_default_policy_id_list()

        if empty_list:
            pytest.fail("Empty list should be falsy")

        if not non_empty_list:
            pytest.fail("Non-empty list should be truthy")


class TestPolicyIdListAppend:
    """Tests for PolicyIdList.append() method."""

    def test_can_append_to_empty_list(self):
        """Test that policy ID can be appended to empty list."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.append(policy_id)
        assert len(policy_list) == 1
        assert policy_list[0] == policy_id

    def test_append_is_alias_for_add(self):
        """Test that append is an alias for add."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.append(policy_id)
        assert len(policy_list) == 1
        assert policy_list[0] == policy_id

    def test_can_append_multiple_policy_ids(self):
        """Test that multiple policy IDs can be appended."""
        policy_list = PolicyIdList()
        policy_list.append(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        policy_list.append(Blake2bHash.from_hex(POLICY_ID_HEX_2))
        policy_list.append(Blake2bHash.from_hex(POLICY_ID_HEX_3))
        assert len(policy_list) == 3

    def test_raises_error_for_none(self):
        """Test that appending None raises an error."""
        policy_list = PolicyIdList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            policy_list.append(None)


class TestPolicyIdListIndex:
    """Tests for PolicyIdList.index() method."""

    def test_can_find_index_of_first_element(self):
        """Test that index of first element can be found."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        index = policy_list.index(policy_id)
        assert index == 0

    def test_can_find_index_of_last_element(self):
        """Test that index of last element can be found."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_4)
        index = policy_list.index(policy_id)
        assert index == 3

    def test_can_find_index_of_middle_element(self):
        """Test that index of middle element can be found."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_2)
        index = policy_list.index(policy_id)
        assert index == 1

    def test_raises_error_for_non_existing_element(self):
        """Test that ValueError is raised for non-existing element."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex("00" * 28)
        with pytest.raises(ValueError):
            policy_list.index(policy_id)

    def test_raises_error_for_empty_list(self):
        """Test that ValueError is raised for empty list."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        with pytest.raises(ValueError):
            policy_list.index(policy_id)

    def test_can_use_start_parameter(self):
        """Test that start parameter works correctly."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.add(policy_id)
        policy_list.add(policy_id)
        policy_list.add(policy_id)

        assert policy_list.index(policy_id, 0) == 0
        assert policy_list.index(policy_id, 1) == 1
        assert policy_list.index(policy_id, 2) == 2

    def test_can_use_stop_parameter(self):
        """Test that stop parameter works correctly."""
        policy_list = PolicyIdList()
        policy_id1 = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_id2 = Blake2bHash.from_hex(POLICY_ID_HEX_2)
        policy_id3 = Blake2bHash.from_hex(POLICY_ID_HEX_3)
        policy_list.add(policy_id1)
        policy_list.add(policy_id2)
        policy_list.add(policy_id3)

        assert policy_list.index(policy_id1, 0, 1) == 0
        with pytest.raises(ValueError):
            policy_list.index(policy_id3, 0, 2)

    def test_returns_first_occurrence(self):
        """Test that index returns first occurrence of duplicate elements."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.add(policy_id)
        policy_list.add(policy_id)
        policy_list.add(policy_id)

        assert policy_list.index(policy_id) == 0


class TestPolicyIdListCount:
    """Tests for PolicyIdList.count() method."""

    def test_returns_zero_for_non_existing_element(self):
        """Test that count returns 0 for non-existing element."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex("00" * 28)
        assert policy_list.count(policy_id) == 0

    def test_returns_zero_for_empty_list(self):
        """Test that count returns 0 for empty list."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        assert policy_list.count(policy_id) == 0

    def test_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        policy_list = create_default_policy_id_list()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        assert policy_list.count(policy_id) == 1

    def test_returns_correct_count_for_multiple_occurrences(self):
        """Test that count returns correct count for multiple occurrences."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_list.add(policy_id)
        policy_list.add(policy_id)
        policy_list.add(policy_id)
        assert policy_list.count(policy_id) == 3

    def test_counts_only_matching_elements(self):
        """Test that count only counts matching elements."""
        policy_list = create_default_policy_id_list()
        policy_id1 = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_id2 = Blake2bHash.from_hex(POLICY_ID_HEX_2)
        policy_list.add(policy_id1)
        policy_list.add(policy_id1)

        assert policy_list.count(policy_id1) == 3
        assert policy_list.count(policy_id2) == 1


class TestPolicyIdListReversed:
    """Tests for PolicyIdList.__reversed__() method."""

    def test_can_reverse_empty_list(self):
        """Test that empty list can be reversed."""
        policy_list = PolicyIdList()
        reversed_list = list(reversed(policy_list))
        assert not reversed_list

    def test_can_reverse_non_empty_list(self):
        """Test that non-empty list can be reversed."""
        policy_list = create_default_policy_id_list()
        reversed_list = list(reversed(policy_list))
        assert len(reversed_list) == 4
        assert reversed_list[0].to_hex() == POLICY_ID_HEX_4
        assert reversed_list[1].to_hex() == POLICY_ID_HEX_3
        assert reversed_list[2].to_hex() == POLICY_ID_HEX_2
        assert reversed_list[3].to_hex() == POLICY_ID_HEX_1

    def test_reversed_does_not_modify_original_list(self):
        """Test that reversing does not modify original list."""
        policy_list = create_default_policy_id_list()
        _ = list(reversed(policy_list))
        assert policy_list[0].to_hex() == POLICY_ID_HEX_1
        assert policy_list[3].to_hex() == POLICY_ID_HEX_4

    def test_can_use_reversed_in_for_loop(self):
        """Test that reversed can be used in for loop."""
        policy_list = create_default_policy_id_list()
        hexes = [POLICY_ID_HEX_4, POLICY_ID_HEX_3, POLICY_ID_HEX_2, POLICY_ID_HEX_1]
        for i, policy_id in enumerate(reversed(policy_list)):
            assert policy_id.to_hex() == hexes[i]


class TestPolicyIdListRepr:
    """Tests for PolicyIdList.__repr__() method."""

    def test_repr_for_empty_list(self):
        """Test that repr works for empty list."""
        policy_list = PolicyIdList()
        assert repr(policy_list) == "PolicyIdList(len=0)"

    def test_repr_for_non_empty_list(self):
        """Test that repr works for non-empty list."""
        policy_list = create_default_policy_id_list()
        assert repr(policy_list) == "PolicyIdList(len=4)"

    def test_repr_updates_after_add(self):
        """Test that repr updates after adding elements."""
        policy_list = PolicyIdList()
        assert repr(policy_list) == "PolicyIdList(len=0)"
        policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        assert repr(policy_list) == "PolicyIdList(len=1)"


class TestPolicyIdListContextManager:
    """Tests for PolicyIdList context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that PolicyIdList can be used as context manager."""
        with PolicyIdList() as policy_list:
            assert policy_list is not None
            policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
            assert len(policy_list) == 1

    def test_context_manager_does_not_affect_functionality(self):
        """Test that using context manager does not affect functionality."""
        with PolicyIdList() as policy_list:
            policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
            policy_list.add(Blake2bHash.from_hex(POLICY_ID_HEX_2))
            assert len(policy_list) == 2


class TestPolicyIdListSequenceCompliance:
    """Tests for Sequence protocol compliance."""

    def test_implements_sequence_protocol(self):
        """Test that PolicyIdList implements Sequence protocol."""
        from collections.abc import Sequence
        policy_list = PolicyIdList()
        assert isinstance(policy_list, Sequence)

    def test_can_use_with_list_comprehension(self):
        """Test that PolicyIdList can be used in list comprehension."""
        policy_list = create_default_policy_id_list()
        hexes = [p.to_hex() for p in policy_list]
        assert len(hexes) == 4
        assert hexes[0] == POLICY_ID_HEX_1
        assert hexes[3] == POLICY_ID_HEX_4

    def test_can_use_with_any_function(self):
        """Test that PolicyIdList can be used with any() function."""
        policy_list = create_default_policy_id_list()
        assert any(policy_list)

        empty_list = PolicyIdList()
        assert not any(empty_list)

    def test_can_use_with_all_function(self):
        """Test that PolicyIdList can be used with all() function."""
        policy_list = create_default_policy_id_list()
        assert all(policy_list)

        empty_list = PolicyIdList()
        assert all(empty_list)

    def test_can_convert_to_list(self):
        """Test that PolicyIdList can be converted to list."""
        policy_list = create_default_policy_id_list()
        py_list = list(policy_list)
        assert len(py_list) == 4
        assert all(isinstance(p, Blake2bHash) for p in py_list)

    def test_can_use_in_filter(self):
        """Test that PolicyIdList can be used with filter()."""
        policy_list = create_default_policy_id_list()
        filtered = list(filter(
            lambda p: p.to_hex().startswith("f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"),
            policy_list
        ))
        assert len(filtered) == 1

    def test_can_use_in_map(self):
        """Test that PolicyIdList can be used with map()."""
        policy_list = create_default_policy_id_list()
        mapped = list(map(lambda p: p.to_hex(), policy_list))
        assert len(mapped) == 4
        assert all(isinstance(h, str) for h in mapped)


class TestPolicyIdListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_can_add_same_policy_id_multiple_times(self):
        """Test that same policy ID can be added multiple times."""
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        for _ in range(10):
            policy_list.add(policy_id)
        assert len(policy_list) == 10
        assert all(p == policy_id for p in policy_list)

    def test_can_handle_large_list(self):
        """Test that large lists can be handled."""
        policy_list = PolicyIdList()
        policy_ids = [POLICY_ID_HEX_1, POLICY_ID_HEX_2, POLICY_ID_HEX_3, POLICY_ID_HEX_4]

        for i in range(100):
            policy_list.add(Blake2bHash.from_hex(policy_ids[i % 4]))

        assert len(policy_list) == 100
        assert policy_list[0].to_hex() == POLICY_ID_HEX_1
        assert policy_list[99].to_hex() == POLICY_ID_HEX_4

    def test_maintains_insertion_order(self):
        """Test that insertion order is maintained."""
        policy_list = PolicyIdList()
        hexes = [POLICY_ID_HEX_1, POLICY_ID_HEX_2, POLICY_ID_HEX_3, POLICY_ID_HEX_4]

        for hex_str in hexes:
            policy_list.add(Blake2bHash.from_hex(hex_str))

        for i, policy_id in enumerate(policy_list):
            assert policy_id.to_hex() == hexes[i]

    def test_equality_comparison_between_policy_ids(self):
        """Test that policy IDs can be compared for equality."""
        policy_id1 = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_id2 = Blake2bHash.from_hex(POLICY_ID_HEX_1)
        policy_id3 = Blake2bHash.from_hex(POLICY_ID_HEX_2)

        assert policy_id1 == policy_id2
        assert policy_id1 != policy_id3

    def test_list_after_cleanup(self):
        """Test that list works after cleanup and recreation."""
        policy_list1 = PolicyIdList()
        policy_list1.add(Blake2bHash.from_hex(POLICY_ID_HEX_1))
        del policy_list1

        policy_list2 = PolicyIdList()
        policy_list2.add(Blake2bHash.from_hex(POLICY_ID_HEX_2))
        assert len(policy_list2) == 1
