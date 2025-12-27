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
    GovernanceActionIdList,
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CardanoError,
)


GOVERNANCE_ACTION_ID_CBOR_1 = "825820000000000000000000000000000000000000000000000000000000000000000001"
GOVERNANCE_ACTION_ID_CBOR_2 = "825820000000000000000000000000000000000000000000000000000000000000000002"
GOVERNANCE_ACTION_ID_CBOR_3 = "825820000000000000000000000000000000000000000000000000000000000000000003"
GOVERNANCE_ACTION_ID_CBOR_4 = "825820000000000000000000000000000000000000000000000000000000000000000004"
GOVERNANCE_ACTION_ID_CBOR_DIFFERENT = "82582011111111111111111111111111111111111111111111111111111111111111111864"


def create_governance_action_id(cbor_hex: str) -> GovernanceActionId:
    """Helper function to create a GovernanceActionId from CBOR hex - adapted from C test."""
    reader = CborReader.from_hex(cbor_hex)
    return GovernanceActionId.from_cbor(reader)


def create_different_governance_action_id() -> GovernanceActionId:
    """Helper function to create a different GovernanceActionId using the new() method."""
    tx_hash = Blake2bHash.from_hex("1111111111111111111111111111111111111111111111111111111111111111")
    return GovernanceActionId.new(tx_hash, 100)


def create_default_list() -> GovernanceActionIdList:
    """Helper function to create a default GovernanceActionIdList with 4 elements - adapted from C test."""
    action_list = GovernanceActionIdList()
    action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
    action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
    action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_3))
    action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_4))
    return action_list


class TestGovernanceActionIdListNew:
    """Tests for GovernanceActionIdList constructor - adapted from C test."""

    def test_can_create_empty_list(self):
        """Test that an empty GovernanceActionIdList can be created - adapted from C test."""
        action_list = GovernanceActionIdList()
        assert action_list is not None
        assert len(action_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        action_list = GovernanceActionIdList()
        assert not action_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        assert action_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        action_list = GovernanceActionIdList()
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        assert "len=2" in repr(action_list)

    def test_context_manager(self):
        """Test that GovernanceActionIdList works as a context manager."""
        with GovernanceActionIdList() as action_list:
            action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
            assert len(action_list) == 1

    def test_raises_error_for_null_pointer(self):
        """Test that passing NULL pointer raises CardanoError - adapted from C test."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            GovernanceActionIdList(ffi.NULL)


class TestGovernanceActionIdListFromList:
    """Tests for GovernanceActionIdList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that GovernanceActionIdList can be created from an empty list."""
        action_list = GovernanceActionIdList.from_list([])
        assert len(action_list) == 0

    def test_can_create_from_single_action_id(self):
        """Test that GovernanceActionIdList can be created from a single action ID."""
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list = GovernanceActionIdList.from_list([action_id])
        assert len(action_list) == 1

    def test_can_create_from_multiple_action_ids(self):
        """Test that GovernanceActionIdList can be created from multiple action IDs."""
        action_id1 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_id2 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2)
        action_id3 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_3)
        action_list = GovernanceActionIdList.from_list([action_id1, action_id2, action_id3])
        assert len(action_list) == 3

    def test_can_create_from_tuple(self):
        """Test that GovernanceActionIdList can be created from a tuple."""
        action_id1 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_id2 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2)
        action_list = GovernanceActionIdList.from_list((action_id1, action_id2))
        assert len(action_list) == 2

    def test_can_create_from_generator(self):
        """Test that GovernanceActionIdList can be created from a generator."""
        action_ids = [
            create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1),
            create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2),
            create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_3)
        ]
        action_list = GovernanceActionIdList.from_list(aid for aid in action_ids)
        assert len(action_list) == 3


class TestGovernanceActionIdListAdd:
    """Tests for GovernanceActionIdList.add() method - adapted from C test."""

    def test_can_add_action_id(self):
        """Test that an action ID can be added to the list."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        assert len(action_list) == 1

    def test_can_add_multiple_action_ids(self):
        """Test that multiple action IDs can be added - adapted from C test."""
        action_list = GovernanceActionIdList()
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_3))
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_4))
        assert len(action_list) == 4

    def test_can_add_duplicate_action_ids(self):
        """Test that duplicate action IDs can be added."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        action_list.add(action_id)
        assert len(action_list) == 2

    def test_add_returns_none(self):
        """Test that add method returns None."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        result = action_list.add(action_id)
        assert result is None


class TestGovernanceActionIdListAppend:
    """Tests for GovernanceActionIdList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.append(action_id)
        assert len(action_list) == 1

    def test_can_append_multiple(self):
        """Test that multiple action IDs can be appended."""
        action_list = GovernanceActionIdList()
        action_list.append(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        action_list.append(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        action_list.append(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_3))
        assert len(action_list) == 3


class TestGovernanceActionIdListGet:
    """Tests for GovernanceActionIdList.get() method - adapted from C test."""

    def test_can_get_action_id_by_index(self):
        """Test that an action ID can be retrieved by index - adapted from C test."""
        action_list = create_default_list()
        action_id = action_list.get(0)
        assert action_id is not None
        assert action_id.index == 1

    def test_can_get_first_action_id(self):
        """Test that the first action ID can be retrieved."""
        action_list = create_default_list()
        action_id = action_list.get(0)
        assert action_id.index == 1

    def test_can_get_last_action_id(self):
        """Test that the last action ID can be retrieved."""
        action_list = create_default_list()
        action_id = action_list.get(3)
        assert action_id.index == 4

    def test_can_get_middle_action_id(self):
        """Test that a middle action ID can be retrieved."""
        action_list = create_default_list()
        action_id = action_list.get(1)
        assert action_id.index == 2

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        action_list = create_default_list()
        with pytest.raises(IndexError):
            action_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError - adapted from C test."""
        action_list = create_default_list()
        with pytest.raises(IndexError):
            action_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError - adapted from C test."""
        action_list = GovernanceActionIdList()
        with pytest.raises(IndexError):
            action_list.get(0)


class TestGovernanceActionIdListGetItem:
    """Tests for GovernanceActionIdList.__getitem__() method (bracket notation)."""

    def test_can_use_bracket_notation(self):
        """Test that bracket notation works for accessing elements."""
        action_list = create_default_list()
        action_id = action_list[0]
        assert action_id.index == 1

    def test_can_use_negative_index(self):
        """Test that negative indices work correctly."""
        action_list = create_default_list()
        last = action_list[-1]
        assert last.index == 4

    def test_negative_index_second_to_last(self):
        """Test that negative index -2 gets second to last element."""
        action_list = create_default_list()
        second_last = action_list[-2]
        assert second_last.index == 3

    def test_raises_index_error_for_negative_out_of_bounds(self):
        """Test that negative out of bounds raises IndexError."""
        action_list = create_default_list()
        with pytest.raises(IndexError):
            _ = action_list[-10]


class TestGovernanceActionIdListLen:
    """Tests for len() function with GovernanceActionIdList."""

    def test_len_returns_zero_for_empty_list(self):
        """Test that len returns 0 for empty list."""
        action_list = GovernanceActionIdList()
        assert len(action_list) == 0

    def test_len_returns_correct_count(self):
        """Test that len returns correct count after adding elements."""
        action_list = create_default_list()
        assert len(action_list) == 4

    def test_len_increases_with_add(self):
        """Test that len increases as elements are added."""
        action_list = GovernanceActionIdList()
        assert len(action_list) == 0
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        assert len(action_list) == 1
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        assert len(action_list) == 2


class TestGovernanceActionIdListIter:
    """Tests for GovernanceActionIdList.__iter__() method."""

    def test_can_iterate_over_list(self):
        """Test that list can be iterated over."""
        action_list = create_default_list()
        count = 0
        for action_id in action_list:
            assert action_id is not None
            count += 1
        assert count == 4

    def test_iteration_yields_correct_indices(self):
        """Test that iteration yields elements in correct order."""
        action_list = create_default_list()
        indices = [action_id.index for action_id in action_list]
        assert indices == [1, 2, 3, 4]

    def test_can_iterate_empty_list(self):
        """Test that iterating empty list works without error."""
        action_list = GovernanceActionIdList()
        count = 0
        for _ in action_list:
            count += 1
        assert count == 0

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        action_list = create_default_list()
        indices = [action_id.index for action_id in action_list]
        assert len(indices) == 4
        assert indices[0] == 1

    def test_can_convert_to_list(self):
        """Test that list can be converted to Python list."""
        action_list = create_default_list()
        python_list = list(action_list)
        assert len(python_list) == 4
        assert all(isinstance(item, GovernanceActionId) for item in python_list)


class TestGovernanceActionIdListReversed:
    """Tests for GovernanceActionIdList.__reversed__() method."""

    def test_can_reverse_iterate(self):
        """Test that list can be iterated in reverse."""
        action_list = create_default_list()
        indices = [action_id.index for action_id in reversed(action_list)]
        assert indices == [4, 3, 2, 1]

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        action_list = GovernanceActionIdList()
        reversed_list = list(reversed(action_list))
        assert len(reversed_list) == 0

    def test_reversed_single_element(self):
        """Test reversing list with single element."""
        action_list = GovernanceActionIdList()
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        reversed_list = list(reversed(action_list))
        assert len(reversed_list) == 1
        assert reversed_list[0].index == 1


class TestGovernanceActionIdListIndex:
    """Tests for GovernanceActionIdList.index() method."""

    def test_can_find_index_of_element(self):
        """Test that index of an element can be found."""
        action_list = create_default_list()
        action_id = action_list[1]
        index = action_list.index(action_id)
        assert index == 1

    def test_finds_first_occurrence(self):
        """Test that index finds the first occurrence of duplicate elements."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        action_list.add(action_id)
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        index = action_list.index(action_id)
        assert index == 0

    def test_raises_value_error_if_not_found(self):
        """Test that ValueError is raised if element is not found."""
        action_list = create_default_list()
        different_action = create_different_governance_action_id()
        with pytest.raises(ValueError):
            action_list.index(different_action)

    def test_index_with_start_parameter(self):
        """Test that index search can start from a specific position."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        action_list.add(action_id)
        action_list.add(action_id)
        index = action_list.index(action_id, start=2)
        assert index == 2

    def test_index_with_stop_parameter(self):
        """Test that index search can stop at a specific position."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        action_list.add(action_id)
        action_list.add(action_id)
        with pytest.raises(ValueError):
            action_list.index(action_id, start=0, stop=1)

    def test_index_empty_list_raises_value_error(self):
        """Test that searching empty list raises ValueError."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        with pytest.raises(ValueError):
            action_list.index(action_id)


class TestGovernanceActionIdListCount:
    """Tests for GovernanceActionIdList.count() method."""

    def test_count_returns_zero_for_missing_element(self):
        """Test that count returns 0 for elements not in list."""
        action_list = create_default_list()
        different_action = create_different_governance_action_id()
        assert action_list.count(different_action) == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        action_list = create_default_list()
        action_id = action_list[0]
        assert action_list.count(action_id) == 1

    def test_count_returns_correct_number_for_duplicates(self):
        """Test that count returns correct number for duplicate elements."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        action_list.add(action_id)
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2))
        action_list.add(action_id)
        assert action_list.count(action_id) == 3

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        assert action_list.count(action_id) == 0


class TestGovernanceActionIdListSequenceProtocol:
    """Tests for Sequence protocol implementation."""

    def test_is_sequence(self):
        """Test that GovernanceActionIdList is a Sequence."""
        from collections.abc import Sequence
        action_list = GovernanceActionIdList()
        assert isinstance(action_list, Sequence)

    def test_supports_in_operator(self):
        """Test that 'in' operator works."""
        action_list = create_default_list()
        action_id = action_list[0]
        assert action_id in action_list

    def test_in_operator_returns_false_for_missing(self):
        """Test that 'in' operator returns False for missing elements."""
        action_list = create_default_list()
        different_action = create_different_governance_action_id()
        assert different_action not in action_list

    def test_not_in_operator(self):
        """Test that 'not in' operator works."""
        action_list = create_default_list()
        different_action = create_different_governance_action_id()
        assert different_action not in action_list


class TestGovernanceActionIdListEquality:
    """Tests for equality comparisons between action IDs in list."""

    def test_same_action_ids_are_equal(self):
        """Test that action IDs with same values are equal."""
        action_id1 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_id2 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        assert action_id1 == action_id2

    def test_different_action_ids_are_not_equal(self):
        """Test that action IDs with different values are not equal."""
        action_id1 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_id2 = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_2)
        assert action_id1 != action_id2

    def test_equality_works_in_list_operations(self):
        """Test that equality works correctly in list operations."""
        action_list = create_default_list()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        found_index = None
        for i, item in enumerate(action_list):
            if item == action_id:
                found_index = i
                break
        assert found_index == 0


class TestGovernanceActionIdListMemoryManagement:
    """Tests for memory management and cleanup."""

    def test_list_cleanup_on_deletion(self):
        """Test that list is properly cleaned up when deleted."""
        action_list = create_default_list()
        assert len(action_list) == 4
        del action_list

    def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up."""
        with GovernanceActionIdList() as action_list:
            action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
            assert len(action_list) == 1

    def test_multiple_references_to_same_action_id(self):
        """Test that same action ID can be added multiple times safely."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        action_list.add(action_id)
        assert len(action_list) == 2


class TestGovernanceActionIdListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_list_operations(self):
        """Test that operations on empty list behave correctly."""
        action_list = GovernanceActionIdList()
        assert len(action_list) == 0
        assert not action_list
        assert list(action_list) == []

    def test_single_element_list(self):
        """Test list operations with single element."""
        action_list = GovernanceActionIdList()
        action_id = create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1)
        action_list.add(action_id)
        assert len(action_list) == 1
        assert action_list[0] == action_id
        assert action_list[-1] == action_id

    def test_large_list(self):
        """Test that large lists work correctly."""
        action_list = GovernanceActionIdList()
        for i in range(100):
            action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        assert len(action_list) == 100

    def test_repr_with_empty_list(self):
        """Test repr with empty list."""
        action_list = GovernanceActionIdList()
        assert "len=0" in repr(action_list)

    def test_bool_conversion_empty(self):
        """Test bool conversion of empty list is False."""
        action_list = GovernanceActionIdList()
        assert bool(action_list) is False

    def test_bool_conversion_non_empty(self):
        """Test bool conversion of non-empty list is True."""
        action_list = GovernanceActionIdList()
        action_list.add(create_governance_action_id(GOVERNANCE_ACTION_ID_CBOR_1))
        assert bool(action_list) is True
