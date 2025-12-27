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
    VoterList,
    Voter,
    CborReader,
    CardanoError,
)


VOTER_CBOR_1 = "8200581c00000000000000000000000000000000000000000000000000000000"
VOTER_CBOR_2 = "8201581c00000000000000000000000000000000000000000000000000000000"
VOTER_CBOR_3 = "8202581c00000000000000000000000000000000000000000000000000000000"
VOTER_CBOR_4 = "8203581c00000000000000000000000000000000000000000000000000000000"
VOTER_CBOR_DIFFERENT = "8204581c11111111111111111111111111111111111111111111111111111111"


def create_voter(cbor_hex: str) -> Voter:
    """Helper function to create a Voter from CBOR hex - adapted from C test."""
    reader = CborReader.from_hex(cbor_hex)
    return Voter.from_cbor(reader)


def create_default_list() -> VoterList:
    """Helper function to create a default VoterList with 4 elements - adapted from C test."""
    voter_list = VoterList()
    voter_list.add(create_voter(VOTER_CBOR_1))
    voter_list.add(create_voter(VOTER_CBOR_2))
    voter_list.add(create_voter(VOTER_CBOR_3))
    voter_list.add(create_voter(VOTER_CBOR_4))
    return voter_list


class TestVoterListNew:
    """Tests for VoterList constructor - adapted from C test."""

    def test_can_create_empty_list(self):
        """Test that an empty VoterList can be created - adapted from C test."""
        voter_list = VoterList()
        assert voter_list is not None
        assert len(voter_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        voter_list = VoterList()
        assert not voter_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        assert voter_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        voter_list = VoterList()
        voter_list.add(create_voter(VOTER_CBOR_1))
        voter_list.add(create_voter(VOTER_CBOR_2))
        assert "len=2" in repr(voter_list)

    def test_context_manager(self):
        """Test that VoterList works as a context manager."""
        with VoterList() as voter_list:
            voter_list.add(create_voter(VOTER_CBOR_1))
            assert len(voter_list) == 1

    def test_raises_error_for_null_pointer(self):
        """Test that passing NULL pointer raises CardanoError - adapted from C test."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            VoterList(ffi.NULL)


class TestVoterListFromList:
    """Tests for VoterList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that VoterList can be created from an empty list."""
        voter_list = VoterList.from_list([])
        assert len(voter_list) == 0

    def test_can_create_from_single_voter(self):
        """Test that VoterList can be created from a single voter."""
        voter = create_voter(VOTER_CBOR_1)
        voter_list = VoterList.from_list([voter])
        assert len(voter_list) == 1

    def test_can_create_from_multiple_voters(self):
        """Test that VoterList can be created from multiple voters."""
        voter1 = create_voter(VOTER_CBOR_1)
        voter2 = create_voter(VOTER_CBOR_2)
        voter3 = create_voter(VOTER_CBOR_3)
        voter_list = VoterList.from_list([voter1, voter2, voter3])
        assert len(voter_list) == 3

    def test_can_create_from_tuple(self):
        """Test that VoterList can be created from a tuple."""
        voter1 = create_voter(VOTER_CBOR_1)
        voter2 = create_voter(VOTER_CBOR_2)
        voter_list = VoterList.from_list((voter1, voter2))
        assert len(voter_list) == 2

    def test_can_create_from_generator(self):
        """Test that VoterList can be created from a generator."""
        voters = [
            create_voter(VOTER_CBOR_1),
            create_voter(VOTER_CBOR_2),
            create_voter(VOTER_CBOR_3)
        ]
        voter_list = VoterList.from_list(voter for voter in voters)
        assert len(voter_list) == 3


class TestVoterListAdd:
    """Tests for VoterList.add() method - adapted from C test."""

    def test_can_add_voter(self):
        """Test that a voter can be added to the list."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        assert len(voter_list) == 1

    def test_can_add_multiple_voters(self):
        """Test that multiple voters can be added - adapted from C test."""
        voter_list = VoterList()
        voter_list.add(create_voter(VOTER_CBOR_1))
        voter_list.add(create_voter(VOTER_CBOR_2))
        voter_list.add(create_voter(VOTER_CBOR_3))
        voter_list.add(create_voter(VOTER_CBOR_4))
        assert len(voter_list) == 4

    def test_can_add_duplicate_voters(self):
        """Test that duplicate voters can be added."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        voter_list.add(voter)
        assert len(voter_list) == 2

    def test_add_returns_none(self):
        """Test that add method returns None."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        result = voter_list.add(voter)
        assert result is None


class TestVoterListAppend:
    """Tests for VoterList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.append(voter)
        assert len(voter_list) == 1

    def test_can_append_multiple(self):
        """Test that multiple voters can be appended."""
        voter_list = VoterList()
        voter_list.append(create_voter(VOTER_CBOR_1))
        voter_list.append(create_voter(VOTER_CBOR_2))
        voter_list.append(create_voter(VOTER_CBOR_3))
        assert len(voter_list) == 3


class TestVoterListGet:
    """Tests for VoterList.get() method - adapted from C test."""

    def test_can_get_voter_by_index(self):
        """Test that a voter can be retrieved by index - adapted from C test."""
        voter_list = create_default_list()
        voter = voter_list.get(0)
        assert voter is not None
        assert voter.voter_type.value == 0

    def test_can_get_first_voter(self):
        """Test that the first voter can be retrieved."""
        voter_list = create_default_list()
        voter = voter_list.get(0)
        assert voter.voter_type.value == 0

    def test_can_get_last_voter(self):
        """Test that the last voter can be retrieved."""
        voter_list = create_default_list()
        voter = voter_list.get(3)
        assert voter.voter_type.value == 3

    def test_can_get_middle_voter(self):
        """Test that a middle voter can be retrieved."""
        voter_list = create_default_list()
        voter = voter_list.get(1)
        assert voter.voter_type.value == 1

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        voter_list = create_default_list()
        with pytest.raises(IndexError):
            voter_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError - adapted from C test."""
        voter_list = create_default_list()
        with pytest.raises(IndexError):
            voter_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError - adapted from C test."""
        voter_list = VoterList()
        with pytest.raises(IndexError):
            voter_list.get(0)


class TestVoterListGetItem:
    """Tests for VoterList.__getitem__() method (bracket notation)."""

    def test_can_use_bracket_notation(self):
        """Test that bracket notation works for accessing elements."""
        voter_list = create_default_list()
        voter = voter_list[0]
        assert voter.voter_type.value == 0

    def test_can_use_negative_index(self):
        """Test that negative indices work correctly."""
        voter_list = create_default_list()
        last = voter_list[-1]
        assert last.voter_type.value == 3

    def test_negative_index_second_to_last(self):
        """Test that negative index -2 gets second to last element."""
        voter_list = create_default_list()
        second_last = voter_list[-2]
        assert second_last.voter_type.value == 2

    def test_raises_index_error_for_negative_out_of_bounds(self):
        """Test that negative out of bounds raises IndexError."""
        voter_list = create_default_list()
        with pytest.raises(IndexError):
            _ = voter_list[-10]


class TestVoterListLen:
    """Tests for len() function with VoterList."""

    def test_len_returns_zero_for_empty_list(self):
        """Test that len returns 0 for empty list."""
        voter_list = VoterList()
        assert len(voter_list) == 0

    def test_len_returns_correct_count(self):
        """Test that len returns correct count after adding elements."""
        voter_list = create_default_list()
        assert len(voter_list) == 4

    def test_len_increases_with_add(self):
        """Test that len increases as elements are added."""
        voter_list = VoterList()
        assert len(voter_list) == 0
        voter_list.add(create_voter(VOTER_CBOR_1))
        assert len(voter_list) == 1
        voter_list.add(create_voter(VOTER_CBOR_2))
        assert len(voter_list) == 2


class TestVoterListIter:
    """Tests for VoterList.__iter__() method."""

    def test_can_iterate_over_list(self):
        """Test that list can be iterated over."""
        voter_list = create_default_list()
        count = 0
        for voter in voter_list:
            assert voter is not None
            count += 1
        assert count == 4

    def test_iteration_yields_correct_types(self):
        """Test that iteration yields elements in correct order."""
        voter_list = create_default_list()
        types = [voter.voter_type.value for voter in voter_list]
        assert types == [0, 1, 2, 3]

    def test_can_iterate_empty_list(self):
        """Test that iterating empty list works without error."""
        voter_list = VoterList()
        count = 0
        for _ in voter_list:
            count += 1
        assert count == 0

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        voter_list = create_default_list()
        types = [voter.voter_type.value for voter in voter_list]
        assert len(types) == 4
        assert types[0] == 0

    def test_can_convert_to_list(self):
        """Test that list can be converted to Python list."""
        voter_list = create_default_list()
        python_list = list(voter_list)
        assert len(python_list) == 4
        assert all(isinstance(item, Voter) for item in python_list)


class TestVoterListReversed:
    """Tests for VoterList.__reversed__() method."""

    def test_can_reverse_iterate(self):
        """Test that list can be iterated in reverse."""
        voter_list = create_default_list()
        types = [voter.voter_type.value for voter in reversed(voter_list)]
        assert types == [3, 2, 1, 0]

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        voter_list = VoterList()
        reversed_list = list(reversed(voter_list))
        assert len(reversed_list) == 0

    def test_reversed_single_element(self):
        """Test reversing list with single element."""
        voter_list = VoterList()
        voter_list.add(create_voter(VOTER_CBOR_1))
        reversed_list = list(reversed(voter_list))
        assert len(reversed_list) == 1
        assert reversed_list[0].voter_type.value == 0


class TestVoterListIndex:
    """Tests for VoterList.index() method."""

    def test_can_find_index_of_element(self):
        """Test that index of an element can be found."""
        voter_list = create_default_list()
        voter = voter_list[1]
        index = voter_list.index(voter)
        assert index == 1

    def test_finds_first_occurrence(self):
        """Test that index finds the first occurrence of duplicate elements."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        voter_list.add(voter)
        voter_list.add(create_voter(VOTER_CBOR_2))
        index = voter_list.index(voter)
        assert index == 0

    def test_raises_value_error_if_not_found(self):
        """Test that ValueError is raised if element is not found."""
        voter_list = create_default_list()
        different_voter = create_voter(VOTER_CBOR_DIFFERENT)
        with pytest.raises(ValueError):
            voter_list.index(different_voter)

    def test_index_with_start_parameter(self):
        """Test that index search can start from a specific position."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(create_voter(VOTER_CBOR_2))
        voter_list.add(voter)
        voter_list.add(voter)
        index = voter_list.index(voter, start=2)
        assert index == 2

    def test_index_with_stop_parameter(self):
        """Test that index search can stop at a specific position."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(create_voter(VOTER_CBOR_2))
        voter_list.add(voter)
        voter_list.add(voter)
        with pytest.raises(ValueError):
            voter_list.index(voter, start=0, stop=1)

    def test_index_empty_list_raises_value_error(self):
        """Test that searching empty list raises ValueError."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        with pytest.raises(ValueError):
            voter_list.index(voter)


class TestVoterListCount:
    """Tests for VoterList.count() method."""

    def test_count_returns_zero_for_missing_element(self):
        """Test that count returns 0 for elements not in list."""
        voter_list = create_default_list()
        different_voter = create_voter(VOTER_CBOR_DIFFERENT)
        assert voter_list.count(different_voter) == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        voter_list = create_default_list()
        voter = voter_list[0]
        assert voter_list.count(voter) == 1

    def test_count_returns_correct_number_for_duplicates(self):
        """Test that count returns correct number for duplicate elements."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        voter_list.add(voter)
        voter_list.add(create_voter(VOTER_CBOR_2))
        voter_list.add(voter)
        assert voter_list.count(voter) == 3

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        assert voter_list.count(voter) == 0


class TestVoterListSequenceProtocol:
    """Tests for Sequence protocol implementation."""

    def test_is_sequence(self):
        """Test that VoterList is a Sequence."""
        from collections.abc import Sequence
        voter_list = VoterList()
        assert isinstance(voter_list, Sequence)

    def test_supports_in_operator(self):
        """Test that 'in' operator works."""
        voter_list = create_default_list()
        voter = voter_list[0]
        assert voter in voter_list

    def test_in_operator_returns_false_for_missing(self):
        """Test that 'in' operator returns False for missing elements."""
        voter_list = create_default_list()
        different_voter = create_voter(VOTER_CBOR_DIFFERENT)
        assert different_voter not in voter_list

    def test_not_in_operator(self):
        """Test that 'not in' operator works."""
        voter_list = create_default_list()
        different_voter = create_voter(VOTER_CBOR_DIFFERENT)
        assert different_voter not in voter_list


class TestVoterListEquality:
    """Tests for equality comparisons between voters in list."""

    def test_same_voters_are_equal(self):
        """Test that voters with same values are equal."""
        voter1 = create_voter(VOTER_CBOR_1)
        voter2 = create_voter(VOTER_CBOR_1)
        assert voter1 == voter2

    def test_different_voters_are_not_equal(self):
        """Test that voters with different values are not equal."""
        voter1 = create_voter(VOTER_CBOR_1)
        voter2 = create_voter(VOTER_CBOR_2)
        assert voter1 != voter2

    def test_equality_works_in_list_operations(self):
        """Test that equality works correctly in list operations."""
        voter_list = create_default_list()
        voter = create_voter(VOTER_CBOR_1)
        found_index = None
        for i, item in enumerate(voter_list):
            if item == voter:
                found_index = i
                break
        assert found_index == 0


class TestVoterListMemoryManagement:
    """Tests for memory management and cleanup."""

    def test_list_cleanup_on_deletion(self):
        """Test that list is properly cleaned up when deleted."""
        voter_list = create_default_list()
        assert len(voter_list) == 4
        del voter_list

    def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up."""
        with VoterList() as voter_list:
            voter_list.add(create_voter(VOTER_CBOR_1))
            assert len(voter_list) == 1

    def test_multiple_references_to_same_voter(self):
        """Test that same voter can be added multiple times safely."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        voter_list.add(voter)
        assert len(voter_list) == 2


class TestVoterListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_list_operations(self):
        """Test that operations on empty list behave correctly."""
        voter_list = VoterList()
        assert len(voter_list) == 0
        assert not voter_list
        assert list(voter_list) == []

    def test_single_element_list(self):
        """Test list operations with single element."""
        voter_list = VoterList()
        voter = create_voter(VOTER_CBOR_1)
        voter_list.add(voter)
        assert len(voter_list) == 1
        assert voter_list[0] == voter
        assert voter_list[-1] == voter

    def test_large_list(self):
        """Test that large lists work correctly."""
        voter_list = VoterList()
        for i in range(100):
            voter_list.add(create_voter(VOTER_CBOR_1))
        assert len(voter_list) == 100

    def test_repr_with_empty_list(self):
        """Test repr with empty list."""
        voter_list = VoterList()
        assert "len=0" in repr(voter_list)

    def test_bool_conversion_empty(self):
        """Test bool conversion of empty list is False."""
        voter_list = VoterList()
        assert bool(voter_list) is False

    def test_bool_conversion_non_empty(self):
        """Test bool conversion of non-empty list is True."""
        voter_list = VoterList()
        voter_list.add(create_voter(VOTER_CBOR_1))
        assert bool(voter_list) is True
