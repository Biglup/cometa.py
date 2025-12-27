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
    VotingProcedureList,
    VotingProcedure,
    CborReader,
    CardanoError,
)


VOTING_PROCEDURE_CBOR_1 = "8200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
VOTING_PROCEDURE_CBOR_2 = "8201827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
VOTING_PROCEDURE_CBOR_3 = "8202827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
VOTING_PROCEDURE_CBOR_DIFFERENT = "8200f6"


def create_voting_procedure(cbor_hex: str) -> VotingProcedure:
    """Helper function to create a VotingProcedure from CBOR hex - adapted from C test."""
    reader = CborReader.from_hex(cbor_hex)
    return VotingProcedure.from_cbor(reader)


def create_default_list() -> VotingProcedureList:
    """Helper function to create a default VotingProcedureList with 3 elements - adapted from C test."""
    procedure_list = VotingProcedureList()
    procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
    procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_2))
    procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_3))
    return procedure_list


class TestVotingProcedureListNew:
    """Tests for VotingProcedureList constructor - adapted from C test."""

    def test_can_create_empty_list(self):
        """Test that an empty VotingProcedureList can be created - adapted from C test."""
        procedure_list = VotingProcedureList()
        assert procedure_list is not None
        assert len(procedure_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        procedure_list = VotingProcedureList()
        assert not procedure_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.add(procedure)
        assert procedure_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        procedure_list = VotingProcedureList()
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_2))
        assert "len=2" in repr(procedure_list)

    def test_context_manager(self):
        """Test that VotingProcedureList works as a context manager."""
        with VotingProcedureList() as procedure_list:
            procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
            assert len(procedure_list) == 1

    def test_raises_error_for_null_pointer(self):
        """Test that passing NULL pointer raises CardanoError - adapted from C test."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            VotingProcedureList(ffi.NULL)


class TestVotingProcedureListFromList:
    """Tests for VotingProcedureList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that VotingProcedureList can be created from an empty list."""
        procedure_list = VotingProcedureList.from_list([])
        assert len(procedure_list) == 0

    def test_can_create_from_single_procedure(self):
        """Test that VotingProcedureList can be created from a single procedure."""
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list = VotingProcedureList.from_list([procedure])
        assert len(procedure_list) == 1

    def test_can_create_from_multiple_procedures(self):
        """Test that VotingProcedureList can be created from multiple procedures."""
        procedure1 = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure2 = create_voting_procedure(VOTING_PROCEDURE_CBOR_2)
        procedure3 = create_voting_procedure(VOTING_PROCEDURE_CBOR_3)
        procedure_list = VotingProcedureList.from_list([procedure1, procedure2, procedure3])
        assert len(procedure_list) == 3

    def test_can_create_from_tuple(self):
        """Test that VotingProcedureList can be created from a tuple."""
        procedure1 = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure2 = create_voting_procedure(VOTING_PROCEDURE_CBOR_2)
        procedure_list = VotingProcedureList.from_list((procedure1, procedure2))
        assert len(procedure_list) == 2

    def test_can_create_from_generator(self):
        """Test that VotingProcedureList can be created from a generator."""
        procedures = [
            create_voting_procedure(VOTING_PROCEDURE_CBOR_1),
            create_voting_procedure(VOTING_PROCEDURE_CBOR_2),
            create_voting_procedure(VOTING_PROCEDURE_CBOR_3)
        ]
        procedure_list = VotingProcedureList.from_list(proc for proc in procedures)
        assert len(procedure_list) == 3


class TestVotingProcedureListAdd:
    """Tests for VotingProcedureList.add() method - adapted from C test."""

    def test_can_add_procedure(self):
        """Test that a procedure can be added to the list."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.add(procedure)
        assert len(procedure_list) == 1

    def test_can_add_multiple_procedures(self):
        """Test that multiple procedures can be added - adapted from C test."""
        procedure_list = VotingProcedureList()
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_2))
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_3))
        assert len(procedure_list) == 3

    def test_can_add_duplicate_procedures(self):
        """Test that duplicate procedures can be added."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.add(procedure)
        procedure_list.add(procedure)
        assert len(procedure_list) == 2

    def test_add_returns_none(self):
        """Test that add method returns None."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        result = procedure_list.add(procedure)
        assert result is None


class TestVotingProcedureListAppend:
    """Tests for VotingProcedureList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.append(procedure)
        assert len(procedure_list) == 1

    def test_can_append_multiple(self):
        """Test that multiple procedures can be appended."""
        procedure_list = VotingProcedureList()
        procedure_list.append(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        procedure_list.append(create_voting_procedure(VOTING_PROCEDURE_CBOR_2))
        procedure_list.append(create_voting_procedure(VOTING_PROCEDURE_CBOR_3))
        assert len(procedure_list) == 3


class TestVotingProcedureListGet:
    """Tests for VotingProcedureList.get() method - adapted from C test."""

    def test_can_get_procedure_by_index(self):
        """Test that a procedure can be retrieved by index - adapted from C test."""
        procedure_list = create_default_list()
        procedure = procedure_list.get(0)
        assert procedure is not None
        assert procedure.vote.value == 0

    def test_can_get_first_procedure(self):
        """Test that the first procedure can be retrieved."""
        procedure_list = create_default_list()
        procedure = procedure_list.get(0)
        assert procedure.vote.value == 0

    def test_can_get_last_procedure(self):
        """Test that the last procedure can be retrieved."""
        procedure_list = create_default_list()
        procedure = procedure_list.get(2)
        assert procedure.vote.value == 2

    def test_can_get_middle_procedure(self):
        """Test that a middle procedure can be retrieved."""
        procedure_list = create_default_list()
        procedure = procedure_list.get(1)
        assert procedure.vote.value == 1

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        procedure_list = create_default_list()
        with pytest.raises(IndexError):
            procedure_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError - adapted from C test."""
        procedure_list = create_default_list()
        with pytest.raises(IndexError):
            procedure_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError - adapted from C test."""
        procedure_list = VotingProcedureList()
        with pytest.raises(IndexError):
            procedure_list.get(0)


class TestVotingProcedureListGetItem:
    """Tests for VotingProcedureList.__getitem__() method (bracket notation)."""

    def test_can_use_bracket_notation(self):
        """Test that bracket notation works for accessing elements."""
        procedure_list = create_default_list()
        procedure = procedure_list[0]
        assert procedure.vote.value == 0

    def test_can_use_negative_index(self):
        """Test that negative indices work correctly."""
        procedure_list = create_default_list()
        last = procedure_list[-1]
        assert last.vote.value == 2

    def test_negative_index_second_to_last(self):
        """Test that negative index -2 gets second to last element."""
        procedure_list = create_default_list()
        second_last = procedure_list[-2]
        assert second_last.vote.value == 1

    def test_raises_index_error_for_negative_out_of_bounds(self):
        """Test that negative out of bounds raises IndexError."""
        procedure_list = create_default_list()
        with pytest.raises(IndexError):
            _ = procedure_list[-10]


class TestVotingProcedureListLen:
    """Tests for len() function with VotingProcedureList."""

    def test_len_returns_zero_for_empty_list(self):
        """Test that len returns 0 for empty list."""
        procedure_list = VotingProcedureList()
        assert len(procedure_list) == 0

    def test_len_returns_correct_count(self):
        """Test that len returns correct count after adding elements."""
        procedure_list = create_default_list()
        assert len(procedure_list) == 3

    def test_len_increases_with_add(self):
        """Test that len increases as elements are added."""
        procedure_list = VotingProcedureList()
        assert len(procedure_list) == 0
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        assert len(procedure_list) == 1
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_2))
        assert len(procedure_list) == 2


class TestVotingProcedureListIter:
    """Tests for VotingProcedureList.__iter__() method."""

    def test_can_iterate_over_list(self):
        """Test that list can be iterated over."""
        procedure_list = create_default_list()
        count = 0
        for procedure in procedure_list:
            assert procedure is not None
            count += 1
        assert count == 3

    def test_iteration_yields_correct_votes(self):
        """Test that iteration yields elements in correct order."""
        procedure_list = create_default_list()
        votes = [procedure.vote.value for procedure in procedure_list]
        assert votes == [0, 1, 2]

    def test_can_iterate_empty_list(self):
        """Test that iterating empty list works without error."""
        procedure_list = VotingProcedureList()
        count = 0
        for _ in procedure_list:
            count += 1
        assert count == 0

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        procedure_list = create_default_list()
        votes = [procedure.vote.value for procedure in procedure_list]
        assert len(votes) == 3
        assert votes[0] == 0

    def test_can_convert_to_list(self):
        """Test that list can be converted to Python list."""
        procedure_list = create_default_list()
        python_list = list(procedure_list)
        assert len(python_list) == 3
        assert all(isinstance(item, VotingProcedure) for item in python_list)


class TestVotingProcedureListReversed:
    """Tests for VotingProcedureList.__reversed__() method."""

    def test_can_reverse_iterate(self):
        """Test that list can be iterated in reverse."""
        procedure_list = create_default_list()
        votes = [procedure.vote.value for procedure in reversed(procedure_list)]
        assert votes == [2, 1, 0]

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        procedure_list = VotingProcedureList()
        reversed_list = list(reversed(procedure_list))
        assert len(reversed_list) == 0

    def test_reversed_single_element(self):
        """Test reversing list with single element."""
        procedure_list = VotingProcedureList()
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        reversed_list = list(reversed(procedure_list))
        assert len(reversed_list) == 1
        assert reversed_list[0].vote.value == 0


class TestVotingProcedureListIndex:
    """Tests for VotingProcedureList.index() method."""

    def test_can_find_index_by_vote_value(self):
        """Test that we can search for procedures by comparing vote values."""
        procedure_list = create_default_list()
        for i, procedure in enumerate(procedure_list):
            if procedure.vote.value == 1:
                assert i == 1
                break

    def test_index_empty_list_raises_value_error(self):
        """Test that searching empty list raises ValueError."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        with pytest.raises(ValueError):
            procedure_list.index(procedure)


class TestVotingProcedureListCount:
    """Tests for VotingProcedureList.count() method."""

    def test_count_by_vote_value(self):
        """Test that we can count procedures by vote value."""
        procedure_list = create_default_list()
        no_count = sum(1 for p in procedure_list if p.vote.value == 0)
        yes_count = sum(1 for p in procedure_list if p.vote.value == 1)
        abstain_count = sum(1 for p in procedure_list if p.vote.value == 2)
        assert no_count == 1
        assert yes_count == 1
        assert abstain_count == 1

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        assert procedure_list.count(procedure) == 0


class TestVotingProcedureListSequenceProtocol:
    """Tests for Sequence protocol implementation."""

    def test_is_sequence(self):
        """Test that VotingProcedureList is a Sequence."""
        from collections.abc import Sequence
        procedure_list = VotingProcedureList()
        assert isinstance(procedure_list, Sequence)

    def test_can_check_existence_by_vote_value(self):
        """Test that we can check existence by vote value."""
        procedure_list = create_default_list()
        has_no_vote = any(p.vote.value == 0 for p in procedure_list)
        has_yes_vote = any(p.vote.value == 1 for p in procedure_list)
        has_abstain_vote = any(p.vote.value == 2 for p in procedure_list)
        assert has_no_vote
        assert has_yes_vote
        assert has_abstain_vote


class TestVotingProcedureListMemoryManagement:
    """Tests for memory management and cleanup."""

    def test_list_cleanup_on_deletion(self):
        """Test that list is properly cleaned up when deleted."""
        procedure_list = create_default_list()
        assert len(procedure_list) == 3
        del procedure_list

    def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up."""
        with VotingProcedureList() as procedure_list:
            procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
            assert len(procedure_list) == 1

    def test_multiple_references_to_same_procedure(self):
        """Test that same procedure can be added multiple times safely."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.add(procedure)
        procedure_list.add(procedure)
        assert len(procedure_list) == 2


class TestVotingProcedureListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_list_operations(self):
        """Test that operations on empty list behave correctly."""
        procedure_list = VotingProcedureList()
        assert len(procedure_list) == 0
        assert not procedure_list
        assert list(procedure_list) == []

    def test_single_element_list(self):
        """Test list operations with single element."""
        procedure_list = VotingProcedureList()
        procedure = create_voting_procedure(VOTING_PROCEDURE_CBOR_1)
        procedure_list.add(procedure)
        assert len(procedure_list) == 1
        assert procedure_list[0].vote.value == 0
        assert procedure_list[-1].vote.value == 0

    def test_large_list(self):
        """Test that large lists work correctly."""
        procedure_list = VotingProcedureList()
        for i in range(100):
            procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        assert len(procedure_list) == 100

    def test_repr_with_empty_list(self):
        """Test repr with empty list."""
        procedure_list = VotingProcedureList()
        assert "len=0" in repr(procedure_list)

    def test_bool_conversion_empty(self):
        """Test bool conversion of empty list is False."""
        procedure_list = VotingProcedureList()
        assert bool(procedure_list) is False

    def test_bool_conversion_non_empty(self):
        """Test bool conversion of non-empty list is True."""
        procedure_list = VotingProcedureList()
        procedure_list.add(create_voting_procedure(VOTING_PROCEDURE_CBOR_1))
        assert bool(procedure_list) is True
