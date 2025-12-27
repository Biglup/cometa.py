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
from cometa import Vote


class TestVote:
    """Tests for Vote enum."""

    def test_values(self):
        """Test vote enum values match expected constants."""
        assert Vote.NO == 0
        assert Vote.YES == 1
        assert Vote.ABSTAIN == 2

    def test_is_int_enum(self):
        """Test that Vote is an IntEnum and can be used as int."""
        assert isinstance(Vote.YES, int)
        assert isinstance(Vote.NO, int)
        assert isinstance(Vote.ABSTAIN, int)

    def test_name_attribute(self):
        """Test vote name attribute access."""
        assert Vote.YES.name == "YES"
        assert Vote.NO.name == "NO"
        assert Vote.ABSTAIN.name == "ABSTAIN"

    def test_value_attribute(self):
        """Test vote value attribute access."""
        assert Vote.YES.value == 1
        assert Vote.NO.value == 0
        assert Vote.ABSTAIN.value == 2

    def test_to_string_no(self):
        """Test to_string() for NO vote - adapted from C test."""
        vote = Vote.NO
        result = vote.to_string()
        assert result == "Vote: No"

    def test_to_string_yes(self):
        """Test to_string() for YES vote - adapted from C test."""
        vote = Vote.YES
        result = vote.to_string()
        assert result == "Vote: Yes"

    def test_to_string_abstain(self):
        """Test to_string() for ABSTAIN vote - adapted from C test."""
        vote = Vote.ABSTAIN
        result = vote.to_string()
        assert result == "Vote: Abstain"

    def test_to_string_unknown(self):
        """Test to_string() for unknown vote value - adapted from C test.

        Note: We cannot directly test this in Python as IntEnum prevents creating
        invalid enum values. The C library returns 'Vote: Unknown' for invalid values.
        This test documents the expected behavior.
        """
        from cometa._ffi import lib, ffi
        result = ffi.string(lib.cardano_vote_to_string(100)).decode('utf-8')
        assert result == "Vote: Unknown"

    def test_equality(self):
        """Test vote equality comparison."""
        assert Vote.YES == Vote.YES
        assert Vote.NO == Vote.NO
        assert Vote.ABSTAIN == Vote.ABSTAIN

    def test_inequality(self):
        """Test vote inequality comparison."""
        assert Vote.YES != Vote.NO
        assert Vote.YES != Vote.ABSTAIN
        assert Vote.NO != Vote.ABSTAIN

    def test_equality_with_int(self):
        """Test that Vote enum can be compared with integers."""
        assert Vote.NO == 0
        assert Vote.YES == 1
        assert Vote.ABSTAIN == 2

    def test_hash(self):
        """Test that Vote enum values are hashable."""
        vote_set = {Vote.YES, Vote.NO, Vote.ABSTAIN}
        assert len(vote_set) == 3
        assert Vote.YES in vote_set
        assert Vote.NO in vote_set
        assert Vote.ABSTAIN in vote_set

    def test_use_in_dict(self):
        """Test that Vote enum can be used as dictionary keys."""
        vote_dict = {
            Vote.YES: "approved",
            Vote.NO: "rejected",
            Vote.ABSTAIN: "abstained"
        }
        assert vote_dict[Vote.YES] == "approved"
        assert vote_dict[Vote.NO] == "rejected"
        assert vote_dict[Vote.ABSTAIN] == "abstained"

    def test_str_representation(self):
        """Test string representation of Vote enum."""
        assert str(Vote.YES) == "Vote.YES"
        assert str(Vote.NO) == "Vote.NO"
        assert str(Vote.ABSTAIN) == "Vote.ABSTAIN"

    def test_repr_representation(self):
        """Test repr representation of Vote enum."""
        repr_yes = repr(Vote.YES)
        assert "Vote" in repr_yes or "1" in repr_yes

    def test_iteration(self):
        """Test iterating over all Vote values."""
        votes = list(Vote)
        assert len(votes) == 3
        assert Vote.NO in votes
        assert Vote.YES in votes
        assert Vote.ABSTAIN in votes

    def test_membership(self):
        """Test membership testing for Vote enum."""
        assert Vote.YES in Vote
        assert Vote.NO in Vote
        assert Vote.ABSTAIN in Vote

    def test_from_value(self):
        """Test creating Vote from integer value."""
        vote_yes = Vote(1)
        vote_no = Vote(0)
        vote_abstain = Vote(2)

        assert vote_yes == Vote.YES
        assert vote_no == Vote.NO
        assert vote_abstain == Vote.ABSTAIN

    def test_from_invalid_value(self):
        """Test creating Vote from invalid value raises ValueError."""
        with pytest.raises(ValueError):
            Vote(999)

    def test_comparison_with_other_types(self):
        """Test comparison with non-int types."""
        assert Vote.YES != "YES"
        assert Vote.YES is not None
        assert Vote.YES != []

    def test_bool_conversion(self):
        """Test boolean conversion of Vote enum values."""
        assert bool(Vote.YES) is True
        assert bool(Vote.NO) is False
        assert bool(Vote.ABSTAIN) is True

    def test_arithmetic_operations(self):
        """Test that Vote can be used in arithmetic as int."""
        assert Vote.YES + 1 == 2
        assert Vote.ABSTAIN - 1 == 1
        assert Vote.NO + Vote.YES == 1

    def test_to_string_consistency(self):
        """Test that to_string() returns consistent results."""
        vote = Vote.YES
        result1 = vote.to_string()
        result2 = vote.to_string()
        assert result1 == result2

    def test_all_votes_have_string_representation(self):
        """Test that all vote values have a valid string representation."""
        for vote in Vote:
            result = vote.to_string()
            assert isinstance(result, str)
            assert len(result) > 0
