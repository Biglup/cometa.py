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
from cometa import GovernanceActionType


class TestGovernanceActionType:
    """Tests for the GovernanceActionType enum."""

    # pylint: disable=no-self-use

    def test_governance_action_type_values(self):
        """Test that GovernanceActionType enum values are correct."""
        assert GovernanceActionType.PARAMETER_CHANGE == 0
        assert GovernanceActionType.HARD_FORK_INITIATION == 1
        assert GovernanceActionType.TREASURY_WITHDRAWALS == 2
        assert GovernanceActionType.NO_CONFIDENCE == 3
        assert GovernanceActionType.UPDATE_COMMITTEE == 4
        assert GovernanceActionType.NEW_CONSTITUTION == 5
        assert GovernanceActionType.INFO == 6

    def test_governance_action_type_from_int(self):
        """Test creating GovernanceActionType from integer values."""
        assert GovernanceActionType(0) == GovernanceActionType.PARAMETER_CHANGE
        assert GovernanceActionType(1) == GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType(2) == GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType(3) == GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType(4) == GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType(5) == GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType(6) == GovernanceActionType.INFO

    def test_governance_action_type_comparison(self):
        """Test comparison between GovernanceActionType values."""
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType.PARAMETER_CHANGE != GovernanceActionType.INFO
        assert GovernanceActionType.PARAMETER_CHANGE == GovernanceActionType.PARAMETER_CHANGE
        assert GovernanceActionType.HARD_FORK_INITIATION == GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType.TREASURY_WITHDRAWALS == GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType.NO_CONFIDENCE == GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType.UPDATE_COMMITTEE == GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType.NEW_CONSTITUTION == GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType.INFO == GovernanceActionType.INFO

    def test_governance_action_type_names(self):
        """Test that GovernanceActionType enum has correct names."""
        assert GovernanceActionType.PARAMETER_CHANGE.name == "PARAMETER_CHANGE"
        assert GovernanceActionType.HARD_FORK_INITIATION.name == "HARD_FORK_INITIATION"
        assert GovernanceActionType.TREASURY_WITHDRAWALS.name == "TREASURY_WITHDRAWALS"
        assert GovernanceActionType.NO_CONFIDENCE.name == "NO_CONFIDENCE"
        assert GovernanceActionType.UPDATE_COMMITTEE.name == "UPDATE_COMMITTEE"
        assert GovernanceActionType.NEW_CONSTITUTION.name == "NEW_CONSTITUTION"
        assert GovernanceActionType.INFO.name == "INFO"

    def test_governance_action_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            GovernanceActionType(7)
        with pytest.raises(ValueError):
            GovernanceActionType(-1)
        with pytest.raises(ValueError):
            GovernanceActionType(100)

    def test_governance_action_type_is_int_enum(self):
        """Test that GovernanceActionType values can be used as integers."""
        assert isinstance(GovernanceActionType.PARAMETER_CHANGE, int)
        assert isinstance(GovernanceActionType.HARD_FORK_INITIATION, int)
        assert isinstance(GovernanceActionType.TREASURY_WITHDRAWALS, int)
        assert isinstance(GovernanceActionType.NO_CONFIDENCE, int)
        assert isinstance(GovernanceActionType.UPDATE_COMMITTEE, int)
        assert isinstance(GovernanceActionType.NEW_CONSTITUTION, int)
        assert isinstance(GovernanceActionType.INFO, int)
        assert GovernanceActionType.PARAMETER_CHANGE + 1 == 1
        assert GovernanceActionType.HARD_FORK_INITIATION - 1 == 0
        assert GovernanceActionType.TREASURY_WITHDRAWALS + 1 == 3
        assert GovernanceActionType.NO_CONFIDENCE - 1 == 2
        assert GovernanceActionType.UPDATE_COMMITTEE + 1 == 5
        assert GovernanceActionType.NEW_CONSTITUTION - 1 == 4
        assert GovernanceActionType.INFO - 1 == 5

    def test_governance_action_type_iteration(self):
        """Test iteration over GovernanceActionType enum."""
        values = list(GovernanceActionType)
        assert len(values) == 7
        assert GovernanceActionType.PARAMETER_CHANGE in values
        assert GovernanceActionType.HARD_FORK_INITIATION in values
        assert GovernanceActionType.TREASURY_WITHDRAWALS in values
        assert GovernanceActionType.NO_CONFIDENCE in values
        assert GovernanceActionType.UPDATE_COMMITTEE in values
        assert GovernanceActionType.NEW_CONSTITUTION in values
        assert GovernanceActionType.INFO in values

    def test_governance_action_type_membership(self):
        """Test membership testing with GovernanceActionType."""
        assert 0 in GovernanceActionType.__members__.values()
        assert 1 in GovernanceActionType.__members__.values()
        assert 2 in GovernanceActionType.__members__.values()
        assert 3 in GovernanceActionType.__members__.values()
        assert 4 in GovernanceActionType.__members__.values()
        assert 5 in GovernanceActionType.__members__.values()
        assert 6 in GovernanceActionType.__members__.values()
        assert "PARAMETER_CHANGE" in GovernanceActionType.__members__
        assert "HARD_FORK_INITIATION" in GovernanceActionType.__members__
        assert "TREASURY_WITHDRAWALS" in GovernanceActionType.__members__
        assert "NO_CONFIDENCE" in GovernanceActionType.__members__
        assert "UPDATE_COMMITTEE" in GovernanceActionType.__members__
        assert "NEW_CONSTITUTION" in GovernanceActionType.__members__
        assert "INFO" in GovernanceActionType.__members__

    def test_governance_action_type_string_representation(self):
        """Test string representation of GovernanceActionType values."""
        assert str(GovernanceActionType.PARAMETER_CHANGE) == "GovernanceActionType.PARAMETER_CHANGE"
        assert str(GovernanceActionType.HARD_FORK_INITIATION) == "GovernanceActionType.HARD_FORK_INITIATION"
        assert str(GovernanceActionType.TREASURY_WITHDRAWALS) == "GovernanceActionType.TREASURY_WITHDRAWALS"
        assert str(GovernanceActionType.NO_CONFIDENCE) == "GovernanceActionType.NO_CONFIDENCE"
        assert str(GovernanceActionType.UPDATE_COMMITTEE) == "GovernanceActionType.UPDATE_COMMITTEE"
        assert str(GovernanceActionType.NEW_CONSTITUTION) == "GovernanceActionType.NEW_CONSTITUTION"
        assert str(GovernanceActionType.INFO) == "GovernanceActionType.INFO"

    def test_governance_action_type_repr(self):
        """Test repr of GovernanceActionType values."""
        assert repr(GovernanceActionType.PARAMETER_CHANGE) == "<GovernanceActionType.PARAMETER_CHANGE: 0>"
        assert repr(GovernanceActionType.HARD_FORK_INITIATION) == "<GovernanceActionType.HARD_FORK_INITIATION: 1>"
        assert repr(GovernanceActionType.TREASURY_WITHDRAWALS) == "<GovernanceActionType.TREASURY_WITHDRAWALS: 2>"
        assert repr(GovernanceActionType.NO_CONFIDENCE) == "<GovernanceActionType.NO_CONFIDENCE: 3>"
        assert repr(GovernanceActionType.UPDATE_COMMITTEE) == "<GovernanceActionType.UPDATE_COMMITTEE: 4>"
        assert repr(GovernanceActionType.NEW_CONSTITUTION) == "<GovernanceActionType.NEW_CONSTITUTION: 5>"
        assert repr(GovernanceActionType.INFO) == "<GovernanceActionType.INFO: 6>"

    def test_governance_action_type_bool_conversion(self):
        """Test boolean conversion of GovernanceActionType values."""
        assert bool(GovernanceActionType.PARAMETER_CHANGE) is False
        assert bool(GovernanceActionType.HARD_FORK_INITIATION) is True
        assert bool(GovernanceActionType.TREASURY_WITHDRAWALS) is True
        assert bool(GovernanceActionType.NO_CONFIDENCE) is True
        assert bool(GovernanceActionType.UPDATE_COMMITTEE) is True
        assert bool(GovernanceActionType.NEW_CONSTITUTION) is True
        assert bool(GovernanceActionType.INFO) is True

    def test_governance_action_type_arithmetic(self):
        """Test arithmetic operations with GovernanceActionType values."""
        assert GovernanceActionType.PARAMETER_CHANGE + GovernanceActionType.HARD_FORK_INITIATION == 1
        assert GovernanceActionType.HARD_FORK_INITIATION * 2 == 2
        assert GovernanceActionType.TREASURY_WITHDRAWALS // 2 == 1
        assert GovernanceActionType.NO_CONFIDENCE - GovernanceActionType.TREASURY_WITHDRAWALS == 1
        assert GovernanceActionType.UPDATE_COMMITTEE // 2 == 2
        assert GovernanceActionType.NEW_CONSTITUTION - 1 == 4
        assert GovernanceActionType.INFO - GovernanceActionType.NEW_CONSTITUTION == 1

    def test_governance_action_type_hash(self):
        """Test that GovernanceActionType values are hashable."""
        action_set = {
            GovernanceActionType.PARAMETER_CHANGE,
            GovernanceActionType.HARD_FORK_INITIATION,
            GovernanceActionType.TREASURY_WITHDRAWALS,
            GovernanceActionType.NO_CONFIDENCE,
            GovernanceActionType.UPDATE_COMMITTEE,
            GovernanceActionType.NEW_CONSTITUTION,
            GovernanceActionType.INFO
        }
        assert len(action_set) == 7
        assert GovernanceActionType.PARAMETER_CHANGE in action_set
        assert GovernanceActionType.HARD_FORK_INITIATION in action_set
        assert GovernanceActionType.TREASURY_WITHDRAWALS in action_set
        assert GovernanceActionType.NO_CONFIDENCE in action_set
        assert GovernanceActionType.UPDATE_COMMITTEE in action_set
        assert GovernanceActionType.NEW_CONSTITUTION in action_set
        assert GovernanceActionType.INFO in action_set

    def test_governance_action_type_as_dict_key(self):
        """Test using GovernanceActionType as dictionary key."""
        action_dict = {
            GovernanceActionType.PARAMETER_CHANGE: "parameter_change",
            GovernanceActionType.HARD_FORK_INITIATION: "hard_fork_initiation",
            GovernanceActionType.TREASURY_WITHDRAWALS: "treasury_withdrawals",
            GovernanceActionType.NO_CONFIDENCE: "no_confidence",
            GovernanceActionType.UPDATE_COMMITTEE: "update_committee",
            GovernanceActionType.NEW_CONSTITUTION: "new_constitution",
            GovernanceActionType.INFO: "info"
        }
        assert action_dict[GovernanceActionType.PARAMETER_CHANGE] == "parameter_change"
        assert action_dict[GovernanceActionType.HARD_FORK_INITIATION] == "hard_fork_initiation"
        assert action_dict[GovernanceActionType.TREASURY_WITHDRAWALS] == "treasury_withdrawals"
        assert action_dict[GovernanceActionType.NO_CONFIDENCE] == "no_confidence"
        assert action_dict[GovernanceActionType.UPDATE_COMMITTEE] == "update_committee"
        assert action_dict[GovernanceActionType.NEW_CONSTITUTION] == "new_constitution"
        assert action_dict[GovernanceActionType.INFO] == "info"

    def test_governance_action_type_ordering(self):
        """Test ordering comparison between GovernanceActionType values."""
        assert GovernanceActionType.PARAMETER_CHANGE < GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType.HARD_FORK_INITIATION < GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType.TREASURY_WITHDRAWALS < GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType.NO_CONFIDENCE < GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType.UPDATE_COMMITTEE < GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType.NEW_CONSTITUTION < GovernanceActionType.INFO
        assert GovernanceActionType.INFO > GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType.NEW_CONSTITUTION > GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType.UPDATE_COMMITTEE > GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType.NO_CONFIDENCE > GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType.TREASURY_WITHDRAWALS > GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType.HARD_FORK_INITIATION > GovernanceActionType.PARAMETER_CHANGE
        assert GovernanceActionType.PARAMETER_CHANGE <= GovernanceActionType.PARAMETER_CHANGE
        assert GovernanceActionType.HARD_FORK_INITIATION <= GovernanceActionType.HARD_FORK_INITIATION
        assert GovernanceActionType.TREASURY_WITHDRAWALS >= GovernanceActionType.TREASURY_WITHDRAWALS
        assert GovernanceActionType.NO_CONFIDENCE >= GovernanceActionType.NO_CONFIDENCE
        assert GovernanceActionType.UPDATE_COMMITTEE >= GovernanceActionType.UPDATE_COMMITTEE
        assert GovernanceActionType.NEW_CONSTITUTION >= GovernanceActionType.NEW_CONSTITUTION
        assert GovernanceActionType.INFO >= GovernanceActionType.INFO

    def test_governance_action_type_to_string_parameter_change(self):
        """Test converting PARAMETER_CHANGE to string (from C test: canConvertParameterChange)."""
        result = GovernanceActionType.PARAMETER_CHANGE.to_string()
        assert result == "Governance Action Type: Parameter Change"

    def test_governance_action_type_to_string_hard_fork_initiation(self):
        """Test converting HARD_FORK_INITIATION to string (from C test: canConvertHardForkInitiation)."""
        result = GovernanceActionType.HARD_FORK_INITIATION.to_string()
        assert result == "Governance Action Type: Hard Fork Initiation"

    def test_governance_action_type_to_string_treasury_withdrawals(self):
        """Test converting TREASURY_WITHDRAWALS to string (from C test: canConvertTreasuryWithdrawals)."""
        result = GovernanceActionType.TREASURY_WITHDRAWALS.to_string()
        assert result == "Governance Action Type: Treasury Withdrawals"

    def test_governance_action_type_to_string_no_confidence(self):
        """Test converting NO_CONFIDENCE to string (from C test: canConvertNoConfidence)."""
        result = GovernanceActionType.NO_CONFIDENCE.to_string()
        assert result == "Governance Action Type: No Confidence"

    def test_governance_action_type_to_string_update_committee(self):
        """Test converting UPDATE_COMMITTEE to string (from C test: canConvertUpdateCommittee)."""
        result = GovernanceActionType.UPDATE_COMMITTEE.to_string()
        assert result == "Governance Action Type: Update Committee"

    def test_governance_action_type_to_string_new_constitution(self):
        """Test converting NEW_CONSTITUTION to string (from C test: canConvertNewConstitution)."""
        result = GovernanceActionType.NEW_CONSTITUTION.to_string()
        assert result == "Governance Action Type: New Constitution"

    def test_governance_action_type_to_string_info(self):
        """Test converting INFO to string (from C test: canConvertInfo)."""
        result = GovernanceActionType.INFO.to_string()
        assert result == "Governance Action Type: Info"

    def test_governance_action_type_to_string_unknown(self):
        """Test converting unknown value to string (from C test: canConvertUnknown)."""
        with pytest.raises(ValueError):
            GovernanceActionType(100)

    def test_governance_action_type_to_string_returns_string(self):
        """Test that to_string() returns a string for all valid values."""
        for action_type in GovernanceActionType:
            result = action_type.to_string()
            assert isinstance(result, str)
            assert len(result) > 0
            assert result.startswith("Governance Action Type:")

    def test_governance_action_type_unique_values(self):
        """Test that all GovernanceActionType values are unique."""
        values = [action_type.value for action_type in GovernanceActionType]
        assert len(values) == len(set(values))

    def test_governance_action_type_type_checking(self):
        """Test type checking of GovernanceActionType instances."""
        from enum import IntEnum
        assert isinstance(GovernanceActionType.PARAMETER_CHANGE, GovernanceActionType)
        assert isinstance(GovernanceActionType.PARAMETER_CHANGE, IntEnum)
        assert isinstance(GovernanceActionType.PARAMETER_CHANGE, int)
