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
from cometa import GovernanceKeyType


class TestGovernanceKeyType:
    """Tests for the GovernanceKeyType enum."""

    def test_governance_key_type_values(self):
        """Test that GovernanceKeyType enum values are correct."""
        assert GovernanceKeyType.CC_HOT == 0
        assert GovernanceKeyType.CC_COLD == 1
        assert GovernanceKeyType.DREP == 2

    def test_governance_key_type_from_int(self):
        """Test creating GovernanceKeyType from integer values."""
        assert GovernanceKeyType(0) == GovernanceKeyType.CC_HOT
        assert GovernanceKeyType(1) == GovernanceKeyType.CC_COLD
        assert GovernanceKeyType(2) == GovernanceKeyType.DREP

    def test_governance_key_type_comparison(self):
        """Test comparison between GovernanceKeyType values."""
        assert GovernanceKeyType.CC_HOT != GovernanceKeyType.CC_COLD
        assert GovernanceKeyType.CC_HOT != GovernanceKeyType.DREP
        assert GovernanceKeyType.CC_COLD != GovernanceKeyType.DREP
        assert GovernanceKeyType.CC_HOT == GovernanceKeyType.CC_HOT
        assert GovernanceKeyType.CC_COLD == GovernanceKeyType.CC_COLD
        assert GovernanceKeyType.DREP == GovernanceKeyType.DREP

    def test_governance_key_type_names(self):
        """Test that GovernanceKeyType enum has correct names."""
        assert GovernanceKeyType.CC_HOT.name == "CC_HOT"
        assert GovernanceKeyType.CC_COLD.name == "CC_COLD"
        assert GovernanceKeyType.DREP.name == "DREP"

    def test_governance_key_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            GovernanceKeyType(3)
        with pytest.raises(ValueError):
            GovernanceKeyType(-1)
        with pytest.raises(ValueError):
            GovernanceKeyType(100)

    def test_governance_key_type_is_int_enum(self):
        """Test that GovernanceKeyType values can be used as integers."""
        assert isinstance(GovernanceKeyType.CC_HOT, int)
        assert isinstance(GovernanceKeyType.CC_COLD, int)
        assert isinstance(GovernanceKeyType.DREP, int)
        assert GovernanceKeyType.CC_HOT + 1 == 1
        assert GovernanceKeyType.CC_COLD - 1 == 0
        assert GovernanceKeyType.DREP + 1 == 3

    def test_governance_key_type_iteration(self):
        """Test iteration over GovernanceKeyType enum."""
        values = list(GovernanceKeyType)
        assert len(values) == 3
        assert GovernanceKeyType.CC_HOT in values
        assert GovernanceKeyType.CC_COLD in values
        assert GovernanceKeyType.DREP in values

    def test_governance_key_type_membership(self):
        """Test membership testing with GovernanceKeyType."""
        assert 0 in GovernanceKeyType.__members__.values()
        assert 1 in GovernanceKeyType.__members__.values()
        assert 2 in GovernanceKeyType.__members__.values()
        assert "CC_HOT" in GovernanceKeyType.__members__
        assert "CC_COLD" in GovernanceKeyType.__members__
        assert "DREP" in GovernanceKeyType.__members__

    def test_governance_key_type_string_representation(self):
        """Test string representation of GovernanceKeyType values."""
        assert str(GovernanceKeyType.CC_HOT) == "GovernanceKeyType.CC_HOT"
        assert str(GovernanceKeyType.CC_COLD) == "GovernanceKeyType.CC_COLD"
        assert str(GovernanceKeyType.DREP) == "GovernanceKeyType.DREP"

    def test_governance_key_type_repr(self):
        """Test repr of GovernanceKeyType values."""
        assert repr(GovernanceKeyType.CC_HOT) == "<GovernanceKeyType.CC_HOT: 0>"
        assert repr(GovernanceKeyType.CC_COLD) == "<GovernanceKeyType.CC_COLD: 1>"
        assert repr(GovernanceKeyType.DREP) == "<GovernanceKeyType.DREP: 2>"

    def test_governance_key_type_bool_conversion(self):
        """Test boolean conversion of GovernanceKeyType values."""
        assert bool(GovernanceKeyType.CC_HOT) is False
        assert bool(GovernanceKeyType.CC_COLD) is True
        assert bool(GovernanceKeyType.DREP) is True

    def test_governance_key_type_arithmetic(self):
        """Test arithmetic operations with GovernanceKeyType values."""
        assert GovernanceKeyType.CC_HOT + GovernanceKeyType.CC_COLD == 1
        assert GovernanceKeyType.CC_COLD * 2 == 2
        assert GovernanceKeyType.DREP // 2 == 1
        assert GovernanceKeyType.DREP - GovernanceKeyType.CC_COLD == 1

    def test_governance_key_type_hash(self):
        """Test that GovernanceKeyType values are hashable."""
        governance_set = {
            GovernanceKeyType.CC_HOT,
            GovernanceKeyType.CC_COLD,
            GovernanceKeyType.DREP
        }
        assert len(governance_set) == 3
        assert GovernanceKeyType.CC_HOT in governance_set
        assert GovernanceKeyType.CC_COLD in governance_set
        assert GovernanceKeyType.DREP in governance_set

    def test_governance_key_type_as_dict_key(self):
        """Test using GovernanceKeyType as dictionary key."""
        governance_dict = {
            GovernanceKeyType.CC_HOT: "cc_hot",
            GovernanceKeyType.CC_COLD: "cc_cold",
            GovernanceKeyType.DREP: "drep"
        }
        assert governance_dict[GovernanceKeyType.CC_HOT] == "cc_hot"
        assert governance_dict[GovernanceKeyType.CC_COLD] == "cc_cold"
        assert governance_dict[GovernanceKeyType.DREP] == "drep"

    def test_governance_key_type_ordering(self):
        """Test ordering comparison between GovernanceKeyType values."""
        assert GovernanceKeyType.CC_HOT < GovernanceKeyType.CC_COLD
        assert GovernanceKeyType.CC_COLD < GovernanceKeyType.DREP
        assert GovernanceKeyType.DREP > GovernanceKeyType.CC_COLD
        assert GovernanceKeyType.CC_COLD > GovernanceKeyType.CC_HOT
        assert GovernanceKeyType.CC_HOT <= GovernanceKeyType.CC_HOT
        assert GovernanceKeyType.CC_COLD <= GovernanceKeyType.CC_COLD
        assert GovernanceKeyType.DREP >= GovernanceKeyType.DREP
        assert GovernanceKeyType.CC_HOT >= GovernanceKeyType.CC_HOT
