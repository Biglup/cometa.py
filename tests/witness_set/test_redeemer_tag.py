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
from cometa.witness_set import RedeemerTag


class TestRedeemerTag:
    """Tests for the RedeemerTag enum."""

    def test_redeemer_tag_values(self):
        """Test that RedeemerTag enum values are correct."""
        assert RedeemerTag.SPEND == 0
        assert RedeemerTag.MINT == 1
        assert RedeemerTag.CERTIFYING == 2
        assert RedeemerTag.REWARD == 3
        assert RedeemerTag.VOTING == 4
        assert RedeemerTag.PROPOSING == 5

    def test_redeemer_tag_from_int(self):
        """Test creating RedeemerTag from integer values."""
        assert RedeemerTag(0) == RedeemerTag.SPEND
        assert RedeemerTag(1) == RedeemerTag.MINT
        assert RedeemerTag(2) == RedeemerTag.CERTIFYING
        assert RedeemerTag(3) == RedeemerTag.REWARD
        assert RedeemerTag(4) == RedeemerTag.VOTING
        assert RedeemerTag(5) == RedeemerTag.PROPOSING

    def test_redeemer_tag_comparison(self):
        """Test comparison between RedeemerTag values."""
        assert RedeemerTag.SPEND != RedeemerTag.MINT
        assert RedeemerTag.SPEND == RedeemerTag.SPEND
        assert RedeemerTag.MINT == RedeemerTag.MINT
        assert RedeemerTag.CERTIFYING == RedeemerTag.CERTIFYING
        assert RedeemerTag.REWARD == RedeemerTag.REWARD
        assert RedeemerTag.VOTING == RedeemerTag.VOTING
        assert RedeemerTag.PROPOSING == RedeemerTag.PROPOSING

    def test_redeemer_tag_names(self):
        """Test that RedeemerTag enum has correct names."""
        assert RedeemerTag.SPEND.name == "SPEND"
        assert RedeemerTag.MINT.name == "MINT"
        assert RedeemerTag.CERTIFYING.name == "CERTIFYING"
        assert RedeemerTag.REWARD.name == "REWARD"
        assert RedeemerTag.VOTING.name == "VOTING"
        assert RedeemerTag.PROPOSING.name == "PROPOSING"

    def test_redeemer_tag_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            RedeemerTag(6)
        with pytest.raises(ValueError):
            RedeemerTag(-1)
        with pytest.raises(ValueError):
            RedeemerTag(100)
        with pytest.raises(ValueError):
            RedeemerTag(999)

    def test_redeemer_tag_is_int_enum(self):
        """Test that RedeemerTag values can be used as integers."""
        assert isinstance(RedeemerTag.SPEND, int)
        assert isinstance(RedeemerTag.MINT, int)
        assert isinstance(RedeemerTag.CERTIFYING, int)
        assert isinstance(RedeemerTag.REWARD, int)
        assert isinstance(RedeemerTag.VOTING, int)
        assert isinstance(RedeemerTag.PROPOSING, int)
        assert RedeemerTag.SPEND + 1 == 1
        assert RedeemerTag.MINT - 1 == 0
        assert RedeemerTag.PROPOSING - 1 == 4

    def test_redeemer_tag_iteration(self):
        """Test iteration over RedeemerTag enum."""
        values = list(RedeemerTag)
        assert len(values) == 6
        assert RedeemerTag.SPEND in values
        assert RedeemerTag.MINT in values
        assert RedeemerTag.CERTIFYING in values
        assert RedeemerTag.REWARD in values
        assert RedeemerTag.VOTING in values
        assert RedeemerTag.PROPOSING in values

    def test_redeemer_tag_membership(self):
        """Test membership testing with RedeemerTag."""
        assert 0 in RedeemerTag.__members__.values()
        assert 1 in RedeemerTag.__members__.values()
        assert 2 in RedeemerTag.__members__.values()
        assert 3 in RedeemerTag.__members__.values()
        assert 4 in RedeemerTag.__members__.values()
        assert 5 in RedeemerTag.__members__.values()
        assert "SPEND" in RedeemerTag.__members__
        assert "MINT" in RedeemerTag.__members__
        assert "CERTIFYING" in RedeemerTag.__members__
        assert "REWARD" in RedeemerTag.__members__
        assert "VOTING" in RedeemerTag.__members__
        assert "PROPOSING" in RedeemerTag.__members__

    def test_redeemer_tag_string_representation(self):
        """Test string representation of RedeemerTag values."""
        assert str(RedeemerTag.SPEND) == "RedeemerTag.SPEND"
        assert str(RedeemerTag.MINT) == "RedeemerTag.MINT"
        assert str(RedeemerTag.CERTIFYING) == "RedeemerTag.CERTIFYING"
        assert str(RedeemerTag.REWARD) == "RedeemerTag.REWARD"
        assert str(RedeemerTag.VOTING) == "RedeemerTag.VOTING"
        assert str(RedeemerTag.PROPOSING) == "RedeemerTag.PROPOSING"

    def test_redeemer_tag_repr(self):
        """Test repr of RedeemerTag values."""
        assert repr(RedeemerTag.SPEND) == "<RedeemerTag.SPEND: 0>"
        assert repr(RedeemerTag.MINT) == "<RedeemerTag.MINT: 1>"
        assert repr(RedeemerTag.CERTIFYING) == "<RedeemerTag.CERTIFYING: 2>"
        assert repr(RedeemerTag.REWARD) == "<RedeemerTag.REWARD: 3>"
        assert repr(RedeemerTag.VOTING) == "<RedeemerTag.VOTING: 4>"
        assert repr(RedeemerTag.PROPOSING) == "<RedeemerTag.PROPOSING: 5>"

    def test_redeemer_tag_bool_conversion(self):
        """Test boolean conversion of RedeemerTag values."""
        assert bool(RedeemerTag.SPEND) is False
        assert bool(RedeemerTag.MINT) is True
        assert bool(RedeemerTag.CERTIFYING) is True
        assert bool(RedeemerTag.REWARD) is True
        assert bool(RedeemerTag.VOTING) is True
        assert bool(RedeemerTag.PROPOSING) is True

    def test_redeemer_tag_arithmetic(self):
        """Test arithmetic operations with RedeemerTag values."""
        assert RedeemerTag.SPEND + RedeemerTag.MINT == 1
        assert RedeemerTag.MINT + RedeemerTag.CERTIFYING == 3
        assert RedeemerTag.PROPOSING - RedeemerTag.VOTING == 1
        assert RedeemerTag.MINT * 2 == 2
        assert RedeemerTag.REWARD // 1 == 3

    def test_redeemer_tag_hash(self):
        """Test that RedeemerTag values are hashable."""
        tag_set = {
            RedeemerTag.SPEND,
            RedeemerTag.MINT,
            RedeemerTag.CERTIFYING,
            RedeemerTag.REWARD,
            RedeemerTag.VOTING,
            RedeemerTag.PROPOSING
        }
        assert len(tag_set) == 6
        assert RedeemerTag.SPEND in tag_set
        assert RedeemerTag.MINT in tag_set
        assert RedeemerTag.CERTIFYING in tag_set
        assert RedeemerTag.REWARD in tag_set
        assert RedeemerTag.VOTING in tag_set
        assert RedeemerTag.PROPOSING in tag_set

    def test_redeemer_tag_as_dict_key(self):
        """Test using RedeemerTag as dictionary key."""
        tag_dict = {
            RedeemerTag.SPEND: "spend",
            RedeemerTag.MINT: "mint",
            RedeemerTag.CERTIFYING: "certifying",
            RedeemerTag.REWARD: "reward",
            RedeemerTag.VOTING: "voting",
            RedeemerTag.PROPOSING: "proposing"
        }
        assert tag_dict[RedeemerTag.SPEND] == "spend"
        assert tag_dict[RedeemerTag.MINT] == "mint"
        assert tag_dict[RedeemerTag.CERTIFYING] == "certifying"
        assert tag_dict[RedeemerTag.REWARD] == "reward"
        assert tag_dict[RedeemerTag.VOTING] == "voting"
        assert tag_dict[RedeemerTag.PROPOSING] == "proposing"

    def test_redeemer_tag_ordering(self):
        """Test ordering comparison between RedeemerTag values."""
        assert RedeemerTag.SPEND < RedeemerTag.MINT
        assert RedeemerTag.MINT < RedeemerTag.CERTIFYING
        assert RedeemerTag.CERTIFYING < RedeemerTag.REWARD
        assert RedeemerTag.REWARD < RedeemerTag.VOTING
        assert RedeemerTag.VOTING < RedeemerTag.PROPOSING
        assert RedeemerTag.PROPOSING > RedeemerTag.SPEND
        assert RedeemerTag.SPEND <= RedeemerTag.SPEND
        assert RedeemerTag.PROPOSING >= RedeemerTag.PROPOSING

    def test_redeemer_tag_all_members_unique(self):
        """Test that all RedeemerTag members have unique values."""
        values = [tag.value for tag in RedeemerTag]
        assert len(values) == len(set(values))

    def test_redeemer_tag_sequential_values(self):
        """Test that RedeemerTag values are sequential starting from 0."""
        values = sorted([tag.value for tag in RedeemerTag])
        assert values == list(range(6))

    def test_redeemer_tag_type_checking(self):
        """Test type checking for RedeemerTag values."""
        from enum import IntEnum
        assert isinstance(RedeemerTag.SPEND, IntEnum)
        assert isinstance(RedeemerTag.MINT, IntEnum)
        assert issubclass(RedeemerTag, IntEnum)

    def test_redeemer_tag_invalid_type(self):
        """Test that invalid types raise ValueError or TypeError."""
        with pytest.raises(ValueError):
            RedeemerTag("SPEND")
        with pytest.raises((ValueError, TypeError)):
            RedeemerTag(1.5)
        with pytest.raises((ValueError, TypeError)):
            RedeemerTag(None)

    def test_redeemer_tag_identity(self):
        """Test identity checks for RedeemerTag values."""
        spend1 = RedeemerTag.SPEND
        spend2 = RedeemerTag(0)
        assert spend1 is spend2
        assert spend1 is RedeemerTag.SPEND

    def test_redeemer_tag_contains_all_expected_members(self):
        """Test that RedeemerTag contains all expected members."""
        expected_members = {"SPEND", "MINT", "CERTIFYING", "REWARD", "VOTING", "PROPOSING"}
        actual_members = set(RedeemerTag.__members__.keys())
        assert expected_members == actual_members

    def test_redeemer_tag_boundary_values(self):
        """Test RedeemerTag with boundary values."""
        assert RedeemerTag(0) == RedeemerTag.SPEND
        assert RedeemerTag(5) == RedeemerTag.PROPOSING
        with pytest.raises(ValueError):
            RedeemerTag(-1)
        with pytest.raises(ValueError):
            RedeemerTag(6)
