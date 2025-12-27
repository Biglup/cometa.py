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
from cometa import VoterType


class TestVoterType:
    """Tests for the VoterType enum."""

    # pylint: disable=no-self-use

    def test_voter_type_values(self):
        """Test that VoterType enum values are correct."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH == 0
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH == 1
        assert VoterType.DREP_KEY_HASH == 2
        assert VoterType.DREP_SCRIPT_HASH == 3
        assert VoterType.STAKE_POOL_KEY_HASH == 4

    def test_voter_type_from_int(self):
        """Test creating VoterType from integer values."""
        assert VoterType(0) == VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH
        assert VoterType(1) == VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType(2) == VoterType.DREP_KEY_HASH
        assert VoterType(3) == VoterType.DREP_SCRIPT_HASH
        assert VoterType(4) == VoterType.STAKE_POOL_KEY_HASH

    def test_voter_type_comparison(self):
        """Test comparison between VoterType values."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH != VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH != VoterType.DREP_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH != VoterType.DREP_SCRIPT_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH != VoterType.STAKE_POOL_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH != VoterType.DREP_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH != VoterType.DREP_SCRIPT_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH != VoterType.STAKE_POOL_KEY_HASH
        assert VoterType.DREP_KEY_HASH != VoterType.DREP_SCRIPT_HASH
        assert VoterType.DREP_KEY_HASH != VoterType.STAKE_POOL_KEY_HASH
        assert VoterType.DREP_SCRIPT_HASH != VoterType.STAKE_POOL_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH == VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH == VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType.DREP_KEY_HASH == VoterType.DREP_KEY_HASH
        assert VoterType.DREP_SCRIPT_HASH == VoterType.DREP_SCRIPT_HASH
        assert VoterType.STAKE_POOL_KEY_HASH == VoterType.STAKE_POOL_KEY_HASH

    def test_voter_type_names(self):
        """Test that VoterType enum has correct names."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH.name == "CONSTITUTIONAL_COMMITTEE_KEY_HASH"
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH.name == "CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH"
        assert VoterType.DREP_KEY_HASH.name == "DREP_KEY_HASH"
        assert VoterType.DREP_SCRIPT_HASH.name == "DREP_SCRIPT_HASH"
        assert VoterType.STAKE_POOL_KEY_HASH.name == "STAKE_POOL_KEY_HASH"

    def test_voter_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            VoterType(5)
        with pytest.raises(ValueError):
            VoterType(-1)
        with pytest.raises(ValueError):
            VoterType(100)

    def test_voter_type_is_int_enum(self):
        """Test that VoterType values can be used as integers."""
        assert isinstance(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, int)
        assert isinstance(VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH, int)
        assert isinstance(VoterType.DREP_KEY_HASH, int)
        assert isinstance(VoterType.DREP_SCRIPT_HASH, int)
        assert isinstance(VoterType.STAKE_POOL_KEY_HASH, int)
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH + 1 == 1
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH - 1 == 0
        assert VoterType.DREP_KEY_HASH + 1 == 3
        assert VoterType.DREP_SCRIPT_HASH - 1 == 2
        assert VoterType.STAKE_POOL_KEY_HASH - 1 == 3

    def test_voter_type_iteration(self):
        """Test iteration over VoterType enum."""
        values = list(VoterType)
        assert len(values) == 5
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH in values
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH in values
        assert VoterType.DREP_KEY_HASH in values
        assert VoterType.DREP_SCRIPT_HASH in values
        assert VoterType.STAKE_POOL_KEY_HASH in values

    def test_voter_type_membership(self):
        """Test membership testing with VoterType."""
        assert 0 in VoterType.__members__.values()
        assert 1 in VoterType.__members__.values()
        assert 2 in VoterType.__members__.values()
        assert 3 in VoterType.__members__.values()
        assert 4 in VoterType.__members__.values()
        assert "CONSTITUTIONAL_COMMITTEE_KEY_HASH" in VoterType.__members__
        assert "CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH" in VoterType.__members__
        assert "DREP_KEY_HASH" in VoterType.__members__
        assert "DREP_SCRIPT_HASH" in VoterType.__members__
        assert "STAKE_POOL_KEY_HASH" in VoterType.__members__

    def test_voter_type_string_representation(self):
        """Test string representation of VoterType values."""
        assert str(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH) == "VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH"
        assert str(VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH) == "VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH"
        assert str(VoterType.DREP_KEY_HASH) == "VoterType.DREP_KEY_HASH"
        assert str(VoterType.DREP_SCRIPT_HASH) == "VoterType.DREP_SCRIPT_HASH"
        assert str(VoterType.STAKE_POOL_KEY_HASH) == "VoterType.STAKE_POOL_KEY_HASH"

    def test_voter_type_repr(self):
        """Test repr of VoterType values."""
        assert repr(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH) == "<VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH: 0>"
        assert repr(VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH) == "<VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH: 1>"
        assert repr(VoterType.DREP_KEY_HASH) == "<VoterType.DREP_KEY_HASH: 2>"
        assert repr(VoterType.DREP_SCRIPT_HASH) == "<VoterType.DREP_SCRIPT_HASH: 3>"
        assert repr(VoterType.STAKE_POOL_KEY_HASH) == "<VoterType.STAKE_POOL_KEY_HASH: 4>"

    def test_voter_type_bool_conversion(self):
        """Test boolean conversion of VoterType values."""
        assert bool(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH) is False
        assert bool(VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH) is True
        assert bool(VoterType.DREP_KEY_HASH) is True
        assert bool(VoterType.DREP_SCRIPT_HASH) is True
        assert bool(VoterType.STAKE_POOL_KEY_HASH) is True

    def test_voter_type_arithmetic(self):
        """Test arithmetic operations with VoterType values."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH + VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH == 1
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH * 2 == 2
        assert VoterType.DREP_KEY_HASH // 2 == 1
        assert VoterType.DREP_SCRIPT_HASH - VoterType.DREP_KEY_HASH == 1
        assert VoterType.STAKE_POOL_KEY_HASH // 2 == 2
        assert VoterType.STAKE_POOL_KEY_HASH - 1 == 3

    def test_voter_type_hash(self):
        """Test that VoterType values are hashable."""
        voter_set = {
            VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH,
            VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH,
            VoterType.DREP_KEY_HASH,
            VoterType.DREP_SCRIPT_HASH,
            VoterType.STAKE_POOL_KEY_HASH
        }
        assert len(voter_set) == 5
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH in voter_set
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH in voter_set
        assert VoterType.DREP_KEY_HASH in voter_set
        assert VoterType.DREP_SCRIPT_HASH in voter_set
        assert VoterType.STAKE_POOL_KEY_HASH in voter_set

    def test_voter_type_as_dict_key(self):
        """Test using VoterType as dictionary key."""
        voter_dict = {
            VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH: "cc_key_hash",
            VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH: "cc_script_hash",
            VoterType.DREP_KEY_HASH: "drep_key_hash",
            VoterType.DREP_SCRIPT_HASH: "drep_script_hash",
            VoterType.STAKE_POOL_KEY_HASH: "stake_pool_key_hash"
        }
        assert voter_dict[VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH] == "cc_key_hash"
        assert voter_dict[VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH] == "cc_script_hash"
        assert voter_dict[VoterType.DREP_KEY_HASH] == "drep_key_hash"
        assert voter_dict[VoterType.DREP_SCRIPT_HASH] == "drep_script_hash"
        assert voter_dict[VoterType.STAKE_POOL_KEY_HASH] == "stake_pool_key_hash"

    def test_voter_type_ordering(self):
        """Test ordering comparison between VoterType values."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH < VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH < VoterType.DREP_KEY_HASH
        assert VoterType.DREP_KEY_HASH < VoterType.DREP_SCRIPT_HASH
        assert VoterType.DREP_SCRIPT_HASH < VoterType.STAKE_POOL_KEY_HASH
        assert VoterType.STAKE_POOL_KEY_HASH > VoterType.DREP_SCRIPT_HASH
        assert VoterType.DREP_SCRIPT_HASH > VoterType.DREP_KEY_HASH
        assert VoterType.DREP_KEY_HASH > VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH > VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH <= VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH <= VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert VoterType.DREP_KEY_HASH >= VoterType.DREP_KEY_HASH
        assert VoterType.DREP_SCRIPT_HASH >= VoterType.DREP_SCRIPT_HASH
        assert VoterType.STAKE_POOL_KEY_HASH >= VoterType.STAKE_POOL_KEY_HASH

    def test_voter_type_to_string_constitutional_committee_key_hash(self):
        """Test converting CONSTITUTIONAL_COMMITTEE_KEY_HASH to string (from C test: canConvertConstitutionalCommitteeKeyHash)."""
        result = VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH.to_string()
        assert result == "Voter Type: Constitutional Committee Key Hash"

    def test_voter_type_to_string_constitutional_committee_script_hash(self):
        """Test converting CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH to string (from C test: canConvertConstitutionalCommitteeScriptHash)."""
        result = VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH.to_string()
        assert result == "Voter Type: Constitutional Committee Script Hash"

    def test_voter_type_to_string_drep_key_hash(self):
        """Test converting DREP_KEY_HASH to string (from C test: canConvertDRepKeyHash)."""
        result = VoterType.DREP_KEY_HASH.to_string()
        assert result == "Voter Type: DRep Key Hash"

    def test_voter_type_to_string_drep_script_hash(self):
        """Test converting DREP_SCRIPT_HASH to string (from C test: canConvertDRepScriptHash)."""
        result = VoterType.DREP_SCRIPT_HASH.to_string()
        assert result == "Voter Type: DRep Script Hash"

    def test_voter_type_to_string_stake_pool_key_hash(self):
        """Test converting STAKE_POOL_KEY_HASH to string (from C test: canConvertStakePoolKeyHash)."""
        result = VoterType.STAKE_POOL_KEY_HASH.to_string()
        assert result == "Voter Type: Stake Pool Key Hash"

    def test_voter_type_to_string_unknown(self):
        """Test converting unknown value to string (from C test: canConvertUnknown)."""
        with pytest.raises(ValueError):
            VoterType(100)

    def test_voter_type_to_string_returns_string(self):
        """Test that to_string() returns a string for all valid values."""
        for voter_type in VoterType:
            result = voter_type.to_string()
            assert isinstance(result, str)
            assert len(result) > 0
            assert result.startswith("Voter Type:")

    def test_voter_type_unique_values(self):
        """Test that all VoterType values are unique."""
        values = [voter_type.value for voter_type in VoterType]
        assert len(values) == len(set(values))

    def test_voter_type_type_checking(self):
        """Test type checking of VoterType instances."""
        from enum import IntEnum
        assert isinstance(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, VoterType)
        assert isinstance(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, IntEnum)
        assert isinstance(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, int)
