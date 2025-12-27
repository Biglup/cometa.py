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
from cometa import DRepType


class TestDRepType:
    """Tests for the DRepType enum."""

    def test_drep_type_values(self):
        """Test that DRepType enum values are correct."""
        assert DRepType.KEY_HASH == 0
        assert DRepType.SCRIPT_HASH == 1
        assert DRepType.ABSTAIN == 2
        assert DRepType.NO_CONFIDENCE == 3

    def test_drep_type_from_int(self):
        """Test creating DRepType from integer values."""
        assert DRepType(0) == DRepType.KEY_HASH
        assert DRepType(1) == DRepType.SCRIPT_HASH
        assert DRepType(2) == DRepType.ABSTAIN
        assert DRepType(3) == DRepType.NO_CONFIDENCE

    def test_drep_type_comparison(self):
        """Test comparison between DRepType values."""
        assert DRepType.KEY_HASH != DRepType.SCRIPT_HASH
        assert DRepType.KEY_HASH != DRepType.ABSTAIN
        assert DRepType.KEY_HASH != DRepType.NO_CONFIDENCE
        assert DRepType.SCRIPT_HASH != DRepType.ABSTAIN
        assert DRepType.SCRIPT_HASH != DRepType.NO_CONFIDENCE
        assert DRepType.ABSTAIN != DRepType.NO_CONFIDENCE
        assert DRepType.KEY_HASH == DRepType.KEY_HASH
        assert DRepType.SCRIPT_HASH == DRepType.SCRIPT_HASH
        assert DRepType.ABSTAIN == DRepType.ABSTAIN
        assert DRepType.NO_CONFIDENCE == DRepType.NO_CONFIDENCE

    def test_drep_type_names(self):
        """Test that DRepType enum has correct names."""
        assert DRepType.KEY_HASH.name == "KEY_HASH"
        assert DRepType.SCRIPT_HASH.name == "SCRIPT_HASH"
        assert DRepType.ABSTAIN.name == "ABSTAIN"
        assert DRepType.NO_CONFIDENCE.name == "NO_CONFIDENCE"

    def test_drep_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            DRepType(4)
        with pytest.raises(ValueError):
            DRepType(-1)
        with pytest.raises(ValueError):
            DRepType(100)

    def test_drep_type_is_int_enum(self):
        """Test that DRepType values can be used as integers."""
        assert isinstance(DRepType.KEY_HASH, int)
        assert isinstance(DRepType.SCRIPT_HASH, int)
        assert isinstance(DRepType.ABSTAIN, int)
        assert isinstance(DRepType.NO_CONFIDENCE, int)
        assert DRepType.KEY_HASH + 1 == 1
        assert DRepType.SCRIPT_HASH - 1 == 0
        assert DRepType.ABSTAIN + 1 == 3
        assert DRepType.NO_CONFIDENCE - 1 == 2

    def test_drep_type_iteration(self):
        """Test iteration over DRepType enum."""
        values = list(DRepType)
        assert len(values) == 4
        assert DRepType.KEY_HASH in values
        assert DRepType.SCRIPT_HASH in values
        assert DRepType.ABSTAIN in values
        assert DRepType.NO_CONFIDENCE in values

    def test_drep_type_membership(self):
        """Test membership testing with DRepType."""
        assert 0 in DRepType.__members__.values()
        assert 1 in DRepType.__members__.values()
        assert 2 in DRepType.__members__.values()
        assert 3 in DRepType.__members__.values()
        assert "KEY_HASH" in DRepType.__members__
        assert "SCRIPT_HASH" in DRepType.__members__
        assert "ABSTAIN" in DRepType.__members__
        assert "NO_CONFIDENCE" in DRepType.__members__

    def test_drep_type_string_representation(self):
        """Test string representation of DRepType values."""
        assert str(DRepType.KEY_HASH) == "DRepType.KEY_HASH"
        assert str(DRepType.SCRIPT_HASH) == "DRepType.SCRIPT_HASH"
        assert str(DRepType.ABSTAIN) == "DRepType.ABSTAIN"
        assert str(DRepType.NO_CONFIDENCE) == "DRepType.NO_CONFIDENCE"

    def test_drep_type_repr(self):
        """Test repr of DRepType values."""
        assert repr(DRepType.KEY_HASH) == "<DRepType.KEY_HASH: 0>"
        assert repr(DRepType.SCRIPT_HASH) == "<DRepType.SCRIPT_HASH: 1>"
        assert repr(DRepType.ABSTAIN) == "<DRepType.ABSTAIN: 2>"
        assert repr(DRepType.NO_CONFIDENCE) == "<DRepType.NO_CONFIDENCE: 3>"

    def test_drep_type_bool_conversion(self):
        """Test boolean conversion of DRepType values."""
        assert bool(DRepType.KEY_HASH) is False
        assert bool(DRepType.SCRIPT_HASH) is True
        assert bool(DRepType.ABSTAIN) is True
        assert bool(DRepType.NO_CONFIDENCE) is True

    def test_drep_type_arithmetic(self):
        """Test arithmetic operations with DRepType values."""
        assert DRepType.KEY_HASH + DRepType.SCRIPT_HASH == 1
        assert DRepType.SCRIPT_HASH * 2 == 2
        assert DRepType.ABSTAIN // 2 == 1
        assert DRepType.NO_CONFIDENCE - DRepType.ABSTAIN == 1

    def test_drep_type_hash(self):
        """Test that DRepType values are hashable."""
        drep_set = {
            DRepType.KEY_HASH,
            DRepType.SCRIPT_HASH,
            DRepType.ABSTAIN,
            DRepType.NO_CONFIDENCE
        }
        assert len(drep_set) == 4
        assert DRepType.KEY_HASH in drep_set
        assert DRepType.SCRIPT_HASH in drep_set
        assert DRepType.ABSTAIN in drep_set
        assert DRepType.NO_CONFIDENCE in drep_set

    def test_drep_type_as_dict_key(self):
        """Test using DRepType as dictionary key."""
        drep_dict = {
            DRepType.KEY_HASH: "key_hash",
            DRepType.SCRIPT_HASH: "script_hash",
            DRepType.ABSTAIN: "abstain",
            DRepType.NO_CONFIDENCE: "no_confidence"
        }
        assert drep_dict[DRepType.KEY_HASH] == "key_hash"
        assert drep_dict[DRepType.SCRIPT_HASH] == "script_hash"
        assert drep_dict[DRepType.ABSTAIN] == "abstain"
        assert drep_dict[DRepType.NO_CONFIDENCE] == "no_confidence"

    def test_drep_type_ordering(self):
        """Test ordering comparison between DRepType values."""
        assert DRepType.KEY_HASH < DRepType.SCRIPT_HASH
        assert DRepType.SCRIPT_HASH < DRepType.ABSTAIN
        assert DRepType.ABSTAIN < DRepType.NO_CONFIDENCE
        assert DRepType.NO_CONFIDENCE > DRepType.ABSTAIN
        assert DRepType.ABSTAIN > DRepType.SCRIPT_HASH
        assert DRepType.SCRIPT_HASH > DRepType.KEY_HASH
        assert DRepType.KEY_HASH <= DRepType.KEY_HASH
        assert DRepType.SCRIPT_HASH <= DRepType.SCRIPT_HASH
        assert DRepType.ABSTAIN >= DRepType.ABSTAIN
        assert DRepType.NO_CONFIDENCE >= DRepType.NO_CONFIDENCE
