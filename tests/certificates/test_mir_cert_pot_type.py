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
from cometa import MirCertPotType


class TestMirCertPotType:
    """Tests for the MirCertPotType enum."""

    def test_mir_cert_pot_type_values(self):
        """Test that MirCertPotType enum values are correct."""
        assert MirCertPotType.RESERVE == 0
        assert MirCertPotType.TREASURY == 1

    def test_mir_cert_pot_type_from_int(self):
        """Test creating MirCertPotType from integer values."""
        assert MirCertPotType(0) == MirCertPotType.RESERVE
        assert MirCertPotType(1) == MirCertPotType.TREASURY

    def test_mir_cert_pot_type_comparison(self):
        """Test comparison between MirCertPotType values."""
        assert MirCertPotType.RESERVE != MirCertPotType.TREASURY
        assert MirCertPotType.RESERVE == MirCertPotType.RESERVE
        assert MirCertPotType.TREASURY == MirCertPotType.TREASURY

    def test_mir_cert_pot_type_names(self):
        """Test that MirCertPotType enum has correct names."""
        assert MirCertPotType.RESERVE.name == "RESERVE"
        assert MirCertPotType.TREASURY.name == "TREASURY"

    def test_mir_cert_pot_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            MirCertPotType(2)
        with pytest.raises(ValueError):
            MirCertPotType(-1)
        with pytest.raises(ValueError):
            MirCertPotType(100)

    def test_mir_cert_pot_type_is_int_enum(self):
        """Test that MirCertPotType values can be used as integers."""
        assert isinstance(MirCertPotType.RESERVE, int)
        assert isinstance(MirCertPotType.TREASURY, int)
        assert MirCertPotType.RESERVE + 1 == 1
        assert MirCertPotType.TREASURY - 1 == 0

    def test_mir_cert_pot_type_iteration(self):
        """Test iteration over MirCertPotType enum."""
        values = list(MirCertPotType)
        assert len(values) == 2
        assert MirCertPotType.RESERVE in values
        assert MirCertPotType.TREASURY in values

    def test_mir_cert_pot_type_membership(self):
        """Test membership testing with MirCertPotType."""
        assert 0 in MirCertPotType.__members__.values()
        assert 1 in MirCertPotType.__members__.values()
        assert "RESERVE" in MirCertPotType.__members__
        assert "TREASURY" in MirCertPotType.__members__

    def test_mir_cert_pot_type_string_representation(self):
        """Test string representation of MirCertPotType values."""
        assert str(MirCertPotType.RESERVE) == "MirCertPotType.RESERVE"
        assert str(MirCertPotType.TREASURY) == "MirCertPotType.TREASURY"

    def test_mir_cert_pot_type_repr(self):
        """Test repr of MirCertPotType values."""
        assert repr(MirCertPotType.RESERVE) == "<MirCertPotType.RESERVE: 0>"
        assert repr(MirCertPotType.TREASURY) == "<MirCertPotType.TREASURY: 1>"

    def test_mir_cert_pot_type_bool_conversion(self):
        """Test boolean conversion of MirCertPotType values."""
        assert bool(MirCertPotType.RESERVE) is False
        assert bool(MirCertPotType.TREASURY) is True

    def test_mir_cert_pot_type_arithmetic(self):
        """Test arithmetic operations with MirCertPotType values."""
        assert MirCertPotType.RESERVE + MirCertPotType.TREASURY == 1
        assert MirCertPotType.TREASURY * 2 == 2
        assert MirCertPotType.TREASURY // 1 == 1

    def test_mir_cert_pot_type_hash(self):
        """Test that MirCertPotType values are hashable."""
        pot_set = {MirCertPotType.RESERVE, MirCertPotType.TREASURY}
        assert len(pot_set) == 2
        assert MirCertPotType.RESERVE in pot_set
        assert MirCertPotType.TREASURY in pot_set

    def test_mir_cert_pot_type_as_dict_key(self):
        """Test using MirCertPotType as dictionary key."""
        pot_dict = {
            MirCertPotType.RESERVE: "reserve",
            MirCertPotType.TREASURY: "treasury"
        }
        assert pot_dict[MirCertPotType.RESERVE] == "reserve"
        assert pot_dict[MirCertPotType.TREASURY] == "treasury"

    def test_mir_cert_pot_type_ordering(self):
        """Test ordering comparison between MirCertPotType values."""
        assert MirCertPotType.RESERVE < MirCertPotType.TREASURY
        assert MirCertPotType.TREASURY > MirCertPotType.RESERVE
        assert MirCertPotType.RESERVE <= MirCertPotType.RESERVE
        assert MirCertPotType.TREASURY >= MirCertPotType.TREASURY
