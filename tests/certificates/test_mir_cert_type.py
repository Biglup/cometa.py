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
from cometa import MirCertType


class TestMirCertType:
    """Tests for the MirCertType enum."""

    def test_mir_cert_type_values(self):
        """Test that MirCertType enum values are correct."""
        assert MirCertType.TO_POT == 0
        assert MirCertType.TO_STAKE_CREDS == 1

    def test_mir_cert_type_from_int(self):
        """Test creating MirCertType from integer values."""
        assert MirCertType(0) == MirCertType.TO_POT
        assert MirCertType(1) == MirCertType.TO_STAKE_CREDS

    def test_mir_cert_type_comparison(self):
        """Test comparison between MirCertType values."""
        assert MirCertType.TO_POT != MirCertType.TO_STAKE_CREDS
        assert MirCertType.TO_POT == MirCertType.TO_POT
        assert MirCertType.TO_STAKE_CREDS == MirCertType.TO_STAKE_CREDS

    def test_mir_cert_type_names(self):
        """Test that MirCertType enum has correct names."""
        assert MirCertType.TO_POT.name == "TO_POT"
        assert MirCertType.TO_STAKE_CREDS.name == "TO_STAKE_CREDS"

    def test_mir_cert_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            MirCertType(2)
        with pytest.raises(ValueError):
            MirCertType(-1)
        with pytest.raises(ValueError):
            MirCertType(100)

    def test_mir_cert_type_is_int_enum(self):
        """Test that MirCertType values can be used as integers."""
        assert isinstance(MirCertType.TO_POT, int)
        assert isinstance(MirCertType.TO_STAKE_CREDS, int)
        assert MirCertType.TO_POT + 1 == 1
        assert MirCertType.TO_STAKE_CREDS - 1 == 0

    def test_mir_cert_type_iteration(self):
        """Test iteration over MirCertType enum."""
        values = list(MirCertType)
        assert len(values) == 2
        assert MirCertType.TO_POT in values
        assert MirCertType.TO_STAKE_CREDS in values

    def test_mir_cert_type_membership(self):
        """Test membership testing with MirCertType."""
        assert 0 in MirCertType.__members__.values()
        assert 1 in MirCertType.__members__.values()
        assert "TO_POT" in MirCertType.__members__
        assert "TO_STAKE_CREDS" in MirCertType.__members__

    def test_mir_cert_type_string_representation(self):
        """Test string representation of MirCertType values."""
        assert str(MirCertType.TO_POT) == "MirCertType.TO_POT"
        assert str(MirCertType.TO_STAKE_CREDS) == "MirCertType.TO_STAKE_CREDS"

    def test_mir_cert_type_repr(self):
        """Test repr of MirCertType values."""
        assert repr(MirCertType.TO_POT) == "<MirCertType.TO_POT: 0>"
        assert repr(MirCertType.TO_STAKE_CREDS) == "<MirCertType.TO_STAKE_CREDS: 1>"

    def test_mir_cert_type_bool_conversion(self):
        """Test boolean conversion of MirCertType values."""
        assert bool(MirCertType.TO_POT) is False
        assert bool(MirCertType.TO_STAKE_CREDS) is True

    def test_mir_cert_type_arithmetic(self):
        """Test arithmetic operations with MirCertType values."""
        assert MirCertType.TO_POT + MirCertType.TO_STAKE_CREDS == 1
        assert MirCertType.TO_STAKE_CREDS * 2 == 2
        assert MirCertType.TO_STAKE_CREDS // 1 == 1

    def test_mir_cert_type_hash(self):
        """Test that MirCertType values are hashable."""
        type_set = {MirCertType.TO_POT, MirCertType.TO_STAKE_CREDS}
        assert len(type_set) == 2
        assert MirCertType.TO_POT in type_set
        assert MirCertType.TO_STAKE_CREDS in type_set

    def test_mir_cert_type_as_dict_key(self):
        """Test using MirCertType as dictionary key."""
        type_dict = {
            MirCertType.TO_POT: "to_pot",
            MirCertType.TO_STAKE_CREDS: "to_stake_creds"
        }
        assert type_dict[MirCertType.TO_POT] == "to_pot"
        assert type_dict[MirCertType.TO_STAKE_CREDS] == "to_stake_creds"

    def test_mir_cert_type_ordering(self):
        """Test ordering comparison between MirCertType values."""
        assert MirCertType.TO_POT < MirCertType.TO_STAKE_CREDS
        assert MirCertType.TO_STAKE_CREDS > MirCertType.TO_POT
        assert MirCertType.TO_POT <= MirCertType.TO_POT
        assert MirCertType.TO_STAKE_CREDS >= MirCertType.TO_STAKE_CREDS
