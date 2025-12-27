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
from cometa.address import ByronAddressType


class TestByronAddressType:
    """Tests for the ByronAddressType enum."""

    def test_byron_address_type_values(self):
        """Test that ByronAddressType enum values are correct."""
        assert ByronAddressType.PUBKEY == 0
        assert ByronAddressType.SCRIPT == 1
        assert ByronAddressType.REDEEM == 2

    def test_byron_address_type_from_int(self):
        """Test creating ByronAddressType from integer values."""
        assert ByronAddressType(0) == ByronAddressType.PUBKEY
        assert ByronAddressType(1) == ByronAddressType.SCRIPT
        assert ByronAddressType(2) == ByronAddressType.REDEEM

    def test_byron_address_type_comparison(self):
        """Test comparison between ByronAddressType values."""
        assert ByronAddressType.PUBKEY != ByronAddressType.SCRIPT
        assert ByronAddressType.PUBKEY != ByronAddressType.REDEEM
        assert ByronAddressType.SCRIPT != ByronAddressType.REDEEM
        assert ByronAddressType.PUBKEY == ByronAddressType.PUBKEY
        assert ByronAddressType.SCRIPT == ByronAddressType.SCRIPT
        assert ByronAddressType.REDEEM == ByronAddressType.REDEEM

    def test_byron_address_type_names(self):
        """Test that ByronAddressType enum has correct names."""
        assert ByronAddressType.PUBKEY.name == "PUBKEY"
        assert ByronAddressType.SCRIPT.name == "SCRIPT"
        assert ByronAddressType.REDEEM.name == "REDEEM"

    def test_byron_address_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            ByronAddressType(3)
        with pytest.raises(ValueError):
            ByronAddressType(-1)
        with pytest.raises(ValueError):
            ByronAddressType(100)
        with pytest.raises(ValueError):
            ByronAddressType(10)

    def test_byron_address_type_is_int_enum(self):
        """Test that ByronAddressType values can be used as integers."""
        assert isinstance(ByronAddressType.PUBKEY, int)
        assert isinstance(ByronAddressType.SCRIPT, int)
        assert isinstance(ByronAddressType.REDEEM, int)
        assert ByronAddressType.PUBKEY + 1 == 1
        assert ByronAddressType.SCRIPT + 1 == 2
        assert ByronAddressType.REDEEM - 1 == 1
        assert ByronAddressType.REDEEM * 2 == 4

    def test_byron_address_type_iteration(self):
        """Test iteration over ByronAddressType enum."""
        values = list(ByronAddressType)
        assert len(values) == 3
        assert ByronAddressType.PUBKEY in values
        assert ByronAddressType.SCRIPT in values
        assert ByronAddressType.REDEEM in values

    def test_byron_address_type_membership(self):
        """Test membership testing with ByronAddressType."""
        assert 0 in ByronAddressType.__members__.values()
        assert 1 in ByronAddressType.__members__.values()
        assert 2 in ByronAddressType.__members__.values()
        assert "PUBKEY" in ByronAddressType.__members__
        assert "SCRIPT" in ByronAddressType.__members__
        assert "REDEEM" in ByronAddressType.__members__

    def test_byron_address_type_string_representation(self):
        """Test string representation of ByronAddressType values."""
        assert str(ByronAddressType.PUBKEY) == "ByronAddressType.PUBKEY"
        assert str(ByronAddressType.SCRIPT) == "ByronAddressType.SCRIPT"
        assert str(ByronAddressType.REDEEM) == "ByronAddressType.REDEEM"

    def test_byron_address_type_repr(self):
        """Test repr of ByronAddressType values."""
        assert repr(ByronAddressType.PUBKEY) == "<ByronAddressType.PUBKEY: 0>"
        assert repr(ByronAddressType.SCRIPT) == "<ByronAddressType.SCRIPT: 1>"
        assert repr(ByronAddressType.REDEEM) == "<ByronAddressType.REDEEM: 2>"

    def test_byron_address_type_bool_conversion(self):
        """Test boolean conversion of ByronAddressType values."""
        assert bool(ByronAddressType.PUBKEY) is False
        assert bool(ByronAddressType.SCRIPT) is True
        assert bool(ByronAddressType.REDEEM) is True

    def test_byron_address_type_arithmetic(self):
        """Test arithmetic operations with ByronAddressType values."""
        assert ByronAddressType.PUBKEY + ByronAddressType.SCRIPT == 1
        assert ByronAddressType.REDEEM * 2 == 4
        assert ByronAddressType.REDEEM // 2 == 1
        assert ByronAddressType.REDEEM - ByronAddressType.SCRIPT == 1
        assert ByronAddressType.SCRIPT + ByronAddressType.REDEEM == 3

    def test_byron_address_type_hash(self):
        """Test that ByronAddressType values are hashable."""
        byron_set = {
            ByronAddressType.PUBKEY,
            ByronAddressType.SCRIPT,
            ByronAddressType.REDEEM
        }
        assert len(byron_set) == 3
        assert ByronAddressType.PUBKEY in byron_set
        assert ByronAddressType.SCRIPT in byron_set
        assert ByronAddressType.REDEEM in byron_set

    def test_byron_address_type_as_dict_key(self):
        """Test using ByronAddressType as dictionary key."""
        byron_dict = {
            ByronAddressType.PUBKEY: "public key",
            ByronAddressType.SCRIPT: "script",
            ByronAddressType.REDEEM: "redeem"
        }
        assert byron_dict[ByronAddressType.PUBKEY] == "public key"
        assert byron_dict[ByronAddressType.SCRIPT] == "script"
        assert byron_dict[ByronAddressType.REDEEM] == "redeem"

    def test_byron_address_type_ordering(self):
        """Test ordering comparison between ByronAddressType values."""
        assert ByronAddressType.PUBKEY < ByronAddressType.SCRIPT
        assert ByronAddressType.SCRIPT < ByronAddressType.REDEEM
        assert ByronAddressType.PUBKEY < ByronAddressType.REDEEM
        assert ByronAddressType.REDEEM > ByronAddressType.SCRIPT
        assert ByronAddressType.SCRIPT > ByronAddressType.PUBKEY
        assert ByronAddressType.PUBKEY <= ByronAddressType.PUBKEY
        assert ByronAddressType.REDEEM >= ByronAddressType.REDEEM

    def test_byron_address_type_equality_with_int(self):
        """Test that ByronAddressType values can be compared with integers."""
        assert ByronAddressType.PUBKEY == 0
        assert ByronAddressType.SCRIPT == 1
        assert ByronAddressType.REDEEM == 2
        assert 0 == ByronAddressType.PUBKEY
        assert 1 == ByronAddressType.SCRIPT
        assert 2 == ByronAddressType.REDEEM

    def test_byron_address_type_all_types_unique(self):
        """Test that all Byron address types have unique values."""
        types = [
            ByronAddressType.PUBKEY,
            ByronAddressType.SCRIPT,
            ByronAddressType.REDEEM
        ]
        values = [t.value for t in types]
        assert len(values) == len(set(values))

    def test_byron_address_type_sequential_values(self):
        """Test that Byron address type values are sequential starting from 0."""
        assert ByronAddressType.PUBKEY == 0
        assert ByronAddressType.SCRIPT == ByronAddressType.PUBKEY + 1
        assert ByronAddressType.REDEEM == ByronAddressType.SCRIPT + 1

    def test_byron_address_type_min_max(self):
        """Test minimum and maximum Byron address type values."""
        all_types = list(ByronAddressType)
        assert min(all_types) == ByronAddressType.PUBKEY
        assert max(all_types) == ByronAddressType.REDEEM

    def test_byron_address_type_count(self):
        """Test that there are exactly 3 Byron address types."""
        assert len(ByronAddressType) == 3
        assert len(list(ByronAddressType)) == 3
        assert len(ByronAddressType.__members__) == 3

    def test_byron_address_type_type_checking(self):
        """Test type checking for ByronAddressType values."""
        from enum import IntEnum
        assert isinstance(ByronAddressType.PUBKEY, ByronAddressType)
        assert isinstance(ByronAddressType.SCRIPT, ByronAddressType)
        assert isinstance(ByronAddressType.REDEEM, ByronAddressType)
        assert isinstance(ByronAddressType.PUBKEY, IntEnum)
        assert isinstance(ByronAddressType.SCRIPT, IntEnum)
        assert isinstance(ByronAddressType.REDEEM, IntEnum)

    def test_byron_address_type_immutability(self):
        """Test that ByronAddressType values are immutable."""
        with pytest.raises(AttributeError):
            ByronAddressType.PUBKEY.value = 10
        with pytest.raises(AttributeError):
            ByronAddressType.SCRIPT.name = "CHANGED"

    def test_byron_address_type_value_attribute(self):
        """Test accessing value attribute of ByronAddressType members."""
        assert hasattr(ByronAddressType.PUBKEY, 'value')
        assert hasattr(ByronAddressType.SCRIPT, 'value')
        assert hasattr(ByronAddressType.REDEEM, 'value')
        assert ByronAddressType.PUBKEY.value == 0
        assert ByronAddressType.SCRIPT.value == 1
        assert ByronAddressType.REDEEM.value == 2

    def test_byron_address_type_name_attribute(self):
        """Test accessing name attribute of ByronAddressType members."""
        assert hasattr(ByronAddressType.PUBKEY, 'name')
        assert hasattr(ByronAddressType.SCRIPT, 'name')
        assert hasattr(ByronAddressType.REDEEM, 'name')
        assert ByronAddressType.PUBKEY.name == "PUBKEY"
        assert ByronAddressType.SCRIPT.name == "SCRIPT"
        assert ByronAddressType.REDEEM.name == "REDEEM"

    def test_byron_address_type_identity(self):
        """Test that enum members maintain identity."""
        assert ByronAddressType.PUBKEY is ByronAddressType.PUBKEY
        assert ByronAddressType.SCRIPT is ByronAddressType.SCRIPT
        assert ByronAddressType.REDEEM is ByronAddressType.REDEEM
        assert ByronAddressType(0) is ByronAddressType.PUBKEY
        assert ByronAddressType(1) is ByronAddressType.SCRIPT
        assert ByronAddressType(2) is ByronAddressType.REDEEM

    def test_byron_address_type_bitwise_operations(self):
        """Test bitwise operations on ByronAddressType values."""
        assert ByronAddressType.PUBKEY & 0b11 == 0
        assert ByronAddressType.SCRIPT & 0b11 == 1
        assert ByronAddressType.REDEEM & 0b11 == 2
        assert ByronAddressType.PUBKEY | 0b01 == 1
        assert ByronAddressType.SCRIPT ^ 0b01 == 0
        assert ~ByronAddressType.PUBKEY == -1
        assert ~ByronAddressType.SCRIPT == -2
        assert ~ByronAddressType.REDEEM == -3
