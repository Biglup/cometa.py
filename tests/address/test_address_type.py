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
from cometa.address import AddressType


class TestAddressType:
    """Tests for the AddressType enum."""

    def test_address_type_values(self):
        """Test that AddressType enum values are correct."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY == 0b0000
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY == 0b0001
        assert AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT == 0b0010
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT == 0b0011
        assert AddressType.POINTER_KEY == 0b0100
        assert AddressType.POINTER_SCRIPT == 0b0101
        assert AddressType.ENTERPRISE_KEY == 0b0110
        assert AddressType.ENTERPRISE_SCRIPT == 0b0111
        assert AddressType.BYRON == 0b1000
        assert AddressType.REWARD_KEY == 0b1110
        assert AddressType.REWARD_SCRIPT == 0b1111

    def test_address_type_decimal_values(self):
        """Test that AddressType enum values match expected decimal values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY == 0
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY == 1
        assert AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT == 2
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT == 3
        assert AddressType.POINTER_KEY == 4
        assert AddressType.POINTER_SCRIPT == 5
        assert AddressType.ENTERPRISE_KEY == 6
        assert AddressType.ENTERPRISE_SCRIPT == 7
        assert AddressType.BYRON == 8
        assert AddressType.REWARD_KEY == 14
        assert AddressType.REWARD_SCRIPT == 15

    def test_address_type_from_int(self):
        """Test creating AddressType from integer values."""
        assert AddressType(0) == AddressType.BASE_PAYMENT_KEY_STAKE_KEY
        assert AddressType(1) == AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY
        assert AddressType(2) == AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT
        assert AddressType(3) == AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT
        assert AddressType(4) == AddressType.POINTER_KEY
        assert AddressType(5) == AddressType.POINTER_SCRIPT
        assert AddressType(6) == AddressType.ENTERPRISE_KEY
        assert AddressType(7) == AddressType.ENTERPRISE_SCRIPT
        assert AddressType(8) == AddressType.BYRON
        assert AddressType(14) == AddressType.REWARD_KEY
        assert AddressType(15) == AddressType.REWARD_SCRIPT

    def test_address_type_comparison(self):
        """Test comparison between AddressType values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY != AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY == AddressType.BASE_PAYMENT_KEY_STAKE_KEY
        assert AddressType.ENTERPRISE_KEY != AddressType.ENTERPRISE_SCRIPT
        assert AddressType.REWARD_KEY != AddressType.REWARD_SCRIPT
        assert AddressType.POINTER_KEY != AddressType.POINTER_SCRIPT

    def test_address_type_names(self):
        """Test that AddressType enum has correct names."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY.name == "BASE_PAYMENT_KEY_STAKE_KEY"
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY.name == "BASE_PAYMENT_SCRIPT_STAKE_KEY"
        assert AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT.name == "BASE_PAYMENT_KEY_STAKE_SCRIPT"
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT.name == "BASE_PAYMENT_SCRIPT_STAKE_SCRIPT"
        assert AddressType.POINTER_KEY.name == "POINTER_KEY"
        assert AddressType.POINTER_SCRIPT.name == "POINTER_SCRIPT"
        assert AddressType.ENTERPRISE_KEY.name == "ENTERPRISE_KEY"
        assert AddressType.ENTERPRISE_SCRIPT.name == "ENTERPRISE_SCRIPT"
        assert AddressType.BYRON.name == "BYRON"
        assert AddressType.REWARD_KEY.name == "REWARD_KEY"
        assert AddressType.REWARD_SCRIPT.name == "REWARD_SCRIPT"

    def test_address_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            AddressType(9)
        with pytest.raises(ValueError):
            AddressType(10)
        with pytest.raises(ValueError):
            AddressType(11)
        with pytest.raises(ValueError):
            AddressType(12)
        with pytest.raises(ValueError):
            AddressType(13)
        with pytest.raises(ValueError):
            AddressType(16)
        with pytest.raises(ValueError):
            AddressType(-1)
        with pytest.raises(ValueError):
            AddressType(100)

    def test_address_type_is_int_enum(self):
        """Test that AddressType values can be used as integers."""
        assert isinstance(AddressType.BASE_PAYMENT_KEY_STAKE_KEY, int)
        assert isinstance(AddressType.ENTERPRISE_KEY, int)
        assert isinstance(AddressType.REWARD_KEY, int)
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY + 1 == 1
        assert AddressType.ENTERPRISE_KEY - 2 == 4
        assert AddressType.BYRON * 2 == 16

    def test_address_type_iteration(self):
        """Test iteration over AddressType enum."""
        values = list(AddressType)
        assert len(values) == 11
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY in values
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY in values
        assert AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT in values
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT in values
        assert AddressType.POINTER_KEY in values
        assert AddressType.POINTER_SCRIPT in values
        assert AddressType.ENTERPRISE_KEY in values
        assert AddressType.ENTERPRISE_SCRIPT in values
        assert AddressType.BYRON in values
        assert AddressType.REWARD_KEY in values
        assert AddressType.REWARD_SCRIPT in values

    def test_address_type_membership(self):
        """Test membership testing with AddressType."""
        assert 0 in AddressType.__members__.values()
        assert 1 in AddressType.__members__.values()
        assert 8 in AddressType.__members__.values()
        assert 14 in AddressType.__members__.values()
        assert 15 in AddressType.__members__.values()
        assert "BASE_PAYMENT_KEY_STAKE_KEY" in AddressType.__members__
        assert "ENTERPRISE_KEY" in AddressType.__members__
        assert "REWARD_KEY" in AddressType.__members__
        assert "BYRON" in AddressType.__members__

    def test_address_type_string_representation(self):
        """Test string representation of AddressType values."""
        assert str(AddressType.BASE_PAYMENT_KEY_STAKE_KEY) == "AddressType.BASE_PAYMENT_KEY_STAKE_KEY"
        assert str(AddressType.ENTERPRISE_KEY) == "AddressType.ENTERPRISE_KEY"
        assert str(AddressType.REWARD_KEY) == "AddressType.REWARD_KEY"
        assert str(AddressType.BYRON) == "AddressType.BYRON"

    def test_address_type_repr(self):
        """Test repr of AddressType values."""
        assert repr(AddressType.BASE_PAYMENT_KEY_STAKE_KEY) == "<AddressType.BASE_PAYMENT_KEY_STAKE_KEY: 0>"
        assert repr(AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY) == "<AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY: 1>"
        assert repr(AddressType.ENTERPRISE_KEY) == "<AddressType.ENTERPRISE_KEY: 6>"
        assert repr(AddressType.BYRON) == "<AddressType.BYRON: 8>"
        assert repr(AddressType.REWARD_KEY) == "<AddressType.REWARD_KEY: 14>"
        assert repr(AddressType.REWARD_SCRIPT) == "<AddressType.REWARD_SCRIPT: 15>"

    def test_address_type_bool_conversion(self):
        """Test boolean conversion of AddressType values."""
        assert bool(AddressType.BASE_PAYMENT_KEY_STAKE_KEY) is False
        assert bool(AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY) is True
        assert bool(AddressType.ENTERPRISE_KEY) is True
        assert bool(AddressType.BYRON) is True
        assert bool(AddressType.REWARD_KEY) is True

    def test_address_type_arithmetic(self):
        """Test arithmetic operations with AddressType values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY + AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY == 1
        assert AddressType.ENTERPRISE_KEY * 2 == 12
        assert AddressType.BYRON // 2 == 4
        assert AddressType.REWARD_SCRIPT - AddressType.REWARD_KEY == 1

    def test_address_type_hash(self):
        """Test that AddressType values are hashable."""
        address_set = {
            AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            AddressType.ENTERPRISE_KEY,
            AddressType.REWARD_KEY,
            AddressType.BYRON
        }
        assert len(address_set) == 4
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY in address_set
        assert AddressType.ENTERPRISE_KEY in address_set
        assert AddressType.REWARD_KEY in address_set
        assert AddressType.BYRON in address_set

    def test_address_type_as_dict_key(self):
        """Test using AddressType as dictionary key."""
        address_dict = {
            AddressType.BASE_PAYMENT_KEY_STAKE_KEY: "base",
            AddressType.ENTERPRISE_KEY: "enterprise",
            AddressType.REWARD_KEY: "reward",
            AddressType.BYRON: "byron",
            AddressType.POINTER_KEY: "pointer"
        }
        assert address_dict[AddressType.BASE_PAYMENT_KEY_STAKE_KEY] == "base"
        assert address_dict[AddressType.ENTERPRISE_KEY] == "enterprise"
        assert address_dict[AddressType.REWARD_KEY] == "reward"
        assert address_dict[AddressType.BYRON] == "byron"
        assert address_dict[AddressType.POINTER_KEY] == "pointer"

    def test_address_type_ordering(self):
        """Test ordering comparison between AddressType values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY < AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY
        assert AddressType.ENTERPRISE_KEY > AddressType.POINTER_SCRIPT
        assert AddressType.REWARD_SCRIPT > AddressType.REWARD_KEY
        assert AddressType.BYRON < AddressType.REWARD_KEY
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY <= AddressType.BASE_PAYMENT_KEY_STAKE_KEY
        assert AddressType.REWARD_SCRIPT >= AddressType.REWARD_SCRIPT

    def test_address_type_base_variants(self):
        """Test all base address type variants exist and have correct values."""
        base_types = [
            AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
            AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT
        ]
        assert len(base_types) == 4
        assert all(0 <= addr_type <= 3 for addr_type in base_types)

    def test_address_type_pointer_variants(self):
        """Test pointer address type variants exist and have correct values."""
        pointer_types = [
            AddressType.POINTER_KEY,
            AddressType.POINTER_SCRIPT
        ]
        assert len(pointer_types) == 2
        assert AddressType.POINTER_KEY == 4
        assert AddressType.POINTER_SCRIPT == 5

    def test_address_type_enterprise_variants(self):
        """Test enterprise address type variants exist and have correct values."""
        enterprise_types = [
            AddressType.ENTERPRISE_KEY,
            AddressType.ENTERPRISE_SCRIPT
        ]
        assert len(enterprise_types) == 2
        assert AddressType.ENTERPRISE_KEY == 6
        assert AddressType.ENTERPRISE_SCRIPT == 7

    def test_address_type_reward_variants(self):
        """Test reward address type variants exist and have correct values."""
        reward_types = [
            AddressType.REWARD_KEY,
            AddressType.REWARD_SCRIPT
        ]
        assert len(reward_types) == 2
        assert AddressType.REWARD_KEY == 14
        assert AddressType.REWARD_SCRIPT == 15

    def test_address_type_byron_standalone(self):
        """Test Byron address type exists and has correct value."""
        assert AddressType.BYRON == 8
        assert AddressType.BYRON.name == "BYRON"

    def test_address_type_bitwise_operations(self):
        """Test bitwise operations on AddressType values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY & 0b1111 == 0
        assert AddressType.BYRON & 0b1000 == 8
        assert AddressType.REWARD_KEY & 0b1110 == 14
        assert AddressType.ENTERPRISE_KEY | 0b0001 == 7
        assert AddressType.POINTER_KEY ^ 0b0001 == 5

    def test_address_type_credential_bits(self):
        """Test that credential bits in address types are correct."""
        assert (AddressType.BASE_PAYMENT_KEY_STAKE_KEY & 0b0001) == 0
        assert (AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY & 0b0001) == 1
        assert (AddressType.POINTER_KEY & 0b0001) == 0
        assert (AddressType.POINTER_SCRIPT & 0b0001) == 1
        assert (AddressType.ENTERPRISE_KEY & 0b0001) == 0
        assert (AddressType.ENTERPRISE_SCRIPT & 0b0001) == 1
        assert (AddressType.REWARD_KEY & 0b0001) == 0
        assert (AddressType.REWARD_SCRIPT & 0b0001) == 1

    def test_address_type_equality_with_int(self):
        """Test that AddressType values can be compared with integers."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY == 0
        assert AddressType.ENTERPRISE_KEY == 6
        assert AddressType.BYRON == 8
        assert AddressType.REWARD_KEY == 14
        assert AddressType.REWARD_SCRIPT == 15
        assert 0 == AddressType.BASE_PAYMENT_KEY_STAKE_KEY
        assert 8 == AddressType.BYRON
