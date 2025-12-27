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
from cometa import CertificateType


class TestCertificateType:
    """Tests for the CertificateType enum."""

    def test_certificate_type_values(self):
        """Test that CertificateType enum values are correct."""
        assert CertificateType.STAKE_REGISTRATION == 0
        assert CertificateType.STAKE_DEREGISTRATION == 1
        assert CertificateType.STAKE_DELEGATION == 2
        assert CertificateType.POOL_REGISTRATION == 3
        assert CertificateType.POOL_RETIREMENT == 4
        assert CertificateType.GENESIS_KEY_DELEGATION == 5
        assert CertificateType.MOVE_INSTANTANEOUS_REWARDS == 6
        assert CertificateType.REGISTRATION == 7
        assert CertificateType.UNREGISTRATION == 8
        assert CertificateType.VOTE_DELEGATION == 9
        assert CertificateType.STAKE_VOTE_DELEGATION == 10
        assert CertificateType.STAKE_REGISTRATION_DELEGATION == 11
        assert CertificateType.VOTE_REGISTRATION_DELEGATION == 12
        assert CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION == 13
        assert CertificateType.AUTH_COMMITTEE_HOT == 14
        assert CertificateType.RESIGN_COMMITTEE_COLD == 15
        assert CertificateType.DREP_REGISTRATION == 16
        assert CertificateType.DREP_UNREGISTRATION == 17
        assert CertificateType.UPDATE_DREP == 18

    def test_certificate_type_from_int(self):
        """Test creating CertificateType from integer values."""
        assert CertificateType(0) == CertificateType.STAKE_REGISTRATION
        assert CertificateType(1) == CertificateType.STAKE_DEREGISTRATION
        assert CertificateType(2) == CertificateType.STAKE_DELEGATION
        assert CertificateType(3) == CertificateType.POOL_REGISTRATION
        assert CertificateType(4) == CertificateType.POOL_RETIREMENT
        assert CertificateType(5) == CertificateType.GENESIS_KEY_DELEGATION
        assert CertificateType(6) == CertificateType.MOVE_INSTANTANEOUS_REWARDS
        assert CertificateType(7) == CertificateType.REGISTRATION
        assert CertificateType(8) == CertificateType.UNREGISTRATION
        assert CertificateType(9) == CertificateType.VOTE_DELEGATION
        assert CertificateType(10) == CertificateType.STAKE_VOTE_DELEGATION
        assert CertificateType(11) == CertificateType.STAKE_REGISTRATION_DELEGATION
        assert CertificateType(12) == CertificateType.VOTE_REGISTRATION_DELEGATION
        assert CertificateType(13) == CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION
        assert CertificateType(14) == CertificateType.AUTH_COMMITTEE_HOT
        assert CertificateType(15) == CertificateType.RESIGN_COMMITTEE_COLD
        assert CertificateType(16) == CertificateType.DREP_REGISTRATION
        assert CertificateType(17) == CertificateType.DREP_UNREGISTRATION
        assert CertificateType(18) == CertificateType.UPDATE_DREP

    def test_certificate_type_comparison(self):
        """Test comparison between CertificateType values."""
        assert CertificateType.STAKE_REGISTRATION != CertificateType.STAKE_DEREGISTRATION
        assert CertificateType.STAKE_REGISTRATION == CertificateType.STAKE_REGISTRATION
        assert CertificateType.POOL_REGISTRATION != CertificateType.POOL_RETIREMENT
        assert CertificateType.DREP_REGISTRATION == CertificateType.DREP_REGISTRATION

    def test_certificate_type_names(self):
        """Test that CertificateType enum has correct names."""
        assert CertificateType.STAKE_REGISTRATION.name == "STAKE_REGISTRATION"
        assert CertificateType.STAKE_DEREGISTRATION.name == "STAKE_DEREGISTRATION"
        assert CertificateType.STAKE_DELEGATION.name == "STAKE_DELEGATION"
        assert CertificateType.POOL_REGISTRATION.name == "POOL_REGISTRATION"
        assert CertificateType.POOL_RETIREMENT.name == "POOL_RETIREMENT"
        assert CertificateType.GENESIS_KEY_DELEGATION.name == "GENESIS_KEY_DELEGATION"
        assert CertificateType.MOVE_INSTANTANEOUS_REWARDS.name == "MOVE_INSTANTANEOUS_REWARDS"
        assert CertificateType.REGISTRATION.name == "REGISTRATION"
        assert CertificateType.UNREGISTRATION.name == "UNREGISTRATION"
        assert CertificateType.VOTE_DELEGATION.name == "VOTE_DELEGATION"
        assert CertificateType.STAKE_VOTE_DELEGATION.name == "STAKE_VOTE_DELEGATION"
        assert CertificateType.STAKE_REGISTRATION_DELEGATION.name == "STAKE_REGISTRATION_DELEGATION"
        assert CertificateType.VOTE_REGISTRATION_DELEGATION.name == "VOTE_REGISTRATION_DELEGATION"
        assert CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION.name == "STAKE_VOTE_REGISTRATION_DELEGATION"
        assert CertificateType.AUTH_COMMITTEE_HOT.name == "AUTH_COMMITTEE_HOT"
        assert CertificateType.RESIGN_COMMITTEE_COLD.name == "RESIGN_COMMITTEE_COLD"
        assert CertificateType.DREP_REGISTRATION.name == "DREP_REGISTRATION"
        assert CertificateType.DREP_UNREGISTRATION.name == "DREP_UNREGISTRATION"
        assert CertificateType.UPDATE_DREP.name == "UPDATE_DREP"

    def test_certificate_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CertificateType(19)
        with pytest.raises(ValueError):
            CertificateType(-1)
        with pytest.raises(ValueError):
            CertificateType(100)

    def test_certificate_type_is_int_enum(self):
        """Test that CertificateType values can be used as integers."""
        assert isinstance(CertificateType.STAKE_REGISTRATION, int)
        assert isinstance(CertificateType.POOL_REGISTRATION, int)
        assert isinstance(CertificateType.DREP_REGISTRATION, int)
        assert CertificateType.STAKE_REGISTRATION + 1 == 1
        assert CertificateType.POOL_RETIREMENT - 1 == 3
        assert CertificateType.UPDATE_DREP - 1 == 17

    def test_certificate_type_iteration(self):
        """Test iteration over CertificateType enum."""
        values = list(CertificateType)
        assert len(values) == 19
        assert CertificateType.STAKE_REGISTRATION in values
        assert CertificateType.STAKE_DEREGISTRATION in values
        assert CertificateType.STAKE_DELEGATION in values
        assert CertificateType.POOL_REGISTRATION in values
        assert CertificateType.POOL_RETIREMENT in values
        assert CertificateType.GENESIS_KEY_DELEGATION in values
        assert CertificateType.MOVE_INSTANTANEOUS_REWARDS in values
        assert CertificateType.REGISTRATION in values
        assert CertificateType.UNREGISTRATION in values
        assert CertificateType.VOTE_DELEGATION in values
        assert CertificateType.STAKE_VOTE_DELEGATION in values
        assert CertificateType.STAKE_REGISTRATION_DELEGATION in values
        assert CertificateType.VOTE_REGISTRATION_DELEGATION in values
        assert CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION in values
        assert CertificateType.AUTH_COMMITTEE_HOT in values
        assert CertificateType.RESIGN_COMMITTEE_COLD in values
        assert CertificateType.DREP_REGISTRATION in values
        assert CertificateType.DREP_UNREGISTRATION in values
        assert CertificateType.UPDATE_DREP in values

    def test_certificate_type_membership(self):
        """Test membership testing with CertificateType."""
        assert 0 in CertificateType.__members__.values()
        assert 1 in CertificateType.__members__.values()
        assert 18 in CertificateType.__members__.values()
        assert "STAKE_REGISTRATION" in CertificateType.__members__
        assert "POOL_REGISTRATION" in CertificateType.__members__
        assert "DREP_REGISTRATION" in CertificateType.__members__

    def test_certificate_type_string_representation(self):
        """Test string representation of CertificateType values."""
        assert str(CertificateType.STAKE_REGISTRATION) == "CertificateType.STAKE_REGISTRATION"
        assert str(CertificateType.POOL_REGISTRATION) == "CertificateType.POOL_REGISTRATION"
        assert str(CertificateType.DREP_REGISTRATION) == "CertificateType.DREP_REGISTRATION"

    def test_certificate_type_repr(self):
        """Test repr of CertificateType values."""
        assert repr(CertificateType.STAKE_REGISTRATION) == "<CertificateType.STAKE_REGISTRATION: 0>"
        assert repr(CertificateType.POOL_REGISTRATION) == "<CertificateType.POOL_REGISTRATION: 3>"
        assert repr(CertificateType.UPDATE_DREP) == "<CertificateType.UPDATE_DREP: 18>"

    def test_certificate_type_bool_conversion(self):
        """Test boolean conversion of CertificateType values."""
        assert bool(CertificateType.STAKE_REGISTRATION) is False
        assert bool(CertificateType.STAKE_DEREGISTRATION) is True
        assert bool(CertificateType.UPDATE_DREP) is True

    def test_certificate_type_arithmetic(self):
        """Test arithmetic operations with CertificateType values."""
        assert CertificateType.STAKE_REGISTRATION + CertificateType.STAKE_DEREGISTRATION == 1
        assert CertificateType.POOL_REGISTRATION * 2 == 6
        assert CertificateType.UPDATE_DREP // 2 == 9

    def test_certificate_type_hash(self):
        """Test that CertificateType values are hashable."""
        certificate_set = {
            CertificateType.STAKE_REGISTRATION,
            CertificateType.POOL_REGISTRATION,
            CertificateType.DREP_REGISTRATION
        }
        assert len(certificate_set) == 3
        assert CertificateType.STAKE_REGISTRATION in certificate_set
        assert CertificateType.POOL_REGISTRATION in certificate_set
        assert CertificateType.DREP_REGISTRATION in certificate_set

    def test_certificate_type_as_dict_key(self):
        """Test using CertificateType as dictionary key."""
        certificate_dict = {
            CertificateType.STAKE_REGISTRATION: "stake_registration",
            CertificateType.POOL_REGISTRATION: "pool_registration",
            CertificateType.DREP_REGISTRATION: "drep_registration"
        }
        assert certificate_dict[CertificateType.STAKE_REGISTRATION] == "stake_registration"
        assert certificate_dict[CertificateType.POOL_REGISTRATION] == "pool_registration"
        assert certificate_dict[CertificateType.DREP_REGISTRATION] == "drep_registration"

    def test_certificate_type_ordering(self):
        """Test ordering comparison between CertificateType values."""
        assert CertificateType.STAKE_REGISTRATION < CertificateType.STAKE_DEREGISTRATION
        assert CertificateType.POOL_REGISTRATION < CertificateType.POOL_RETIREMENT
        assert CertificateType.DREP_UNREGISTRATION < CertificateType.UPDATE_DREP
        assert CertificateType.UPDATE_DREP > CertificateType.DREP_REGISTRATION
        assert CertificateType.STAKE_REGISTRATION <= CertificateType.STAKE_REGISTRATION
        assert CertificateType.UPDATE_DREP >= CertificateType.UPDATE_DREP


class TestCertificateTypeToString:
    """Tests for the to_string() method of CertificateType."""

    def test_stake_registration_to_string(self):
        """Test converting STAKE_REGISTRATION to string."""
        cert_type = CertificateType.STAKE_REGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Registration"

    def test_stake_deregistration_to_string(self):
        """Test converting STAKE_DEREGISTRATION to string."""
        cert_type = CertificateType.STAKE_DEREGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Deregistration"

    def test_stake_delegation_to_string(self):
        """Test converting STAKE_DELEGATION to string."""
        cert_type = CertificateType.STAKE_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Delegation"

    def test_pool_registration_to_string(self):
        """Test converting POOL_REGISTRATION to string."""
        cert_type = CertificateType.POOL_REGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Pool Registration"

    def test_pool_retirement_to_string(self):
        """Test converting POOL_RETIREMENT to string."""
        cert_type = CertificateType.POOL_RETIREMENT
        result = cert_type.to_string()
        assert result == "Certificate Type: Pool Retirement"

    def test_genesis_key_delegation_to_string(self):
        """Test converting GENESIS_KEY_DELEGATION to string."""
        cert_type = CertificateType.GENESIS_KEY_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Genesis Key Delegation"

    def test_move_instantaneous_rewards_to_string(self):
        """Test converting MOVE_INSTANTANEOUS_REWARDS to string."""
        cert_type = CertificateType.MOVE_INSTANTANEOUS_REWARDS
        result = cert_type.to_string()
        assert result == "Certificate Type: Move Instantaneous Rewards"

    def test_registration_to_string(self):
        """Test converting REGISTRATION to string."""
        cert_type = CertificateType.REGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Registration"

    def test_unregistration_to_string(self):
        """Test converting UNREGISTRATION to string."""
        cert_type = CertificateType.UNREGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Unregistration"

    def test_vote_delegation_to_string(self):
        """Test converting VOTE_DELEGATION to string."""
        cert_type = CertificateType.VOTE_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Vote Delegation"

    def test_stake_vote_delegation_to_string(self):
        """Test converting STAKE_VOTE_DELEGATION to string."""
        cert_type = CertificateType.STAKE_VOTE_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Vote Delegation"

    def test_stake_registration_delegation_to_string(self):
        """Test converting STAKE_REGISTRATION_DELEGATION to string."""
        cert_type = CertificateType.STAKE_REGISTRATION_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Registration Delegation"

    def test_vote_registration_delegation_to_string(self):
        """Test converting VOTE_REGISTRATION_DELEGATION to string."""
        cert_type = CertificateType.VOTE_REGISTRATION_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Vote Registration Delegation"

    def test_stake_vote_registration_delegation_to_string(self):
        """Test converting STAKE_VOTE_REGISTRATION_DELEGATION to string."""
        cert_type = CertificateType.STAKE_VOTE_REGISTRATION_DELEGATION
        result = cert_type.to_string()
        assert result == "Certificate Type: Stake Vote Registration Delegation"

    def test_auth_committee_hot_to_string(self):
        """Test converting AUTH_COMMITTEE_HOT to string."""
        cert_type = CertificateType.AUTH_COMMITTEE_HOT
        result = cert_type.to_string()
        assert result == "Certificate Type: Auth Committee Hot"

    def test_resign_committee_cold_to_string(self):
        """Test converting RESIGN_COMMITTEE_COLD to string."""
        cert_type = CertificateType.RESIGN_COMMITTEE_COLD
        result = cert_type.to_string()
        assert result == "Certificate Type: Resign Committee Cold"

    def test_drep_registration_to_string(self):
        """Test converting DREP_REGISTRATION to string."""
        cert_type = CertificateType.DREP_REGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: DRep Registration"

    def test_drep_unregistration_to_string(self):
        """Test converting DREP_UNREGISTRATION to string."""
        cert_type = CertificateType.DREP_UNREGISTRATION
        result = cert_type.to_string()
        assert result == "Certificate Type: DRep Unregistration"

    def test_update_drep_to_string(self):
        """Test converting UPDATE_DREP to string."""
        cert_type = CertificateType.UPDATE_DREP
        result = cert_type.to_string()
        assert result == "Certificate Type: Update DRep"

    def test_all_enum_members_have_to_string(self):
        """Test that all enum members can be converted to string without error."""
        for cert_type in CertificateType:
            result = cert_type.to_string()
            assert isinstance(result, str)
            assert len(result) > 0
            assert result.startswith("Certificate Type:")


class TestCertificateTypeEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert CertificateType.STAKE_REGISTRATION == CertificateType.STAKE_REGISTRATION
        assert CertificateType.STAKE_REGISTRATION != CertificateType.STAKE_DEREGISTRATION

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        ct1 = CertificateType.STAKE_REGISTRATION
        ct2 = CertificateType.STAKE_REGISTRATION
        assert ct1 is ct2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(CertificateType.STAKE_REGISTRATION) == 0
        assert int(CertificateType.POOL_REGISTRATION) == 3
        assert int(CertificateType.UPDATE_DREP) == 18

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_values = list(CertificateType)
        assert len(all_values) == 19

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert CertificateType.STAKE_REGISTRATION in CertificateType
        assert CertificateType.POOL_REGISTRATION in CertificateType
        assert CertificateType.UPDATE_DREP in CertificateType

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert CertificateType.STAKE_REGISTRATION.name == "STAKE_REGISTRATION"
        assert CertificateType.POOL_REGISTRATION.name == "POOL_REGISTRATION"
        assert CertificateType.UPDATE_DREP.name == "UPDATE_DREP"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert CertificateType.STAKE_REGISTRATION.value == 0
        assert CertificateType.POOL_REGISTRATION.value == 3
        assert CertificateType.UPDATE_DREP.value == 18

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert CertificateType(0) == CertificateType.STAKE_REGISTRATION
        assert CertificateType(3) == CertificateType.POOL_REGISTRATION
        assert CertificateType(18) == CertificateType.UPDATE_DREP

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CertificateType(100)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            CertificateType(-1)

    def test_invalid_value_nineteen(self):
        """Test that value 19 raises ValueError."""
        with pytest.raises(ValueError):
            CertificateType(19)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(CertificateType.STAKE_REGISTRATION) == "CertificateType.STAKE_REGISTRATION"
        assert repr(CertificateType.POOL_REGISTRATION) == "<CertificateType.POOL_REGISTRATION: 3>"
