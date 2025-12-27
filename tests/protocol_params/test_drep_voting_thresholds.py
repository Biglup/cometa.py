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
from cometa import (
    DRepVotingThresholds,
    UnitInterval,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR_HEX = "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"


def create_test_thresholds():
    """
    Helper function to create a DRepVotingThresholds instance with test data.
    Adapted from the C test file init_drep_voting_thresholds function.
    """
    motion_no_confidence = UnitInterval.new(0, 0)
    committee_normal = UnitInterval.new(1, 1)
    committee_no_confidence = UnitInterval.new(2, 2)
    update_constitution = UnitInterval.new(3, 3)
    hard_fork_initiation = UnitInterval.new(4, 4)
    pp_network_group = UnitInterval.new(5, 5)
    pp_economic_group = UnitInterval.new(6, 6)
    pp_technical_group = UnitInterval.new(7, 7)
    pp_governance_group = UnitInterval.new(8, 8)
    treasury_withdrawal = UnitInterval.new(9, 9)

    return DRepVotingThresholds.new(
        motion_no_confidence,
        committee_normal,
        committee_no_confidence,
        update_constitution,
        hard_fork_initiation,
        pp_network_group,
        pp_economic_group,
        pp_technical_group,
        pp_governance_group,
        treasury_withdrawal,
    )


class TestDRepVotingThresholdsNew:
    """Tests for DRepVotingThresholds.new() factory method."""

    def test_new_success(self):
        """Test creating DRepVotingThresholds with valid arguments."""
        thresholds = create_test_thresholds()
        assert thresholds is not None

    def test_new_with_different_values(self):
        """Test creating thresholds with varied values."""
        motion_no_confidence = UnitInterval.new(1, 10)
        committee_normal = UnitInterval.new(2, 10)
        committee_no_confidence = UnitInterval.new(3, 10)
        update_constitution = UnitInterval.new(4, 10)
        hard_fork_initiation = UnitInterval.new(5, 10)
        pp_network_group = UnitInterval.new(6, 10)
        pp_economic_group = UnitInterval.new(7, 10)
        pp_technical_group = UnitInterval.new(8, 10)
        pp_governance_group = UnitInterval.new(9, 10)
        treasury_withdrawal = UnitInterval.new(10, 10)

        thresholds = DRepVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            update_constitution,
            hard_fork_initiation,
            pp_network_group,
            pp_economic_group,
            pp_technical_group,
            pp_governance_group,
            treasury_withdrawal,
        )
        assert thresholds is not None
        assert thresholds.motion_no_confidence.numerator == 1
        assert thresholds.motion_no_confidence.denominator == 10


class TestDRepVotingThresholdsFromCbor:
    """Tests for DRepVotingThresholds.from_cbor() deserialization."""

    def test_from_cbor_success(self):
        """Test deserializing DRepVotingThresholds from valid CBOR."""
        reader = CborReader.from_hex(CBOR_HEX)
        thresholds = DRepVotingThresholds.from_cbor(reader)
        assert thresholds is not None

    def test_from_cbor_invalid_array(self):
        """Test error with invalid CBOR array structure."""
        reader = CborReader.from_hex("04")
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_motion_no_confidence(self):
        """Test error with invalid motion_no_confidence in CBOR."""
        reader = CborReader.from_hex(
            "8ad81ea20000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_committee_normal(self):
        """Test error with invalid committee_normal in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81ea20101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_committee_no_confidence(self):
        """Test error with invalid committee_no_confidence in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81ea20202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_update_constitution(self):
        """Test error with invalid update_constitution in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81ea20303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_hard_fork_initiation(self):
        """Test error with invalid hard_fork_initiation in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81ea20404d81e820505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_pp_network_group(self):
        """Test error with invalid pp_network_group in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81ea20505d81e820606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_pp_economic_group(self):
        """Test error with invalid pp_economic_group in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81ea20606d81e820707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_pp_technical_group(self):
        """Test error with invalid pp_technical_group in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81ea20707d81e820808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_pp_governance_group(self):
        """Test error with invalid pp_governance_group in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81ea20808d81e820909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_treasury_withdrawal(self):
        """Test error with invalid treasury_withdrawal in CBOR."""
        reader = CborReader.from_hex(
            "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81ea20909"
        )
        with pytest.raises(CardanoError):
            DRepVotingThresholds.from_cbor(reader)


class TestDRepVotingThresholdsToCbor:
    """Tests for DRepVotingThresholds.to_cbor() serialization."""

    def test_to_cbor_success(self):
        """Test serializing DRepVotingThresholds to CBOR."""
        thresholds = create_test_thresholds()
        writer = CborWriter()
        thresholds.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_HEX

    def test_to_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        original = create_test_thresholds()
        writer = CborWriter()
        original.to_cbor(writer)
        reader = CborReader.from_hex(writer.to_hex())
        deserialized = DRepVotingThresholds.from_cbor(reader)
        assert deserialized is not None
        assert deserialized.motion_no_confidence.numerator == 0
        assert deserialized.motion_no_confidence.denominator == 0


class TestDRepVotingThresholdsGetters:
    """Tests for DRepVotingThresholds getter properties."""

    @pytest.fixture
    def thresholds(self):
        """Create a thresholds fixture."""
        return create_test_thresholds()

    def test_get_motion_no_confidence(self, thresholds):
        """Test getting motion_no_confidence threshold."""
        value = thresholds.motion_no_confidence
        assert value is not None
        assert value.numerator == 0
        assert value.denominator == 0

    def test_get_committee_normal(self, thresholds):
        """Test getting committee_normal threshold."""
        value = thresholds.committee_normal
        assert value is not None
        assert value.numerator == 1
        assert value.denominator == 1

    def test_get_committee_no_confidence(self, thresholds):
        """Test getting committee_no_confidence threshold."""
        value = thresholds.committee_no_confidence
        assert value is not None
        assert value.numerator == 2
        assert value.denominator == 2

    def test_get_update_constitution(self, thresholds):
        """Test getting update_constitution threshold."""
        value = thresholds.update_constitution
        assert value is not None
        assert value.numerator == 3
        assert value.denominator == 3

    def test_get_hard_fork_initiation(self, thresholds):
        """Test getting hard_fork_initiation threshold."""
        value = thresholds.hard_fork_initiation
        assert value is not None
        assert value.numerator == 4
        assert value.denominator == 4

    def test_get_pp_network_group(self, thresholds):
        """Test getting pp_network_group threshold."""
        value = thresholds.pp_network_group
        assert value is not None
        assert value.numerator == 5
        assert value.denominator == 5

    def test_get_pp_economic_group(self, thresholds):
        """Test getting pp_economic_group threshold."""
        value = thresholds.pp_economic_group
        assert value is not None
        assert value.numerator == 6
        assert value.denominator == 6

    def test_get_pp_technical_group(self, thresholds):
        """Test getting pp_technical_group threshold."""
        value = thresholds.pp_technical_group
        assert value is not None
        assert value.numerator == 7
        assert value.denominator == 7

    def test_get_pp_governance_group(self, thresholds):
        """Test getting pp_governance_group threshold."""
        value = thresholds.pp_governance_group
        assert value is not None
        assert value.numerator == 8
        assert value.denominator == 8

    def test_get_treasury_withdrawal(self, thresholds):
        """Test getting treasury_withdrawal threshold."""
        value = thresholds.treasury_withdrawal
        assert value is not None
        assert value.numerator == 9
        assert value.denominator == 9


class TestDRepVotingThresholdsSetters:
    """Tests for DRepVotingThresholds setter properties."""

    @pytest.fixture
    def thresholds(self):
        """Create a thresholds fixture."""
        return create_test_thresholds()

    def test_set_motion_no_confidence(self, thresholds):
        """Test setting motion_no_confidence threshold."""
        new_value = UnitInterval.new(99, 99)
        thresholds.motion_no_confidence = new_value
        result = thresholds.motion_no_confidence
        assert result.numerator == 99
        assert result.denominator == 99

    def test_set_committee_normal(self, thresholds):
        """Test setting committee_normal threshold."""
        new_value = UnitInterval.new(98, 98)
        thresholds.committee_normal = new_value
        result = thresholds.committee_normal
        assert result.numerator == 98
        assert result.denominator == 98

    def test_set_committee_no_confidence(self, thresholds):
        """Test setting committee_no_confidence threshold."""
        new_value = UnitInterval.new(97, 97)
        thresholds.committee_no_confidence = new_value
        result = thresholds.committee_no_confidence
        assert result.numerator == 97
        assert result.denominator == 97

    def test_set_update_constitution(self, thresholds):
        """Test setting update_constitution threshold."""
        new_value = UnitInterval.new(96, 96)
        thresholds.update_constitution = new_value
        result = thresholds.update_constitution
        assert result.numerator == 96
        assert result.denominator == 96

    def test_set_hard_fork_initiation(self, thresholds):
        """Test setting hard_fork_initiation threshold."""
        new_value = UnitInterval.new(95, 95)
        thresholds.hard_fork_initiation = new_value
        result = thresholds.hard_fork_initiation
        assert result.numerator == 95
        assert result.denominator == 95

    def test_set_pp_network_group(self, thresholds):
        """Test setting pp_network_group threshold."""
        new_value = UnitInterval.new(94, 94)
        thresholds.pp_network_group = new_value
        result = thresholds.pp_network_group
        assert result.numerator == 94
        assert result.denominator == 94

    def test_set_pp_economic_group(self, thresholds):
        """Test setting pp_economic_group threshold."""
        new_value = UnitInterval.new(93, 93)
        thresholds.pp_economic_group = new_value
        result = thresholds.pp_economic_group
        assert result.numerator == 93
        assert result.denominator == 93

    def test_set_pp_technical_group(self, thresholds):
        """Test setting pp_technical_group threshold."""
        new_value = UnitInterval.new(92, 92)
        thresholds.pp_technical_group = new_value
        result = thresholds.pp_technical_group
        assert result.numerator == 92
        assert result.denominator == 92

    def test_set_pp_governance_group(self, thresholds):
        """Test setting pp_governance_group threshold."""
        new_value = UnitInterval.new(91, 91)
        thresholds.pp_governance_group = new_value
        result = thresholds.pp_governance_group
        assert result.numerator == 91
        assert result.denominator == 91

    def test_set_treasury_withdrawal(self, thresholds):
        """Test setting treasury_withdrawal threshold."""
        new_value = UnitInterval.new(90, 90)
        thresholds.treasury_withdrawal = new_value
        result = thresholds.treasury_withdrawal
        assert result.numerator == 90
        assert result.denominator == 90


class TestDRepVotingThresholdsToCip116Json:
    """Tests for DRepVotingThresholds.to_cip116_json() method."""

    def test_to_cip116_json_success(self):
        """Test converting DRepVotingThresholds to CIP-116 JSON."""
        thresholds = create_test_thresholds()
        writer = JsonWriter()
        thresholds.to_cip116_json(writer)
        json_str = writer.encode()
        expected = (
            '{"motion_no_confidence":{"numerator":"0","denominator":"0"},'
            '"committee_normal":{"numerator":"1","denominator":"1"},'
            '"committee_no_confidence":{"numerator":"2","denominator":"2"},'
            '"update_constitution":{"numerator":"3","denominator":"3"},'
            '"hard_fork_initiation":{"numerator":"4","denominator":"4"},'
            '"pp_network_group":{"numerator":"5","denominator":"5"},'
            '"pp_economic_group":{"numerator":"6","denominator":"6"},'
            '"pp_technical_group":{"numerator":"7","denominator":"7"},'
            '"pp_gov_group":{"numerator":"8","denominator":"8"},'
            '"treasury_withdrawal":{"numerator":"9","denominator":"9"}}'
        )
        assert json_str == expected

    def test_to_cip116_json_invalid_writer_type(self):
        """Test error with invalid writer type."""
        thresholds = create_test_thresholds()
        with pytest.raises(TypeError):
            thresholds.to_cip116_json("not a writer")


class TestDRepVotingThresholdsMagicMethods:
    """Tests for DRepVotingThresholds magic methods."""

    def test_repr(self):
        """Test __repr__ magic method."""
        thresholds = create_test_thresholds()
        repr_str = repr(thresholds)
        assert repr_str == "DRepVotingThresholds(...)"

    def test_context_manager(self):
        """Test using DRepVotingThresholds as a context manager."""
        with create_test_thresholds() as thresholds:
            assert thresholds is not None
            assert thresholds.motion_no_confidence is not None


class TestDRepVotingThresholdsEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_modification_persistence(self):
        """Test that modifications persist correctly."""
        thresholds = create_test_thresholds()
        original_value = thresholds.motion_no_confidence
        new_value = UnitInterval.new(50, 100)
        thresholds.motion_no_confidence = new_value
        result = thresholds.motion_no_confidence
        assert result.numerator == 50
        assert result.denominator == 100
        assert result.numerator != original_value.numerator

    def test_multiple_modifications(self):
        """Test multiple consecutive modifications."""
        thresholds = create_test_thresholds()
        for i in range(10):
            new_value = UnitInterval.new(i, 100)
            thresholds.motion_no_confidence = new_value
            result = thresholds.motion_no_confidence
            assert result.numerator == i

    def test_extreme_values(self):
        """Test with extreme unit interval values."""
        large_num = 2**32 - 1
        motion_no_confidence = UnitInterval.new(large_num, large_num)
        committee_normal = UnitInterval.new(large_num, large_num)
        committee_no_confidence = UnitInterval.new(large_num, large_num)
        update_constitution = UnitInterval.new(large_num, large_num)
        hard_fork_initiation = UnitInterval.new(large_num, large_num)
        pp_network_group = UnitInterval.new(large_num, large_num)
        pp_economic_group = UnitInterval.new(large_num, large_num)
        pp_technical_group = UnitInterval.new(large_num, large_num)
        pp_governance_group = UnitInterval.new(large_num, large_num)
        treasury_withdrawal = UnitInterval.new(large_num, large_num)

        thresholds = DRepVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            update_constitution,
            hard_fork_initiation,
            pp_network_group,
            pp_economic_group,
            pp_technical_group,
            pp_governance_group,
            treasury_withdrawal,
        )
        assert thresholds.motion_no_confidence.numerator == large_num

    def test_zero_values(self):
        """Test with zero values for all thresholds."""
        zero_interval = UnitInterval.new(0, 1)
        thresholds = DRepVotingThresholds.new(
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
            zero_interval,
        )
        assert thresholds.motion_no_confidence.numerator == 0

    def test_serialization_after_modification(self):
        """Test that serialization works after modifying values."""
        thresholds = create_test_thresholds()
        new_value = UnitInterval.new(50, 100)
        thresholds.motion_no_confidence = new_value
        writer = CborWriter()
        thresholds.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex is not None
        reader = CborReader.from_hex(cbor_hex)
        deserialized = DRepVotingThresholds.from_cbor(reader)
        assert deserialized.motion_no_confidence.numerator == 50

    def test_all_thresholds_independent(self):
        """Test that modifying one threshold doesn't affect others."""
        thresholds = create_test_thresholds()
        original_committee_normal = thresholds.committee_normal.numerator
        new_motion = UnitInterval.new(99, 100)
        thresholds.motion_no_confidence = new_motion
        assert thresholds.committee_normal.numerator == original_committee_normal
