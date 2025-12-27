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
    PoolVotingThresholds,
    UnitInterval,
    CborReader,
    CborWriter,
    CardanoError,
    JsonWriter,
)


class TestPoolVotingThresholdsCreation:
    """Tests for PoolVotingThresholds factory methods and initialization."""

    def test_new_basic(self):
        """Test creating pool voting thresholds with basic values (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        assert thresholds is not None
        assert thresholds.motion_no_confidence.numerator == 0
        assert thresholds.motion_no_confidence.denominator == 0
        assert thresholds.committee_normal.numerator == 1
        assert thresholds.committee_normal.denominator == 1
        assert thresholds.committee_no_confidence.numerator == 2
        assert thresholds.committee_no_confidence.denominator == 2
        assert thresholds.hard_fork_initiation.numerator == 3
        assert thresholds.hard_fork_initiation.denominator == 3
        assert thresholds.security_relevant_param.numerator == 4
        assert thresholds.security_relevant_param.denominator == 4

    def test_new_with_realistic_values(self):
        """Test creating pool voting thresholds with realistic threshold values."""
        motion_no_confidence = UnitInterval.from_float(0.51)
        committee_normal = UnitInterval.from_float(0.51)
        committee_no_confidence = UnitInterval.from_float(0.51)
        hard_fork_initiation = UnitInterval.from_float(0.51)
        security_relevant_param = UnitInterval.from_float(0.51)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        assert thresholds is not None
        assert thresholds.motion_no_confidence.to_float() == pytest.approx(0.51, rel=1e-5)
        assert thresholds.committee_normal.to_float() == pytest.approx(0.51, rel=1e-5)
        assert thresholds.committee_no_confidence.to_float() == pytest.approx(0.51, rel=1e-5)
        assert thresholds.hard_fork_initiation.to_float() == pytest.approx(0.51, rel=1e-5)
        assert thresholds.security_relevant_param.to_float() == pytest.approx(0.51, rel=1e-5)


class TestPoolVotingThresholdsCborSerialization:
    """Tests for PoolVotingThresholds CBOR serialization and deserialization."""

    def test_to_cbor_basic(self):
        """Test serializing pool voting thresholds to CBOR (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = CborWriter()
        thresholds.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == "85d81e820000d81e820101d81e820202d81e820303d81e820404"

    def test_from_cbor_basic(self):
        """Test deserializing pool voting thresholds from CBOR (from C test)."""
        cbor_hex = "85d81e820000d81e820101d81e820202d81e820303d81e820404"
        reader = CborReader.from_hex(cbor_hex)
        thresholds = PoolVotingThresholds.from_cbor(reader)

        assert thresholds is not None
        assert thresholds.motion_no_confidence.numerator == 0
        assert thresholds.motion_no_confidence.denominator == 0
        assert thresholds.committee_normal.numerator == 1
        assert thresholds.committee_normal.denominator == 1
        assert thresholds.committee_no_confidence.numerator == 2
        assert thresholds.committee_no_confidence.denominator == 2
        assert thresholds.hard_fork_initiation.numerator == 3
        assert thresholds.hard_fork_initiation.denominator == 3
        assert thresholds.security_relevant_param.numerator == 4
        assert thresholds.security_relevant_param.denominator == 4

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        motion_no_confidence = UnitInterval.new(10, 20)
        committee_normal = UnitInterval.new(30, 40)
        committee_no_confidence = UnitInterval.new(50, 60)
        hard_fork_initiation = UnitInterval.new(70, 80)
        security_relevant_param = UnitInterval.new(90, 100)

        original = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = PoolVotingThresholds.from_cbor(reader)

        assert deserialized.motion_no_confidence.numerator == 10
        assert deserialized.motion_no_confidence.denominator == 20
        assert deserialized.committee_normal.numerator == 30
        assert deserialized.committee_normal.denominator == 40
        assert deserialized.committee_no_confidence.numerator == 50
        assert deserialized.committee_no_confidence.denominator == 60
        assert deserialized.hard_fork_initiation.numerator == 70
        assert deserialized.hard_fork_initiation.denominator == 80
        assert deserialized.security_relevant_param.numerator == 90
        assert deserialized.security_relevant_param.denominator == 100

    def test_from_cbor_invalid_array(self):
        """Test that deserializing invalid array raises error (from C test)."""
        reader = CborReader.from_hex("04")
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_motion_no_confidence(self):
        """Test that deserializing with invalid motion_no_confidence raises error (from C test)."""
        reader = CborReader.from_hex(
            "85d81ea20000d81e820101d81e820202d81e820303d81e820404"
        )
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_committee_normal(self):
        """Test that deserializing with invalid committee_normal raises error (from C test)."""
        reader = CborReader.from_hex(
            "85d81e820000d81ea20101d81e820202d81e820303d81e820404"
        )
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_committee_no_confidence(self):
        """Test that deserializing with invalid committee_no_confidence raises error (from C test)."""
        reader = CborReader.from_hex(
            "85d81e820000d81e820101d81ea20202d81e820303d81e820404"
        )
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_hard_fork_initiation(self):
        """Test that deserializing with invalid hard_fork_initiation raises error (from C test)."""
        reader = CborReader.from_hex(
            "85d81e820000d81e820101d81e820202d81ea20303d81e820404"
        )
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)

    def test_from_cbor_invalid_security_param(self):
        """Test that deserializing with invalid security_relevant_param raises error (from C test)."""
        reader = CborReader.from_hex(
            "85d81e820000d81e820101d81e820202d81e820303d81ea20404"
        )
        with pytest.raises(CardanoError):
            PoolVotingThresholds.from_cbor(reader)


class TestPoolVotingThresholdsProperties:
    """Tests for PoolVotingThresholds property getters and setters."""

    def test_get_motion_no_confidence(self):
        """Test getting motion_no_confidence property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        result = thresholds.motion_no_confidence
        assert result.numerator == 0
        assert result.denominator == 0

    def test_set_motion_no_confidence(self):
        """Test setting motion_no_confidence property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        new_value = UnitInterval.new(99, 99)
        thresholds.motion_no_confidence = new_value

        result = thresholds.motion_no_confidence
        assert result.numerator == 99
        assert result.denominator == 99

    def test_get_committee_normal(self):
        """Test getting committee_normal property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        result = thresholds.committee_normal
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_committee_normal(self):
        """Test setting committee_normal property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        new_value = UnitInterval.new(98, 98)
        thresholds.committee_normal = new_value

        result = thresholds.committee_normal
        assert result.numerator == 98
        assert result.denominator == 98

    def test_get_committee_no_confidence(self):
        """Test getting committee_no_confidence property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        result = thresholds.committee_no_confidence
        assert result.numerator == 2
        assert result.denominator == 2

    def test_set_committee_no_confidence(self):
        """Test setting committee_no_confidence property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        new_value = UnitInterval.new(97, 97)
        thresholds.committee_no_confidence = new_value

        result = thresholds.committee_no_confidence
        assert result.numerator == 97
        assert result.denominator == 97

    def test_get_hard_fork_initiation(self):
        """Test getting hard_fork_initiation property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        result = thresholds.hard_fork_initiation
        assert result.numerator == 3
        assert result.denominator == 3

    def test_set_hard_fork_initiation(self):
        """Test setting hard_fork_initiation property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        new_value = UnitInterval.new(95, 95)
        thresholds.hard_fork_initiation = new_value

        result = thresholds.hard_fork_initiation
        assert result.numerator == 95
        assert result.denominator == 95

    def test_get_security_relevant_param(self):
        """Test getting security_relevant_param property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        result = thresholds.security_relevant_param
        assert result.numerator == 4
        assert result.denominator == 4

    def test_set_security_relevant_param(self):
        """Test setting security_relevant_param property (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        new_value = UnitInterval.new(94, 94)
        thresholds.security_relevant_param = new_value

        result = thresholds.security_relevant_param
        assert result.numerator == 94
        assert result.denominator == 94


class TestPoolVotingThresholdsJsonSerialization:
    """Tests for PoolVotingThresholds JSON serialization."""

    def test_to_cip116_json(self):
        """Test converting to CIP-116 JSON format (from C test)."""
        motion_no_confidence = UnitInterval.new(0, 0)
        committee_normal = UnitInterval.new(1, 1)
        committee_no_confidence = UnitInterval.new(2, 2)
        hard_fork_initiation = UnitInterval.new(3, 3)
        security_relevant_param = UnitInterval.new(4, 4)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = JsonWriter()
        thresholds.to_cip116_json(writer)
        json_str = writer.encode()

        expected = (
            '{"motion_no_confidence":{"numerator":"0","denominator":"0"},'
            '"committee_normal":{"numerator":"1","denominator":"1"},'
            '"committee_no_confidence":{"numerator":"2","denominator":"2"},'
            '"hard_fork_initiation":{"numerator":"3","denominator":"3"},'
            '"security_relevant_param":{"numerator":"4","denominator":"4"}}'
        )
        assert json_str == expected

    def test_to_cip116_json_format(self):
        """Test that CIP-116 JSON has correct structure."""
        motion_no_confidence = UnitInterval.new(1, 2)
        committee_normal = UnitInterval.new(1, 2)
        committee_no_confidence = UnitInterval.new(1, 2)
        hard_fork_initiation = UnitInterval.new(1, 2)
        security_relevant_param = UnitInterval.new(1, 2)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = JsonWriter()
        thresholds.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.startswith("{")
        assert json_str.endswith("}")
        assert "motion_no_confidence" in json_str
        assert "committee_normal" in json_str
        assert "committee_no_confidence" in json_str
        assert "hard_fork_initiation" in json_str
        assert "security_relevant_param" in json_str

    def test_to_cip116_json_invalid_writer(self):
        """Test that passing invalid writer raises error."""
        motion_no_confidence = UnitInterval.new(1, 2)
        committee_normal = UnitInterval.new(1, 2)
        committee_no_confidence = UnitInterval.new(1, 2)
        hard_fork_initiation = UnitInterval.new(1, 2)
        security_relevant_param = UnitInterval.new(1, 2)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        with pytest.raises(TypeError):
            thresholds.to_cip116_json("not a writer")


class TestPoolVotingThresholdsMagicMethods:
    """Tests for PoolVotingThresholds magic methods."""

    def test_repr(self):
        """Test __repr__ method."""
        motion_no_confidence = UnitInterval.new(1, 2)
        committee_normal = UnitInterval.new(1, 2)
        committee_no_confidence = UnitInterval.new(1, 2)
        hard_fork_initiation = UnitInterval.new(1, 2)
        security_relevant_param = UnitInterval.new(1, 2)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        assert repr(thresholds) == "PoolVotingThresholds(...)"


class TestPoolVotingThresholdsContextManager:
    """Tests for PoolVotingThresholds context manager protocol."""

    def test_context_manager(self):
        """Test that PoolVotingThresholds can be used as context manager."""
        motion_no_confidence = UnitInterval.new(1, 2)
        committee_normal = UnitInterval.new(1, 2)
        committee_no_confidence = UnitInterval.new(1, 2)
        hard_fork_initiation = UnitInterval.new(1, 2)
        security_relevant_param = UnitInterval.new(1, 2)

        with PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        ) as thresholds:
            assert thresholds.motion_no_confidence.numerator == 1
            assert thresholds.committee_normal.numerator == 1

    def test_context_manager_exception(self):
        """Test context manager with exception."""
        motion_no_confidence = UnitInterval.new(1, 2)
        committee_normal = UnitInterval.new(1, 2)
        committee_no_confidence = UnitInterval.new(1, 2)
        hard_fork_initiation = UnitInterval.new(1, 2)
        security_relevant_param = UnitInterval.new(1, 2)

        try:
            with PoolVotingThresholds.new(
                motion_no_confidence,
                committee_normal,
                committee_no_confidence,
                hard_fork_initiation,
                security_relevant_param,
            ) as thresholds:
                assert thresholds is not None
                raise ValueError("test exception")
        except ValueError:
            pass


class TestPoolVotingThresholdsEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_create_with_large_values(self):
        """Test creating thresholds with large unit interval values."""
        large_num = 18446744073709551615
        large_denom = 18446744073709551614

        motion_no_confidence = UnitInterval.new(large_num, large_denom)
        committee_normal = UnitInterval.new(large_num, large_denom)
        committee_no_confidence = UnitInterval.new(large_num, large_denom)
        hard_fork_initiation = UnitInterval.new(large_num, large_denom)
        security_relevant_param = UnitInterval.new(large_num, large_denom)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        assert thresholds.motion_no_confidence.numerator == large_num
        assert thresholds.motion_no_confidence.denominator == large_denom

    def test_cbor_serialization_with_large_values(self):
        """Test CBOR serialization with large values."""
        large_num = 999999999
        large_denom = 1000000000

        motion_no_confidence = UnitInterval.new(large_num, large_denom)
        committee_normal = UnitInterval.new(large_num, large_denom)
        committee_no_confidence = UnitInterval.new(large_num, large_denom)
        hard_fork_initiation = UnitInterval.new(large_num, large_denom)
        security_relevant_param = UnitInterval.new(large_num, large_denom)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = CborWriter()
        thresholds.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = PoolVotingThresholds.from_cbor(reader)

        assert deserialized.motion_no_confidence.numerator == large_num
        assert deserialized.motion_no_confidence.denominator == large_denom
        assert deserialized.committee_normal.numerator == large_num
        assert deserialized.committee_normal.denominator == large_denom

    def test_json_serialization_with_large_values(self):
        """Test JSON serialization with large values."""
        large_num = 18446744073709551615
        large_denom = 18446744073709551614

        motion_no_confidence = UnitInterval.new(large_num, large_denom)
        committee_normal = UnitInterval.new(large_num, large_denom)
        committee_no_confidence = UnitInterval.new(large_num, large_denom)
        hard_fork_initiation = UnitInterval.new(large_num, large_denom)
        security_relevant_param = UnitInterval.new(large_num, large_denom)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        writer = JsonWriter()
        thresholds.to_cip116_json(writer)
        json_str = writer.encode()

        assert f'"{large_num}"' in json_str
        assert f'"{large_denom}"' in json_str

    def test_modify_all_properties(self):
        """Test modifying all properties sequentially."""
        motion_no_confidence = UnitInterval.new(1, 1)
        committee_normal = UnitInterval.new(2, 2)
        committee_no_confidence = UnitInterval.new(3, 3)
        hard_fork_initiation = UnitInterval.new(4, 4)
        security_relevant_param = UnitInterval.new(5, 5)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )

        thresholds.motion_no_confidence = UnitInterval.new(10, 10)
        thresholds.committee_normal = UnitInterval.new(20, 20)
        thresholds.committee_no_confidence = UnitInterval.new(30, 30)
        thresholds.hard_fork_initiation = UnitInterval.new(40, 40)
        thresholds.security_relevant_param = UnitInterval.new(50, 50)

        assert thresholds.motion_no_confidence.numerator == 10
        assert thresholds.committee_normal.numerator == 20
        assert thresholds.committee_no_confidence.numerator == 30
        assert thresholds.hard_fork_initiation.numerator == 40
        assert thresholds.security_relevant_param.numerator == 50

    def test_zero_threshold_values(self):
        """Test creating thresholds with all zero values."""
        zero = UnitInterval.new(0, 1)

        thresholds = PoolVotingThresholds.new(zero, zero, zero, zero, zero)

        assert thresholds.motion_no_confidence.to_float() == 0.0
        assert thresholds.committee_normal.to_float() == 0.0
        assert thresholds.committee_no_confidence.to_float() == 0.0
        assert thresholds.hard_fork_initiation.to_float() == 0.0
        assert thresholds.security_relevant_param.to_float() == 0.0

    def test_max_threshold_values(self):
        """Test creating thresholds with maximum values (1.0)."""
        one = UnitInterval.new(1, 1)

        thresholds = PoolVotingThresholds.new(one, one, one, one, one)

        assert thresholds.motion_no_confidence.to_float() == 1.0
        assert thresholds.committee_normal.to_float() == 1.0
        assert thresholds.committee_no_confidence.to_float() == 1.0
        assert thresholds.hard_fork_initiation.to_float() == 1.0
        assert thresholds.security_relevant_param.to_float() == 1.0

    def test_cbor_deserialization_independence(self):
        """Test that deserialized objects are independent from source."""
        cbor_hex = "85d81e820000d81e820101d81e820202d81e820303d81e820404"
        reader1 = CborReader.from_hex(cbor_hex)
        thresholds1 = PoolVotingThresholds.from_cbor(reader1)

        reader2 = CborReader.from_hex(cbor_hex)
        thresholds2 = PoolVotingThresholds.from_cbor(reader2)

        thresholds1.motion_no_confidence = UnitInterval.new(99, 99)

        assert thresholds1.motion_no_confidence.numerator == 99
        assert thresholds2.motion_no_confidence.numerator == 0
