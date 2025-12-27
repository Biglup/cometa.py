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
from cometa import UnitInterval, CborReader, CborWriter, CardanoError, JsonWriter


class TestUnitIntervalCreation:
    """Tests for UnitInterval factory methods and initialization."""

    def test_new_basic(self):
        """Test creating a unit interval with basic values (from C test)."""
        interval = UnitInterval.new(1, 5)
        assert interval.numerator == 1
        assert interval.denominator == 5

    def test_new_different_values(self):
        """Test creating unit intervals with different numerator/denominator."""
        interval = UnitInterval.new(3, 4)
        assert interval.numerator == 3
        assert interval.denominator == 4

    def test_new_large_values(self):
        """Test creating unit interval with large values."""
        numerator = 123456789
        denominator = 987654321
        interval = UnitInterval.new(numerator, denominator)
        assert interval.numerator == numerator
        assert interval.denominator == denominator

    def test_new_zero_numerator(self):
        """Test creating unit interval with zero numerator."""
        interval = UnitInterval.new(0, 5)
        assert interval.numerator == 0
        assert interval.denominator == 5

    def test_from_float_basic(self):
        """Test creating unit interval from float (from C test)."""
        interval = UnitInterval.from_float(0.2)
        assert interval.numerator == 1
        assert interval.denominator == 5

    def test_from_float_quarter(self):
        """Test creating unit interval from 0.25."""
        interval = UnitInterval.from_float(0.25)
        assert interval.to_float() == 0.25

    def test_from_float_whole_number(self):
        """Test creating unit interval from whole number (from C test)."""
        interval = UnitInterval.from_float(15.0)
        assert interval.numerator == 15
        assert interval.denominator == 1

    def test_from_float_zero(self):
        """Test creating unit interval from zero."""
        interval = UnitInterval.from_float(0.0)
        assert interval.numerator == 0
        assert interval.to_float() == 0.0

    def test_from_float_negative_raises_error(self):
        """Test that creating unit interval from negative float raises error (from C test)."""
        with pytest.raises(CardanoError):
            UnitInterval.from_float(-0.2)


class TestUnitIntervalCborSerialization:
    """Tests for UnitInterval CBOR serialization and deserialization."""

    def test_to_cbor_basic(self):
        """Test serializing unit interval to CBOR (from C test)."""
        interval = UnitInterval.new(1, 5)
        writer = CborWriter()
        interval.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == "d81e820105"

    def test_from_cbor_basic(self):
        """Test deserializing unit interval from CBOR (from C test)."""
        cbor_hex = "d81e820105"
        reader = CborReader.from_hex(cbor_hex)
        interval = UnitInterval.from_cbor(reader)
        assert interval.numerator == 1
        assert interval.denominator == 5

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        original = UnitInterval.new(123, 345)
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        deserialized = UnitInterval.from_cbor(reader)

        assert deserialized.numerator == original.numerator
        assert deserialized.denominator == original.denominator

    def test_from_cbor_missing_tag(self):
        """Test that deserializing without tag raises error (from C test)."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            UnitInterval.from_cbor(reader)

    def test_from_cbor_invalid_array_size(self):
        """Test that deserializing with wrong array size raises error (from C test)."""
        reader = CborReader.from_hex("d81e850105")
        with pytest.raises(CardanoError):
            UnitInterval.from_cbor(reader)

    def test_from_cbor_invalid_first_element(self):
        """Test that deserializing with non-uint first element raises error (from C test)."""
        reader = CborReader.from_hex("d81e82ff05")
        with pytest.raises(CardanoError):
            UnitInterval.from_cbor(reader)

    def test_from_cbor_invalid_second_element(self):
        """Test that deserializing with non-uint second element raises error (from C test)."""
        reader = CborReader.from_hex("d81e8201fe")
        with pytest.raises(CardanoError):
            UnitInterval.from_cbor(reader)


class TestUnitIntervalProperties:
    """Tests for UnitInterval property getters and setters."""

    def test_get_numerator(self):
        """Test getting numerator (from C test)."""
        interval = UnitInterval.new(1, 5)
        assert interval.numerator == 1

    def test_get_denominator(self):
        """Test getting denominator (from C test)."""
        interval = UnitInterval.new(1, 5)
        assert interval.denominator == 5

    def test_set_numerator(self):
        """Test setting numerator (from C test)."""
        interval = UnitInterval.new(1, 5)
        interval.numerator = 987654321
        assert interval.numerator == 987654321

    def test_set_denominator(self):
        """Test setting denominator (from C test)."""
        interval = UnitInterval.new(1, 5)
        interval.denominator = 123456789
        assert interval.denominator == 123456789

    def test_set_numerator_to_zero(self):
        """Test setting numerator to zero."""
        interval = UnitInterval.new(1, 5)
        interval.numerator = 0
        assert interval.numerator == 0
        assert interval.to_float() == 0.0

    def test_set_denominator_updates_value(self):
        """Test that setting denominator updates the interval value."""
        interval = UnitInterval.new(1, 2)
        assert interval.to_float() == 0.5
        interval.denominator = 4
        assert interval.to_float() == 0.25


class TestUnitIntervalConversions:
    """Tests for UnitInterval conversion methods."""

    def test_to_float_basic(self):
        """Test converting unit interval to float (from C test)."""
        interval = UnitInterval.new(1, 5)
        assert interval.to_float() == 0.2

    def test_to_float_zero_numerator(self):
        """Test converting unit interval with zero numerator."""
        interval = UnitInterval.new(0, 5)
        assert interval.to_float() == 0.0

    def test_to_float_one_half(self):
        """Test converting 1/2 to float."""
        interval = UnitInterval.new(1, 2)
        assert interval.to_float() == 0.5

    def test_to_float_three_quarters(self):
        """Test converting 3/4 to float."""
        interval = UnitInterval.new(3, 4)
        assert interval.to_float() == 0.75

    def test_to_float_whole_number(self):
        """Test converting whole number to float."""
        interval = UnitInterval.new(15, 1)
        assert interval.to_float() == 15.0

    def test_float_magic_method(self):
        """Test __float__ magic method."""
        interval = UnitInterval.new(1, 4)
        assert float(interval) == 0.25


class TestUnitIntervalJsonSerialization:
    """Tests for UnitInterval JSON serialization."""

    def test_to_cip116_json(self):
        """Test converting to CIP-116 JSON format (from C test)."""
        interval = UnitInterval.new(123, 345)
        writer = JsonWriter()
        interval.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"numerator":"123"' in json_str
        assert '"denominator":"345"' in json_str

    def test_to_cip116_json_format(self):
        """Test that CIP-116 JSON has correct format."""
        interval = UnitInterval.new(1, 2)
        writer = JsonWriter()
        interval.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str.startswith("{")
        assert json_str.endswith("}")

    def test_to_cip116_json_invalid_writer(self):
        """Test that passing invalid writer raises error."""
        interval = UnitInterval.new(1, 2)
        with pytest.raises(TypeError):
            interval.to_cip116_json("not a writer")


class TestUnitIntervalMagicMethods:
    """Tests for UnitInterval magic methods."""

    def test_repr(self):
        """Test __repr__ method."""
        interval = UnitInterval.new(1, 4)
        assert repr(interval) == "UnitInterval(1/4)"

    def test_str(self):
        """Test __str__ method."""
        interval = UnitInterval.new(3, 4)
        assert str(interval) == "3/4"

    def test_eq_equal_intervals(self):
        """Test equality of two equal intervals."""
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 4)
        assert interval1 == interval2

    def test_eq_different_intervals(self):
        """Test inequality of different intervals."""
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 5)
        assert interval1 != interval2

    def test_eq_with_non_interval(self):
        """Test equality comparison with non-UnitInterval object."""
        interval = UnitInterval.new(1, 4)
        assert interval != "1/4"
        assert interval != 0.25
        assert interval != None

    def test_hash(self):
        """Test that intervals can be hashed."""
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 4)
        interval3 = UnitInterval.new(1, 5)

        assert hash(interval1) == hash(interval2)
        assert hash(interval1) != hash(interval3)

    def test_hash_in_set(self):
        """Test that intervals can be used in sets."""
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 4)
        interval3 = UnitInterval.new(1, 5)

        interval_set = {interval1, interval2, interval3}
        assert len(interval_set) == 2

    def test_hash_in_dict(self):
        """Test that intervals can be used as dictionary keys."""
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 5)

        interval_dict = {interval1: "quarter", interval2: "fifth"}
        assert interval_dict[interval1] == "quarter"
        assert interval_dict[interval2] == "fifth"


class TestUnitIntervalContextManager:
    """Tests for UnitInterval context manager protocol."""

    def test_context_manager(self):
        """Test that UnitInterval can be used as context manager."""
        with UnitInterval.new(1, 4) as interval:
            assert interval.numerator == 1
            assert interval.denominator == 4
            assert interval.to_float() == 0.25

    def test_context_manager_exception(self):
        """Test context manager with exception."""
        try:
            with UnitInterval.new(1, 4) as interval:
                assert interval.numerator == 1
                raise ValueError("test exception")
        except ValueError:
            pass


class TestUnitIntervalEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_large_numerator_and_denominator(self):
        """Test with very large numerator and denominator."""
        numerator = 18446744073709551615
        denominator = 18446744073709551614
        interval = UnitInterval.new(numerator, denominator)
        assert interval.numerator == numerator
        assert interval.denominator == denominator

    def test_from_float_precision(self):
        """Test precision of float conversion."""
        original_float = 0.123456789
        interval = UnitInterval.from_float(original_float)
        converted_float = interval.to_float()
        assert abs(converted_float - original_float) < 0.000001

    def test_multiple_conversions(self):
        """Test multiple conversions maintain consistency."""
        interval = UnitInterval.new(7, 13)
        float_val = interval.to_float()
        interval2 = UnitInterval.from_float(float_val)
        float_val2 = interval2.to_float()
        assert abs(float_val - float_val2) < 0.000001

    def test_cbor_serialization_with_large_values(self):
        """Test CBOR serialization with large values."""
        interval = UnitInterval.new(999999999, 1000000000)
        writer = CborWriter()
        interval.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = UnitInterval.from_cbor(reader)
        assert deserialized.numerator == 999999999
        assert deserialized.denominator == 1000000000

    def test_json_serialization_with_large_values(self):
        """Test JSON serialization with large values."""
        numerator = 18446744073709551615
        denominator = 18446744073709551614
        interval = UnitInterval.new(numerator, denominator)
        writer = JsonWriter()
        interval.to_cip116_json(writer)
        json_str = writer.encode()
        assert f'"{numerator}"' in json_str
        assert f'"{denominator}"' in json_str
