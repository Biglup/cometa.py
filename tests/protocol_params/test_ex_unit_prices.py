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
    ExUnitPrices,
    UnitInterval,
    CborWriter,
    CborReader,
    CardanoError,
    JsonWriter,
    JsonFormat,
)


class TestExUnitPrices:
    """Tests for ExUnitPrices class."""

    CBOR_HEX = "82d81e820102d81e820103"

    @pytest.fixture
    def memory_price(self):
        """Create a test memory price (1/2)."""
        return UnitInterval.new(1, 2)

    @pytest.fixture
    def steps_price(self):
        """Create a test steps price (1/3)."""
        return UnitInterval.new(1, 3)

    def test_new_creates_ex_unit_prices(self, memory_price, steps_price):
        """Test that new() creates an ExUnitPrices instance."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        assert prices is not None
        assert isinstance(prices, ExUnitPrices)

    def test_new_with_none_memory_raises_error(self, steps_price):
        """Test that new() raises error when memory_prices is None."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.new(None, steps_price)

    def test_new_with_none_steps_raises_error(self, memory_price):
        """Test that new() raises error when steps_prices is None."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.new(memory_price, None)

    def test_new_with_invalid_memory_type_raises_error(self, steps_price):
        """Test that new() raises error when memory_prices has wrong type."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.new("invalid", steps_price)

    def test_new_with_invalid_steps_type_raises_error(self, memory_price):
        """Test that new() raises error when steps_prices has wrong type."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.new(memory_price, "invalid")

    def test_get_memory_prices(self, memory_price, steps_price):
        """Test getting memory prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        mem = prices.memory_prices
        assert mem is not None
        assert isinstance(mem, UnitInterval)
        assert mem.numerator == 1
        assert mem.denominator == 2

    def test_get_steps_prices(self, memory_price, steps_price):
        """Test getting steps prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        steps = prices.steps_prices
        assert steps is not None
        assert isinstance(steps, UnitInterval)
        assert steps.numerator == 1
        assert steps.denominator == 3

    def test_set_memory_prices(self, memory_price, steps_price):
        """Test setting memory prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        new_mem = UnitInterval.new(2, 5)
        prices.memory_prices = new_mem

        result = prices.memory_prices
        assert result.numerator == 2
        assert result.denominator == 5

    def test_set_memory_prices_with_none_raises_error(self, memory_price, steps_price):
        """Test that setting memory_prices to None raises error."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.memory_prices = None

    def test_set_memory_prices_with_invalid_type_raises_error(self, memory_price, steps_price):
        """Test that setting memory_prices to invalid type raises error."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.memory_prices = "invalid"

    def test_set_steps_prices(self, memory_price, steps_price):
        """Test setting steps prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        new_steps = UnitInterval.new(3, 7)
        prices.steps_prices = new_steps

        result = prices.steps_prices
        assert result.numerator == 3
        assert result.denominator == 7

    def test_set_steps_prices_with_none_raises_error(self, memory_price, steps_price):
        """Test that setting steps_prices to None raises error."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.steps_prices = None

    def test_set_steps_prices_with_invalid_type_raises_error(self, memory_price, steps_price):
        """Test that setting steps_prices to invalid type raises error."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.steps_prices = "invalid"

    def test_to_cbor_serializes_correctly(self, memory_price, steps_price):
        """Test CBOR serialization produces correct output."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        writer = CborWriter()
        prices.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == self.CBOR_HEX

    def test_to_cbor_with_none_writer_raises_error(self, memory_price, steps_price):
        """Test that to_cbor raises error when writer is None."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.to_cbor(None)

    def test_to_cbor_with_invalid_writer_type_raises_error(self, memory_price, steps_price):
        """Test that to_cbor raises error when writer has wrong type."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            prices.to_cbor("invalid")

    def test_from_cbor_deserializes_correctly(self):
        """Test CBOR deserialization."""
        reader = CborReader.from_hex(self.CBOR_HEX)
        prices = ExUnitPrices.from_cbor(reader)

        assert prices is not None
        assert isinstance(prices, ExUnitPrices)

        mem = prices.memory_prices
        steps = prices.steps_prices

        assert abs(mem.to_float() - 0.5) < 0.01
        assert abs(steps.to_float() - 0.33) < 0.01

    def test_from_cbor_with_none_reader_raises_error(self):
        """Test that from_cbor raises error when reader is None."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.from_cbor(None)

    def test_from_cbor_with_invalid_reader_type_raises_error(self):
        """Test that from_cbor raises error when reader has wrong type."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnitPrices.from_cbor("invalid")

    def test_from_cbor_with_invalid_array_size_raises_error(self):
        """Test that from_cbor raises error with wrong array size."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            ExUnitPrices.from_cbor(reader)

    def test_from_cbor_with_invalid_first_element_raises_error(self):
        """Test that from_cbor raises error with invalid first element."""
        reader = CborReader.from_hex("82ff")
        with pytest.raises(CardanoError):
            ExUnitPrices.from_cbor(reader)

    def test_from_cbor_with_invalid_memory_element_raises_error(self):
        """Test that from_cbor raises error with invalid memory element."""
        reader = CborReader.from_hex("82d81ea20102d81e820103")
        with pytest.raises(CardanoError):
            ExUnitPrices.from_cbor(reader)

    def test_from_cbor_with_invalid_steps_element_raises_error(self):
        """Test that from_cbor raises error with invalid steps element."""
        reader = CborReader.from_hex("82d81e820102d81ea20103")
        with pytest.raises(CardanoError):
            ExUnitPrices.from_cbor(reader)

    def test_cbor_roundtrip(self, memory_price, steps_price):
        """Test CBOR serialization/deserialization roundtrip."""
        original = ExUnitPrices.new(memory_price, steps_price)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        restored = ExUnitPrices.from_cbor(reader)

        assert restored.memory_prices.numerator == original.memory_prices.numerator
        assert restored.memory_prices.denominator == original.memory_prices.denominator
        assert restored.steps_prices.numerator == original.steps_prices.numerator
        assert restored.steps_prices.denominator == original.steps_prices.denominator

    def test_to_cip116_json_produces_correct_output(self):
        """Test CIP-116 JSON serialization."""
        mem_price = UnitInterval.new(1, 2)
        step_price = UnitInterval.new(3, 4)
        prices = ExUnitPrices.new(mem_price, step_price)

        writer = JsonWriter(JsonFormat.COMPACT)
        prices.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"mem_price":{"numerator":"1","denominator":"2"},"step_price":{"numerator":"3","denominator":"4"}}'
        assert json_str == expected

    def test_to_cip116_json_with_none_writer_raises_error(self, memory_price, steps_price):
        """Test that to_cip116_json raises error when writer is None."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError)):
            prices.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_type_raises_error(self, memory_price, steps_price):
        """Test that to_cip116_json raises error when writer has wrong type."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        with pytest.raises((CardanoError, TypeError)):
            prices.to_cip116_json("invalid")

    def test_repr(self, memory_price, steps_price):
        """Test string representation."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        repr_str = repr(prices)

        assert "ExUnitPrices" in repr_str
        assert "memory" in repr_str
        assert "steps" in repr_str

    def test_context_manager(self, memory_price, steps_price):
        """Test context manager support."""
        with ExUnitPrices.new(memory_price, steps_price) as prices:
            assert prices is not None
            mem = prices.memory_prices
            assert mem.numerator == 1
            assert mem.denominator == 2

    def test_multiple_instances_independent(self):
        """Test that multiple instances are independent."""
        prices1 = ExUnitPrices.new(UnitInterval.new(1, 2), UnitInterval.new(1, 3))
        prices2 = ExUnitPrices.new(UnitInterval.new(2, 5), UnitInterval.new(3, 7))

        assert prices1.memory_prices.numerator != prices2.memory_prices.numerator
        assert prices1.steps_prices.numerator != prices2.steps_prices.numerator

        prices1.memory_prices = UnitInterval.new(10, 20)

        assert prices1.memory_prices.numerator == 10
        assert prices2.memory_prices.numerator == 2

    def test_equality_after_modification(self, memory_price, steps_price):
        """Test that modifications persist correctly."""
        prices = ExUnitPrices.new(memory_price, steps_price)

        new_mem = UnitInterval.new(5, 10)
        new_steps = UnitInterval.new(7, 14)

        prices.memory_prices = new_mem
        prices.steps_prices = new_steps

        retrieved_mem = prices.memory_prices
        retrieved_steps = prices.steps_prices

        assert retrieved_mem.numerator == 5
        assert retrieved_mem.denominator == 10
        assert retrieved_steps.numerator == 7
        assert retrieved_steps.denominator == 14

    def test_realistic_mainnet_values(self):
        """Test with realistic mainnet-like values."""
        mem_price = UnitInterval.new(577, 10000)
        step_price = UnitInterval.new(721, 10000000)
        prices = ExUnitPrices.new(mem_price, step_price)

        assert prices.memory_prices.numerator == 577
        assert prices.memory_prices.denominator == 10000
        assert prices.steps_prices.numerator == 721
        assert prices.steps_prices.denominator == 10000000

        writer = CborWriter()
        prices.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        restored = ExUnitPrices.from_cbor(reader)

        assert restored.memory_prices.numerator == 577
        assert restored.steps_prices.numerator == 721

    def test_zero_numerator_values(self):
        """Test with zero numerator values."""
        mem_price = UnitInterval.new(0, 1)
        step_price = UnitInterval.new(0, 1)
        prices = ExUnitPrices.new(mem_price, step_price)

        assert prices.memory_prices.numerator == 0
        assert prices.steps_prices.numerator == 0

    def test_large_denominator_values(self):
        """Test with large denominator values."""
        mem_price = UnitInterval.new(1, 1000000000)
        step_price = UnitInterval.new(1, 1000000000)
        prices = ExUnitPrices.new(mem_price, step_price)

        assert prices.memory_prices.denominator == 1000000000
        assert prices.steps_prices.denominator == 1000000000
