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
from cometa import ExUnits, CborReader, CborWriter, JsonWriter, CardanoError


EX_UNITS_CBOR = "821b000086788ffc4e831b00015060e9e46451"


class TestExUnitsNew:
    """Tests for ExUnits.new() factory method."""

    def test_can_create_ex_units(self):
        """Test that ExUnits can be created with valid memory and cpu_steps."""
        ex_units = ExUnits.new(memory=147852369874563, cpu_steps=369852147852369)
        assert ex_units is not None
        assert ex_units.memory == 147852369874563
        assert ex_units.cpu_steps == 369852147852369

    def test_can_create_ex_units_with_zero_values(self):
        """Test that ExUnits can be created with zero values."""
        ex_units = ExUnits.new(memory=0, cpu_steps=0)
        assert ex_units is not None
        assert ex_units.memory == 0
        assert ex_units.cpu_steps == 0

    def test_can_create_ex_units_with_max_values(self):
        """Test that ExUnits can be created with maximum uint64 values."""
        max_uint64 = 18446744073709551615
        ex_units = ExUnits.new(memory=max_uint64, cpu_steps=max_uint64)
        assert ex_units is not None
        assert ex_units.memory == max_uint64
        assert ex_units.cpu_steps == max_uint64

    def test_raises_error_for_negative_memory(self):
        """Test that negative memory values raise an error."""
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            ExUnits.new(memory=-1, cpu_steps=100)

    def test_raises_error_for_negative_cpu_steps(self):
        """Test that negative cpu_steps values raise an error."""
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            ExUnits.new(memory=100, cpu_steps=-1)

    def test_raises_error_for_invalid_memory_type(self):
        """Test that invalid memory type raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            ExUnits.new(memory="invalid", cpu_steps=100)

    def test_raises_error_for_invalid_cpu_steps_type(self):
        """Test that invalid cpu_steps type raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            ExUnits.new(memory=100, cpu_steps="invalid")


class TestExUnitsCbor:
    """Tests for CBOR serialization/deserialization."""

    def test_can_serialize_to_cbor(self):
        """Test that ExUnits can be serialized to CBOR."""
        ex_units = ExUnits.new(memory=147852369874563, cpu_steps=369852147852369)
        writer = CborWriter()
        ex_units.to_cbor(writer)
        result = writer.to_hex()
        assert result == EX_UNITS_CBOR

    def test_can_deserialize_from_cbor(self):
        """Test that ExUnits can be deserialized from CBOR."""
        reader = CborReader.from_hex(EX_UNITS_CBOR)
        ex_units = ExUnits.from_cbor(reader)
        assert ex_units is not None
        assert ex_units.memory == 147852369874563
        assert ex_units.cpu_steps == 369852147852369

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        original = ExUnits.new(memory=123456, cpu_steps=789012)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ExUnits.from_cbor(reader)

        assert deserialized.memory == original.memory
        assert deserialized.cpu_steps == original.cpu_steps

    def test_to_cbor_raises_error_with_invalid_writer(self):
        """Test that to_cbor raises error with invalid writer."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ex_units.to_cbor(None)

    def test_from_cbor_raises_error_with_invalid_reader(self):
        """Test that from_cbor raises error with invalid reader."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ExUnits.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_array_size(self):
        """Test that from_cbor raises error with invalid CBOR array size."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            ExUnits.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_first_element(self):
        """Test that from_cbor raises error when first element is not uint."""
        reader = CborReader.from_hex("82ff")
        with pytest.raises(CardanoError):
            ExUnits.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_second_element(self):
        """Test that from_cbor raises error when second element is not uint."""
        reader = CborReader.from_hex("8200ff")
        with pytest.raises(CardanoError):
            ExUnits.from_cbor(reader)


class TestExUnitsProperties:
    """Tests for ExUnits properties (memory, cpu_steps)."""

    def test_get_memory_returns_correct_value(self):
        """Test that memory property returns the correct value."""
        ex_units = ExUnits.new(memory=147852369874563, cpu_steps=369852147852369)
        assert ex_units.memory == 147852369874563

    def test_get_cpu_steps_returns_correct_value(self):
        """Test that cpu_steps property returns the correct value."""
        ex_units = ExUnits.new(memory=147852369874563, cpu_steps=369852147852369)
        assert ex_units.cpu_steps == 369852147852369

    def test_set_memory_updates_value(self):
        """Test that memory property setter updates the value."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        ex_units.memory = 123456789
        assert ex_units.memory == 123456789

    def test_set_cpu_steps_updates_value(self):
        """Test that cpu_steps property setter updates the value."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        ex_units.cpu_steps = 987654321
        assert ex_units.cpu_steps == 987654321

    def test_set_memory_with_zero(self):
        """Test that memory can be set to zero."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        ex_units.memory = 0
        assert ex_units.memory == 0

    def test_set_cpu_steps_with_zero(self):
        """Test that cpu_steps can be set to zero."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        ex_units.cpu_steps = 0
        assert ex_units.cpu_steps == 0

    def test_set_memory_with_max_uint64(self):
        """Test that memory can be set to maximum uint64 value."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        max_uint64 = 18446744073709551615
        ex_units.memory = max_uint64
        assert ex_units.memory == max_uint64

    def test_set_cpu_steps_with_max_uint64(self):
        """Test that cpu_steps can be set to maximum uint64 value."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        max_uint64 = 18446744073709551615
        ex_units.cpu_steps = max_uint64
        assert ex_units.cpu_steps == max_uint64

    def test_set_memory_raises_error_for_negative(self):
        """Test that setting negative memory raises an error."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            ex_units.memory = -1

    def test_set_cpu_steps_raises_error_for_negative(self):
        """Test that setting negative cpu_steps raises an error."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            ex_units.cpu_steps = -1

    def test_set_memory_raises_error_for_invalid_type(self):
        """Test that setting memory with invalid type raises an error."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, TypeError)):
            ex_units.memory = "invalid"

    def test_set_cpu_steps_raises_error_for_invalid_type(self):
        """Test that setting cpu_steps with invalid type raises an error."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, TypeError)):
            ex_units.cpu_steps = "invalid"


class TestExUnitsJson:
    """Tests for JSON serialization."""

    def test_to_cip116_json_produces_correct_format(self):
        """Test that to_cip116_json produces correct CIP-116 format."""
        ex_units = ExUnits.new(memory=123, cpu_steps=456)
        writer = JsonWriter()
        ex_units.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"mem":"123"' in json_str
        assert '"steps":"456"' in json_str

    def test_to_cip116_json_with_zero_values(self):
        """Test that to_cip116_json works with zero values."""
        ex_units = ExUnits.new(memory=0, cpu_steps=0)
        writer = JsonWriter()
        ex_units.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"mem":"0"' in json_str
        assert '"steps":"0"' in json_str

    def test_to_cip116_json_with_large_values(self):
        """Test that to_cip116_json works with large values."""
        ex_units = ExUnits.new(memory=147852369874563, cpu_steps=369852147852369)
        writer = JsonWriter()
        ex_units.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"mem":"147852369874563"' in json_str
        assert '"steps":"369852147852369"' in json_str

    def test_to_cip116_json_raises_error_with_invalid_writer(self):
        """Test that to_cip116_json raises error with invalid writer."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, TypeError)):
            ex_units.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_wrong_writer_type(self):
        """Test that to_cip116_json raises error with wrong writer type."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with pytest.raises((CardanoError, TypeError)):
            ex_units.to_cip116_json("not a writer")


class TestExUnitsMagicMethods:
    """Tests for magic methods (__eq__, __hash__, __repr__, __str__)."""

    def test_equality_with_same_values(self):
        """Test that two ExUnits with same values are equal."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=100, cpu_steps=200)
        assert ex_units1 == ex_units2

    def test_inequality_with_different_memory(self):
        """Test that ExUnits with different memory are not equal."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=101, cpu_steps=200)
        assert ex_units1 != ex_units2

    def test_inequality_with_different_cpu_steps(self):
        """Test that ExUnits with different cpu_steps are not equal."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=100, cpu_steps=201)
        assert ex_units1 != ex_units2

    def test_inequality_with_non_ex_units_object(self):
        """Test that ExUnits is not equal to non-ExUnits objects."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        assert ex_units != "not an ExUnits"
        assert ex_units != 123
        assert ex_units != None

    def test_hash_consistency(self):
        """Test that hash is consistent for the same object."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        hash1 = hash(ex_units)
        hash2 = hash(ex_units)
        assert hash1 == hash2

    def test_hash_equality_for_equal_objects(self):
        """Test that equal ExUnits have the same hash."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=100, cpu_steps=200)
        assert hash(ex_units1) == hash(ex_units2)

    def test_can_use_in_set(self):
        """Test that ExUnits can be used in a set."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units3 = ExUnits.new(memory=200, cpu_steps=300)

        ex_units_set = {ex_units1, ex_units2, ex_units3}
        assert len(ex_units_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that ExUnits can be used as a dictionary key."""
        ex_units1 = ExUnits.new(memory=100, cpu_steps=200)
        ex_units2 = ExUnits.new(memory=100, cpu_steps=200)

        ex_units_dict = {ex_units1: "value1"}
        ex_units_dict[ex_units2] = "value2"

        assert len(ex_units_dict) == 1
        assert ex_units_dict[ex_units1] == "value2"

    def test_repr_contains_memory_and_cpu_steps(self):
        """Test that __repr__ contains memory and cpu_steps values."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        repr_str = repr(ex_units)
        assert "ExUnits" in repr_str
        assert "memory=100" in repr_str
        assert "cpu_steps=200" in repr_str

    def test_str_contains_memory_and_cpu_steps(self):
        """Test that __str__ contains memory and cpu_steps values."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        str_repr = str(ex_units)
        assert "mem:" in str_repr or "100" in str_repr
        assert "steps:" in str_repr or "200" in str_repr


class TestExUnitsContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that ExUnits can be used as a context manager."""
        with ExUnits.new(memory=100, cpu_steps=200) as ex_units:
            assert ex_units is not None
            assert ex_units.memory == 100
            assert ex_units.cpu_steps == 200

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        with ex_units:
            pass


class TestExUnitsEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_property_updates(self):
        """Test that multiple property updates work correctly."""
        ex_units = ExUnits.new(memory=100, cpu_steps=200)
        ex_units.memory = 300
        ex_units.cpu_steps = 400
        ex_units.memory = 500
        ex_units.cpu_steps = 600
        assert ex_units.memory == 500
        assert ex_units.cpu_steps == 600

    def test_create_modify_serialize_deserialize(self):
        """Test complete workflow: create, modify, serialize, deserialize."""
        original = ExUnits.new(memory=100, cpu_steps=200)
        original.memory = 300
        original.cpu_steps = 400

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ExUnits.from_cbor(reader)

        assert deserialized.memory == 300
        assert deserialized.cpu_steps == 400

    def test_json_and_cbor_serialization_consistency(self):
        """Test that both JSON and CBOR serialization work on same object."""
        ex_units = ExUnits.new(memory=123, cpu_steps=456)

        cbor_writer = CborWriter()
        ex_units.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        ex_units.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert '"mem":"123"' in json_str
        assert '"steps":"456"' in json_str
