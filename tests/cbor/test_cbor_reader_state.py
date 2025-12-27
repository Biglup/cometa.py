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
from cometa import CborReaderState


class TestCborReaderState:
    """Tests for the CborReaderState enum."""

    def test_undefined_value(self):
        """Test that UNDEFINED has the correct value."""
        assert CborReaderState.UNDEFINED == 0

    def test_unsigned_integer_value(self):
        """Test that UNSIGNED_INTEGER has the correct value."""
        assert CborReaderState.UNSIGNED_INTEGER == 1

    def test_negative_integer_value(self):
        """Test that NEGATIVE_INTEGER has the correct value."""
        assert CborReaderState.NEGATIVE_INTEGER == 2

    def test_bytestring_value(self):
        """Test that BYTESTRING has the correct value."""
        assert CborReaderState.BYTESTRING == 3

    def test_start_indefinite_length_bytestring_value(self):
        """Test that START_INDEFINITE_LENGTH_BYTESTRING has the correct value."""
        assert CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING == 4

    def test_end_indefinite_length_bytestring_value(self):
        """Test that END_INDEFINITE_LENGTH_BYTESTRING has the correct value."""
        assert CborReaderState.END_INDEFINITE_LENGTH_BYTESTRING == 5

    def test_textstring_value(self):
        """Test that TEXTSTRING has the correct value."""
        assert CborReaderState.TEXTSTRING == 6

    def test_start_indefinite_length_textstring_value(self):
        """Test that START_INDEFINITE_LENGTH_TEXTSTRING has the correct value."""
        assert CborReaderState.START_INDEFINITE_LENGTH_TEXTSTRING == 7

    def test_end_indefinite_length_textstring_value(self):
        """Test that END_INDEFINITE_LENGTH_TEXTSTRING has the correct value."""
        assert CborReaderState.END_INDEFINITE_LENGTH_TEXTSTRING == 8

    def test_start_array_value(self):
        """Test that START_ARRAY has the correct value."""
        assert CborReaderState.START_ARRAY == 9

    def test_end_array_value(self):
        """Test that END_ARRAY has the correct value."""
        assert CborReaderState.END_ARRAY == 10

    def test_start_map_value(self):
        """Test that START_MAP has the correct value."""
        assert CborReaderState.START_MAP == 11

    def test_end_map_value(self):
        """Test that END_MAP has the correct value."""
        assert CborReaderState.END_MAP == 12

    def test_tag_value(self):
        """Test that TAG has the correct value."""
        assert CborReaderState.TAG == 13

    def test_simple_value_value(self):
        """Test that SIMPLE_VALUE has the correct value."""
        assert CborReaderState.SIMPLE_VALUE == 14

    def test_half_precision_float_value(self):
        """Test that HALF_PRECISION_FLOAT has the correct value."""
        assert CborReaderState.HALF_PRECISION_FLOAT == 15

    def test_single_precision_float_value(self):
        """Test that SINGLE_PRECISION_FLOAT has the correct value."""
        assert CborReaderState.SINGLE_PRECISION_FLOAT == 16

    def test_double_precision_float_value(self):
        """Test that DOUBLE_PRECISION_FLOAT has the correct value."""
        assert CborReaderState.DOUBLE_PRECISION_FLOAT == 17

    def test_null_value(self):
        """Test that NULL has the correct value."""
        assert CborReaderState.NULL == 18

    def test_boolean_value(self):
        """Test that BOOLEAN has the correct value."""
        assert CborReaderState.BOOLEAN == 19

    def test_finished_value(self):
        """Test that FINISHED has the correct value."""
        assert CborReaderState.FINISHED == 20


class TestCborReaderStateToString:
    """Tests for the to_string() method of CborReaderState."""

    def test_undefined_to_string(self):
        """Test converting UNDEFINED to string."""
        state = CborReaderState.UNDEFINED
        result = state.to_string()
        assert result == "Reader State: Undefined"

    def test_unsigned_integer_to_string(self):
        """Test converting UNSIGNED_INTEGER to string."""
        state = CborReaderState.UNSIGNED_INTEGER
        result = state.to_string()
        assert result == "Reader State: Unsigned Integer"

    def test_negative_integer_to_string(self):
        """Test converting NEGATIVE_INTEGER to string."""
        state = CborReaderState.NEGATIVE_INTEGER
        result = state.to_string()
        assert result == "Reader State: Negative Integer"

    def test_bytestring_to_string(self):
        """Test converting BYTESTRING to string."""
        state = CborReaderState.BYTESTRING
        result = state.to_string()
        assert result == "Reader State: Byte String"

    def test_start_indefinite_length_bytestring_to_string(self):
        """Test converting START_INDEFINITE_LENGTH_BYTESTRING to string."""
        state = CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING
        result = state.to_string()
        assert result == "Reader State: Start Indefinite Length Byte String"

    def test_end_indefinite_length_bytestring_to_string(self):
        """Test converting END_INDEFINITE_LENGTH_BYTESTRING to string."""
        state = CborReaderState.END_INDEFINITE_LENGTH_BYTESTRING
        result = state.to_string()
        assert result == "Reader State: End Indefinite Length Byte String"

    def test_textstring_to_string(self):
        """Test converting TEXTSTRING to string."""
        state = CborReaderState.TEXTSTRING
        result = state.to_string()
        assert result == "Reader State: Text String"

    def test_start_indefinite_length_textstring_to_string(self):
        """Test converting START_INDEFINITE_LENGTH_TEXTSTRING to string."""
        state = CborReaderState.START_INDEFINITE_LENGTH_TEXTSTRING
        result = state.to_string()
        assert result == "Reader State: Start Indefinite Length Text String"

    def test_end_indefinite_length_textstring_to_string(self):
        """Test converting END_INDEFINITE_LENGTH_TEXTSTRING to string."""
        state = CborReaderState.END_INDEFINITE_LENGTH_TEXTSTRING
        result = state.to_string()
        assert result == "Reader State: End Indefinite Length Text String"

    def test_start_array_to_string(self):
        """Test converting START_ARRAY to string."""
        state = CborReaderState.START_ARRAY
        result = state.to_string()
        assert result == "Reader State: Start Array"

    def test_end_array_to_string(self):
        """Test converting END_ARRAY to string."""
        state = CborReaderState.END_ARRAY
        result = state.to_string()
        assert result == "Reader State: End Array"

    def test_start_map_to_string(self):
        """Test converting START_MAP to string."""
        state = CborReaderState.START_MAP
        result = state.to_string()
        assert result == "Reader State: Start Map"

    def test_end_map_to_string(self):
        """Test converting END_MAP to string."""
        state = CborReaderState.END_MAP
        result = state.to_string()
        assert result == "Reader State: End Map"

    def test_tag_to_string(self):
        """Test converting TAG to string."""
        state = CborReaderState.TAG
        result = state.to_string()
        assert result == "Reader State: Tag"

    def test_simple_value_to_string(self):
        """Test converting SIMPLE_VALUE to string."""
        state = CborReaderState.SIMPLE_VALUE
        result = state.to_string()
        assert result == "Reader State: Simple Value"

    def test_half_precision_float_to_string(self):
        """Test converting HALF_PRECISION_FLOAT to string."""
        state = CborReaderState.HALF_PRECISION_FLOAT
        result = state.to_string()
        assert result == "Reader State: Half-Precision Float"

    def test_single_precision_float_to_string(self):
        """Test converting SINGLE_PRECISION_FLOAT to string."""
        state = CborReaderState.SINGLE_PRECISION_FLOAT
        result = state.to_string()
        assert result == "Reader State: Single-Precision Float"

    def test_double_precision_float_to_string(self):
        """Test converting DOUBLE_PRECISION_FLOAT to string."""
        state = CborReaderState.DOUBLE_PRECISION_FLOAT
        result = state.to_string()
        assert result == "Reader State: Double-Precision Float"

    def test_null_to_string(self):
        """Test converting NULL to string."""
        state = CborReaderState.NULL
        result = state.to_string()
        assert result == "Reader State: Null"

    def test_boolean_to_string(self):
        """Test converting BOOLEAN to string."""
        state = CborReaderState.BOOLEAN
        result = state.to_string()
        assert result == "Reader State: Boolean"

    def test_finished_to_string(self):
        """Test converting FINISHED to string."""
        state = CborReaderState.FINISHED
        result = state.to_string()
        assert result == "Reader State: Finished"

    def test_unknown_state_to_string(self):
        """Test converting an unknown state to string by creating a mock state."""
        from cometa._ffi import lib, ffi
        result = ffi.string(lib.cardano_cbor_reader_state_to_string(10000)).decode("utf-8")
        assert result == "Reader State: Unknown"

    def test_all_enum_members_have_to_string(self):
        """Test that all enum members can be converted to string without error."""
        for state in CborReaderState:
            result = state.to_string()
            assert isinstance(result, str)
            assert len(result) > 0
            assert result.startswith("Reader State:")


class TestCborReaderStateEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert CborReaderState.UNDEFINED == CborReaderState.UNDEFINED
        assert CborReaderState.UNDEFINED != CborReaderState.UNSIGNED_INTEGER
        assert CborReaderState.START_ARRAY != CborReaderState.END_ARRAY

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        state1 = CborReaderState.UNSIGNED_INTEGER
        state2 = CborReaderState.UNSIGNED_INTEGER
        assert state1 is state2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(CborReaderState.UNDEFINED) == 0
        assert int(CborReaderState.UNSIGNED_INTEGER) == 1
        assert int(CborReaderState.FINISHED) == 20

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_states = list(CborReaderState)
        assert len(all_states) == 21
        assert CborReaderState.UNDEFINED in all_states
        assert CborReaderState.FINISHED in all_states
        assert CborReaderState.UNSIGNED_INTEGER in all_states

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert CborReaderState.UNDEFINED in CborReaderState
        assert CborReaderState.START_ARRAY in CborReaderState
        assert CborReaderState.FINISHED in CborReaderState
        assert CborReaderState.NULL in CborReaderState

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert CborReaderState.UNDEFINED.name == "UNDEFINED"
        assert CborReaderState.UNSIGNED_INTEGER.name == "UNSIGNED_INTEGER"
        assert CborReaderState.START_ARRAY.name == "START_ARRAY"
        assert CborReaderState.FINISHED.name == "FINISHED"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert CborReaderState.UNDEFINED.value == 0
        assert CborReaderState.UNSIGNED_INTEGER.value == 1
        assert CborReaderState.NEGATIVE_INTEGER.value == 2
        assert CborReaderState.FINISHED.value == 20

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert CborReaderState(0) == CborReaderState.UNDEFINED
        assert CborReaderState(1) == CborReaderState.UNSIGNED_INTEGER
        assert CborReaderState(9) == CborReaderState.START_ARRAY
        assert CborReaderState(20) == CborReaderState.FINISHED

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborReaderState(100)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            CborReaderState(-1)

    def test_invalid_value_large_positive(self):
        """Test that large invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborReaderState(10000)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(CborReaderState.UNDEFINED) == "CborReaderState.UNDEFINED"
        assert str(CborReaderState.START_ARRAY) == "CborReaderState.START_ARRAY"
        assert str(CborReaderState.FINISHED) == "CborReaderState.FINISHED"

    def test_repr_representation(self):
        """Test repr representation of enum members."""
        assert repr(CborReaderState.UNDEFINED) == "<CborReaderState.UNDEFINED: 0>"
        assert repr(CborReaderState.START_ARRAY) == "<CborReaderState.START_ARRAY: 9>"
        assert repr(CborReaderState.FINISHED) == "<CborReaderState.FINISHED: 20>"

    def test_enum_ordering(self):
        """Test that enum members can be ordered by their values."""
        assert CborReaderState.UNDEFINED.value < CborReaderState.UNSIGNED_INTEGER.value
        assert CborReaderState.UNSIGNED_INTEGER.value < CborReaderState.NEGATIVE_INTEGER.value
        assert CborReaderState.NEGATIVE_INTEGER.value < CborReaderState.FINISHED.value

    def test_enum_hash(self):
        """Test that enum members are hashable."""
        state_set = {
            CborReaderState.UNDEFINED,
            CborReaderState.UNSIGNED_INTEGER,
            CborReaderState.START_ARRAY
        }
        assert CborReaderState.UNDEFINED in state_set
        assert CborReaderState.UNSIGNED_INTEGER in state_set
        assert CborReaderState.FINISHED not in state_set

    def test_enum_dict_key(self):
        """Test that enum members can be used as dictionary keys."""
        state_dict = {
            CborReaderState.UNDEFINED: "undefined",
            CborReaderState.UNSIGNED_INTEGER: "uint",
            CborReaderState.START_ARRAY: "array_start"
        }
        assert state_dict[CborReaderState.UNDEFINED] == "undefined"
        assert state_dict[CborReaderState.UNSIGNED_INTEGER] == "uint"
        assert state_dict[CborReaderState.START_ARRAY] == "array_start"

    def test_enum_bool_conversion(self):
        """Test enum boolean conversion behavior."""
        assert bool(CborReaderState.UNDEFINED) is False
        for state in CborReaderState:
            if state != CborReaderState.UNDEFINED:
                assert bool(state) is True

    def test_enum_equality_with_int(self):
        """Test that enum members can be compared with their integer values."""
        assert CborReaderState.UNDEFINED == 0
        assert CborReaderState.UNSIGNED_INTEGER == 1
        assert CborReaderState.FINISHED == 20

    def test_sequential_values(self):
        """Test that most enum values are sequential starting from 0."""
        states_list = [
            CborReaderState.UNDEFINED,
            CborReaderState.UNSIGNED_INTEGER,
            CborReaderState.NEGATIVE_INTEGER,
            CborReaderState.BYTESTRING,
            CborReaderState.START_INDEFINITE_LENGTH_BYTESTRING,
            CborReaderState.END_INDEFINITE_LENGTH_BYTESTRING,
            CborReaderState.TEXTSTRING,
            CborReaderState.START_INDEFINITE_LENGTH_TEXTSTRING,
            CborReaderState.END_INDEFINITE_LENGTH_TEXTSTRING,
            CborReaderState.START_ARRAY,
            CborReaderState.END_ARRAY,
            CborReaderState.START_MAP,
            CborReaderState.END_MAP,
            CborReaderState.TAG,
            CborReaderState.SIMPLE_VALUE,
            CborReaderState.HALF_PRECISION_FLOAT,
            CborReaderState.SINGLE_PRECISION_FLOAT,
            CborReaderState.DOUBLE_PRECISION_FLOAT,
            CborReaderState.NULL,
            CborReaderState.BOOLEAN,
            CborReaderState.FINISHED
        ]
        for i, state in enumerate(states_list):
            assert state.value == i

    def test_all_cbor_major_types_represented(self):
        """Test that all major CBOR types have corresponding reader states."""
        assert CborReaderState.UNSIGNED_INTEGER.value == 1
        assert CborReaderState.NEGATIVE_INTEGER.value == 2
        assert CborReaderState.BYTESTRING.value == 3
        assert CborReaderState.TEXTSTRING.value == 6
        assert CborReaderState.START_ARRAY.value == 9
        assert CborReaderState.START_MAP.value == 11
        assert CborReaderState.TAG.value == 13

    def test_indefinite_length_states_exist(self):
        """Test that indefinite length states are properly defined."""
        assert hasattr(CborReaderState, "START_INDEFINITE_LENGTH_BYTESTRING")
        assert hasattr(CborReaderState, "END_INDEFINITE_LENGTH_BYTESTRING")
        assert hasattr(CborReaderState, "START_INDEFINITE_LENGTH_TEXTSTRING")
        assert hasattr(CborReaderState, "END_INDEFINITE_LENGTH_TEXTSTRING")

    def test_float_precision_states_exist(self):
        """Test that float precision states are properly defined."""
        assert hasattr(CborReaderState, "HALF_PRECISION_FLOAT")
        assert hasattr(CborReaderState, "SINGLE_PRECISION_FLOAT")
        assert hasattr(CborReaderState, "DOUBLE_PRECISION_FLOAT")

    def test_special_value_states_exist(self):
        """Test that special value states are properly defined."""
        assert hasattr(CborReaderState, "NULL")
        assert hasattr(CborReaderState, "BOOLEAN")
        assert hasattr(CborReaderState, "SIMPLE_VALUE")
