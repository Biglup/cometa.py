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
from cometa import CborSimpleValue


class TestCborSimpleValue:
    """Tests for the CborSimpleValue enum."""

    def test_false_value(self):
        """Test that FALSE has the correct value."""
        assert CborSimpleValue.FALSE == 20

    def test_true_value(self):
        """Test that TRUE has the correct value."""
        assert CborSimpleValue.TRUE == 21

    def test_null_value(self):
        """Test that NULL has the correct value."""
        assert CborSimpleValue.NULL == 22

    def test_undefined_value(self):
        """Test that UNDEFINED has the correct value."""
        assert CborSimpleValue.UNDEFINED == 23


class TestCborSimpleValueToString:
    """Tests for the to_string() method of CborSimpleValue."""

    def test_false_to_string(self):
        """Test converting FALSE to string."""
        simple_value = CborSimpleValue.FALSE
        result = simple_value.to_string()
        assert result == "Simple Value: False"

    def test_true_to_string(self):
        """Test converting TRUE to string."""
        simple_value = CborSimpleValue.TRUE
        result = simple_value.to_string()
        assert result == "Simple Value: True"

    def test_null_to_string(self):
        """Test converting NULL to string."""
        simple_value = CborSimpleValue.NULL
        result = simple_value.to_string()
        assert result == "Simple Value: Null"

    def test_undefined_to_string(self):
        """Test converting UNDEFINED to string."""
        simple_value = CborSimpleValue.UNDEFINED
        result = simple_value.to_string()
        assert result == "Simple Value: Undefined"

    def test_all_enum_members_have_to_string(self):
        """Test that all enum members can be converted to string without error."""
        for simple_value in CborSimpleValue:
            result = simple_value.to_string()
            assert isinstance(result, str)
            assert len(result) > 0


class TestCborSimpleValueEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert CborSimpleValue.FALSE == CborSimpleValue.FALSE
        assert CborSimpleValue.FALSE != CborSimpleValue.TRUE

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        sv1 = CborSimpleValue.FALSE
        sv2 = CborSimpleValue.FALSE
        assert sv1 is sv2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(CborSimpleValue.FALSE) == 20
        assert int(CborSimpleValue.TRUE) == 21
        assert int(CborSimpleValue.NULL) == 22
        assert int(CborSimpleValue.UNDEFINED) == 23

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_values = list(CborSimpleValue)
        assert len(all_values) == 4
        assert CborSimpleValue.FALSE in all_values
        assert CborSimpleValue.TRUE in all_values
        assert CborSimpleValue.NULL in all_values
        assert CborSimpleValue.UNDEFINED in all_values

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert CborSimpleValue.FALSE in CborSimpleValue
        assert CborSimpleValue.TRUE in CborSimpleValue
        assert CborSimpleValue.NULL in CborSimpleValue
        assert CborSimpleValue.UNDEFINED in CborSimpleValue

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert CborSimpleValue.FALSE.name == "FALSE"
        assert CborSimpleValue.TRUE.name == "TRUE"
        assert CborSimpleValue.NULL.name == "NULL"
        assert CborSimpleValue.UNDEFINED.name == "UNDEFINED"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert CborSimpleValue.FALSE.value == 20
        assert CborSimpleValue.TRUE.value == 21
        assert CborSimpleValue.NULL.value == 22
        assert CborSimpleValue.UNDEFINED.value == 23

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert CborSimpleValue(20) == CborSimpleValue.FALSE
        assert CborSimpleValue(21) == CborSimpleValue.TRUE
        assert CborSimpleValue(22) == CborSimpleValue.NULL
        assert CborSimpleValue(23) == CborSimpleValue.UNDEFINED

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborSimpleValue(100)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            CborSimpleValue(-1)

    def test_invalid_value_zero(self):
        """Test that zero raises ValueError."""
        with pytest.raises(ValueError):
            CborSimpleValue(0)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(CborSimpleValue.FALSE) == "CborSimpleValue.FALSE"
        assert repr(CborSimpleValue.TRUE) == "<CborSimpleValue.TRUE: 21>"
