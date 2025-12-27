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
from cometa import CborMajorType


class TestCborMajorType:
    """Tests for the CborMajorType enum."""

    def test_unsigned_integer_value(self):
        """Test that UNSIGNED_INTEGER has the correct value."""
        assert CborMajorType.UNSIGNED_INTEGER == 0

    def test_negative_integer_value(self):
        """Test that NEGATIVE_INTEGER has the correct value."""
        assert CborMajorType.NEGATIVE_INTEGER == 1

    def test_byte_string_value(self):
        """Test that BYTE_STRING has the correct value."""
        assert CborMajorType.BYTE_STRING == 2

    def test_utf8_string_value(self):
        """Test that UTF8_STRING has the correct value."""
        assert CborMajorType.UTF8_STRING == 3

    def test_array_value(self):
        """Test that ARRAY has the correct value."""
        assert CborMajorType.ARRAY == 4

    def test_map_value(self):
        """Test that MAP has the correct value."""
        assert CborMajorType.MAP == 5

    def test_tag_value(self):
        """Test that TAG has the correct value."""
        assert CborMajorType.TAG == 6

    def test_simple_value(self):
        """Test that SIMPLE has the correct value."""
        assert CborMajorType.SIMPLE == 7

    def test_undefined_value(self):
        """Test that UNDEFINED has the correct value."""
        assert CborMajorType.UNDEFINED == 0xFFFFFFFF


class TestCborMajorTypeToString:
    """Tests for the to_string() method of CborMajorType."""

    def test_unsigned_integer_to_string(self):
        """Test converting UNSIGNED_INTEGER to string."""
        major_type = CborMajorType.UNSIGNED_INTEGER
        result = major_type.to_string()
        assert result == "Major Type: Unsigned Integer"

    def test_negative_integer_to_string(self):
        """Test converting NEGATIVE_INTEGER to string."""
        major_type = CborMajorType.NEGATIVE_INTEGER
        result = major_type.to_string()
        assert result == "Major Type: Negative Integer"

    def test_byte_string_to_string(self):
        """Test converting BYTE_STRING to string."""
        major_type = CborMajorType.BYTE_STRING
        result = major_type.to_string()
        assert result == "Major Type: Byte String"

    def test_utf8_string_to_string(self):
        """Test converting UTF8_STRING to string."""
        major_type = CborMajorType.UTF8_STRING
        result = major_type.to_string()
        assert result == "Major Type: UTF-8 String"

    def test_array_to_string(self):
        """Test converting ARRAY to string."""
        major_type = CborMajorType.ARRAY
        result = major_type.to_string()
        assert result == "Major Type: Array"

    def test_map_to_string(self):
        """Test converting MAP to string."""
        major_type = CborMajorType.MAP
        result = major_type.to_string()
        assert result == "Major Type: Map"

    def test_tag_to_string(self):
        """Test converting TAG to string."""
        major_type = CborMajorType.TAG
        result = major_type.to_string()
        assert result == "Major Type: Tag"

    def test_simple_to_string(self):
        """Test converting SIMPLE to string."""
        major_type = CborMajorType.SIMPLE
        result = major_type.to_string()
        assert result == "Major Type: Simple"

    def test_undefined_to_string(self):
        """Test converting UNDEFINED to string."""
        major_type = CborMajorType.UNDEFINED
        result = major_type.to_string()
        assert result == "Major Type: Unknown"

    def test_all_enum_members_have_to_string(self):
        """Test that all enum members can be converted to string without error."""
        for major_type in CborMajorType:
            result = major_type.to_string()
            assert isinstance(result, str)
            assert len(result) > 0


class TestCborMajorTypeEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert CborMajorType.UNSIGNED_INTEGER == CborMajorType.UNSIGNED_INTEGER
        assert CborMajorType.UNSIGNED_INTEGER != CborMajorType.NEGATIVE_INTEGER

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        mt1 = CborMajorType.UNSIGNED_INTEGER
        mt2 = CborMajorType.UNSIGNED_INTEGER
        assert mt1 is mt2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(CborMajorType.UNSIGNED_INTEGER) == 0
        assert int(CborMajorType.SIMPLE) == 7

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_types = list(CborMajorType)
        assert len(all_types) == 9
        assert CborMajorType.UNSIGNED_INTEGER in all_types
        assert CborMajorType.UNDEFINED in all_types

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert CborMajorType.UNSIGNED_INTEGER in CborMajorType
        assert CborMajorType.ARRAY in CborMajorType
        assert CborMajorType.UNDEFINED in CborMajorType

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert CborMajorType.UNSIGNED_INTEGER.name == "UNSIGNED_INTEGER"
        assert CborMajorType.BYTE_STRING.name == "BYTE_STRING"
        assert CborMajorType.UNDEFINED.name == "UNDEFINED"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert CborMajorType.UNSIGNED_INTEGER.value == 0
        assert CborMajorType.NEGATIVE_INTEGER.value == 1
        assert CborMajorType.UNDEFINED.value == 0xFFFFFFFF

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert CborMajorType(0) == CborMajorType.UNSIGNED_INTEGER
        assert CborMajorType(7) == CborMajorType.SIMPLE
        assert CborMajorType(0xFFFFFFFF) == CborMajorType.UNDEFINED

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborMajorType(100)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            CborMajorType(-1)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(CborMajorType.UNSIGNED_INTEGER) == "CborMajorType.UNSIGNED_INTEGER"
        assert repr(CborMajorType.ARRAY) == "<CborMajorType.ARRAY: 4>"
