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
from cometa import JsonObjectType


class TestJsonObjectType:
    """Tests for the JsonObjectType enum."""

    def test_json_object_type_values(self):
        """Test that JsonObjectType enum values are correct."""
        assert JsonObjectType.OBJECT == 0
        assert JsonObjectType.ARRAY == 1
        assert JsonObjectType.STRING == 2
        assert JsonObjectType.NUMBER == 3
        assert JsonObjectType.BOOLEAN == 4
        assert JsonObjectType.NULL == 5

    def test_json_object_type_from_int(self):
        """Test creating JsonObjectType from integer values."""
        assert JsonObjectType(0) == JsonObjectType.OBJECT
        assert JsonObjectType(1) == JsonObjectType.ARRAY
        assert JsonObjectType(2) == JsonObjectType.STRING
        assert JsonObjectType(3) == JsonObjectType.NUMBER
        assert JsonObjectType(4) == JsonObjectType.BOOLEAN
        assert JsonObjectType(5) == JsonObjectType.NULL

    def test_json_object_type_comparison(self):
        """Test comparison between JsonObjectType values."""
        assert JsonObjectType.OBJECT != JsonObjectType.ARRAY
        assert JsonObjectType.OBJECT == JsonObjectType.OBJECT
        assert JsonObjectType.ARRAY == JsonObjectType.ARRAY
        assert JsonObjectType.STRING == JsonObjectType.STRING
        assert JsonObjectType.NUMBER == JsonObjectType.NUMBER
        assert JsonObjectType.BOOLEAN == JsonObjectType.BOOLEAN
        assert JsonObjectType.NULL == JsonObjectType.NULL

    def test_json_object_type_names(self):
        """Test that JsonObjectType enum has correct names."""
        assert JsonObjectType.OBJECT.name == "OBJECT"
        assert JsonObjectType.ARRAY.name == "ARRAY"
        assert JsonObjectType.STRING.name == "STRING"
        assert JsonObjectType.NUMBER.name == "NUMBER"
        assert JsonObjectType.BOOLEAN.name == "BOOLEAN"
        assert JsonObjectType.NULL.name == "NULL"

    def test_json_object_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            JsonObjectType(6)
        with pytest.raises(ValueError):
            JsonObjectType(-1)
        with pytest.raises(ValueError):
            JsonObjectType(100)
        with pytest.raises(ValueError):
            JsonObjectType(999)

    def test_json_object_type_is_int_enum(self):
        """Test that JsonObjectType values can be used as integers."""
        assert isinstance(JsonObjectType.OBJECT, int)
        assert isinstance(JsonObjectType.ARRAY, int)
        assert isinstance(JsonObjectType.STRING, int)
        assert isinstance(JsonObjectType.NUMBER, int)
        assert isinstance(JsonObjectType.BOOLEAN, int)
        assert isinstance(JsonObjectType.NULL, int)
        assert JsonObjectType.OBJECT + 1 == 1
        assert JsonObjectType.ARRAY - 1 == 0
        assert JsonObjectType.NULL - 3 == 2

    def test_json_object_type_iteration(self):
        """Test iteration over JsonObjectType enum."""
        values = list(JsonObjectType)
        assert len(values) == 6
        assert JsonObjectType.OBJECT in values
        assert JsonObjectType.ARRAY in values
        assert JsonObjectType.STRING in values
        assert JsonObjectType.NUMBER in values
        assert JsonObjectType.BOOLEAN in values
        assert JsonObjectType.NULL in values

    def test_json_object_type_membership(self):
        """Test membership testing with JsonObjectType."""
        assert 0 in JsonObjectType.__members__.values()
        assert 1 in JsonObjectType.__members__.values()
        assert 2 in JsonObjectType.__members__.values()
        assert 3 in JsonObjectType.__members__.values()
        assert 4 in JsonObjectType.__members__.values()
        assert 5 in JsonObjectType.__members__.values()
        assert "OBJECT" in JsonObjectType.__members__
        assert "ARRAY" in JsonObjectType.__members__
        assert "STRING" in JsonObjectType.__members__
        assert "NUMBER" in JsonObjectType.__members__
        assert "BOOLEAN" in JsonObjectType.__members__
        assert "NULL" in JsonObjectType.__members__

    def test_json_object_type_string_representation(self):
        """Test string representation of JsonObjectType values."""
        assert str(JsonObjectType.OBJECT) == "JsonObjectType.OBJECT"
        assert str(JsonObjectType.ARRAY) == "JsonObjectType.ARRAY"
        assert str(JsonObjectType.STRING) == "JsonObjectType.STRING"
        assert str(JsonObjectType.NUMBER) == "JsonObjectType.NUMBER"
        assert str(JsonObjectType.BOOLEAN) == "JsonObjectType.BOOLEAN"
        assert str(JsonObjectType.NULL) == "JsonObjectType.NULL"

    def test_json_object_type_repr(self):
        """Test repr of JsonObjectType values."""
        assert repr(JsonObjectType.OBJECT) == "<JsonObjectType.OBJECT: 0>"
        assert repr(JsonObjectType.ARRAY) == "<JsonObjectType.ARRAY: 1>"
        assert repr(JsonObjectType.STRING) == "<JsonObjectType.STRING: 2>"
        assert repr(JsonObjectType.NUMBER) == "<JsonObjectType.NUMBER: 3>"
        assert repr(JsonObjectType.BOOLEAN) == "<JsonObjectType.BOOLEAN: 4>"
        assert repr(JsonObjectType.NULL) == "<JsonObjectType.NULL: 5>"

    def test_json_object_type_bool_conversion(self):
        """Test boolean conversion of JsonObjectType values."""
        assert bool(JsonObjectType.OBJECT) is False
        assert bool(JsonObjectType.ARRAY) is True
        assert bool(JsonObjectType.STRING) is True
        assert bool(JsonObjectType.NUMBER) is True
        assert bool(JsonObjectType.BOOLEAN) is True
        assert bool(JsonObjectType.NULL) is True

    def test_json_object_type_arithmetic(self):
        """Test arithmetic operations with JsonObjectType values."""
        assert JsonObjectType.OBJECT + JsonObjectType.ARRAY == 1
        assert JsonObjectType.ARRAY + JsonObjectType.STRING == 3
        assert JsonObjectType.NULL - JsonObjectType.BOOLEAN == 1
        assert JsonObjectType.STRING * 2 == 4
        assert JsonObjectType.NUMBER // 3 == 1
        assert JsonObjectType.BOOLEAN % 3 == 1

    def test_json_object_type_hash(self):
        """Test that JsonObjectType values are hashable."""
        json_type_set = {
            JsonObjectType.OBJECT,
            JsonObjectType.ARRAY,
            JsonObjectType.STRING,
            JsonObjectType.NUMBER,
            JsonObjectType.BOOLEAN,
            JsonObjectType.NULL
        }
        assert len(json_type_set) == 6
        assert JsonObjectType.OBJECT in json_type_set
        assert JsonObjectType.ARRAY in json_type_set
        assert JsonObjectType.STRING in json_type_set
        assert JsonObjectType.NUMBER in json_type_set
        assert JsonObjectType.BOOLEAN in json_type_set
        assert JsonObjectType.NULL in json_type_set

    def test_json_object_type_as_dict_key(self):
        """Test using JsonObjectType as dictionary key."""
        json_type_dict = {
            JsonObjectType.OBJECT: "object",
            JsonObjectType.ARRAY: "array",
            JsonObjectType.STRING: "string",
            JsonObjectType.NUMBER: "number",
            JsonObjectType.BOOLEAN: "boolean",
            JsonObjectType.NULL: "null"
        }
        assert json_type_dict[JsonObjectType.OBJECT] == "object"
        assert json_type_dict[JsonObjectType.ARRAY] == "array"
        assert json_type_dict[JsonObjectType.STRING] == "string"
        assert json_type_dict[JsonObjectType.NUMBER] == "number"
        assert json_type_dict[JsonObjectType.BOOLEAN] == "boolean"
        assert json_type_dict[JsonObjectType.NULL] == "null"

    def test_json_object_type_ordering(self):
        """Test ordering comparison between JsonObjectType values."""
        assert JsonObjectType.OBJECT < JsonObjectType.ARRAY
        assert JsonObjectType.ARRAY < JsonObjectType.STRING
        assert JsonObjectType.STRING < JsonObjectType.NUMBER
        assert JsonObjectType.NUMBER < JsonObjectType.BOOLEAN
        assert JsonObjectType.BOOLEAN < JsonObjectType.NULL
        assert JsonObjectType.NULL > JsonObjectType.OBJECT
        assert JsonObjectType.OBJECT <= JsonObjectType.OBJECT
        assert JsonObjectType.NULL >= JsonObjectType.NULL

    def test_json_object_type_identity(self):
        """Test that enum members maintain identity."""
        obj1 = JsonObjectType.OBJECT
        obj2 = JsonObjectType.OBJECT
        assert obj1 is obj2

        arr1 = JsonObjectType.ARRAY
        arr2 = JsonObjectType(1)
        assert arr1 is arr2

    def test_json_object_type_all_members(self):
        """Test that all expected members exist."""
        members = list(JsonObjectType.__members__.keys())
        expected_members = ["OBJECT", "ARRAY", "STRING", "NUMBER", "BOOLEAN", "NULL"]
        assert sorted(members) == sorted(expected_members)

    def test_json_object_type_value_uniqueness(self):
        """Test that all enum values are unique."""
        values = [member.value for member in JsonObjectType]
        assert len(values) == len(set(values))

    def test_json_object_type_sequential_values(self):
        """Test that enum values are sequential starting from 0."""
        expected_values = [0, 1, 2, 3, 4, 5]
        actual_values = sorted([member.value for member in JsonObjectType])
        assert actual_values == expected_values


class TestJsonObjectTypeEdgeCases:
    """Tests for edge cases and invalid usage."""

    def test_cannot_modify_enum_value(self):
        """Test that enum values cannot be modified."""
        with pytest.raises(AttributeError):
            JsonObjectType.OBJECT = 10

    def test_enum_cannot_be_instantiated(self):
        """Test that JsonObjectType cannot be instantiated directly."""
        with pytest.raises(TypeError):
            JsonObjectType()

    def test_invalid_string_value(self):
        """Test that string values raise appropriate errors."""
        with pytest.raises(KeyError):
            JsonObjectType["INVALID"]

    def test_enum_type_checking(self):
        """Test type checking for JsonObjectType instances."""
        assert isinstance(JsonObjectType.OBJECT, JsonObjectType)
        assert isinstance(JsonObjectType.ARRAY, JsonObjectType)
        assert not isinstance(0, JsonObjectType)
        assert not isinstance("OBJECT", JsonObjectType)

    def test_comparison_with_non_enum(self):
        """Test comparison with non-enum values."""
        assert JsonObjectType.OBJECT == 0
        assert JsonObjectType.ARRAY == 1
        assert JsonObjectType.STRING != 0
        assert JsonObjectType.OBJECT != "OBJECT"

    def test_enum_in_container_operations(self):
        """Test using JsonObjectType in various container operations."""
        type_list = [JsonObjectType.OBJECT, JsonObjectType.ARRAY, JsonObjectType.STRING]
        assert len(type_list) == 3
        assert JsonObjectType.OBJECT in type_list
        assert JsonObjectType.NUMBER not in type_list

        type_tuple = (JsonObjectType.NUMBER, JsonObjectType.BOOLEAN, JsonObjectType.NULL)
        assert type_tuple[0] == JsonObjectType.NUMBER
        assert type_tuple[1] == JsonObjectType.BOOLEAN
        assert type_tuple[2] == JsonObjectType.NULL

    def test_enum_unpacking(self):
        """Test unpacking enum members."""
        obj, arr, string, *rest = JsonObjectType
        assert obj == JsonObjectType.OBJECT
        assert arr == JsonObjectType.ARRAY
        assert string == JsonObjectType.STRING
        assert len(rest) == 3

    def test_enum_max_min_values(self):
        """Test finding max and min values."""
        all_values = list(JsonObjectType)
        assert min(all_values) == JsonObjectType.OBJECT
        assert max(all_values) == JsonObjectType.NULL

    def test_enum_sorting(self):
        """Test sorting enum members."""
        unsorted = [
            JsonObjectType.NULL,
            JsonObjectType.OBJECT,
            JsonObjectType.STRING,
            JsonObjectType.ARRAY
        ]
        sorted_types = sorted(unsorted)
        assert sorted_types == [
            JsonObjectType.OBJECT,
            JsonObjectType.ARRAY,
            JsonObjectType.STRING,
            JsonObjectType.NULL
        ]
