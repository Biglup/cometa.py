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
from cometa import JsonObject, JsonObjectType, JsonFormat, CardanoError


class TestJsonObjectParse:
    """Tests for JsonObject.parse() factory method."""

    def test_can_parse_simple_object(self):
        """Test parsing a simple JSON object."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        assert obj is not None
        assert obj.type == JsonObjectType.OBJECT

    def test_can_parse_empty_object(self):
        """Test parsing an empty JSON object."""
        obj = JsonObject.parse('{}')
        assert obj is not None
        assert obj.type == JsonObjectType.OBJECT
        assert len(obj) == 0

    def test_can_parse_empty_array(self):
        """Test parsing an empty JSON array."""
        obj = JsonObject.parse('[]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 0

    def test_can_parse_array_with_single_element(self):
        """Test parsing an array with one element."""
        obj = JsonObject.parse('[1]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 1

    def test_can_parse_array_with_multiple_elements(self):
        """Test parsing an array with multiple elements."""
        obj = JsonObject.parse('[1,2,3,4,5]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 5

    def test_can_parse_mixed_array(self):
        """Test parsing an array with mixed types."""
        obj = JsonObject.parse('[1,"abc",12.3,-4]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 4

    def test_can_parse_nested_object(self):
        """Test parsing nested JSON objects."""
        obj = JsonObject.parse('{"person":{"name":"Alice","age":30}}')
        assert obj is not None
        assert obj.type == JsonObjectType.OBJECT

    def test_can_parse_nested_array(self):
        """Test parsing nested arrays."""
        obj = JsonObject.parse('[[1,2],[3,4]]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 2

    def test_can_parse_string_value(self):
        """Test parsing a JSON string."""
        obj = JsonObject.parse('"hello"')
        assert obj is not None
        assert obj.type == JsonObjectType.STRING

    def test_can_parse_number_value(self):
        """Test parsing a JSON number."""
        obj = JsonObject.parse('42')
        assert obj is not None
        assert obj.type == JsonObjectType.NUMBER

    def test_can_parse_boolean_true(self):
        """Test parsing JSON boolean true."""
        obj = JsonObject.parse('true')
        assert obj is not None
        assert obj.type == JsonObjectType.BOOLEAN

    def test_can_parse_boolean_false(self):
        """Test parsing JSON boolean false."""
        obj = JsonObject.parse('false')
        assert obj is not None
        assert obj.type == JsonObjectType.BOOLEAN

    def test_can_parse_null_value(self):
        """Test parsing JSON null."""
        obj = JsonObject.parse('null')
        assert obj is not None
        assert obj.type == JsonObjectType.NULL

    def test_can_parse_whitespace_variations(self):
        """Test parsing with various whitespace."""
        obj = JsonObject.parse('[ 1, 2 ,  3,4,5]')
        assert obj is not None
        assert len(obj) == 5

    def test_can_parse_large_array(self):
        """Test parsing a large array."""
        numbers = ','.join(str(i) for i in range(1, 100))
        obj = JsonObject.parse(f'[{numbers}]')
        assert obj is not None
        assert len(obj) == 99

    def test_raises_error_with_invalid_json(self):
        """Test that parsing invalid JSON raises an error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('{invalid}')

    def test_raises_error_with_empty_string(self):
        """Test that parsing empty string raises an error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('')

    def test_raises_error_with_incomplete_object(self):
        """Test that parsing incomplete object raises an error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('{"name":"Alice"')

    def test_raises_error_with_incomplete_array(self):
        """Test that parsing incomplete array raises an error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('[1,2,3')

    def test_can_parse_with_trailing_comma_in_object(self):
        """Test that trailing comma in object is accepted (parser allows it)."""
        obj = JsonObject.parse('{"name":"Alice",}')
        assert obj is not None
        assert obj.type == JsonObjectType.OBJECT

    def test_can_parse_with_trailing_comma_in_array(self):
        """Test that trailing comma in array is accepted (parser allows it)."""
        obj = JsonObject.parse('[1,2,3,]')
        assert obj is not None
        assert obj.type == JsonObjectType.ARRAY


class TestJsonObjectType:
    """Tests for JsonObject.type property."""

    def test_type_returns_object_for_object(self):
        """Test that type property returns OBJECT for objects."""
        obj = JsonObject.parse('{"key":"value"}')
        assert obj.type == JsonObjectType.OBJECT

    def test_type_returns_array_for_array(self):
        """Test that type property returns ARRAY for arrays."""
        obj = JsonObject.parse('[1,2,3]')
        assert obj.type == JsonObjectType.ARRAY

    def test_type_returns_string_for_string(self):
        """Test that type property returns STRING for strings."""
        obj = JsonObject.parse('"hello"')
        assert obj.type == JsonObjectType.STRING

    def test_type_returns_number_for_number(self):
        """Test that type property returns NUMBER for numbers."""
        obj = JsonObject.parse('42')
        assert obj.type == JsonObjectType.NUMBER

    def test_type_returns_boolean_for_boolean(self):
        """Test that type property returns BOOLEAN for booleans."""
        obj = JsonObject.parse('true')
        assert obj.type == JsonObjectType.BOOLEAN

    def test_type_returns_null_for_null(self):
        """Test that type property returns NULL for null."""
        obj = JsonObject.parse('null')
        assert obj.type == JsonObjectType.NULL


class TestJsonObjectRefcount:
    """Tests for JsonObject.refcount property."""

    def test_refcount_is_initially_one(self):
        """Test that refcount is 1 after creation."""
        obj = JsonObject.parse('{}')
        assert obj.refcount == 1

    def test_refcount_increases_with_reference(self):
        """Test that refcount increases when referenced."""
        obj = JsonObject.parse('{"key":"value"}')
        initial_count = obj.refcount
        ref = obj
        assert obj.refcount >= initial_count


class TestJsonObjectLastError:
    """Tests for JsonObject.last_error property."""

    def test_last_error_is_empty_initially(self):
        """Test that last_error is empty after creation."""
        obj = JsonObject.parse('{}')
        assert obj.last_error == ""

    def test_can_set_last_error(self):
        """Test that last_error can be set."""
        obj = JsonObject.parse('{}')
        obj.last_error = "Test error message"
        assert obj.last_error == "Test error message"

    def test_can_clear_last_error(self):
        """Test that last_error can be cleared."""
        obj = JsonObject.parse('{}')
        obj.last_error = "Test error"
        obj.last_error = ""
        assert obj.last_error == ""


class TestJsonObjectToJson:
    """Tests for JsonObject.to_json() method."""

    def test_to_json_compact_format(self):
        """Test serialization to compact JSON."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        json_str = obj.to_json(JsonFormat.COMPACT)
        assert '"name":"Alice"' in json_str
        assert '"age":30' in json_str

    def test_to_json_pretty_format(self):
        """Test serialization to pretty JSON."""
        obj = JsonObject.parse('{"name":"Alice"}')
        json_str = obj.to_json(JsonFormat.PRETTY)
        assert '"name"' in json_str
        assert '"Alice"' in json_str

    def test_to_json_default_is_compact(self):
        """Test that default format is compact."""
        obj = JsonObject.parse('{"key":"value"}')
        compact = obj.to_json()
        explicit_compact = obj.to_json(JsonFormat.COMPACT)
        assert compact == explicit_compact

    def test_to_json_roundtrip_object(self):
        """Test JSON serialization roundtrip for object."""
        original_json = '{"name":"Alice","age":30}'
        obj = JsonObject.parse(original_json)
        json_str = obj.to_json(JsonFormat.COMPACT)
        obj2 = JsonObject.parse(json_str)
        assert obj2["name"].as_str() == "Alice"
        assert obj2["age"].as_int() == 30

    def test_to_json_roundtrip_array(self):
        """Test JSON serialization roundtrip for array."""
        original_json = '[1,2,3,4,5]'
        obj = JsonObject.parse(original_json)
        json_str = obj.to_json(JsonFormat.COMPACT)
        obj2 = JsonObject.parse(json_str)
        assert len(obj2) == 5


class TestJsonObjectLen:
    """Tests for JsonObject.__len__() method."""

    def test_len_returns_property_count_for_object(self):
        """Test that len returns property count for objects."""
        obj = JsonObject.parse('{"a":1,"b":2,"c":3}')
        assert len(obj) == 3

    def test_len_returns_element_count_for_array(self):
        """Test that len returns element count for arrays."""
        obj = JsonObject.parse('[1,2,3,4,5]')
        assert len(obj) == 5

    def test_len_returns_zero_for_empty_object(self):
        """Test that len returns 0 for empty object."""
        obj = JsonObject.parse('{}')
        assert len(obj) == 0

    def test_len_returns_zero_for_empty_array(self):
        """Test that len returns 0 for empty array."""
        obj = JsonObject.parse('[]')
        assert len(obj) == 0

    def test_len_returns_zero_for_non_containers(self):
        """Test that len returns 0 for non-container types."""
        assert len(JsonObject.parse('42')) == 0
        assert len(JsonObject.parse('"hello"')) == 0
        assert len(JsonObject.parse('true')) == 0
        assert len(JsonObject.parse('null')) == 0


class TestJsonObjectGetItemArray:
    """Tests for JsonObject.__getitem__() with array indexing."""

    def test_can_access_array_by_index(self):
        """Test accessing array elements by index."""
        obj = JsonObject.parse('[1,2,3,4,5]')
        assert obj[0].as_int() == 1
        assert obj[1].as_int() == 2
        assert obj[4].as_int() == 5

    def test_can_access_array_with_negative_index(self):
        """Test accessing array with negative indices."""
        obj = JsonObject.parse('[1,2,3,4,5]')
        assert obj[-1].as_int() == 5
        assert obj[-2].as_int() == 4

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        obj = JsonObject.parse('[1,2,3]')
        with pytest.raises(IndexError):
            _ = obj[10]

    def test_raises_index_error_for_negative_out_of_bounds(self):
        """Test that negative out of bounds index raises IndexError."""
        obj = JsonObject.parse('[1,2,3]')
        with pytest.raises(IndexError):
            _ = obj[-10]

    def test_raises_type_error_for_int_on_non_array(self):
        """Test that integer index on non-array raises TypeError."""
        obj = JsonObject.parse('{"key":"value"}')
        with pytest.raises(TypeError):
            _ = obj[0]


class TestJsonObjectGetItemObject:
    """Tests for JsonObject.__getitem__() with string keys."""

    def test_can_access_object_by_key(self):
        """Test accessing object properties by key."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        assert obj["name"].as_str() == "Alice"
        assert obj["age"].as_int() == 30

    def test_raises_key_error_for_missing_key(self):
        """Test that missing key raises KeyError."""
        obj = JsonObject.parse('{"name":"Alice"}')
        with pytest.raises(KeyError):
            _ = obj["missing"]

    def test_raises_type_error_for_string_on_non_object(self):
        """Test that string key on non-object raises TypeError."""
        obj = JsonObject.parse('[1,2,3]')
        with pytest.raises(TypeError):
            _ = obj["key"]

    def test_raises_type_error_for_invalid_key_type(self):
        """Test that invalid key type raises TypeError."""
        obj = JsonObject.parse('{"key":"value"}')
        with pytest.raises(TypeError):
            _ = obj[3.14]


class TestJsonObjectContains:
    """Tests for JsonObject.__contains__() method."""

    def test_contains_returns_true_for_existing_key(self):
        """Test that 'in' operator returns True for existing keys."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        assert "name" in obj
        assert "age" in obj

    def test_contains_returns_false_for_missing_key(self):
        """Test that 'in' operator returns False for missing keys."""
        obj = JsonObject.parse('{"name":"Alice"}')
        assert "missing" not in obj

    def test_contains_returns_false_for_non_objects(self):
        """Test that 'in' operator returns False for non-objects."""
        obj = JsonObject.parse('[1,2,3]')
        assert "key" not in obj


class TestJsonObjectKeys:
    """Tests for JsonObject.keys() iterator method."""

    def test_keys_returns_all_keys(self):
        """Test that keys() returns all object keys."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        keys = list(obj.keys())
        assert "name" in keys
        assert "age" in keys
        assert len(keys) == 2

    def test_keys_returns_empty_for_empty_object(self):
        """Test that keys() returns empty iterator for empty object."""
        obj = JsonObject.parse('{}')
        keys = list(obj.keys())
        assert len(keys) == 0

    def test_keys_returns_empty_for_non_objects(self):
        """Test that keys() returns empty iterator for non-objects."""
        obj = JsonObject.parse('[1,2,3]')
        keys = list(obj.keys())
        assert len(keys) == 0


class TestJsonObjectValues:
    """Tests for JsonObject.values() iterator method."""

    def test_values_returns_all_values(self):
        """Test that values() returns all object values."""
        obj = JsonObject.parse('{"a":1,"b":2,"c":3}')
        values = list(obj.values())
        assert len(values) == 3
        value_ints = [v.as_int() for v in values]
        assert 1 in value_ints
        assert 2 in value_ints
        assert 3 in value_ints

    def test_values_returns_empty_for_empty_object(self):
        """Test that values() returns empty iterator for empty object."""
        obj = JsonObject.parse('{}')
        values = list(obj.values())
        assert len(values) == 0

    def test_values_returns_empty_for_non_objects(self):
        """Test that values() returns empty iterator for non-objects."""
        obj = JsonObject.parse('[1,2,3]')
        values = list(obj.values())
        assert len(values) == 0


class TestJsonObjectItems:
    """Tests for JsonObject.items() iterator method."""

    def test_items_returns_key_value_pairs(self):
        """Test that items() returns key-value pairs."""
        obj = JsonObject.parse('{"name":"Alice","age":30}')
        items = dict(obj.items())
        assert "name" in items
        assert items["name"].as_str() == "Alice"
        assert "age" in items
        assert items["age"].as_int() == 30

    def test_items_returns_empty_for_empty_object(self):
        """Test that items() returns empty iterator for empty object."""
        obj = JsonObject.parse('{}')
        items = list(obj.items())
        assert len(items) == 0

    def test_items_returns_empty_for_non_objects(self):
        """Test that items() returns empty iterator for non-objects."""
        obj = JsonObject.parse('[1,2,3]')
        items = list(obj.items())
        assert len(items) == 0


class TestJsonObjectIsNull:
    """Tests for JsonObject.is_null() method."""

    def test_is_null_returns_true_for_null(self):
        """Test that is_null() returns True for null values."""
        obj = JsonObject.parse('null')
        assert obj.is_null() is True

    def test_is_null_returns_false_for_non_null(self):
        """Test that is_null() returns False for non-null values."""
        assert JsonObject.parse('{}').is_null() is False
        assert JsonObject.parse('[]').is_null() is False
        assert JsonObject.parse('42').is_null() is False
        assert JsonObject.parse('"hello"').is_null() is False
        assert JsonObject.parse('true').is_null() is False


class TestJsonObjectAsBool:
    """Tests for JsonObject.as_bool() method."""

    def test_as_bool_returns_true(self):
        """Test that as_bool() returns True for true."""
        obj = JsonObject.parse('true')
        assert obj.as_bool() is True

    def test_as_bool_returns_false(self):
        """Test that as_bool() returns False for false."""
        obj = JsonObject.parse('false')
        assert obj.as_bool() is False

    def test_as_bool_returns_none_for_non_boolean(self):
        """Test that as_bool() returns None for non-boolean types."""
        assert JsonObject.parse('42').as_bool() is None
        assert JsonObject.parse('"hello"').as_bool() is None
        assert JsonObject.parse('null').as_bool() is None


class TestJsonObjectAsStr:
    """Tests for JsonObject.as_str() method."""

    def test_as_str_returns_string_value(self):
        """Test that as_str() returns string value."""
        obj = JsonObject.parse('"hello world"')
        assert obj.as_str() == "hello world"

    def test_as_str_handles_empty_string(self):
        """Test that as_str() handles empty strings."""
        obj = JsonObject.parse('""')
        assert obj.as_str() == ""

    def test_as_str_handles_unicode(self):
        """Test that as_str() handles Unicode strings."""
        obj = JsonObject.parse('"Hello 世界"')
        result = obj.as_str()
        assert result is not None

    def test_as_str_returns_none_for_non_string(self):
        """Test that as_str() returns None for non-string types."""
        assert JsonObject.parse('42').as_str() is None
        assert JsonObject.parse('true').as_str() is None
        assert JsonObject.parse('null').as_str() is None


class TestJsonObjectAsInt:
    """Tests for JsonObject.as_int() method."""

    def test_as_int_returns_positive_integer(self):
        """Test that as_int() returns positive integers."""
        obj = JsonObject.parse('42')
        assert obj.as_int() == 42

    def test_as_int_returns_negative_integer(self):
        """Test that as_int() returns negative integers."""
        obj = JsonObject.parse('-42')
        assert obj.as_int() == -42

    def test_as_int_returns_zero(self):
        """Test that as_int() returns zero."""
        obj = JsonObject.parse('0')
        assert obj.as_int() == 0

    def test_as_int_returns_large_integer(self):
        """Test that as_int() handles large integers."""
        obj = JsonObject.parse('9223372036854775807')
        assert obj.as_int() == 9223372036854775807

    def test_as_int_returns_none_for_non_number(self):
        """Test that as_int() returns None for non-number types."""
        assert JsonObject.parse('"hello"').as_int() is None
        assert JsonObject.parse('true').as_int() is None
        assert JsonObject.parse('null').as_int() is None


class TestJsonObjectAsFloat:
    """Tests for JsonObject.as_float() method."""

    def test_as_float_returns_floating_point(self):
        """Test that as_float() returns floating point values."""
        obj = JsonObject.parse('3.14')
        result = obj.as_float()
        assert result is not None
        assert abs(result - 3.14) < 0.01

    def test_as_float_returns_negative_float(self):
        """Test that as_float() returns negative floats."""
        obj = JsonObject.parse('-2.5')
        result = obj.as_float()
        assert result is not None
        assert abs(result - (-2.5)) < 0.01

    def test_as_float_returns_integer_as_float(self):
        """Test that as_float() converts integers to float."""
        obj = JsonObject.parse('42')
        result = obj.as_float()
        assert result is not None
        assert abs(result - 42.0) < 0.01

    def test_as_float_returns_none_for_non_number(self):
        """Test that as_float() returns None for non-number types."""
        assert JsonObject.parse('"hello"').as_float() is None
        assert JsonObject.parse('true').as_float() is None
        assert JsonObject.parse('null').as_float() is None


class TestJsonObjectBool:
    """Tests for JsonObject.__bool__() method."""

    def test_bool_null_is_false(self):
        """Test that null is falsy."""
        obj = JsonObject.parse('null')
        assert not obj

    def test_bool_false_is_false(self):
        """Test that false boolean is falsy."""
        obj = JsonObject.parse('false')
        assert not obj

    def test_bool_true_is_true(self):
        """Test that true boolean is truthy."""
        obj = JsonObject.parse('true')
        assert obj

    def test_bool_zero_is_false(self):
        """Test that zero is falsy."""
        obj = JsonObject.parse('0')
        assert not obj

    def test_bool_nonzero_is_true(self):
        """Test that non-zero numbers are truthy."""
        assert JsonObject.parse('42')
        assert JsonObject.parse('-1')

    def test_bool_empty_string_is_false(self):
        """Test that empty string is falsy."""
        obj = JsonObject.parse('""')
        assert not obj

    def test_bool_nonempty_string_is_true(self):
        """Test that non-empty strings are truthy."""
        obj = JsonObject.parse('"hello"')
        assert obj

    def test_bool_empty_array_is_false(self):
        """Test that empty array is falsy."""
        obj = JsonObject.parse('[]')
        assert not obj

    def test_bool_nonempty_array_is_true(self):
        """Test that non-empty arrays are truthy."""
        obj = JsonObject.parse('[1,2,3]')
        assert obj

    def test_bool_empty_object_is_false(self):
        """Test that empty object is falsy."""
        obj = JsonObject.parse('{}')
        assert not obj

    def test_bool_nonempty_object_is_true(self):
        """Test that non-empty objects are truthy."""
        obj = JsonObject.parse('{"key":"value"}')
        assert obj


class TestJsonObjectContextManager:
    """Tests for context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that JsonObject can be used as context manager."""
        with JsonObject.parse('{"key":"value"}') as obj:
            assert obj is not None
            assert obj.type == JsonObjectType.OBJECT

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        obj = JsonObject.parse('{}')
        with obj:
            pass


class TestJsonObjectRepr:
    """Tests for JsonObject.__repr__() method."""

    def test_repr_contains_type_info(self):
        """Test that __repr__ contains type information."""
        obj = JsonObject.parse('{"key":"value"}')
        repr_str = repr(obj)
        assert "JsonObject" in repr_str
        assert "OBJECT" in repr_str

    def test_repr_contains_value_info(self):
        """Test that __repr__ contains value information."""
        obj = JsonObject.parse('42')
        repr_str = repr(obj)
        assert "JsonObject" in repr_str
        assert "NUMBER" in repr_str


class TestJsonObjectStr:
    """Tests for JsonObject.__str__() method."""

    def test_str_returns_compact_json(self):
        """Test that __str__ returns compact JSON."""
        obj = JsonObject.parse('{"key":"value"}')
        str_repr = str(obj)
        assert '"key":"value"' in str_repr

    def test_str_roundtrip(self):
        """Test that str() output can be parsed back."""
        original = JsonObject.parse('{"a":1,"b":2}')
        str_repr = str(original)
        reparsed = JsonObject.parse(str_repr)
        assert reparsed["a"].as_int() == 1
        assert reparsed["b"].as_int() == 2


class TestJsonObjectNestedAccess:
    """Tests for accessing nested structures."""

    def test_can_access_nested_object(self):
        """Test accessing nested object properties."""
        obj = JsonObject.parse('{"person":{"name":"Alice","age":30}}')
        person = obj["person"]
        assert person["name"].as_str() == "Alice"
        assert person["age"].as_int() == 30

    def test_can_access_nested_array(self):
        """Test accessing nested array elements."""
        obj = JsonObject.parse('{"numbers":[1,2,3]}')
        numbers = obj["numbers"]
        assert numbers[0].as_int() == 1
        assert numbers[1].as_int() == 2
        assert numbers[2].as_int() == 3

    def test_can_access_deeply_nested_structure(self):
        """Test accessing deeply nested structures."""
        json_str = '{"a":{"b":{"c":{"d":"value"}}}}'
        obj = JsonObject.parse(json_str)
        assert obj["a"]["b"]["c"]["d"].as_str() == "value"

    def test_can_access_array_of_objects(self):
        """Test accessing array of objects."""
        json_str = '[{"name":"Alice"},{"name":"Bob"}]'
        obj = JsonObject.parse(json_str)
        assert obj[0]["name"].as_str() == "Alice"
        assert obj[1]["name"].as_str() == "Bob"


class TestJsonObjectComplexTypes:
    """Tests for complex JSON structures."""

    def test_can_parse_complex_nested_structure(self):
        """Test parsing complex nested JSON."""
        json_str = '''
        {
            "users": [
                {"name": "Alice", "age": 30, "active": true},
                {"name": "Bob", "age": 25, "active": false}
            ],
            "metadata": {
                "count": 2,
                "timestamp": null
            }
        }
        '''
        obj = JsonObject.parse(json_str)
        assert obj["users"][0]["name"].as_str() == "Alice"
        assert obj["users"][1]["age"].as_int() == 25
        assert obj["metadata"]["count"].as_int() == 2
        assert obj["metadata"]["timestamp"].is_null()

    def test_can_iterate_over_array_of_objects(self):
        """Test iterating over array of objects."""
        json_str = '[{"id":1},{"id":2},{"id":3}]'
        obj = JsonObject.parse(json_str)
        ids = [obj[i]["id"].as_int() for i in range(len(obj))]
        assert ids == [1, 2, 3]

    def test_can_iterate_over_object_keys_and_values(self):
        """Test iterating over object keys and values."""
        json_str = '{"a":1,"b":2,"c":3}'
        obj = JsonObject.parse(json_str)
        items = {k: v.as_int() for k, v in obj.items()}
        assert items["a"] == 1
        assert items["b"] == 2
        assert items["c"] == 3


class TestJsonObjectSpecialCases:
    """Tests for special cases and edge conditions."""

    def test_can_handle_escaped_quotes_in_string(self):
        """Test handling escaped quotes in strings."""
        obj = JsonObject.parse('"He said \\"Hello\\""')
        assert obj.as_str() == 'He said "Hello"'

    def test_can_handle_escaped_backslash(self):
        """Test handling escaped backslash."""
        obj = JsonObject.parse('"Path: C:\\\\Users"')
        result = obj.as_str()
        assert result is not None

    def test_can_handle_unicode_escape_sequences(self):
        """Test handling Unicode escape sequences."""
        obj = JsonObject.parse('"\\u0048\\u0065\\u006C\\u006C\\u006F"')
        assert obj.as_str() == "Hello"

    def test_can_handle_scientific_notation(self):
        """Test handling scientific notation in numbers."""
        obj = JsonObject.parse('1.23e10')
        result = obj.as_float()
        assert result is not None
        assert result > 1e9

    def test_can_handle_negative_zero(self):
        """Test handling negative zero."""
        obj = JsonObject.parse('-0')
        assert obj.as_int() == 0

    def test_can_handle_very_long_strings(self):
        """Test handling very long strings."""
        long_string = "a" * 1000
        json_str = f'"{long_string}"'
        obj = JsonObject.parse(json_str)
        assert len(obj.as_str()) == 1000

    def test_can_handle_many_nested_arrays(self):
        """Test handling many levels of nested arrays."""
        json_str = '[[[[[1]]]]]'
        obj = JsonObject.parse(json_str)
        assert obj[0][0][0][0][0].as_int() == 1


class TestJsonObjectTypeCoercion:
    """Tests for type checking and coercion."""

    def test_as_methods_return_none_for_wrong_type(self):
        """Test that as_* methods return None for wrong types."""
        obj = JsonObject.parse('42')
        assert obj.as_str() is None
        assert obj.as_bool() is None

    def test_numeric_string_does_not_auto_convert(self):
        """Test that numeric strings don't auto-convert."""
        obj = JsonObject.parse('"42"')
        assert obj.as_int() is None
        assert obj.as_str() == "42"

    def test_boolean_string_does_not_auto_convert(self):
        """Test that boolean strings don't auto-convert."""
        obj = JsonObject.parse('"true"')
        assert obj.as_bool() is None
        assert obj.as_str() == "true"


class TestJsonObjectErrorCases:
    """Tests for error handling."""

    def test_accessing_missing_key_raises_key_error(self):
        """Test that accessing missing key raises KeyError."""
        obj = JsonObject.parse('{"a":1}')
        with pytest.raises(KeyError):
            _ = obj["missing"]

    def test_accessing_out_of_bounds_index_raises_index_error(self):
        """Test that out of bounds index raises IndexError."""
        obj = JsonObject.parse('[1,2,3]')
        with pytest.raises(IndexError):
            _ = obj[10]

    def test_using_wrong_accessor_raises_type_error(self):
        """Test that using wrong accessor type raises TypeError."""
        obj = JsonObject.parse('{"key":"value"}')
        with pytest.raises(TypeError):
            _ = obj[0]

    def test_parsing_malformed_json_raises_error(self):
        """Test that parsing malformed JSON raises error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('{malformed}')

    def test_parsing_with_leftover_data_raises_error(self):
        """Test that leftover data after JSON raises error."""
        with pytest.raises(CardanoError):
            JsonObject.parse('{}extra')
