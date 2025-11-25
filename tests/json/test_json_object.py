import pytest
from biglup.cometa.json.json_object import JsonObject
from biglup.cometa.json.json_object_type import JsonObjectType
from biglup.cometa.json.json_format import JsonFormat
from biglup.cometa.errors import CardanoError


class TestJsonObjectFactories:
    def test_parse_object(self):
        json_str = '{"key": "value"}'
        obj = JsonObject.parse(json_str)
        assert obj.type == JsonObjectType.OBJECT
        assert len(obj) == 1
        assert obj.refcount >= 1

    def test_parse_array(self):
        json_str = '[1, 2, 3]'
        obj = JsonObject.parse(json_str)
        assert obj.type == JsonObjectType.ARRAY
        assert len(obj) == 3

    def test_parse_primitives(self):
        assert JsonObject.parse('"string"').type == JsonObjectType.STRING
        assert JsonObject.parse('123').type == JsonObjectType.NUMBER
        assert JsonObject.parse('true').type == JsonObjectType.BOOLEAN
        assert JsonObject.parse('null').type == JsonObjectType.NULL

    def test_parse_invalid(self):
        # Invalid JSON syntax
        with pytest.raises(CardanoError):
            JsonObject.parse('{')


class TestJsonObjectSerialization:
    def test_to_json_compact(self):
        json_str = '{"a":1,"b":2}'
        obj = JsonObject.parse(json_str)
        # Compact should match input if input was compact and sorted (keys might be reordered by implementation)
        # We verify by parsing back or checking structure generally.
        # Simple check:
        output = obj.to_json(JsonFormat.COMPACT)
        assert '"a":1' in output
        assert '"b":2' in output
        assert '{' in output and '}' in output
        assert '\n' not in output

    def test_to_json_pretty(self):
        json_str = '{"a":1}'
        obj = JsonObject.parse(json_str)
        output = obj.to_json(JsonFormat.PRETTY)
        assert '\n' in output or ' ' in output

    def test_str_magic_method(self):
        obj = JsonObject.parse('{"key":"value"}')
        assert str(obj) == obj.to_json(JsonFormat.COMPACT)


class TestJsonObjectAccess:
    def test_object_access(self):
        obj = JsonObject.parse('{"name": "Alice", "age": 30}')

        # __getitem__ string
        assert obj["name"].as_str() == "Alice"
        assert obj["age"].as_int() == 30

        # __contains__
        assert "name" in obj
        assert "missing" not in obj

        # KeyError
        with pytest.raises(KeyError):
            _ = obj["missing"]

        # TypeError on wrong key type
        with pytest.raises(TypeError):
            _ = obj[0]

    def test_array_access(self):
        obj = JsonObject.parse('[10, 20, 30]')

        # __getitem__ int
        assert obj[0].as_int() == 10
        assert obj[1].as_int() == 20
        assert obj[2].as_int() == 30

        # Negative indexing
        assert obj[-1].as_int() == 30
        assert obj[-3].as_int() == 10

        # IndexError
        with pytest.raises(IndexError):
            _ = obj[3]
        with pytest.raises(IndexError):
            _ = obj[-4]

        # TypeError on wrong key type
        with pytest.raises(TypeError):
            _ = obj["key"]

    def test_invalid_access_on_primitives(self):
        obj = JsonObject.parse('123')
        # Primitives have len 0
        assert len(obj) == 0

        # Cannot index primitive
        with pytest.raises(TypeError):
            _ = obj["key"]
        with pytest.raises(TypeError):
            _ = obj[0]


class TestJsonObjectIteration:
    def test_keys(self):
        obj = JsonObject.parse('{"a": 1, "b": 2}')
        keys = list(obj.keys())
        # Order isn't guaranteed by standard JSON but implementation usually preserves insertion or sorts
        assert set(keys) == {"a", "b"}

    def test_values(self):
        obj = JsonObject.parse('{"a": 1, "b": 2}')
        values = [v.as_int() for v in obj.values()]
        assert set(values) == {1, 2}

    def test_items(self):
        obj = JsonObject.parse('{"a": 1, "b": 2}')
        items = {k: v.as_int() for k, v in obj.items()}
        assert items == {"a": 1, "b": 2}

    def test_iteration_on_non_object(self):
        # Should return empty generators/lists
        arr = JsonObject.parse('[1, 2]')
        assert list(arr.keys()) == []
        assert list(arr.values()) == []
        assert list(arr.items()) == []


class TestTypeConversions:
    def test_as_bool(self):
        assert JsonObject.parse('true').as_bool() is True
        assert JsonObject.parse('false').as_bool() is False
        assert JsonObject.parse('1').as_bool() is None  # Strict type check

    def test_as_str(self):
        assert JsonObject.parse('"hello"').as_str() == "hello"
        assert JsonObject.parse('123').as_str() is None

    def test_as_int(self):
        # Unsigned
        assert JsonObject.parse('123').as_int() == 123
        # Signed
        assert JsonObject.parse('-123').as_int() == -123
        # 64-bit limits
        assert JsonObject.parse('18446744073709551615').as_int() == 18446744073709551615
        assert JsonObject.parse('-9223372036854775808').as_int() == -9223372036854775808

        assert JsonObject.parse('"123"').as_int() is None

    def test_as_float(self):
        assert JsonObject.parse('3.14').as_float() == 3.14
        val = JsonObject.parse('100').as_float()
        assert val == 100.0

        assert JsonObject.parse('"3.14"').as_float() is None

    def test_is_null(self):
        assert JsonObject.parse('null').is_null() is True
        assert JsonObject.parse('0').is_null() is False

    def test_truthiness(self):
        # Null -> False
        assert not JsonObject.parse('null')

        # Boolean
        assert JsonObject.parse('true')
        assert not JsonObject.parse('false')

        # Numbers
        assert JsonObject.parse('1')
        assert JsonObject.parse('-1')
        assert not JsonObject.parse('0')
        assert not JsonObject.parse('0.0')

        # Strings
        assert JsonObject.parse('"a"')
        assert not JsonObject.parse('""')

        # Arrays/Objects
        assert JsonObject.parse('[1]')
        assert not JsonObject.parse('[]')
        assert JsonObject.parse('{"a": 1}')
        assert not JsonObject.parse('{}')


class TestErrorHandling:
    def test_last_error(self):
        obj = JsonObject.parse('{}')
        # Default no error
        assert obj.last_error == ""

        # Set error
        msg = "Something went wrong"
        obj.last_error = msg
        assert obj.last_error == msg