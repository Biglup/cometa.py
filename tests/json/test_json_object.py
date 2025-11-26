import pytest
import cometa

class TestJsonObjectFactories:
    def test_parse_object(self):
        json_str = '{"key": "value"}'
        obj = cometa.JsonObject.parse(json_str)
        assert obj.type == cometa.JsonObjectType.OBJECT
        assert len(obj) == 1
        assert obj.refcount >= 1

    def test_parse_array(self):
        json_str = '[1, 2, 3]'
        obj = cometa.JsonObject.parse(json_str)
        assert obj.type == cometa.JsonObjectType.ARRAY
        assert len(obj) == 3

    def test_parse_primitives(self):
        assert cometa.JsonObject.parse('"string"').type == cometa.JsonObjectType.STRING
        assert cometa.JsonObject.parse('123').type == cometa.JsonObjectType.NUMBER
        assert cometa.JsonObject.parse('true').type == cometa.JsonObjectType.BOOLEAN
        assert cometa.JsonObject.parse('null').type == cometa.JsonObjectType.NULL

    def test_parse_invalid(self):
        # Invalid JSON syntax
        with pytest.raises(cometa.CardanoError):
            cometa.JsonObject.parse('{')


class TestJsonObjectSerialization:
    def test_to_json_compact(self):
        json_str = '{"a":1,"b":2}'
        obj = cometa.JsonObject.parse(json_str)
        # Compact should match input if input was compact and sorted (keys might be reordered by implementation)
        # We verify by parsing back or checking structure generally.
        # Simple check:
        output = obj.to_json(cometa.JsonFormat.COMPACT)
        assert '"a":1' in output
        assert '"b":2' in output
        assert '{' in output and '}' in output
        assert '\n' not in output

    def test_to_json_pretty(self):
        json_str = '{"a":1}'
        obj = cometa.JsonObject.parse(json_str)
        output = obj.to_json(cometa.JsonFormat.PRETTY)
        assert '\n' in output or ' ' in output

    def test_str_magic_method(self):
        obj = cometa.JsonObject.parse('{"key":"value"}')
        assert str(obj) == obj.to_json(cometa.JsonFormat.COMPACT)


class TestJsonObjectAccess:
    def test_object_access(self):
        obj = cometa.JsonObject.parse('{"name": "Alice", "age": 30}')

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
        obj = cometa.JsonObject.parse('[10, 20, 30]')

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
        obj = cometa.JsonObject.parse('123')
        # Primitives have len 0
        assert len(obj) == 0

        # Cannot index primitive
        with pytest.raises(TypeError):
            _ = obj["key"]
        with pytest.raises(TypeError):
            _ = obj[0]


class TestJsonObjectIteration:
    def test_keys(self):
        obj = cometa.JsonObject.parse('{"a": 1, "b": 2}')
        keys = list(obj.keys())
        # Order isn't guaranteed by standard JSON but implementation usually preserves insertion or sorts
        assert set(keys) == {"a", "b"}

    def test_values(self):
        obj = cometa.JsonObject.parse('{"a": 1, "b": 2}')
        values = [v.as_int() for v in obj.values()]
        assert set(values) == {1, 2}

    def test_items(self):
        obj = cometa.JsonObject.parse('{"a": 1, "b": 2}')
        items = {k: v.as_int() for k, v in obj.items()}
        assert items == {"a": 1, "b": 2}

    def test_iteration_on_non_object(self):
        # Should return empty generators/lists
        arr = cometa.JsonObject.parse('[1, 2]')
        assert list(arr.keys()) == []
        assert list(arr.values()) == []
        assert list(arr.items()) == []


class TestTypeConversions:
    def test_as_bool(self):
        assert cometa.JsonObject.parse('true').as_bool() is True
        assert cometa.JsonObject.parse('false').as_bool() is False
        assert cometa.JsonObject.parse('1').as_bool() is None  # Strict type check

    def test_as_str(self):
        assert cometa.JsonObject.parse('"hello"').as_str() == "hello"
        assert cometa.JsonObject.parse('123').as_str() is None

    def test_as_int(self):
        # Unsigned
        assert cometa.JsonObject.parse('123').as_int() == 123
        # Signed
        assert cometa.JsonObject.parse('-123').as_int() == -123
        # 64-bit limits
        assert cometa.JsonObject.parse('18446744073709551615').as_int() == 18446744073709551615
        assert cometa.JsonObject.parse('-9223372036854775808').as_int() == -9223372036854775808

        assert cometa.JsonObject.parse('"123"').as_int() is None

    def test_as_float(self):
        assert cometa.JsonObject.parse('3.14').as_float() == 3.14
        val = cometa.JsonObject.parse('100').as_float()
        assert val == 100.0

        assert cometa.JsonObject.parse('"3.14"').as_float() is None

    def test_is_null(self):
        assert cometa.JsonObject.parse('null').is_null() is True
        assert cometa.JsonObject.parse('0').is_null() is False

    def test_truthiness(self):
        # Null -> False
        assert not cometa.JsonObject.parse('null')

        # Boolean
        assert cometa.JsonObject.parse('true')
        assert not cometa.JsonObject.parse('false')

        # Numbers
        assert cometa.JsonObject.parse('1')
        assert cometa.JsonObject.parse('-1')
        assert not cometa.JsonObject.parse('0')
        assert not cometa.JsonObject.parse('0.0')

        # Strings
        assert cometa.JsonObject.parse('"a"')
        assert not cometa.JsonObject.parse('""')

        # Arrays/Objects
        assert cometa.JsonObject.parse('[1]')
        assert not cometa.JsonObject.parse('[]')
        assert cometa.JsonObject.parse('{"a": 1}')
        assert not cometa.JsonObject.parse('{}')


class TestErrorHandling:
    def test_last_error(self):
        obj = cometa.JsonObject.parse('{}')
        # Default no error
        assert obj.last_error == ""

        # Set error
        msg = "Something went wrong"
        obj.last_error = msg
        assert obj.last_error == msg