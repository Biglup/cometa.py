"""
Tests for JsonWriter class.

Copyright 2025 Biglup Labs.
Licensed under the Apache License, Version 2.0.
"""

import pytest
from cometa import JsonWriter, JsonFormat, JsonContext, Buffer
from cometa.common import BigInt
from cometa.errors import CardanoError


class TestJsonWriterLifecycle:
    """Tests for JsonWriter lifecycle management."""

    def test_init_default(self):
        """Test JsonWriter initialization with default format."""
        writer = JsonWriter()
        assert writer.encoded_size == 1
        assert writer.context == JsonContext.ROOT
        assert writer.refcount >= 1
        assert writer.last_error == ""

    def test_init_compact(self):
        """Test JsonWriter initialization with compact format."""
        writer = JsonWriter(JsonFormat.COMPACT)
        assert writer.context == JsonContext.ROOT

    def test_init_pretty(self):
        """Test JsonWriter initialization with pretty format."""
        writer = JsonWriter(JsonFormat.PRETTY)
        assert writer.context == JsonContext.ROOT

    def test_context_manager(self):
        """Test JsonWriter as context manager."""
        with JsonWriter() as writer:
            writer.write_start_object()
            assert writer.context == JsonContext.OBJECT

    def test_reset(self):
        """Test resetting writer state."""
        writer = JsonWriter()
        writer.write_start_object()
        assert writer.encoded_size > 1

        writer.reset()
        assert writer.encoded_size == 1
        assert writer.context == JsonContext.ROOT

    def test_refcount(self):
        """Test reference counting."""
        writer = JsonWriter()
        initial_count = writer.refcount
        assert initial_count >= 1

    def test_last_error_get_set(self):
        """Test getting and setting last error."""
        writer = JsonWriter()
        assert writer.last_error == ""

        msg = "Test error message"
        writer.last_error = msg
        assert writer.last_error == msg

    def test_repr(self):
        """Test string representation."""
        writer = JsonWriter()
        repr_str = repr(writer)
        assert "JsonWriter" in repr_str
        assert "encoded_size" in repr_str
        assert "context" in repr_str


class TestJsonWriterStructure:
    """Tests for JSON structure creation."""

    def test_empty_object_compact(self):
        """Test creating empty object in compact format."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_end_object()
        assert writer.encode() == "{}"

    def test_empty_object_pretty(self):
        """Test creating empty object in pretty format."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_end_object()
        assert writer.encode() == "{}"

    def test_empty_array_compact(self):
        """Test creating empty array in compact format."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_array()
        writer.write_end_array()
        assert writer.encode() == "[]"

    def test_empty_array_pretty(self):
        """Test creating empty array in pretty format."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_array()
        writer.write_end_array()
        assert writer.encode() == "[]"

    def test_empty_array_in_object_compact(self):
        """Test empty array inside object (compact)."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{"a":[]}'

    def test_empty_array_in_object_pretty(self):
        """Test empty array inside object (pretty)."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{\n  "a": []\n}'

    def test_array_of_empty_objects_compact(self):
        """Test array of empty objects (compact)."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_start_object()
        writer.write_end_object()
        writer.write_start_object()
        writer.write_end_object()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{"a":[{},{}]}'

    def test_array_of_empty_objects_pretty(self):
        """Test array of empty objects (pretty)."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_start_object()
        writer.write_end_object()
        writer.write_start_object()
        writer.write_end_object()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{\n  "a": [\n    {},\n    {}\n  ]\n}'

    def test_nested_structure(self):
        """Test nested structure with mixed types."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_int(1)
        writer.write_start_object()
        writer.write_end_object()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{"a":[1,{}]}'

    def test_deeply_nested_objects(self):
        """Test deeply nested object and array structures."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()

        writer.write_start_object()
        writer.write_property_name("b")
        writer.write_start_array()
        writer.write_end_array()
        writer.write_end_object()

        writer.write_start_object()
        writer.write_property_name("c")
        writer.write_start_object()
        writer.write_property_name("d")
        writer.write_start_array()
        writer.write_end_array()
        writer.write_end_object()
        writer.write_end_object()

        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{"a":[{"b":[]},{"c":{"d":[]}}]}'

    def test_array_of_arrays(self):
        """Test array of arrays."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("array")
        writer.write_start_array()
        writer.write_start_array()
        writer.write_int(1)
        writer.write_int(2)
        writer.write_end_array()
        writer.write_start_array()
        writer.write_int(3)
        writer.write_int(4)
        writer.write_end_array()
        writer.write_end_array()
        writer.write_end_object()
        assert writer.encode() == '{"array":[[1,2],[3,4]]}'


class TestJsonWriterPropertyName:
    """Tests for write_property_name."""

    def test_write_property_name(self):
        """Test writing property name."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("name")
        writer.write_str("Hello, World!")
        writer.write_end_object()
        assert writer.encode() == '{\n  "name": "Hello, World!"\n}'

    def test_write_property_name_empty(self):
        """Test writing empty property name."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("")
        writer.write_null()
        writer.write_end_object()
        assert writer.encode() == '{"":null}'

    def test_write_property_name_unicode(self):
        """Test writing property name with unicode."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("key🔑")
        writer.write_int(1)
        writer.write_end_object()
        result = writer.encode()
        assert "key" in result
        assert "1" in result


class TestJsonWriterPrimitives:
    """Tests for primitive value writing."""

    def test_write_null(self):
        """Test writing null value."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_null()
        writer.write_end_array()
        assert writer.encode() == "[null]"

    def test_write_null_at_root(self):
        """Test writing null at root level."""
        writer = JsonWriter()
        writer.write_null()
        assert writer.encode() == "null"

    def test_write_null_in_object(self):
        """Test writing null in object."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("null")
        writer.write_null()
        writer.write_end_object()
        assert writer.encode() == '{\n  "null": null\n}'

    def test_write_bool_true(self):
        """Test writing true boolean."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_bool(True)
        writer.write_end_array()
        assert writer.encode() == "[true]"

    def test_write_bool_false(self):
        """Test writing false boolean."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_bool(False)
        writer.write_end_array()
        assert writer.encode() == "[false]"

    def test_write_bool_at_root(self):
        """Test writing boolean at root level."""
        writer = JsonWriter()
        writer.write_bool(True)
        assert writer.encode() == "true"

    def test_write_bool_in_object(self):
        """Test writing boolean in object."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("bool")
        writer.write_bool(True)
        writer.write_end_object()
        assert writer.encode() == '{\n  "bool": true\n}'

    def test_write_bool_multiple(self):
        """Test writing multiple booleans."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_bool(True)
        writer.write_bool(False)
        writer.write_end_array()
        assert writer.encode() == "[true,false]"

    def test_write_str_simple(self):
        """Test writing simple string."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("key")
        writer.write_str("value")
        writer.write_end_object()
        assert writer.encode() == '{"key":"value"}'

    def test_write_str_at_root(self):
        """Test writing string at root level."""
        writer = JsonWriter()
        writer.write_str("Hello, World!")
        assert writer.encode() == '"Hello, World!"'

    def test_write_str_empty(self):
        """Test writing empty string."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_str("")
        writer.write_end_array()
        assert writer.encode() == '[""]'

    def test_write_str_escaping_newline(self):
        """Test string escaping for newline."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_str("Line\nBreak")
        writer.write_end_array()
        assert writer.encode() == '["Line\\nBreak"]'

    def test_write_str_escaping_quotes(self):
        """Test string escaping for quotes."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_str('"Quotes"')
        writer.write_end_array()
        assert writer.encode() == '["\\"Quotes\\""]'

    def test_write_str_escaping_backslash(self):
        """Test string escaping for backslash."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_str("back\\slash")
        writer.write_end_array()
        result = writer.encode()
        assert "back" in result and "slash" in result

    def test_write_str_unicode(self):
        """Test writing unicode strings."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_str("\U00010151")
        writer.write_end_array()
        assert len(writer.encode()) > 0


class TestJsonWriterNumbers:
    """Tests for numeric value writing."""

    def test_write_int_positive(self):
        """Test writing positive integer."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_int(123)
        writer.write_end_array()
        assert writer.encode() == "[123]"

    def test_write_int_negative(self):
        """Test writing negative integer."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_int(-456)
        writer.write_end_array()
        assert writer.encode() == "[-456]"

    def test_write_int_zero(self):
        """Test writing zero."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_int(0)
        writer.write_end_array()
        assert writer.encode() == "[0]"

    def test_write_int_at_root(self):
        """Test writing integer at root level."""
        writer = JsonWriter()
        writer.write_int(2147483647)
        assert writer.encode() == "2147483647"

    def test_write_int_max_uint64(self):
        """Test writing max uint64 value."""
        writer = JsonWriter()
        writer.write_int(18446744073709551615)
        assert writer.encode() == "18446744073709551615"

    def test_write_int_min_int64(self):
        """Test writing min int64 value."""
        writer = JsonWriter()
        writer.write_int(-9223372036854775808)
        assert writer.encode() == "-9223372036854775808"

    def test_write_int_as_string(self):
        """Test writing integer as string."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_int(123, as_string=True)
        writer.write_int(-456, as_string=True)
        writer.write_end_array()
        assert writer.encode() == '["123","-456"]'

    def test_write_int_large_as_string(self):
        """Test writing large integer automatically as string."""
        writer = JsonWriter()
        massive = 18446744073709551616
        writer.write_start_array()
        writer.write_int(massive)
        writer.write_end_array()
        expected = f'["{massive}"]'
        assert writer.encode() == expected

    def test_write_int_bigint_object(self):
        """Test writing BigInt object."""
        writer = JsonWriter()
        massive = 18446744073709551616
        bi = BigInt.from_int(massive)
        writer.write_start_array()
        writer.write_int(bi)
        writer.write_end_array()
        expected = f'["{massive}"]'
        assert writer.encode() == expected

    def test_write_int_bigint_string(self):
        """Test writing BigInt from string."""
        writer = JsonWriter()
        bi = BigInt.from_string("123456789123456789")
        writer.write_start_array()
        writer.write_int(bi)
        writer.write_end_array()
        assert writer.encode() == '["123456789123456789"]'

    def test_write_int_bigint_at_root(self):
        """Test writing BigInt at root level."""
        writer = JsonWriter()
        bi = BigInt.from_string("123456789123456789")
        writer.write_int(bi)
        assert writer.encode() == '"123456789123456789"'

    def test_write_int_bigint_in_object(self):
        """Test writing BigInt in object."""
        writer = JsonWriter(JsonFormat.PRETTY)
        bi = BigInt.from_string("123456789123456789")
        writer.write_start_object()
        writer.write_property_name("bigNumber")
        writer.write_int(bi)
        writer.write_end_object()
        assert writer.encode() == '{\n  "bigNumber": "123456789123456789"\n}'

    def test_write_int_bigint_array(self):
        """Test writing array of BigInts."""
        writer = JsonWriter(JsonFormat.PRETTY)
        bi = BigInt.from_string("123456789123456789")
        writer.write_start_object()
        writer.write_property_name("bigNumbers")
        writer.write_start_array()
        writer.write_int(bi)
        writer.write_int(bi)
        writer.write_end_array()
        writer.write_end_object()
        result = writer.encode()
        assert '"bigNumbers"' in result
        assert '"123456789123456789"' in result

    def test_write_int_invalid_type(self):
        """Test writing invalid type raises error."""
        writer = JsonWriter()
        with pytest.raises(TypeError):
            writer.write_int("not an int")

    def test_write_float_positive(self):
        """Test writing positive float."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_float(3.14)
        writer.write_end_array()
        output = writer.encode()
        assert "3.14" in output

    def test_write_float_negative(self):
        """Test writing negative float."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_float(-2.5)
        writer.write_end_array()
        output = writer.encode()
        assert "-2.5" in output

    def test_write_float_at_root(self):
        """Test writing float at root level."""
        writer = JsonWriter()
        writer.write_float(3.4028234663852886e+38)
        assert "3.4028234663852886e+38" in writer.encode()

    def test_write_float_as_string(self):
        """Test writing float as string."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_float(1.5, as_string=True)
        writer.write_end_array()
        output = writer.encode()
        assert '"1.5"' in output or '"1.50"' in output

    def test_write_primitives_mixed(self):
        """Test writing mixed primitive types in object."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_int(4294967295)
        writer.write_property_name("b")
        writer.write_int(2147483647)
        writer.write_property_name("c")
        writer.write_int(-2147483647)
        writer.write_property_name("d")
        writer.write_float(3.4028234663852886e+38)
        writer.write_property_name("e")
        writer.write_float(-3.4028234663852886e+38)
        writer.write_property_name("f")
        writer.write_str("Hello, World!")
        writer.write_property_name("g")
        writer.write_bool(True)
        writer.write_property_name("h")
        writer.write_bool(False)
        writer.write_property_name("i")
        writer.write_null()
        writer.write_end_object()

        result = writer.encode()
        assert "4294967295" in result
        assert "Hello, World!" in result
        assert "true" in result
        assert "false" in result
        assert "null" in result

    def test_write_primitives_as_string(self):
        """Test writing numeric primitives as strings."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_int(4294967295, as_string=True)
        writer.write_property_name("b")
        writer.write_int(2147483647, as_string=True)
        writer.write_property_name("c")
        writer.write_int(-2147483647, as_string=True)
        writer.write_property_name("d")
        writer.write_float(3.4028234663852886e+38, as_string=True)
        writer.write_property_name("e")
        writer.write_float(-3.4028234663852886e+38, as_string=True)
        writer.write_end_object()

        result = writer.encode()
        assert '"4294967295"' in result
        assert '"2147483647"' in result
        assert '"-2147483647"' in result

    def test_write_array_of_primitives(self):
        """Test writing array of various primitives."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_start_array()
        writer.write_int(4294967295)
        writer.write_int(2147483647)
        writer.write_int(-2147483647)
        writer.write_float(3.4028234663852886e+38)
        writer.write_float(-3.4028234663852886e+38)
        writer.write_str("Hello, World!")
        writer.write_bool(True)
        writer.write_bool(False)
        writer.write_null()
        writer.write_end_array()
        writer.write_end_object()

        result = writer.encode()
        assert "4294967295" in result
        assert "Hello, World!" in result
        assert "true" in result
        assert "false" in result
        assert "null" in result


class TestJsonWriterBinary:
    """Tests for binary data writing."""

    def test_write_bytes_as_hex(self):
        """Test writing bytes as hex string."""
        writer = JsonWriter()
        data = b"\xde\xad\xbe\xef"
        writer.write_start_array()
        writer.write_bytes(data)
        writer.write_end_array()
        assert writer.encode() == '["deadbeef"]'

    def test_write_bytes_empty(self):
        """Test writing empty bytes."""
        writer = JsonWriter()
        data = b""
        writer.write_start_array()
        writer.write_bytes(data)
        writer.write_end_array()
        assert writer.encode() == '[""]'

    def test_write_buffer_as_hex(self):
        """Test writing Buffer as hex string."""
        writer = JsonWriter()
        data = b"\xde\xad\xbe\xef"
        writer.write_start_array()
        writer.write_bytes(Buffer.from_bytes(data))
        writer.write_end_array()
        assert writer.encode() == '["deadbeef"]'

    def test_write_bytes_and_buffer(self):
        """Test writing both bytes and Buffer."""
        writer = JsonWriter()
        data = b"\xde\xad\xbe\xef"
        writer.write_start_array()
        writer.write_bytes(data)
        writer.write_bytes(Buffer.from_bytes(data))
        writer.write_end_array()
        assert writer.encode() == '["deadbeef","deadbeef"]'

    def test_write_bytes_invalid_type(self):
        """Test writing invalid type raises error."""
        writer = JsonWriter()
        with pytest.raises(TypeError):
            writer.write_bytes("not bytes")

    def test_write_bech32_bytes(self):
        """Test writing bech32 from bytes."""
        writer = JsonWriter()
        data = b"\x00" * 20
        writer.write_start_object()
        writer.write_property_name("address")
        writer.write_bech32("stake", data)
        writer.write_end_object()
        output = writer.encode()
        assert "stake1qqqq" in output

    def test_write_bech32_buffer(self):
        """Test writing bech32 from Buffer."""
        writer = JsonWriter()
        data = b"\x00" * 20
        writer.write_start_object()
        writer.write_property_name("address")
        writer.write_bech32("stake", Buffer.from_bytes(data))
        writer.write_end_object()
        output = writer.encode()
        assert "stake1qqqq" in output

    def test_write_bech32_invalid_type(self):
        """Test writing bech32 with invalid type raises error."""
        writer = JsonWriter()
        with pytest.raises(TypeError):
            writer.write_bech32("hrp", "not bytes")


class TestJsonWriterRaw:
    """Tests for raw value writing."""

    def test_write_raw_value_array(self):
        """Test writing raw JSON array value."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("raw")
        writer.write_raw_value("[1, 2, 3]")
        writer.write_end_object()
        assert writer.encode() == '{"raw":[1, 2, 3]}'

    def test_write_raw_value_object(self):
        """Test writing raw JSON object value."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_raw_value('{"nested": true}')
        writer.write_end_array()
        assert writer.encode() == '[{"nested": true}]'

    def test_write_raw_value_number(self):
        """Test writing raw number value."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_raw_value("42")
        writer.write_end_array()
        assert writer.encode() == "[42]"

    def test_write_raw_value_string(self):
        """Test writing raw string value."""
        writer = JsonWriter()
        writer.write_start_array()
        writer.write_raw_value('"raw string"')
        writer.write_end_array()
        assert writer.encode() == '["raw string"]'


class TestJsonWriterFormatting:
    """Tests for output formatting."""

    def test_compact_format(self):
        """Test compact format output."""
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_int(1)
        writer.write_property_name("b")
        writer.write_int(2)
        writer.write_end_object()
        assert writer.encode() == '{"a":1,"b":2}'

    def test_pretty_format(self):
        """Test pretty format output."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("a")
        writer.write_int(1)
        writer.write_end_object()
        output = writer.encode()
        assert "\n" in output or "  " in output

    def test_pretty_format_nested(self):
        """Test pretty format with nested structures."""
        writer = JsonWriter(JsonFormat.PRETTY)
        writer.write_start_object()
        writer.write_property_name("nested")
        writer.write_start_object()
        writer.write_property_name("key")
        writer.write_str("value")
        writer.write_end_object()
        writer.write_end_object()
        output = writer.encode()
        assert "\n" in output


class TestJsonWriterContext:
    """Tests for JSON context tracking."""

    def test_context_root(self):
        """Test ROOT context."""
        writer = JsonWriter()
        assert writer.context == JsonContext.ROOT

    def test_context_object(self):
        """Test OBJECT context."""
        writer = JsonWriter()
        writer.write_start_object()
        assert writer.context == JsonContext.OBJECT

    def test_context_array(self):
        """Test ARRAY context."""
        writer = JsonWriter()
        writer.write_start_array()
        assert writer.context == JsonContext.ARRAY

    def test_context_nested(self):
        """Test context changes in nested structures."""
        writer = JsonWriter()
        assert writer.context == JsonContext.ROOT

        writer.write_start_object()
        assert writer.context == JsonContext.OBJECT

        writer.write_property_name("arr")
        writer.write_start_array()
        assert writer.context == JsonContext.ARRAY

        writer.write_start_object()
        assert writer.context == JsonContext.OBJECT

        writer.write_end_object()
        assert writer.context == JsonContext.ARRAY

        writer.write_end_array()
        assert writer.context == JsonContext.OBJECT

        writer.write_end_object()


class TestJsonWriterToDict:
    """Tests for to_dict method."""

    def test_to_dict_empty_object(self):
        """Test converting empty object to dict."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_end_object()
        assert writer.to_dict() == {}

    def test_to_dict_simple_object(self):
        """Test converting simple object to dict."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("key")
        writer.write_str("value")
        writer.write_end_object()
        assert writer.to_dict() == {"key": "value"}

    def test_to_dict_nested(self):
        """Test converting nested structure to dict."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("nested")
        writer.write_start_object()
        writer.write_property_name("key")
        writer.write_int(42)
        writer.write_end_object()
        writer.write_end_object()
        assert writer.to_dict() == {"nested": {"key": 42}}

    def test_to_dict_with_array(self):
        """Test converting object with array to dict."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("arr")
        writer.write_start_array()
        writer.write_int(1)
        writer.write_int(2)
        writer.write_int(3)
        writer.write_end_array()
        writer.write_end_object()
        assert writer.to_dict() == {"arr": [1, 2, 3]}

    def test_to_dict_empty(self):
        """Test converting empty writer to dict raises error."""
        writer = JsonWriter()
        writer.reset()
        with pytest.raises(CardanoError):
            writer.to_dict()


class TestJsonWriterErrors:
    """Tests for error handling."""

    def test_manual_error_setting(self):
        """Test manually setting error."""
        writer = JsonWriter()
        msg = "Manual error"
        writer.last_error = msg
        assert writer.last_error == msg

    def test_error_clear(self):
        """Test clearing error."""
        writer = JsonWriter()
        writer.last_error = "Error"
        writer.last_error = ""
        assert writer.last_error == ""


class TestJsonWriterEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_values_at_root(self):
        """Test writing single value at root level."""
        writer = JsonWriter()
        writer.write_int(123)
        assert writer.encode() == "123"

    def test_reuse_after_reset(self):
        """Test reusing writer after reset."""
        writer = JsonWriter()
        writer.write_start_object()
        writer.write_property_name("first")
        writer.write_int(1)
        writer.write_end_object()
        first = writer.encode()

        writer.reset()
        writer.write_start_object()
        writer.write_property_name("second")
        writer.write_int(2)
        writer.write_end_object()
        second = writer.encode()

        assert first == '{"first":1}'
        assert second == '{"second":2}'

    def test_encoded_size_tracking(self):
        """Test that encoded_size tracks correctly."""
        writer = JsonWriter()
        initial = writer.encoded_size

        writer.write_start_object()
        after_obj = writer.encoded_size
        assert after_obj > initial

        writer.write_property_name("key")
        after_prop = writer.encoded_size
        assert after_prop > after_obj

        writer.write_str("value")
        after_val = writer.encoded_size
        assert after_val > after_prop

    def test_empty_encode(self):
        """Test encoding empty writer raises error."""
        writer = JsonWriter()
        writer.reset()
        with pytest.raises(CardanoError):
            writer.encode()
