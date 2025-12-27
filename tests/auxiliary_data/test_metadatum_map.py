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
    MetadatumMap,
    Metadatum,
    MetadatumList,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


METADATUM_MAP_CBOR = "a10102"
EMPTY_MAP_CBOR = "a0"
INDEFINITE_MAP_CBOR = "bf0102ff"


class TestMetadatumMapInit:
    """Tests for MetadatumMap initialization."""

    def test_can_create_empty_map(self):
        """Test that an empty MetadatumMap can be created."""
        meta_map = MetadatumMap()
        assert meta_map is not None
        assert len(meta_map) == 0

    def test_empty_map_has_zero_length(self):
        """Test that an empty map has length zero."""
        meta_map = MetadatumMap()
        assert len(meta_map) == 0

    def test_can_use_as_context_manager(self):
        """Test that MetadatumMap can be used as a context manager."""
        with MetadatumMap() as meta_map:
            assert meta_map is not None
            meta_map.insert(1, 2)
            assert len(meta_map) == 1

    def test_repr_shows_length(self):
        """Test that __repr__ shows the map length."""
        meta_map = MetadatumMap()
        assert "len=0" in repr(meta_map)
        meta_map.insert(1, 2)
        assert "len=1" in repr(meta_map)


class TestMetadatumMapFromCbor:
    """Tests for MetadatumMap.from_cbor() factory method."""

    def test_can_deserialize_simple_map(self):
        """Test that a simple map can be deserialized from CBOR."""
        reader = CborReader.from_hex(METADATUM_MAP_CBOR)
        meta_map = MetadatumMap.from_cbor(reader)
        assert meta_map is not None
        assert len(meta_map) == 1

    def test_can_deserialize_empty_map(self):
        """Test that an empty map can be deserialized from CBOR."""
        reader = CborReader.from_hex(EMPTY_MAP_CBOR)
        meta_map = MetadatumMap.from_cbor(reader)
        assert meta_map is not None
        assert len(meta_map) == 0

    def test_can_deserialize_indefinite_map(self):
        """Test that an indefinite-length map can be deserialized."""
        reader = CborReader.from_hex(INDEFINITE_MAP_CBOR)
        meta_map = MetadatumMap.from_cbor(reader)
        assert meta_map is not None
        assert len(meta_map) == 1

    def test_raises_error_if_reader_is_invalid(self):
        """Test that deserialization fails with invalid CBOR."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MetadatumMap.from_cbor(reader)

    def test_raises_error_if_unexpected_break(self):
        """Test that deserialization fails with unexpected break byte."""
        reader = CborReader.from_hex("a1ff")
        with pytest.raises(CardanoError):
            MetadatumMap.from_cbor(reader)

    def test_raises_error_if_invalid_key(self):
        """Test that deserialization fails with invalid key type."""
        reader = CborReader.from_hex("a1f5f5")
        with pytest.raises(CardanoError):
            MetadatumMap.from_cbor(reader)

    def test_raises_error_if_invalid_value(self):
        """Test that deserialization fails with invalid value type."""
        reader = CborReader.from_hex("a101f5")
        with pytest.raises(CardanoError):
            MetadatumMap.from_cbor(reader)


class TestMetadatumMapToCbor:
    """Tests for MetadatumMap.to_cbor() method."""

    def test_can_serialize_empty_map(self):
        """Test that an empty map can be serialized to CBOR."""
        meta_map = MetadatumMap()
        writer = CborWriter()
        meta_map.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == EMPTY_MAP_CBOR

    def test_can_serialize_simple_map(self):
        """Test that a simple map can be serialized to CBOR."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        writer = CborWriter()
        meta_map.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == METADATUM_MAP_CBOR

    def test_can_roundtrip_cbor(self):
        """Test that CBOR serialization and deserialization are reversible."""
        reader = CborReader.from_hex(METADATUM_MAP_CBOR)
        meta_map = MetadatumMap.from_cbor(reader)
        writer = CborWriter()
        meta_map.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == METADATUM_MAP_CBOR

    def test_can_roundtrip_indefinite_map(self):
        """Test that indefinite maps preserve their encoding."""
        reader = CborReader.from_hex(INDEFINITE_MAP_CBOR)
        meta_map = MetadatumMap.from_cbor(reader)
        writer = CborWriter()
        meta_map.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == INDEFINITE_MAP_CBOR


class TestMetadatumMapInsert:
    """Tests for MetadatumMap.insert() method."""

    def test_can_insert_integer_key_and_value(self):
        """Test that integer key-value pairs can be inserted."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        assert len(meta_map) == 1

    def test_can_insert_string_key_and_value(self):
        """Test that string key-value pairs can be inserted."""
        meta_map = MetadatumMap()
        meta_map.insert("name", "Alice")
        assert len(meta_map) == 1

    def test_can_insert_bytes_key_and_value(self):
        """Test that bytes key-value pairs can be inserted."""
        meta_map = MetadatumMap()
        meta_map.insert(b"\x01\x02", b"\x03\x04")
        assert len(meta_map) == 1

    def test_can_insert_mixed_types(self):
        """Test that mixed type key-value pairs can be inserted."""
        meta_map = MetadatumMap()
        meta_map.insert(1, "value")
        meta_map.insert("key", 42)
        meta_map.insert(b"\xde\xad", b"\xbe\xef")
        assert len(meta_map) == 3

    def test_can_insert_metadatum_objects(self):
        """Test that Metadatum objects can be inserted directly."""
        meta_map = MetadatumMap()
        key = Metadatum.from_int(1)
        value = Metadatum.from_int(2)
        meta_map.insert(key, value)
        assert len(meta_map) == 1

    def test_can_update_existing_key(self):
        """Test that inserting with an existing key adds another entry (maps allow duplicate keys)."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        meta_map.insert(1, 3)
        assert len(meta_map) == 2

    def test_raises_error_with_invalid_key_type(self):
        """Test that inserting with invalid key type raises TypeError."""
        meta_map = MetadatumMap()
        with pytest.raises(TypeError):
            meta_map.insert(None, 1)

    def test_raises_error_with_invalid_value_type(self):
        """Test that inserting with invalid value type raises TypeError."""
        meta_map = MetadatumMap()
        with pytest.raises(TypeError):
            meta_map.insert(1, None)

    def test_can_insert_list_as_key(self):
        """Test that MetadatumList can be used as a key."""
        meta_map = MetadatumMap()
        list_key = MetadatumList()
        list_key.add(1)
        key_meta = Metadatum.from_list(list_key)
        meta_map.insert(key_meta, 1)
        assert len(meta_map) == 1

    def test_can_insert_map_as_key(self):
        """Test that MetadatumMap can be used as a key."""
        meta_map = MetadatumMap()
        inner_map = MetadatumMap()
        inner_map.insert(1, 2)
        key_meta = Metadatum.from_map(inner_map)
        meta_map.insert(key_meta, 1)
        assert len(meta_map) == 1


class TestMetadatumMapGet:
    """Tests for MetadatumMap.get() method."""

    def test_can_retrieve_value_by_integer_key(self):
        """Test that values can be retrieved by integer key."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        result = meta_map.get(1)
        assert result is not None
        assert result.to_integer().to_int() == 2

    def test_can_retrieve_value_by_string_key(self):
        """Test that values can be retrieved by string key."""
        meta_map = MetadatumMap()
        meta_map.insert("name", "Alice")
        result = meta_map.get("name")
        assert result is not None
        assert result.to_str() == "Alice"

    def test_can_retrieve_value_by_bytes_key(self):
        """Test that values can be retrieved by bytes key."""
        meta_map = MetadatumMap()
        key_bytes = b"\x01\x02\x03\x04"
        val_bytes = b"\x05\x06\x07\x08"
        meta_map.insert(key_bytes, val_bytes)
        result = meta_map.get(key_bytes)
        assert result is not None
        assert result.to_bytes() == val_bytes

    def test_returns_none_for_missing_key(self):
        """Test that get returns None for a missing key."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        result = meta_map.get(3)
        assert result is None

    def test_returns_default_for_missing_key(self):
        """Test that get returns default value for a missing key."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        default = Metadatum.from_int(999)
        result = meta_map.get(3, default)
        assert result is default

    def test_can_retrieve_value_by_list_key(self):
        """Test that values can be retrieved using a list as key."""
        meta_map = MetadatumMap()
        list_key = MetadatumList()
        list_key.add(1)
        key_meta = Metadatum.from_list(list_key)
        meta_map.insert(key_meta, 1)
        result = meta_map.get(key_meta)
        assert result is not None
        assert result.to_integer().to_int() == 1

    def test_can_retrieve_value_by_map_key(self):
        """Test that values can be retrieved using a map as key."""
        meta_map = MetadatumMap()
        inner_map = MetadatumMap()
        inner_map.insert(1, 2)
        key_meta = Metadatum.from_map(inner_map)
        meta_map.insert(key_meta, 1)
        result = meta_map.get(key_meta)
        assert result is not None
        assert result.to_integer().to_int() == 1


class TestMetadatumMapGetAt:
    """Tests for MetadatumMap.get_at() method."""

    def test_can_get_entry_at_index(self):
        """Test that entries can be retrieved by index."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        key, value = meta_map.get_at(0)
        assert key.to_integer().to_int() == 1
        assert value.to_integer().to_int() == 2

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        with pytest.raises(IndexError):
            meta_map.get_at(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out-of-bounds index raises IndexError."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        with pytest.raises(IndexError):
            meta_map.get_at(1)

    def test_raises_error_for_empty_map(self):
        """Test that accessing index in empty map raises IndexError."""
        meta_map = MetadatumMap()
        with pytest.raises(IndexError):
            meta_map.get_at(0)


class TestMetadatumMapGetKeys:
    """Tests for MetadatumMap.get_keys() method."""

    def test_can_get_keys_from_empty_map(self):
        """Test that get_keys returns empty list for empty map."""
        meta_map = MetadatumMap()
        keys = meta_map.get_keys()
        assert len(keys) == 0

    def test_can_get_keys_from_non_empty_map(self):
        """Test that get_keys returns list of all keys."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        keys = meta_map.get_keys()
        assert len(keys) == 1
        key = keys.get(0)
        assert key.to_integer().to_int() == 1

    def test_keys_list_matches_map_size(self):
        """Test that keys list has same size as map."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        meta_map.insert(3, 4)
        keys = meta_map.get_keys()
        assert len(keys) == 2


class TestMetadatumMapGetValues:
    """Tests for MetadatumMap.get_values() method."""

    def test_can_get_values_from_empty_map(self):
        """Test that get_values returns empty list for empty map."""
        meta_map = MetadatumMap()
        values = meta_map.get_values()
        assert len(values) == 0

    def test_can_get_values_from_non_empty_map(self):
        """Test that get_values returns list of all values."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        values = meta_map.get_values()
        assert len(values) == 1
        value = values.get(0)
        assert value.to_integer().to_int() == 2

    def test_values_list_matches_map_size(self):
        """Test that values list has same size as map."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        meta_map.insert(3, 4)
        values = meta_map.get_values()
        assert len(values) == 2


class TestMetadatumMapEquality:
    """Tests for MetadatumMap.__eq__() method."""

    def test_empty_maps_are_equal(self):
        """Test that two empty maps are equal."""
        map1 = MetadatumMap()
        map2 = MetadatumMap()
        assert map1 == map2

    def test_maps_with_same_entries_are_equal(self):
        """Test that maps with same entries are equal."""
        map1 = MetadatumMap()
        map1.insert(1, 2)
        map2 = MetadatumMap()
        map2.insert(1, 2)
        assert map1 == map2

    def test_maps_with_different_keys_are_not_equal(self):
        """Test that maps with different keys are not equal."""
        map1 = MetadatumMap()
        map1.insert(1, 2)
        map2 = MetadatumMap()
        map2.insert(3, 2)
        assert map1 != map2

    def test_maps_with_different_values_are_not_equal(self):
        """Test that maps with different values are not equal."""
        map1 = MetadatumMap()
        map1.insert(1, 2)
        map2 = MetadatumMap()
        map2.insert(1, 3)
        assert map1 != map2

    def test_empty_and_non_empty_maps_are_not_equal(self):
        """Test that empty and non-empty maps are not equal."""
        map1 = MetadatumMap()
        map2 = MetadatumMap()
        map2.insert(1, 2)
        assert map1 != map2

    def test_map_not_equal_to_non_map_object(self):
        """Test that map is not equal to non-map object."""
        meta_map = MetadatumMap()
        assert meta_map != "not a map"
        assert meta_map != 42
        assert meta_map != None


class TestMetadatumMapDictInterface:
    """Tests for dict-like interface methods."""

    def test_can_use_bracket_notation_to_set(self):
        """Test that bracket notation can be used to set values."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        assert len(meta_map) == 1

    def test_can_use_bracket_notation_to_get(self):
        """Test that bracket notation can be used to get values."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        result = meta_map[1]
        assert result is not None
        assert result.to_integer().to_int() == 2

    def test_bracket_get_returns_none_for_missing_key(self):
        """Test that bracket notation returns None for missing keys."""
        meta_map = MetadatumMap()
        result = meta_map[1]
        assert result is None

    def test_can_use_in_operator(self):
        """Test that 'in' operator works correctly."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        assert 1 in meta_map
        assert 3 not in meta_map

    def test_can_iterate_over_keys(self):
        """Test that iteration yields keys."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        meta_map[3] = 4
        keys = list(meta_map)
        assert len(keys) == 2

    def test_can_use_keys_method(self):
        """Test that keys() method works like dict."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        meta_map[3] = 4
        keys = list(meta_map.keys())
        assert len(keys) == 2

    def test_can_use_values_method(self):
        """Test that values() method works like dict."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        meta_map[3] = 4
        values = list(meta_map.values())
        assert len(values) == 2

    def test_can_use_items_method(self):
        """Test that items() method works like dict."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        meta_map[3] = 4
        items = list(meta_map.items())
        assert len(items) == 2
        for key, value in items:
            assert key is not None
            assert value is not None

    def test_bool_is_false_for_empty_map(self):
        """Test that empty map evaluates to False."""
        meta_map = MetadatumMap()
        assert not meta_map

    def test_bool_is_true_for_non_empty_map(self):
        """Test that non-empty map evaluates to True."""
        meta_map = MetadatumMap()
        meta_map[1] = 2
        assert meta_map


class TestMetadatumMapToCip116Json:
    """Tests for MetadatumMap.to_cip116_json() method."""

    def test_can_serialize_empty_map_to_json(self):
        """Test that empty map can be serialized to CIP-116 JSON."""
        meta_map = MetadatumMap()
        writer = JsonWriter()
        meta_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert "map" in json_str
        assert "contents" in json_str

    def test_can_serialize_simple_map_to_json(self):
        """Test that simple map can be serialized to CIP-116 JSON."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        writer = JsonWriter()
        meta_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert "1" in json_str
        assert "2" in json_str

    def test_raises_error_if_writer_is_not_json_writer(self):
        """Test that passing non-JsonWriter raises TypeError."""
        meta_map = MetadatumMap()
        with pytest.raises(TypeError):
            meta_map.to_cip116_json("not a writer")

    def test_can_serialize_nested_map_to_json(self):
        """Test that nested map can be serialized to CIP-116 JSON."""
        inner_map = MetadatumMap()
        inner_map.insert(1, 2)
        outer_map = MetadatumMap()
        outer_map.insert(Metadatum.from_map(inner_map), 3)
        writer = JsonWriter()
        outer_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert "{" in json_str


class TestMetadatumMapEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_can_handle_large_map(self):
        """Test that map can handle many entries."""
        meta_map = MetadatumMap()
        for i in range(100):
            meta_map.insert(i, i * 2)
        assert len(meta_map) == 100

    def test_can_handle_unicode_strings(self):
        """Test that map can handle Unicode string keys and values."""
        meta_map = MetadatumMap()
        meta_map.insert("hello", "world")
        meta_map.insert("emoji", "🎉")
        result = meta_map.get("emoji")
        assert result is not None
        assert result.to_str() == "🎉"

    def test_can_handle_empty_bytes(self):
        """Test that map can handle empty byte arrays."""
        meta_map = MetadatumMap()
        meta_map.insert(b"", b"")
        assert len(meta_map) == 1

    def test_can_handle_large_integers(self):
        """Test that map can handle large integer values within valid range."""
        meta_map = MetadatumMap()
        large_int = 2**63 - 1
        meta_map.insert(1, large_int)
        result = meta_map.get(1)
        assert result is not None

    def test_iteration_order_is_consistent(self):
        """Test that iteration order is consistent."""
        meta_map = MetadatumMap()
        meta_map.insert(1, 2)
        meta_map.insert(3, 4)
        meta_map.insert(5, 6)

        keys1 = [k.to_integer().to_int() for k in meta_map.keys()]
        keys2 = [k.to_integer().to_int() for k in meta_map.keys()]
        assert keys1 == keys2

    def test_can_mix_different_key_types(self):
        """Test that map can handle different key types simultaneously."""
        meta_map = MetadatumMap()
        meta_map.insert(1, "int_key")
        meta_map.insert("str_key", 2)
        meta_map.insert(b"bytes_key", 3)
        assert len(meta_map) == 3
        assert 1 in meta_map
        assert "str_key" in meta_map
        assert b"bytes_key" in meta_map
