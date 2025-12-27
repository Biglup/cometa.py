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
    PlutusData,
    PlutusDataKind,
    PlutusMap,
    PlutusList,
    CborWriter,
    CborReader,
    JsonWriter,
)


SIMPLE_MAP_CBOR = "a10102"
INDEFINITE_MAP_CBOR = "bf0102ff"


class TestPlutusMapCreation:
    """Tests for PlutusMap creation."""

    def test_create_empty_map(self):
        """Test creating an empty PlutusMap."""
        pmap = PlutusMap()
        assert len(pmap) == 0
        assert not pmap

    def test_create_with_initial_values(self):
        """Test creating map with initial values."""
        pmap = PlutusMap()
        pmap["key1"] = 42
        pmap["key2"] = "value"
        assert len(pmap) == 2


class TestPlutusMapCbor:
    """Tests for PlutusMap CBOR serialization."""

    def test_serialize_simple_map(self):
        """Test CBOR serialization of simple map."""
        pmap = PlutusMap()
        pmap[1] = 2
        writer = CborWriter()
        pmap.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_MAP_CBOR

    def test_deserialize_simple_map(self):
        """Test CBOR deserialization of simple map."""
        reader = CborReader.from_hex(SIMPLE_MAP_CBOR)
        pmap = PlutusMap.from_cbor(reader)
        assert len(pmap) == 1
        assert pmap[1].to_int() == 2

    def test_deserialize_indefinite_map(self):
        """Test CBOR deserialization of indefinite-length map."""
        reader = CborReader.from_hex(INDEFINITE_MAP_CBOR)
        pmap = PlutusMap.from_cbor(reader)
        pmap.clear_cbor_cache()
        assert len(pmap) == 1
        assert pmap[1].to_int() == 2

    def test_roundtrip_cbor(self):
        """Test CBOR roundtrip preserves data."""
        pmap = PlutusMap()
        pmap["key"] = 42
        pmap[123] = "value"
        pmap[b"\x01\x02"] = b"\x03\x04"

        writer = CborWriter()
        pmap.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusMap.from_cbor(reader)

        assert len(restored) == 3
        assert restored["key"].to_int() == 42
        assert restored[123].to_string() == "value"

    def test_from_cbor_not_a_map_raises(self):
        """Test that deserializing non-map CBOR raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(Exception):
            PlutusMap.from_cbor(reader)


class TestPlutusMapAccess:
    """Tests for PlutusMap element access."""

    def test_setitem_and_getitem_int_key(self):
        """Test setting and getting with int key."""
        pmap = PlutusMap()
        pmap[1] = 100
        assert pmap[1].to_int() == 100

    def test_setitem_and_getitem_string_key(self):
        """Test setting and getting with string key."""
        pmap = PlutusMap()
        pmap["hello"] = "world"
        assert pmap["hello"].to_string() == "world"

    def test_setitem_and_getitem_bytes_key(self):
        """Test setting and getting with bytes key."""
        pmap = PlutusMap()
        pmap[b"\xde\xad"] = b"\xbe\xef"
        assert pmap[b"\xde\xad"].to_bytes() == b"\xbe\xef"

    def test_getitem_missing_key_raises(self):
        """Test that missing key raises KeyError."""
        pmap = PlutusMap()
        pmap["exists"] = 1
        with pytest.raises(KeyError):
            _ = pmap["missing"]

    def test_insert_plutus_data(self):
        """Test inserting PlutusData directly."""
        pmap = PlutusMap()
        key = PlutusData.from_int(1)
        value = PlutusData.from_int(2)
        pmap.insert(key, value)
        assert len(pmap) == 1
        assert pmap[1].to_int() == 2


class TestPlutusMapGet:
    """Tests for PlutusMap get method."""

    def test_get_existing_key(self):
        """Test get with existing key."""
        pmap = PlutusMap()
        pmap["key"] = 42
        result = pmap.get("key")
        assert result is not None
        assert result.to_int() == 42

    def test_get_missing_key_returns_none(self):
        """Test get with missing key returns None."""
        pmap = PlutusMap()
        assert pmap.get("missing") is None

    def test_get_missing_key_with_default(self):
        """Test get with missing key returns default."""
        pmap = PlutusMap()
        default = PlutusData.from_int(99)
        result = pmap.get("missing", default)
        assert result.to_int() == 99


class TestPlutusMapContains:
    """Tests for PlutusMap membership testing."""

    def test_contains_int_key(self):
        """Test membership with int key."""
        pmap = PlutusMap()
        pmap[1] = "value"
        assert 1 in pmap
        assert 2 not in pmap

    def test_contains_string_key(self):
        """Test membership with string key."""
        pmap = PlutusMap()
        pmap["key"] = 42
        assert "key" in pmap
        assert "missing" not in pmap

    def test_contains_bytes_key(self):
        """Test membership with bytes key."""
        pmap = PlutusMap()
        pmap[b"\x01"] = "value"
        assert b"\x01" in pmap
        assert b"\x02" not in pmap


class TestPlutusMapIteration:
    """Tests for PlutusMap iteration."""

    def test_keys_iteration(self):
        """Test iterating over keys."""
        pmap = PlutusMap()
        pmap[1] = "one"
        pmap[2] = "two"
        pmap[3] = "three"
        keys = list(pmap.keys())
        assert len(keys) == 3
        key_values = sorted([k.to_int() for k in keys])
        assert key_values == [1, 2, 3]

    def test_values_iteration(self):
        """Test iterating over values."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        pmap["c"] = 3
        values = list(pmap.values())
        assert len(values) == 3
        value_ints = sorted([v.to_int() for v in values])
        assert value_ints == [1, 2, 3]

    def test_items_iteration(self):
        """Test iterating over items."""
        pmap = PlutusMap()
        pmap[1] = "one"
        pmap[2] = "two"
        items = list(pmap.items())
        assert len(items) == 2
        for key, value in items:
            assert key.kind == PlutusDataKind.INTEGER
            assert value.kind == PlutusDataKind.BYTES

    def test_iter_returns_keys(self):
        """Test that iter() returns keys."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        keys_via_iter = list(pmap)
        keys_via_keys = list(pmap.keys())
        assert len(keys_via_iter) == len(keys_via_keys)

    def test_get_keys(self):
        """Test get_keys returns PlutusList."""
        pmap = PlutusMap()
        pmap[1] = "one"
        pmap[2] = "two"
        keys_list = pmap.get_keys()
        assert isinstance(keys_list, PlutusList)
        assert len(keys_list) == 2

    def test_get_values(self):
        """Test get_values returns PlutusList."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        values_list = pmap.get_values()
        assert isinstance(values_list, PlutusList)
        assert len(values_list) == 2


class TestPlutusMapUpdate:
    """Tests for PlutusMap update operations."""

    def test_update_from_dict(self):
        """Test updating from a dict."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap.update({"b": 2, "c": 3})
        assert len(pmap) == 3
        assert pmap["a"].to_int() == 1
        assert pmap["b"].to_int() == 2
        assert pmap["c"].to_int() == 3

    def test_update_from_plutus_map(self):
        """Test updating from another PlutusMap."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["b"] = 2
        pmap2["c"] = 3
        pmap1.update(pmap2)
        assert len(pmap1) == 3

    def test_update_adds_new_keys(self):
        """Test that update adds new keys."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap.update({"b": 2})
        assert len(pmap) == 2
        assert pmap["b"].to_int() == 2


class TestPlutusMapSetdefault:
    """Tests for PlutusMap setdefault method."""

    def test_setdefault_existing_key(self):
        """Test setdefault with existing key."""
        pmap = PlutusMap()
        pmap["existing"] = 1
        result = pmap.setdefault("existing", 99)
        assert result.to_int() == 1
        assert pmap["existing"].to_int() == 1

    def test_setdefault_missing_key(self):
        """Test setdefault with missing key."""
        pmap = PlutusMap()
        result = pmap.setdefault("new", 42)
        assert result.to_int() == 42
        assert pmap["new"].to_int() == 42

    def test_setdefault_with_different_types(self):
        """Test setdefault with different value types."""
        pmap = PlutusMap()
        result = pmap.setdefault("key", "hello")
        assert result.to_string() == "hello"


class TestPlutusMapCopy:
    """Tests for PlutusMap copy operations."""

    def test_copy(self):
        """Test copying map."""
        pmap1 = PlutusMap()
        pmap1["key"] = 42
        pmap1[123] = "value"
        pmap2 = pmap1.copy()
        assert len(pmap2) == 2
        assert pmap2["key"].to_int() == 42
        assert pmap2[123].to_string() == "value"

    def test_copy_is_independent(self):
        """Test that copy creates an independent map."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = pmap1.copy()
        pmap2["b"] = 2
        assert len(pmap1) == 1
        assert len(pmap2) == 2


class TestPlutusMapPop:
    """Tests for PlutusMap pop method (unsupported)."""

    def test_pop_raises_not_implemented(self):
        """Test that pop raises NotImplementedError."""
        pmap = PlutusMap()
        pmap["key"] = 42
        with pytest.raises(NotImplementedError):
            pmap.pop("key")


class TestPlutusMapEquality:
    """Tests for PlutusMap equality."""

    def test_equality_empty_maps(self):
        """Test equality of empty maps."""
        pmap1 = PlutusMap()
        pmap2 = PlutusMap()
        assert pmap1 == pmap2

    def test_equality_same_entries(self):
        """Test equality with same entries."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["a"] = 1
        assert pmap1 == pmap2

    def test_equality_different_values(self):
        """Test inequality with different values."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["a"] = 2
        assert pmap1 != pmap2

    def test_equality_different_keys(self):
        """Test inequality with different keys."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["b"] = 1
        assert pmap1 != pmap2

    def test_equality_different_sizes(self):
        """Test inequality with different sizes."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["a"] = 1
        pmap2["b"] = 2
        assert pmap1 != pmap2

    def test_equality_with_non_map(self):
        """Test inequality with non-PlutusMap."""
        pmap = PlutusMap()
        assert pmap != {"a": 1}
        assert pmap != "test"
        assert pmap != 42


class TestPlutusMapBool:
    """Tests for PlutusMap bool conversion."""

    def test_bool_empty_is_false(self):
        """Test that empty map is falsy."""
        pmap = PlutusMap()
        assert not pmap
        assert bool(pmap) is False

    def test_bool_non_empty_is_true(self):
        """Test that non-empty map is truthy."""
        pmap = PlutusMap()
        pmap["key"] = 1
        assert pmap
        assert bool(pmap) is True


class TestPlutusMapRepr:
    """Tests for PlutusMap string representation."""

    def test_repr_empty(self):
        """Test repr of empty map."""
        pmap = PlutusMap()
        assert repr(pmap) == "PlutusMap(len=0)"

    def test_repr_with_entries(self):
        """Test repr of map with entries."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        assert repr(pmap) == "PlutusMap(len=2)"


class TestPlutusMapContextManager:
    """Tests for PlutusMap context manager."""

    def test_context_manager(self):
        """Test using PlutusMap as context manager."""
        with PlutusMap() as pmap:
            pmap["key"] = 42
            assert len(pmap) == 1


class TestPlutusMapEdgeCases:
    """Tests for PlutusMap edge cases."""

    def test_large_map(self):
        """Test creating a large map."""
        pmap = PlutusMap()
        for i in range(100):
            pmap[i] = i * 10
        assert len(pmap) == 100
        assert pmap[50].to_int() == 500

    def test_map_with_empty_string_key(self):
        """Test map with empty string key."""
        pmap = PlutusMap()
        pmap[""] = "empty key"
        assert len(pmap) == 1
        assert pmap[""].to_string() == "empty key"

    def test_map_with_empty_bytes_key(self):
        """Test map with empty bytes key."""
        pmap = PlutusMap()
        pmap[b""] = "empty bytes key"
        assert len(pmap) == 1
        assert pmap[b""].to_string() == "empty bytes key"

    def test_map_with_zero_key(self):
        """Test map with zero as key."""
        pmap = PlutusMap()
        pmap[0] = "zero"
        assert 0 in pmap
        assert pmap[0].to_string() == "zero"

    def test_map_with_negative_key(self):
        """Test map with negative integer key."""
        pmap = PlutusMap()
        pmap[-1] = "negative"
        assert -1 in pmap
        assert pmap[-1].to_string() == "negative"

    def test_map_with_large_integer_key(self):
        """Test map with large integer key."""
        large_key = 2**64 + 1
        pmap = PlutusMap()
        pmap[large_key] = "large"
        assert large_key in pmap
        assert pmap[large_key].to_string() == "large"

    def test_map_with_list_value(self):
        """Test map with PlutusList as value."""
        plist = PlutusList()
        plist.extend([1, 2, 3])
        pmap = PlutusMap()
        pmap.insert(PlutusData.from_string("list"), PlutusData.from_list(plist))
        assert len(pmap) == 1
        restored = pmap["list"]
        assert restored.kind == PlutusDataKind.LIST
        restored_list = restored.to_list()
        assert len(restored_list) == 3

    def test_map_with_map_value(self):
        """Test map with PlutusMap as value."""
        inner_map = PlutusMap()
        inner_map["inner"] = 42
        pmap = PlutusMap()
        pmap.insert(PlutusData.from_string("outer"), PlutusData.from_map(inner_map))
        assert len(pmap) == 1
        restored = pmap["outer"]
        assert restored.kind == PlutusDataKind.MAP

    def test_insert_multiple_values(self):
        """Test inserting multiple unique values."""
        pmap = PlutusMap()
        pmap["key1"] = 1
        pmap["key2"] = 2
        pmap["key3"] = 3
        assert len(pmap) == 3
        assert pmap["key1"].to_int() == 1
        assert pmap["key2"].to_int() == 2
        assert pmap["key3"].to_int() == 3


class TestPlutusMapCip116Json:
    """Tests for PlutusMap CIP-116 JSON serialization."""

    def test_to_cip116_json_empty_map(self):
        """Test CIP-116 JSON serialization of empty map."""
        pmap = PlutusMap()
        writer = JsonWriter()
        pmap.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"map"' in result
        assert '"contents":[]' in result

    def test_to_cip116_json_with_integer_key_and_bytes_value(self):
        """Test CIP-116 JSON serialization with integer key and bytes value."""
        pmap = PlutusMap()
        pmap[1] = b"\xaa"
        writer = JsonWriter()
        pmap.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"map"' in result
        assert '"key"' in result
        assert '"value"' in result
        assert '"tag":"integer"' in result
        assert '"value":"1"' in result
        assert '"tag":"bytes"' in result
        assert '"value":"aa"' in result

    def test_to_cip116_json_with_bytes_key_and_integer_value(self):
        """Test CIP-116 JSON serialization with bytes key and integer value."""
        pmap = PlutusMap()
        pmap[b"\xbb"] = 2
        writer = JsonWriter()
        pmap.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"map"' in result
        assert '"key"' in result
        assert '"value"' in result
        assert '"tag":"bytes"' in result
        assert '"value":"bb"' in result
        assert '"tag":"integer"' in result
        assert '"value":"2"' in result

    def test_to_cip116_json_with_multiple_entries(self):
        """Test CIP-116 JSON serialization with multiple entries."""
        pmap = PlutusMap()
        pmap[1] = b"\xaa"
        pmap[b"\xbb"] = 2
        writer = JsonWriter()
        pmap.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"map"' in result
        assert '"contents"' in result
        assert result.count('"key"') == 2
        assert result.count('"value"') >= 2

    def test_to_cip116_json_with_string_keys(self):
        """Test CIP-116 JSON serialization with string keys."""
        pmap = PlutusMap()
        pmap["key1"] = 1
        pmap["key2"] = 2
        writer = JsonWriter()
        pmap.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"map"' in result
        assert '"tag":"bytes"' in result

    def test_to_cip116_json_with_invalid_writer_raises(self):
        """Test that to_cip116_json with invalid writer raises error."""
        pmap = PlutusMap()
        with pytest.raises(TypeError):
            pmap.to_cip116_json("not a writer")

    def test_to_cip116_json_with_none_writer_raises(self):
        """Test that to_cip116_json with None writer raises error."""
        pmap = PlutusMap()
        with pytest.raises((TypeError, AttributeError)):
            pmap.to_cip116_json(None)


class TestPlutusMapCborCache:
    """Tests for PlutusMap CBOR cache functionality."""

    def test_clear_cbor_cache(self):
        """Test clearing CBOR cache."""
        reader = CborReader.from_hex(SIMPLE_MAP_CBOR)
        pmap = PlutusMap.from_cbor(reader)
        pmap.clear_cbor_cache()
        writer = CborWriter()
        pmap.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_MAP_CBOR

    def test_cbor_cache_preserved_after_deserialization(self):
        """Test that CBOR cache is preserved after deserialization."""
        reader = CborReader.from_hex(INDEFINITE_MAP_CBOR)
        pmap = PlutusMap.from_cbor(reader)
        writer = CborWriter()
        pmap.to_cbor(writer)
        assert writer.to_hex() == INDEFINITE_MAP_CBOR

    def test_cbor_cache_cleared_after_clear_cbor_cache(self):
        """Test that CBOR cache is cleared after calling clear_cbor_cache."""
        reader = CborReader.from_hex(INDEFINITE_MAP_CBOR)
        pmap = PlutusMap.from_cbor(reader)
        pmap.clear_cbor_cache()
        writer = CborWriter()
        pmap.to_cbor(writer)
        assert writer.to_hex() == INDEFINITE_MAP_CBOR
