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
    AssetNameMap,
    AssetName,
    AssetNameList,
    CardanoError,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
)


CBOR = "a349736b7977616c6b65710149736b7977616c6b65720249736b7977616c6b657303"
ASSET_NAME_CBOR_1 = "49736b7977616c6b6571"
ASSET_NAME_CBOR_2 = "49736b7977616c6b6572"
ASSET_NAME_HEX_1 = "736b7977616c6b6571"
ASSET_NAME_HEX_2 = "736b7977616c6b6572"
ASSET_NAME_HEX_3 = "736b7977616c6b6573"


class TestAssetNameMapNew:
    """Tests for AssetNameMap() constructor."""

    def test_can_create_empty_map(self):
        """Test that an empty AssetNameMap can be created."""
        asset_map = AssetNameMap()
        assert asset_map is not None
        assert len(asset_map) == 0

    def test_new_map_is_empty(self):
        """Test that newly created map has zero length."""
        asset_map = AssetNameMap()
        assert len(asset_map) == 0

    def test_new_map_is_falsy(self):
        """Test that empty map evaluates to False."""
        asset_map = AssetNameMap()
        assert not asset_map

    def test_raises_error_if_invalid_ptr(self):
        """Test that invalid ptr raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            AssetNameMap(ffi.NULL)


class TestAssetNameMapFromCbor:
    """Tests for AssetNameMap.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that AssetNameMap can be deserialized from CBOR."""
        reader = CborReader.from_hex(CBOR)
        asset_map = AssetNameMap.from_cbor(reader)
        assert asset_map is not None
        assert len(asset_map) == 3

    def test_can_roundtrip_cbor(self):
        """Test that CBOR serialization roundtrips correctly."""
        reader = CborReader.from_hex(CBOR)
        asset_map = AssetNameMap.from_cbor(reader)
        writer = CborWriter()
        asset_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_raises_error_if_reader_is_none(self):
        """Test that None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            AssetNameMap.from_cbor(None)

    def test_raises_error_if_invalid_cbor_not_a_map(self):
        """Test that invalid CBOR (not a map) raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            AssetNameMap.from_cbor(reader)

    def test_raises_error_if_invalid_cbor_incomplete_map(self):
        """Test that incomplete map raises an error."""
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            AssetNameMap.from_cbor(reader)

    def test_raises_error_if_invalid_asset_name(self):
        """Test that invalid asset name raises an error."""
        reader = CborReader.from_hex("a3ef736b7977616c6b65710149736b7977616c6b65720249736b7977616c6b657303")
        with pytest.raises(CardanoError):
            AssetNameMap.from_cbor(reader)

    def test_raises_error_if_invalid_value(self):
        """Test that invalid value raises an error."""
        reader = CborReader.from_hex("a349736b7977616c6b6571ef49736b7977616c6b65720249736b7977616c6b657303")
        with pytest.raises(CardanoError):
            AssetNameMap.from_cbor(reader)


class TestAssetNameMapToCbor:
    """Tests for AssetNameMap.to_cbor() method."""

    def test_can_serialize_empty_map(self):
        """Test that empty map serializes to CBOR."""
        asset_map = AssetNameMap()
        writer = CborWriter()
        asset_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == "a0"

    def test_can_serialize_map_with_items(self):
        """Test that map with items serializes correctly."""
        reader = CborReader.from_hex(CBOR)
        asset_map = AssetNameMap.from_cbor(reader)
        writer = CborWriter()
        asset_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_map.to_cbor(None)


class TestAssetNameMapInsert:
    """Tests for AssetNameMap.insert() method."""

    def test_can_insert_asset_name(self):
        """Test that asset name can be inserted."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert len(asset_map) == 1

    def test_can_insert_multiple_asset_names(self):
        """Test that multiple asset names can be inserted."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        assert len(asset_map) == 2

    def test_can_insert_with_negative_value(self):
        """Test that negative values can be inserted (for burning)."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, -50)
        assert asset_map.get(asset_name) == -50

    def test_can_override_existing_value(self):
        """Test that inserting same key updates the value."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        asset_map.insert(asset_name, 200)
        assert asset_map.get(asset_name) == 200
        assert len(asset_map) == 1

    def test_keeps_elements_sorted(self):
        """Test that elements are kept sorted by asset name."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_name3 = AssetName.from_hex(ASSET_NAME_HEX_3)

        asset_map.insert(asset_name3, 300)
        asset_map.insert(asset_name2, 200)
        asset_map.insert(asset_name1, 100)

        key0 = asset_map.get_key_at(0)
        key1 = asset_map.get_key_at(1)
        key2 = asset_map.get_key_at(2)

        assert str(key0) == str(asset_name1)
        assert str(key1) == str(asset_name2)
        assert str(key2) == str(asset_name3)

    def test_raises_error_if_key_is_none(self):
        """Test that None key raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_map.insert(None, 100)


class TestAssetNameMapGet:
    """Tests for AssetNameMap.get() method."""

    def test_can_get_value_by_key(self):
        """Test that value can be retrieved by key."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert asset_map.get(asset_name) == 100

    def test_returns_none_if_key_not_found(self):
        """Test that None is returned if key not found."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert asset_map.get(asset_name) is None

    def test_returns_default_if_key_not_found(self):
        """Test that default value is returned if key not found."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert asset_map.get(asset_name, 999) == 999

    def test_can_get_negative_value(self):
        """Test that negative values can be retrieved."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, -50)
        assert asset_map.get(asset_name) == -50

    def test_can_get_multiple_values(self):
        """Test that multiple values can be retrieved."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        assert asset_map.get(asset_name1) == 100
        assert asset_map.get(asset_name2) == 200

    def test_raises_error_if_key_is_none(self):
        """Test that None key raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_map.get(None)


class TestAssetNameMapGetKeyAt:
    """Tests for AssetNameMap.get_key_at() method."""

    def test_can_get_key_at_index(self):
        """Test that key can be retrieved by index."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        key = asset_map.get_key_at(0)
        assert str(key) == str(asset_name)

    def test_raises_error_if_index_out_of_bounds(self):
        """Test that out of bounds index raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises(IndexError):
            asset_map.get_key_at(0)

    def test_raises_error_if_negative_index(self):
        """Test that negative index raises an error."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        with pytest.raises(IndexError):
            asset_map.get_key_at(-1)


class TestAssetNameMapGetValueAt:
    """Tests for AssetNameMap.get_value_at() method."""

    def test_can_get_value_at_index(self):
        """Test that value can be retrieved by index."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        value = asset_map.get_value_at(0)
        assert value == 100

    def test_can_get_negative_value_at_index(self):
        """Test that negative value can be retrieved by index."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, -50)
        value = asset_map.get_value_at(0)
        assert value == -50

    def test_raises_error_if_index_out_of_bounds(self):
        """Test that out of bounds index raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises(IndexError):
            asset_map.get_value_at(0)

    def test_raises_error_if_negative_index(self):
        """Test that negative index raises an error."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        with pytest.raises(IndexError):
            asset_map.get_value_at(-1)


class TestAssetNameMapGetKeyValueAt:
    """Tests for AssetNameMap.get_key_value_at() method."""

    def test_can_get_key_value_at_index(self):
        """Test that key-value pair can be retrieved by index."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        key, value = asset_map.get_key_value_at(0)
        assert str(key) == str(asset_name)
        assert value == 100

    def test_raises_error_if_index_out_of_bounds(self):
        """Test that out of bounds index raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises(IndexError):
            asset_map.get_key_value_at(0)

    def test_raises_error_if_negative_index(self):
        """Test that negative index raises an error."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        with pytest.raises(IndexError):
            asset_map.get_key_value_at(-1)


class TestAssetNameMapGetKeys:
    """Tests for AssetNameMap.get_keys() method."""

    def test_can_get_keys_from_empty_map(self):
        """Test that keys can be retrieved from empty map."""
        asset_map = AssetNameMap()
        keys = asset_map.get_keys()
        assert keys is not None
        assert len(keys) == 0

    def test_can_get_keys_from_map(self):
        """Test that keys can be retrieved from map."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        keys = asset_map.get_keys()
        assert len(keys) == 2


class TestAssetNameMapAdd:
    """Tests for AssetNameMap.add() method."""

    def test_can_add_two_empty_maps(self):
        """Test that two empty maps can be added."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        result = map1.add(map2)
        assert len(result) == 0

    def test_can_add_two_maps(self):
        """Test that two maps can be added."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name2, 200)
        result = map1.add(map2)
        assert len(result) == 2
        assert result.get(asset_name1) == 100
        assert result.get(asset_name2) == 200

    def test_adds_positive_values_for_same_asset_name(self):
        """Test that positive values are added for same asset name."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name1, 50)
        map2.insert(asset_name2, 200)
        result = map1.add(map2)
        assert len(result) == 2
        assert result.get(asset_name1) == 150
        assert result.get(asset_name2) == 200

    def test_adds_negative_values_for_same_asset_name(self):
        """Test that negative values are added for same asset name."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, -100)
        map2.insert(asset_name1, -50)
        map2.insert(asset_name2, -200)
        result = map1.add(map2)
        assert len(result) == 2
        assert result.get(asset_name1) == -150
        assert result.get(asset_name2) == -200

    def test_raises_error_if_other_is_none(self):
        """Test that None other raises an error."""
        map1 = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            map1.add(None)


class TestAssetNameMapSubtract:
    """Tests for AssetNameMap.subtract() method."""

    def test_can_subtract_two_empty_maps(self):
        """Test that two empty maps can be subtracted."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        result = map1.subtract(map2)
        assert len(result) == 0

    def test_can_subtract_two_maps(self):
        """Test that two maps can be subtracted."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name2, 200)
        result = map1.subtract(map2)
        assert len(result) == 2
        assert result.get(asset_name1) == 100
        assert result.get(asset_name2) == -200

    def test_subtracts_positive_values_for_same_asset_name(self):
        """Test that positive values are subtracted for same asset name."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name1, 100)
        map2.insert(asset_name2, 200)
        result = map1.subtract(map2)
        assert len(result) == 1
        assert result.get(asset_name1) is None
        assert result.get(asset_name2) == -200

    def test_subtracts_negative_values_for_same_asset_name(self):
        """Test that negative values are subtracted correctly."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name1, 400)
        map2.insert(asset_name2, -100)
        result = map1.subtract(map2)
        assert len(result) == 2
        assert result.get(asset_name1) == -300
        assert result.get(asset_name2) == 100

    def test_raises_error_if_other_is_none(self):
        """Test that None other raises an error."""
        map1 = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            map1.subtract(None)


class TestAssetNameMapToCip116Json:
    """Tests for AssetNameMap.to_cip116_json() method."""

    def test_can_convert_empty_map_to_json(self):
        """Test that empty map converts to JSON."""
        asset_map = AssetNameMap()
        writer = JsonWriter(JsonFormat.COMPACT)
        asset_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "{}"

    def test_can_convert_map_to_json(self):
        """Test that map with items converts to JSON."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex("4d794173736574")
        asset_map.insert(asset_name1, 123)
        asset_name2 = AssetName.from_hex("")
        asset_map.insert(asset_name2, -456)
        writer = JsonWriter(JsonFormat.COMPACT)
        asset_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == '{"":"-456","4d794173736574":"123"}'

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        asset_map = AssetNameMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            asset_map.to_cip116_json(None)


class TestAssetNameMapLen:
    """Tests for len(AssetNameMap) built-in."""

    def test_empty_map_has_zero_length(self):
        """Test that empty map has zero length."""
        asset_map = AssetNameMap()
        assert len(asset_map) == 0

    def test_map_with_one_item_has_length_one(self):
        """Test that map with one item has length one."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert len(asset_map) == 1

    def test_map_with_multiple_items_has_correct_length(self):
        """Test that map with multiple items has correct length."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        assert len(asset_map) == 2


class TestAssetNameMapIter:
    """Tests for iter(AssetNameMap) built-in."""

    def test_can_iterate_over_keys(self):
        """Test that map can be iterated over."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        keys = list(asset_map)
        assert len(keys) == 2

    def test_empty_map_iteration(self):
        """Test that empty map iteration works."""
        asset_map = AssetNameMap()
        keys = list(asset_map)
        assert len(keys) == 0


class TestAssetNameMapGetItem:
    """Tests for AssetNameMap[key] bracket notation."""

    def test_can_get_value_with_brackets(self):
        """Test that value can be retrieved using brackets."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert asset_map[asset_name] == 100

    def test_returns_none_if_key_not_found(self):
        """Test that None is returned if key not found."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert asset_map[asset_name] is None


class TestAssetNameMapSetItem:
    """Tests for AssetNameMap[key] = value bracket notation."""

    def test_can_set_value_with_brackets(self):
        """Test that value can be set using brackets."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map[asset_name] = 100
        assert asset_map.get(asset_name) == 100

    def test_can_override_value_with_brackets(self):
        """Test that value can be overridden using brackets."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map[asset_name] = 100
        asset_map[asset_name] = 200
        assert asset_map.get(asset_name) == 200


class TestAssetNameMapBool:
    """Tests for bool(AssetNameMap) built-in."""

    def test_empty_map_is_falsy(self):
        """Test that empty map evaluates to False."""
        asset_map = AssetNameMap()
        assert not asset_map

    def test_non_empty_map_is_truthy(self):
        """Test that non-empty map evaluates to True."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert asset_map


class TestAssetNameMapContains:
    """Tests for 'in' operator with AssetNameMap."""

    def test_contains_returns_true_if_key_exists(self):
        """Test that 'in' returns True if key exists."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        assert asset_name in asset_map

    def test_contains_returns_false_if_key_not_exists(self):
        """Test that 'in' returns False if key does not exist."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        assert asset_name not in asset_map


class TestAssetNameMapEq:
    """Tests for AssetNameMap == operator."""

    def test_empty_maps_are_equal(self):
        """Test that two empty maps are equal."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        assert map1 == map2

    def test_maps_with_same_content_are_equal(self):
        """Test that maps with same content are equal."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        map1.insert(asset_name, 100)
        map2.insert(asset_name, 100)
        assert map1 == map2

    def test_maps_with_different_values_are_not_equal(self):
        """Test that maps with different values are not equal."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        map1.insert(asset_name, 100)
        map2.insert(asset_name, 200)
        assert map1 != map2

    def test_maps_with_different_lengths_are_not_equal(self):
        """Test that maps with different lengths are not equal."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        map1.insert(asset_name, 100)
        assert map1 != map2

    def test_map_not_equal_to_non_map(self):
        """Test that map is not equal to non-map type."""
        map1 = AssetNameMap()
        assert map1 != "not a map"
        assert map1 != 123
        assert map1 != None


class TestAssetNameMapAddOperator:
    """Tests for AssetNameMap + operator."""

    def test_can_add_with_plus_operator(self):
        """Test that + operator works."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name2, 200)
        result = map1 + map2
        assert len(result) == 2
        assert result.get(asset_name1) == 100
        assert result.get(asset_name2) == 200


class TestAssetNameMapSubOperator:
    """Tests for AssetNameMap - operator."""

    def test_can_subtract_with_minus_operator(self):
        """Test that - operator works."""
        map1 = AssetNameMap()
        map2 = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        map1.insert(asset_name1, 100)
        map2.insert(asset_name2, 200)
        result = map1 - map2
        assert len(result) == 2
        assert result.get(asset_name1) == 100
        assert result.get(asset_name2) == -200


class TestAssetNameMapKeys:
    """Tests for AssetNameMap.keys() method."""

    def test_can_get_keys_iterator(self):
        """Test that keys iterator can be obtained."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        keys = list(asset_map.keys())
        assert len(keys) == 2


class TestAssetNameMapValues:
    """Tests for AssetNameMap.values() method."""

    def test_can_get_values_iterator(self):
        """Test that values iterator can be obtained."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        values = list(asset_map.values())
        assert len(values) == 2
        assert 100 in values
        assert 200 in values


class TestAssetNameMapItems:
    """Tests for AssetNameMap.items() method."""

    def test_can_get_items_iterator(self):
        """Test that items iterator can be obtained."""
        asset_map = AssetNameMap()
        asset_name1 = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_name2 = AssetName.from_hex(ASSET_NAME_HEX_2)
        asset_map.insert(asset_name1, 100)
        asset_map.insert(asset_name2, 200)
        items = list(asset_map.items())
        assert len(items) == 2
        keys = [k for k, v in items]
        values = [v for k, v in items]
        assert len(keys) == 2
        assert 100 in values
        assert 200 in values


class TestAssetNameMapRepr:
    """Tests for repr(AssetNameMap) built-in."""

    def test_repr_shows_length(self):
        """Test that repr shows the length."""
        asset_map = AssetNameMap()
        asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
        asset_map.insert(asset_name, 100)
        repr_str = repr(asset_map)
        assert "AssetNameMap" in repr_str
        assert "1" in repr_str


class TestAssetNameMapContextManager:
    """Tests for AssetNameMap context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that AssetNameMap can be used as context manager."""
        with AssetNameMap() as asset_map:
            asset_name = AssetName.from_hex(ASSET_NAME_HEX_1)
            asset_map.insert(asset_name, 100)
            assert len(asset_map) == 1
