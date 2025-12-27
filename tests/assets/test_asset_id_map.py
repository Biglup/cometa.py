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
from cometa import AssetId, AssetIdMap, CardanoError


ASSET_ID_HEX_1 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657241"
ASSET_ID_HEX_2 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657242"
ASSET_ID_HEX_3 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657243"
ASSET_ID_HEX_4 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b657244"


@pytest.fixture
def asset_id_1():
    """Create first test asset ID."""
    return AssetId.from_hex(ASSET_ID_HEX_1)


@pytest.fixture
def asset_id_2():
    """Create second test asset ID."""
    return AssetId.from_hex(ASSET_ID_HEX_2)


@pytest.fixture
def asset_id_3():
    """Create third test asset ID."""
    return AssetId.from_hex(ASSET_ID_HEX_3)


@pytest.fixture
def asset_id_4():
    """Create fourth test asset ID."""
    return AssetId.from_hex(ASSET_ID_HEX_4)


@pytest.fixture
def lovelace_asset_id():
    """Create Lovelace asset ID."""
    return AssetId.new_lovelace()


@pytest.fixture
def empty_map():
    """Create an empty AssetIdMap."""
    return AssetIdMap()


@pytest.fixture
def populated_map(asset_id_1, asset_id_2):
    """Create a map with two entries."""
    asset_map = AssetIdMap()
    asset_map.insert(asset_id_1, 100)
    asset_map.insert(asset_id_2, 200)
    return asset_map


class TestAssetIdMapInit:
    """Tests for AssetIdMap initialization."""

    def test_can_create_empty_map(self):
        """Test that an empty AssetIdMap can be created."""
        asset_map = AssetIdMap()
        assert asset_map is not None
        assert len(asset_map) == 0

    def test_new_map_is_empty(self):
        """Test that a newly created map has no entries."""
        asset_map = AssetIdMap()
        assert len(asset_map) == 0
        assert not asset_map

    def test_context_manager(self):
        """Test that AssetIdMap can be used as a context manager."""
        with AssetIdMap() as asset_map:
            assert asset_map is not None
            assert len(asset_map) == 0


class TestAssetIdMapInsert:
    """Tests for AssetIdMap.insert() method."""

    def test_can_insert_single_entry(self, empty_map, asset_id_1):
        """Test inserting a single entry into the map."""
        empty_map.insert(asset_id_1, 100)
        assert len(empty_map) == 1
        assert empty_map.get(asset_id_1) == 100

    def test_can_insert_multiple_entries(self, empty_map, asset_id_1, asset_id_2):
        """Test inserting multiple entries into the map."""
        empty_map.insert(asset_id_1, 100)
        empty_map.insert(asset_id_2, 200)
        assert len(empty_map) == 2
        assert empty_map.get(asset_id_1) == 100
        assert empty_map.get(asset_id_2) == 200

    def test_can_insert_zero_value(self, empty_map, asset_id_1):
        """Test inserting an entry with zero value."""
        empty_map.insert(asset_id_1, 0)
        assert len(empty_map) == 1
        assert empty_map.get(asset_id_1) == 0

    def test_can_insert_negative_value(self, empty_map, asset_id_1):
        """Test inserting an entry with negative value."""
        empty_map.insert(asset_id_1, -100)
        assert len(empty_map) == 1
        assert empty_map.get(asset_id_1) == -100

    def test_can_override_existing_value(self, empty_map, asset_id_1):
        """Test that inserting an existing key overrides the value."""
        empty_map.insert(asset_id_1, 100)
        empty_map.insert(asset_id_1, 200)
        assert len(empty_map) == 1
        assert empty_map.get(asset_id_1) == 200

    def test_entries_kept_sorted(self, empty_map, asset_id_1, asset_id_2, asset_id_3):
        """Test that entries are kept sorted by asset ID."""
        empty_map.insert(asset_id_3, 3)
        empty_map.insert(asset_id_2, 2)
        empty_map.insert(asset_id_1, 1)
        assert len(empty_map) == 3
        assert empty_map.get_key_at(0).to_hex() == ASSET_ID_HEX_1
        assert empty_map.get_key_at(1).to_hex() == ASSET_ID_HEX_2
        assert empty_map.get_key_at(2).to_hex() == ASSET_ID_HEX_3

    def test_raises_error_for_none_key(self, empty_map):
        """Test that None key raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            empty_map.insert(None, 100)


class TestAssetIdMapGet:
    """Tests for AssetIdMap.get() method."""

    def test_returns_value_for_existing_key(self, populated_map, asset_id_1):
        """Test retrieving value for existing key."""
        value = populated_map.get(asset_id_1)
        assert value == 100

    def test_returns_none_for_nonexistent_key(self, populated_map, asset_id_3):
        """Test that get returns None for nonexistent key."""
        value = populated_map.get(asset_id_3)
        assert value is None

    def test_returns_default_for_nonexistent_key(self, populated_map, asset_id_3):
        """Test that get returns default value for nonexistent key."""
        value = populated_map.get(asset_id_3, -1)
        assert value == -1

    def test_can_get_multiple_values(self, populated_map, asset_id_1, asset_id_2):
        """Test retrieving multiple values."""
        assert populated_map.get(asset_id_1) == 100
        assert populated_map.get(asset_id_2) == 200

    def test_raises_error_for_none_key(self, populated_map):
        """Test that None key raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            populated_map.get(None)


class TestAssetIdMapGetKeys:
    """Tests for AssetIdMap.get_keys() method."""

    def test_returns_empty_list_for_empty_map(self, empty_map):
        """Test that get_keys returns empty list for empty map."""
        keys = empty_map.get_keys()
        assert len(keys) == 0

    def test_returns_all_keys(self, populated_map, asset_id_1, asset_id_2):
        """Test that get_keys returns all keys from map."""
        keys = populated_map.get_keys()
        assert len(keys) == 2
        assert keys.get(0).to_hex() == asset_id_1.to_hex()
        assert keys.get(1).to_hex() == asset_id_2.to_hex()


class TestAssetIdMapGetKeyAt:
    """Tests for AssetIdMap.get_key_at() method."""

    def test_returns_key_at_valid_index(self, populated_map, asset_id_1):
        """Test retrieving key at valid index."""
        key = populated_map.get_key_at(0)
        assert key.to_hex() == asset_id_1.to_hex()

    def test_raises_error_for_negative_index(self, populated_map):
        """Test that negative index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_key_at(-1)

    def test_raises_error_for_out_of_bounds_index(self, populated_map):
        """Test that out of bounds index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_key_at(10)

    def test_raises_error_for_empty_map(self, empty_map):
        """Test that get_key_at raises error for empty map."""
        with pytest.raises(IndexError):
            empty_map.get_key_at(0)


class TestAssetIdMapGetValueAt:
    """Tests for AssetIdMap.get_value_at() method."""

    def test_returns_value_at_valid_index(self, populated_map):
        """Test retrieving value at valid index."""
        value = populated_map.get_value_at(0)
        assert value == 100

    def test_raises_error_for_negative_index(self, populated_map):
        """Test that negative index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_value_at(-1)

    def test_raises_error_for_out_of_bounds_index(self, populated_map):
        """Test that out of bounds index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_value_at(10)

    def test_raises_error_for_empty_map(self, empty_map):
        """Test that get_value_at raises error for empty map."""
        with pytest.raises(IndexError):
            empty_map.get_value_at(0)


class TestAssetIdMapGetKeyValueAt:
    """Tests for AssetIdMap.get_key_value_at() method."""

    def test_returns_key_value_pair(self, populated_map, asset_id_1):
        """Test retrieving key-value pair at valid index."""
        key, value = populated_map.get_key_value_at(0)
        assert key.to_hex() == asset_id_1.to_hex()
        assert value == 100

    def test_raises_error_for_negative_index(self, populated_map):
        """Test that negative index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_key_value_at(-1)

    def test_raises_error_for_out_of_bounds_index(self, populated_map):
        """Test that out of bounds index raises IndexError."""
        with pytest.raises(IndexError):
            populated_map.get_key_value_at(10)

    def test_raises_error_for_empty_map(self, empty_map):
        """Test that get_key_value_at raises error for empty map."""
        with pytest.raises(IndexError):
            empty_map.get_key_value_at(0)


class TestAssetIdMapLen:
    """Tests for len() magic method."""

    def test_empty_map_has_zero_length(self, empty_map):
        """Test that empty map has length 0."""
        assert len(empty_map) == 0

    def test_length_increases_with_insertions(self, empty_map, asset_id_1, asset_id_2):
        """Test that length increases with insertions."""
        assert len(empty_map) == 0
        empty_map.insert(asset_id_1, 100)
        assert len(empty_map) == 1
        empty_map.insert(asset_id_2, 200)
        assert len(empty_map) == 2

    def test_length_unchanged_on_override(self, empty_map, asset_id_1):
        """Test that length is unchanged when overriding value."""
        empty_map.insert(asset_id_1, 100)
        assert len(empty_map) == 1
        empty_map.insert(asset_id_1, 200)
        assert len(empty_map) == 1


class TestAssetIdMapIter:
    """Tests for iteration methods."""

    def test_can_iterate_over_keys(self, populated_map, asset_id_1, asset_id_2):
        """Test iterating over keys."""
        keys = list(populated_map)
        assert len(keys) == 2
        assert keys[0].to_hex() == asset_id_1.to_hex()
        assert keys[1].to_hex() == asset_id_2.to_hex()

    def test_keys_method_returns_iterator(self, populated_map):
        """Test that keys() returns an iterator."""
        keys = list(populated_map.keys())
        assert len(keys) == 2

    def test_values_method_returns_iterator(self, populated_map):
        """Test that values() returns an iterator."""
        values = list(populated_map.values())
        assert len(values) == 2
        assert values[0] == 100
        assert values[1] == 200

    def test_items_method_returns_iterator(self, populated_map, asset_id_1, asset_id_2):
        """Test that items() returns an iterator."""
        items = list(populated_map.items())
        assert len(items) == 2
        assert items[0][0].to_hex() == asset_id_1.to_hex()
        assert items[0][1] == 100
        assert items[1][0].to_hex() == asset_id_2.to_hex()
        assert items[1][1] == 200

    def test_empty_map_iteration(self, empty_map):
        """Test iterating over empty map."""
        keys = list(empty_map)
        assert len(keys) == 0


class TestAssetIdMapContains:
    """Tests for __contains__ magic method."""

    def test_contains_returns_true_for_existing_key(self, populated_map, asset_id_1):
        """Test that contains returns True for existing key."""
        assert asset_id_1 in populated_map

    def test_contains_returns_false_for_nonexistent_key(self, populated_map, asset_id_3):
        """Test that contains returns False for nonexistent key."""
        assert asset_id_3 not in populated_map

    def test_contains_returns_false_for_empty_map(self, empty_map, asset_id_1):
        """Test that contains returns False for empty map."""
        assert asset_id_1 not in empty_map


class TestAssetIdMapBool:
    """Tests for __bool__ magic method."""

    def test_empty_map_is_falsy(self, empty_map):
        """Test that empty map is falsy."""
        assert not empty_map
        assert bool(empty_map) is False

    def test_populated_map_is_truthy(self, populated_map):
        """Test that populated map is truthy."""
        assert populated_map
        assert bool(populated_map) is True


class TestAssetIdMapGetItem:
    """Tests for __getitem__ magic method."""

    def test_can_get_value_with_bracket_notation(self, populated_map, asset_id_1):
        """Test getting value with bracket notation."""
        assert populated_map[asset_id_1] == 100

    def test_returns_none_for_nonexistent_key(self, populated_map, asset_id_3):
        """Test that bracket notation returns None for nonexistent key."""
        assert populated_map[asset_id_3] is None


class TestAssetIdMapSetItem:
    """Tests for __setitem__ magic method."""

    def test_can_set_value_with_bracket_notation(self, empty_map, asset_id_1):
        """Test setting value with bracket notation."""
        empty_map[asset_id_1] = 100
        assert empty_map[asset_id_1] == 100

    def test_can_override_with_bracket_notation(self, populated_map, asset_id_1):
        """Test overriding value with bracket notation."""
        populated_map[asset_id_1] = 999
        assert populated_map[asset_id_1] == 999


class TestAssetIdMapEquals:
    """Tests for __eq__ magic method."""

    def test_empty_maps_are_equal(self):
        """Test that two empty maps are equal."""
        map1 = AssetIdMap()
        map2 = AssetIdMap()
        assert map1 == map2

    def test_maps_with_same_entries_are_equal(self, asset_id_1, asset_id_2):
        """Test that maps with same entries are equal."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map1.insert(asset_id_2, 200)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 100)
        map2.insert(asset_id_2, 200)
        assert map1 == map2

    def test_maps_with_different_values_are_not_equal(self, asset_id_1):
        """Test that maps with different values are not equal."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 200)
        assert map1 != map2

    def test_maps_with_different_lengths_are_not_equal(self, asset_id_1, asset_id_2):
        """Test that maps with different lengths are not equal."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 100)
        map2.insert(asset_id_2, 200)
        assert map1 != map2

    def test_map_not_equal_to_non_map(self, empty_map):
        """Test that map is not equal to non-AssetIdMap object."""
        assert empty_map != "not a map"
        assert empty_map != 123
        assert empty_map != None

    def test_lovelace_asset_equality(self, lovelace_asset_id):
        """Test equality with lovelace asset."""
        map1 = AssetIdMap()
        map1.insert(lovelace_asset_id, 1000)
        map2 = AssetIdMap()
        map2.insert(lovelace_asset_id, 1000)
        assert map1 == map2


class TestAssetIdMapAdd:
    """Tests for __add__ magic method."""

    def test_can_add_two_empty_maps(self):
        """Test adding two empty maps."""
        map1 = AssetIdMap()
        map2 = AssetIdMap()
        result = map1 + map2
        assert len(result) == 0

    def test_can_add_maps_with_different_keys(self, asset_id_1, asset_id_2):
        """Test adding maps with different keys."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_2, 200)
        result = map1 + map2
        assert len(result) == 2
        assert result.get(asset_id_1) == 100
        assert result.get(asset_id_2) == 200

    def test_adds_values_for_same_keys(self, asset_id_1):
        """Test that values are added for same keys."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 50)
        result = map1 + map2
        assert len(result) == 1
        assert result.get(asset_id_1) == 150

    def test_adds_positive_values(self, asset_id_1, asset_id_2):
        """Test adding maps with positive values."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 50)
        map2.insert(asset_id_2, 200)
        result = map1 + map2
        assert len(result) == 2
        assert result.get(asset_id_1) == 150
        assert result.get(asset_id_2) == 200

    def test_adds_negative_values(self, asset_id_1, asset_id_2):
        """Test adding maps with negative values."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, -100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, -50)
        map2.insert(asset_id_2, -200)
        result = map1 + map2
        assert len(result) == 2
        assert result.get(asset_id_1) == -150
        assert result.get(asset_id_2) == -200

    def test_original_maps_unchanged(self, asset_id_1):
        """Test that original maps are unchanged after addition."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 50)
        result = map1 + map2
        assert map1.get(asset_id_1) == 100
        assert map2.get(asset_id_1) == 50


class TestAssetIdMapSubtract:
    """Tests for __sub__ magic method."""

    def test_can_subtract_two_empty_maps(self):
        """Test subtracting two empty maps."""
        map1 = AssetIdMap()
        map2 = AssetIdMap()
        result = map1 - map2
        assert len(result) == 0

    def test_can_subtract_maps_with_different_keys(self, asset_id_1, asset_id_2):
        """Test subtracting maps with different keys."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_2, 200)
        result = map1 - map2
        assert len(result) == 2
        assert result.get(asset_id_1) == 100
        assert result.get(asset_id_2) == -200

    def test_subtracts_values_for_same_keys(self, asset_id_1):
        """Test that values are subtracted for same keys."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 50)
        result = map1 - map2
        assert result.get(asset_id_1) == 50

    def test_subtracts_to_zero_removes_entry(self, asset_id_1, asset_id_2):
        """Test that subtracting to zero removes entry."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 100)
        map2.insert(asset_id_2, 50)
        result = map1 - map2
        assert len(result) == 1
        assert result.get(asset_id_1) is None
        assert result.get(asset_id_2) == -50

    def test_subtracts_negative_values(self, asset_id_1, asset_id_2):
        """Test subtracting maps with negative values."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 400)
        map2.insert(asset_id_2, -100)
        result = map1 - map2
        assert len(result) == 2
        assert result.get(asset_id_1) == -300
        assert result.get(asset_id_2) == 100

    def test_original_maps_unchanged(self, asset_id_1):
        """Test that original maps are unchanged after subtraction."""
        map1 = AssetIdMap()
        map1.insert(asset_id_1, 100)
        map2 = AssetIdMap()
        map2.insert(asset_id_1, 50)
        result = map1 - map2
        assert map1.get(asset_id_1) == 100
        assert map2.get(asset_id_1) == 50


class TestAssetIdMapRepr:
    """Tests for __repr__ magic method."""

    def test_repr_shows_length(self, empty_map, populated_map):
        """Test that repr shows map length."""
        assert "len=0" in repr(empty_map)
        assert "len=2" in repr(populated_map)

    def test_repr_contains_class_name(self, empty_map):
        """Test that repr contains class name."""
        assert "AssetIdMap" in repr(empty_map)


class TestAssetIdMapEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_large_positive_value(self, empty_map, asset_id_1):
        """Test handling of large positive values."""
        large_value = 2**62
        empty_map.insert(asset_id_1, large_value)
        assert empty_map.get(asset_id_1) == large_value

    def test_large_negative_value(self, empty_map, asset_id_1):
        """Test handling of large negative values."""
        large_negative = -(2**62)
        empty_map.insert(asset_id_1, large_negative)
        assert empty_map.get(asset_id_1) == large_negative

    def test_lovelace_asset_operations(self, lovelace_asset_id):
        """Test operations with lovelace asset ID."""
        asset_map = AssetIdMap()
        asset_map.insert(lovelace_asset_id, 1000000)
        assert asset_map.get(lovelace_asset_id) == 1000000
        assert len(asset_map) == 1

    def test_multiple_operations_sequence(self, empty_map, asset_id_1, asset_id_2, asset_id_3):
        """Test a sequence of multiple operations."""
        empty_map.insert(asset_id_1, 100)
        empty_map.insert(asset_id_2, 200)
        empty_map.insert(asset_id_3, 300)
        assert len(empty_map) == 3
        empty_map.insert(asset_id_2, 250)
        assert len(empty_map) == 3
        assert empty_map.get(asset_id_2) == 250
        assert list(empty_map.values()) == [100, 250, 300]
