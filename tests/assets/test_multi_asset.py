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
    MultiAsset,
    AssetName,
    AssetNameMap,
    AssetId,
    Blake2bHash,
    CardanoError,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
)


CBOR = "a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
CBOR_MIXED = "a2581c00000000000000000000000000000000000000000000000000000000a34430313232186444333435361863444041424229581c11111111111111111111111111111111111111111111111111111111a34430313232386344333435361863444041424229"
ASSET_NAME_CBOR_1 = "49736b7977616c6b6571"
ASSET_NAME_CBOR_2 = "49736b7977616c6b6572"
ASSET_NAME_CBOR_3 = "49736b7977616c6b6573"
ASSET_NAME_CBOR_1B = "4430313232"
ASSET_NAME_CBOR_2B = "4433343536"
ASSET_NAME_CBOR_3B = "4440414242"
POLICY_ID_HEX_1 = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
POLICY_ID_HEX_2 = "f1ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
POLICY_ID_HEX_3 = "f2ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
POLICY_ID_HEX_1B = "00000000000000000000000000000000000000000000000000000000"
POLICY_ID_HEX_2B = "11111111111111111111111111111111111111111111111111111111"
ASSET_MAP_CBOR = "a349736b7977616c6b65710149736b7977616c6b65720249736b7977616c6b657303"


def create_default_asset_name(cbor_hex: str) -> AssetName:
    """Helper function to create an asset name from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return AssetName.from_cbor(reader)


def create_default_policy_id(hex_str: str) -> Blake2bHash:
    """Helper function to create a policy ID from hex string."""
    return Blake2bHash.from_hex(hex_str)


def create_default_asset_name_map(cbor_hex: str) -> AssetNameMap:
    """Helper function to create an asset name map from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return AssetNameMap.from_cbor(reader)


class TestMultiAssetNew:
    """Tests for MultiAsset() constructor."""

    def test_can_create_empty_multi_asset(self):
        """Test that an empty MultiAsset can be created."""
        multi_asset = MultiAsset()
        assert multi_asset is not None
        assert len(multi_asset) == 0

    def test_new_multi_asset_is_empty(self):
        """Test that newly created multi-asset has zero policy count."""
        multi_asset = MultiAsset()
        assert multi_asset.policy_count == 0

    def test_new_multi_asset_is_falsy(self):
        """Test that empty multi-asset evaluates to False."""
        multi_asset = MultiAsset()
        assert not multi_asset

    def test_raises_error_if_invalid_ptr(self):
        """Test that invalid ptr raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            MultiAsset(ffi.NULL)


class TestMultiAssetFromCbor:
    """Tests for MultiAsset.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that MultiAsset can be deserialized from CBOR."""
        reader = CborReader.from_hex(CBOR)
        multi_asset = MultiAsset.from_cbor(reader)
        assert multi_asset is not None
        assert multi_asset.policy_count == 2

    def test_can_roundtrip_cbor(self):
        """Test that CBOR serialization roundtrips correctly."""
        reader = CborReader.from_hex(CBOR)
        multi_asset = MultiAsset.from_cbor(reader)
        writer = CborWriter()
        multi_asset.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_raises_error_if_reader_is_none(self):
        """Test that None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            MultiAsset.from_cbor(None)

    def test_raises_error_if_invalid_cbor_not_a_map(self):
        """Test that invalid CBOR (not a map) raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MultiAsset.from_cbor(reader)

    def test_raises_error_if_invalid_cbor_incomplete_map(self):
        """Test that incomplete map raises an error."""
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            MultiAsset.from_cbor(reader)

    def test_raises_error_if_invalid_asset_value(self):
        """Test that invalid asset value raises an error."""
        reader = CborReader.from_hex(
            "a349736b7977616c6b6571ef49736b7977616c6b65720249736b7977616c6b657303"
        )
        with pytest.raises(CardanoError):
            MultiAsset.from_cbor(reader)


class TestMultiAssetToCbor:
    """Tests for MultiAsset.to_cbor() method."""

    def test_can_serialize_empty_multi_asset(self):
        """Test that empty multi-asset serializes to CBOR."""
        multi_asset = MultiAsset()
        writer = CborWriter()
        multi_asset.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == "a0"

    def test_can_serialize_multi_asset_with_items(self):
        """Test that multi-asset with items serializes correctly."""
        reader = CborReader.from_hex(CBOR)
        multi_asset = MultiAsset.from_cbor(reader)
        writer = CborWriter()
        multi_asset.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        multi_asset = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.to_cbor(None)


class TestMultiAssetPolicyCount:
    """Tests for MultiAsset.policy_count property."""

    def test_empty_multi_asset_has_zero_count(self):
        """Test that empty multi-asset has zero policy count."""
        multi_asset = MultiAsset()
        assert multi_asset.policy_count == 0

    def test_returns_correct_count_after_insertion(self):
        """Test that count is correct after inserting assets."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        assert multi_asset.policy_count == 1

    def test_returns_correct_count_with_multiple_policies(self):
        """Test that count is correct with multiple policies."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        assert multi_asset.policy_count == 2


class TestMultiAssetInsertAssets:
    """Tests for MultiAsset.insert_assets() method."""

    def test_can_insert_assets_under_policy_id(self):
        """Test that assets can be inserted under a policy ID."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        assert multi_asset.policy_count == 1

    def test_can_insert_multiple_policies(self):
        """Test that multiple policies can be inserted."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        policy_id3 = create_default_policy_id(POLICY_ID_HEX_3)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id1, asset_map)
        multi_asset.insert_assets(policy_id2, asset_map)
        multi_asset.insert_assets(policy_id3, asset_map)
        assert multi_asset.policy_count == 3

    def test_can_override_existing_policy(self):
        """Test that inserting same policy ID updates the assets."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        multi_asset.insert_assets(policy_id, asset_map)
        assert multi_asset.policy_count == 1

    def test_raises_error_if_policy_id_is_none(self):
        """Test that None policy ID raises an error."""
        multi_asset = MultiAsset()
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.insert_assets(None, asset_map)

    def test_raises_error_if_asset_map_is_none(self):
        """Test that None asset map raises an error."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.insert_assets(policy_id, None)


class TestMultiAssetGetAssets:
    """Tests for MultiAsset.get_assets() method."""

    def test_can_get_assets_by_policy_id(self):
        """Test that assets can be retrieved by policy ID."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        retrieved = multi_asset.get_assets(policy_id)
        assert retrieved is not None
        assert len(retrieved) == 3

    def test_raises_error_if_policy_not_found(self):
        """Test that error is raised if policy ID not found."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        with pytest.raises(CardanoError):
            multi_asset.get_assets(policy_id)

    def test_raises_error_if_policy_id_is_none(self):
        """Test that None policy ID raises an error."""
        multi_asset = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.get_assets(None)


class TestMultiAssetGet:
    """Tests for MultiAsset.get() method."""

    def test_can_get_asset_value(self):
        """Test that asset value can be retrieved."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        value = multi_asset.get(policy_id, asset_name)
        assert value == 1

    def test_can_get_multiple_asset_values(self):
        """Test that multiple asset values can be retrieved."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name1 = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_name2 = create_default_asset_name(ASSET_NAME_CBOR_2)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id1, asset_map)
        multi_asset.insert_assets(policy_id2, asset_map)
        value1 = multi_asset.get(policy_id1, asset_name1)
        value2 = multi_asset.get(policy_id2, asset_name2)
        assert value1 == 1
        assert value2 == 2

    def test_raises_error_if_asset_not_found(self):
        """Test that error is raised if asset not found."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        with pytest.raises(CardanoError):
            multi_asset.get(policy_id, asset_name)

    def test_raises_error_if_policy_id_is_none(self):
        """Test that None policy ID raises an error."""
        multi_asset = MultiAsset()
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.get(None, asset_name)

    def test_raises_error_if_asset_name_is_none(self):
        """Test that None asset name raises an error."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.get(policy_id, None)


class TestMultiAssetGetWithId:
    """Tests for MultiAsset.get_with_id() method."""

    def test_can_get_asset_by_id(self):
        """Test that asset can be retrieved by ID."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        asset_id = AssetId.new(policy_id, asset_name)
        value = multi_asset.get_with_id(asset_id)
        assert value == 1

    def test_raises_error_if_asset_not_found(self):
        """Test that error is raised if asset ID not found."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_id = AssetId.new(policy_id, asset_name)
        with pytest.raises(CardanoError):
            multi_asset.get_with_id(asset_id)

    def test_raises_error_if_asset_id_is_none(self):
        """Test that None asset ID raises an error."""
        multi_asset = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.get_with_id(None)


class TestMultiAssetSet:
    """Tests for MultiAsset.set() method."""

    def test_can_set_asset_value(self):
        """Test that asset value can be set."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        value = multi_asset.get(policy_id, asset_name)
        assert value == 100

    def test_can_set_negative_value(self):
        """Test that negative value can be set (for burning)."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, -50)
        value = multi_asset.get(policy_id, asset_name)
        assert value == -50

    def test_can_override_existing_value(self):
        """Test that existing value can be overridden."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        multi_asset.set(policy_id, asset_name, 200)
        value = multi_asset.get(policy_id, asset_name)
        assert value == 200

    def test_raises_error_if_policy_id_is_none(self):
        """Test that None policy ID raises an error."""
        multi_asset = MultiAsset()
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.set(None, asset_name, 100)

    def test_raises_error_if_asset_name_is_none(self):
        """Test that None asset name raises an error."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.set(policy_id, None, 100)


class TestMultiAssetAdd:
    """Tests for MultiAsset.add() method."""

    def test_can_add_two_empty_multi_assets(self):
        """Test that two empty multi-assets can be added."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        result = ma1.add(ma2)
        assert result.policy_count == 0

    def test_can_add_two_multi_assets(self):
        """Test that two multi-assets can be added."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id1, asset_name, 100)
        ma2.set(policy_id2, asset_name, 200)
        result = ma1.add(ma2)
        assert result.policy_count == 2
        assert result.get(policy_id1, asset_name) == 100
        assert result.get(policy_id2, asset_name) == 200

    def test_adds_values_for_same_asset(self):
        """Test that values are added for same asset."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        ma2.set(policy_id, asset_name, 50)
        result = ma1.add(ma2)
        assert result.get(policy_id, asset_name) == 150

    def test_adds_negative_values(self):
        """Test that negative values are added correctly."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, -100)
        ma2.set(policy_id, asset_name, -50)
        result = ma1.add(ma2)
        assert result.get(policy_id, asset_name) == -150

    def test_raises_error_if_other_is_none(self):
        """Test that None other raises an error."""
        ma1 = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ma1.add(None)


class TestMultiAssetSubtract:
    """Tests for MultiAsset.subtract() method."""

    def test_can_subtract_two_empty_multi_assets(self):
        """Test that two empty multi-assets can be subtracted."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        result = ma1.subtract(ma2)
        assert result.policy_count == 0

    def test_can_subtract_two_multi_assets(self):
        """Test that two multi-assets can be subtracted."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id1, asset_name, 100)
        ma2.set(policy_id2, asset_name, 200)
        result = ma1.subtract(ma2)
        assert result.policy_count == 2
        assert result.get(policy_id1, asset_name) == 100
        assert result.get(policy_id2, asset_name) == -200

    def test_subtracts_values_for_same_asset(self):
        """Test that values are subtracted for same asset."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        ma2.set(policy_id, asset_name, 50)
        result = ma1.subtract(ma2)
        assert result.get(policy_id, asset_name) == 50

    def test_subtracts_negative_values(self):
        """Test that negative values are subtracted correctly."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        ma2.set(policy_id, asset_name, 400)
        result = ma1.subtract(ma2)
        assert result.get(policy_id, asset_name) == -300

    def test_raises_error_if_other_is_none(self):
        """Test that None other raises an error."""
        ma1 = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ma1.subtract(None)


class TestMultiAssetGetPositive:
    """Tests for MultiAsset.get_positive() method."""

    def test_returns_empty_for_empty_multi_asset(self):
        """Test that empty multi-asset returns empty positive."""
        multi_asset = MultiAsset()
        positive = multi_asset.get_positive()
        assert positive.policy_count == 0

    def test_filters_only_positive_values(self):
        """Test that only positive values are included."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name1 = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_name2 = create_default_asset_name(ASSET_NAME_CBOR_2)
        asset_name3 = create_default_asset_name(ASSET_NAME_CBOR_3)
        multi_asset.set(policy_id, asset_name1, 100)
        multi_asset.set(policy_id, asset_name2, -50)
        multi_asset.set(policy_id, asset_name3, 0)
        positive = multi_asset.get_positive()
        assert positive.get(policy_id, asset_name1) == 100
        with pytest.raises(CardanoError):
            positive.get(policy_id, asset_name2)

    def test_excludes_zero_values(self):
        """Test that zero values are excluded."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 0)
        positive = multi_asset.get_positive()
        with pytest.raises(CardanoError):
            positive.get(policy_id, asset_name)


class TestMultiAssetGetNegative:
    """Tests for MultiAsset.get_negative() method."""

    def test_returns_empty_for_empty_multi_asset(self):
        """Test that empty multi-asset returns empty negative."""
        multi_asset = MultiAsset()
        negative = multi_asset.get_negative()
        assert negative.policy_count == 0

    def test_filters_only_negative_values(self):
        """Test that only negative values are included."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name1 = create_default_asset_name(ASSET_NAME_CBOR_1)
        asset_name2 = create_default_asset_name(ASSET_NAME_CBOR_2)
        asset_name3 = create_default_asset_name(ASSET_NAME_CBOR_3)
        multi_asset.set(policy_id, asset_name1, 100)
        multi_asset.set(policy_id, asset_name2, -50)
        multi_asset.set(policy_id, asset_name3, 0)
        negative = multi_asset.get_negative()
        assert negative.get(policy_id, asset_name2) == -50
        with pytest.raises(CardanoError):
            negative.get(policy_id, asset_name1)

    def test_excludes_zero_values(self):
        """Test that zero values are excluded."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 0)
        negative = multi_asset.get_negative()
        with pytest.raises(CardanoError):
            negative.get(policy_id, asset_name)


class TestMultiAssetToCip116Json:
    """Tests for MultiAsset.to_cip116_json() method."""

    def test_can_convert_empty_multi_asset_to_json(self):
        """Test that empty multi-asset converts to JSON."""
        multi_asset = MultiAsset()
        writer = JsonWriter(JsonFormat.COMPACT)
        multi_asset.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "{}"

    def test_can_convert_multi_asset_to_json(self):
        """Test that multi-asset with items converts to JSON."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1B)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1B)
        multi_asset.set(policy_id, asset_name, 100)
        writer = JsonWriter(JsonFormat.COMPACT)
        multi_asset.to_cip116_json(writer)
        json_str = writer.encode()
        assert POLICY_ID_HEX_1B in json_str
        assert "100" in json_str

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        multi_asset = MultiAsset()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            multi_asset.to_cip116_json(None)


class TestMultiAssetLen:
    """Tests for len(MultiAsset) built-in."""

    def test_empty_multi_asset_has_zero_length(self):
        """Test that empty multi-asset has zero length."""
        multi_asset = MultiAsset()
        assert len(multi_asset) == 0

    def test_multi_asset_with_one_policy_has_length_one(self):
        """Test that multi-asset with one policy has length one."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        assert len(multi_asset) == 1

    def test_multi_asset_with_multiple_policies_has_correct_length(self):
        """Test that multi-asset with multiple policies has correct length."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        assert len(multi_asset) == 2


class TestMultiAssetIter:
    """Tests for iter(MultiAsset) built-in."""

    def test_can_iterate_over_policy_ids(self):
        """Test that multi-asset can be iterated over."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        policy_ids = list(multi_asset)
        assert len(policy_ids) == 2

    def test_empty_multi_asset_iteration(self):
        """Test that empty multi-asset iteration works."""
        multi_asset = MultiAsset()
        policy_ids = list(multi_asset)
        assert len(policy_ids) == 0


class TestMultiAssetGetItem:
    """Tests for MultiAsset[key] bracket notation."""

    def test_can_get_assets_with_brackets(self):
        """Test that assets can be retrieved using brackets."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset.insert_assets(policy_id, asset_map)
        retrieved = multi_asset[policy_id]
        assert retrieved is not None
        assert len(retrieved) == 3

    def test_raises_error_if_policy_not_found(self):
        """Test that error is raised if policy not found."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        with pytest.raises(CardanoError):
            _ = multi_asset[policy_id]


class TestMultiAssetSetItem:
    """Tests for MultiAsset[key] = value bracket notation."""

    def test_can_set_assets_with_brackets(self):
        """Test that assets can be set using brackets."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset[policy_id] = asset_map
        retrieved = multi_asset.get_assets(policy_id)
        assert len(retrieved) == 3

    def test_can_override_assets_with_brackets(self):
        """Test that assets can be overridden using brackets."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_map = create_default_asset_name_map(ASSET_MAP_CBOR)
        multi_asset[policy_id] = asset_map
        multi_asset[policy_id] = asset_map
        assert multi_asset.policy_count == 1


class TestMultiAssetBool:
    """Tests for bool(MultiAsset) built-in."""

    def test_empty_multi_asset_is_falsy(self):
        """Test that empty multi-asset evaluates to False."""
        multi_asset = MultiAsset()
        assert not multi_asset

    def test_non_empty_multi_asset_is_truthy(self):
        """Test that non-empty multi-asset evaluates to True."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        assert multi_asset


class TestMultiAssetContains:
    """Tests for 'in' operator with MultiAsset."""

    def test_contains_returns_true_if_policy_exists(self):
        """Test that 'in' returns True if policy ID exists."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        assert policy_id in multi_asset

    def test_contains_returns_false_if_policy_not_exists(self):
        """Test that 'in' returns False if policy ID does not exist."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        assert policy_id not in multi_asset


class TestMultiAssetEq:
    """Tests for MultiAsset == operator."""

    def test_empty_multi_assets_are_equal(self):
        """Test that two empty multi-assets are equal."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        assert ma1 == ma2

    def test_multi_assets_with_same_content_are_equal(self):
        """Test that multi-assets with same content are equal."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        ma2.set(policy_id, asset_name, 100)
        assert ma1 == ma2

    def test_multi_assets_with_different_values_are_not_equal(self):
        """Test that multi-assets with different values are not equal."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        ma2.set(policy_id, asset_name, 200)
        assert ma1 != ma2

    def test_multi_assets_with_different_lengths_are_not_equal(self):
        """Test that multi-assets with different lengths are not equal."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id, asset_name, 100)
        assert ma1 != ma2

    def test_multi_asset_not_equal_to_non_multi_asset(self):
        """Test that multi-asset is not equal to non-multi-asset type."""
        ma1 = MultiAsset()
        assert ma1 != "not a multi-asset"
        assert ma1 != 123
        assert ma1 != None


class TestMultiAssetAddOperator:
    """Tests for MultiAsset + operator."""

    def test_can_add_with_plus_operator(self):
        """Test that + operator works."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id1, asset_name, 100)
        ma2.set(policy_id2, asset_name, 200)
        result = ma1 + ma2
        assert result.policy_count == 2
        assert result.get(policy_id1, asset_name) == 100
        assert result.get(policy_id2, asset_name) == 200


class TestMultiAssetSubOperator:
    """Tests for MultiAsset - operator."""

    def test_can_subtract_with_minus_operator(self):
        """Test that - operator works."""
        ma1 = MultiAsset()
        ma2 = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        ma1.set(policy_id1, asset_name, 100)
        ma2.set(policy_id2, asset_name, 200)
        result = ma1 - ma2
        assert result.policy_count == 2
        assert result.get(policy_id1, asset_name) == 100
        assert result.get(policy_id2, asset_name) == -200


class TestMultiAssetKeys:
    """Tests for MultiAsset.keys() method."""

    def test_can_get_keys_iterator(self):
        """Test that keys iterator can be obtained."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        keys = list(multi_asset.keys())
        assert len(keys) == 2


class TestMultiAssetValues:
    """Tests for MultiAsset.values() method."""

    def test_can_get_values_iterator(self):
        """Test that values iterator can be obtained."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        values = list(multi_asset.values())
        assert len(values) == 2


class TestMultiAssetItems:
    """Tests for MultiAsset.items() method."""

    def test_can_get_items_iterator(self):
        """Test that items iterator can be obtained."""
        multi_asset = MultiAsset()
        policy_id1 = create_default_policy_id(POLICY_ID_HEX_1)
        policy_id2 = create_default_policy_id(POLICY_ID_HEX_2)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id1, asset_name, 100)
        multi_asset.set(policy_id2, asset_name, 200)
        items = list(multi_asset.items())
        assert len(items) == 2
        policy_ids = [p for p, a in items]
        asset_maps = [a for p, a in items]
        assert len(policy_ids) == 2
        assert len(asset_maps) == 2


class TestMultiAssetRepr:
    """Tests for repr(MultiAsset) built-in."""

    def test_repr_shows_policy_count(self):
        """Test that repr shows the policy count."""
        multi_asset = MultiAsset()
        policy_id = create_default_policy_id(POLICY_ID_HEX_1)
        asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
        multi_asset.set(policy_id, asset_name, 100)
        repr_str = repr(multi_asset)
        assert "MultiAsset" in repr_str
        assert "1" in repr_str


class TestMultiAssetContextManager:
    """Tests for MultiAsset context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that MultiAsset can be used as context manager."""
        with MultiAsset() as multi_asset:
            policy_id = create_default_policy_id(POLICY_ID_HEX_1)
            asset_name = create_default_asset_name(ASSET_NAME_CBOR_1)
            multi_asset.set(policy_id, asset_name, 100)
            assert multi_asset.policy_count == 1
