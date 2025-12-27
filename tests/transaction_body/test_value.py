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

from cometa.transaction_body.value import Value
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.assets.multi_asset import MultiAsset
from cometa.assets.asset_id_map import AssetIdMap
from cometa.assets.asset_id import AssetId
from cometa.assets.asset_name import AssetName
from cometa.cryptography.blake2b_hash import Blake2bHash
from cometa.json.json_writer import JsonWriter
from cometa.errors import CardanoError


CBOR = "821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
CBOR2 = "821a000f4240a2581c00000000000000000000000000001100000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
CBOR_VALUE_WITH_TWICE_THE_ASSETS = "821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218c8443334353618c6444041424214581c11111111111111111111111111111111111111111111111111111111a3443031323218c8443334353618c6444041424214"
MULTI_ASSET_CBOR = "a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
POLICY_ID_HEX_1 = "00000000000000000000000000000000000000000000000000000000"
POLICY_ID_HEX_2 = "11111111111111111111111111111111111111111111111111111111"
ASSET_NAME_HEX_1 = "30313232"
ASSET_NAME_HEX_2 = "33343536"
ASSET_NAME_HEX_3 = "40414242"


def test_value_new_with_coin_only():
    """Test creating a new Value with coin only."""
    value = Value.new(1000000, None)
    assert value.coin == 1000000
    multi_asset = value.multi_asset
    assert multi_asset is None or multi_asset.policy_count == 0


def test_value_new_with_coin_and_assets():
    """Test creating a new Value with coin and multi-assets."""
    reader = CborReader.from_hex(MULTI_ASSET_CBOR)
    multi_asset = MultiAsset.from_cbor(reader)

    value = Value.new(1000000, multi_asset)
    assert value.coin == 1000000
    assert value.multi_asset is not None


def test_value_new_with_invalid_handle():
    """Test that creating a Value with NULL pointer raises error."""
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        Value(ffi.NULL)


def test_value_zero():
    """Test creating a zero Value."""
    value = Value.zero()
    assert value.coin == 0
    assert value.is_zero


def test_value_from_coin():
    """Test creating a Value from coin amount."""
    value = Value.from_coin(1500000)
    assert value.coin == 1500000
    multi_asset = value.multi_asset
    assert multi_asset is None or multi_asset.policy_count == 0


def test_value_from_asset_map():
    """Test creating a Value from an asset ID map."""
    asset_id = AssetId.from_hex(POLICY_ID_HEX_1 + ASSET_NAME_HEX_1)
    asset_map = AssetIdMap()
    asset_map.insert(asset_id, 100)

    value = Value.from_asset_map(asset_map)
    assert value is not None
    assert value.asset_count >= 1


def test_value_from_cbor():
    """Test deserializing a Value from CBOR."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    assert value.coin == 1000000
    assert value.multi_asset is not None


def test_value_from_cbor_integer():
    """Test deserializing a Value from CBOR when it's just an integer."""
    reader = CborReader.from_hex("09")
    value = Value.from_cbor(reader)

    assert value.coin == 9
    multi_asset = value.multi_asset
    assert multi_asset is None or multi_asset.policy_count == 0


def test_value_from_cbor_invalid_reader():
    """Test that from_cbor with invalid CBOR raises error."""
    reader = CborReader.from_hex("ef")
    with pytest.raises(CardanoError):
        Value.from_cbor(reader)


def test_value_to_cbor():
    """Test serializing a Value to CBOR."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    writer = CborWriter()
    value.to_cbor(writer)

    cbor_hex = writer.to_hex()
    assert cbor_hex.lower() == CBOR.lower()


def test_value_to_cbor_empty_value():
    """Test serializing an empty Value to CBOR."""
    value = Value.new(0, None)
    writer = CborWriter()
    value.to_cbor(writer)

    cbor_hex = writer.to_hex()
    assert cbor_hex == "00"


def test_value_from_dict_integer():
    """Test creating Value from a dict with just integer."""
    value = Value.from_dict(1500000)
    assert value.coin == 1500000
    multi_asset = value.multi_asset
    assert multi_asset is None or multi_asset.policy_count == 0


def test_value_from_dict_with_assets():
    """Test creating Value from a dict with coin and assets."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = b"TOKEN"

    value = Value.from_dict([
        1500000,
        {
            policy_id: {
                asset_name: 100
            }
        }
    ])

    assert value.coin == 1500000
    assert value.multi_asset is not None


def test_value_from_dict_invalid_format():
    """Test that from_dict with invalid format raises ValueError."""
    with pytest.raises(ValueError, match="Value must be an int or a list"):
        Value.from_dict("invalid")


def test_value_from_dict_invalid_lovelace_type():
    """Test that from_dict with non-integer lovelace raises ValueError."""
    with pytest.raises(ValueError, match="First element.*must be an integer"):
        Value.from_dict(["not_an_int", {}])


def test_value_from_dict_invalid_multi_asset_type():
    """Test that from_dict with non-dict multi_asset raises ValueError."""
    with pytest.raises(ValueError, match="Second element must be a dict"):
        Value.from_dict([1000000, "not_a_dict"])


def test_value_from_dict_invalid_policy_id_type():
    """Test that from_dict with non-bytes policy ID raises ValueError."""
    with pytest.raises(ValueError, match="Policy ID must be bytes"):
        Value.from_dict([1000000, {"not_bytes": {}}])


def test_value_from_dict_invalid_assets_type():
    """Test that from_dict with non-dict assets raises ValueError."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    with pytest.raises(ValueError, match="Assets must be a dict"):
        Value.from_dict([1000000, {policy_id: "not_a_dict"}])


def test_value_from_dict_invalid_asset_name_type():
    """Test that from_dict with non-bytes asset name raises ValueError."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    with pytest.raises(ValueError, match="Asset name must be bytes"):
        Value.from_dict([1000000, {policy_id: {"not_bytes": 100}}])


def test_value_from_dict_invalid_amount_type():
    """Test that from_dict with non-integer amount raises ValueError."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    with pytest.raises(ValueError, match="Asset amount must be an integer"):
        Value.from_dict([1000000, {policy_id: {b"TOKEN": "not_an_int"}}])


def test_value_to_dict_coin_only():
    """Test converting Value with only coin to dict."""
    value = Value.from_coin(1500000)
    result = value.to_dict()

    assert result == 1500000


def test_value_to_dict_with_assets():
    """Test converting Value with assets to dict."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = b"TOKEN"

    value = Value.from_coin(1500000)
    value.add_asset(policy_id, asset_name, 100)

    result = value.to_dict()
    assert isinstance(result, list)
    assert result[0] == 1500000
    assert isinstance(result[1], dict)
    assert policy_id in result[1]


def test_value_coin_property():
    """Test getting and setting coin property."""
    value = Value.from_coin(1000000)
    assert value.coin == 1000000

    value.coin = 2000000
    assert value.coin == 2000000


def test_value_multi_asset_property():
    """Test getting and setting multi_asset property."""
    value = Value.from_coin(1000000)
    multi_asset = value.multi_asset
    assert multi_asset is None or multi_asset.policy_count == 0

    reader = CborReader.from_hex(MULTI_ASSET_CBOR)
    multi_asset = MultiAsset.from_cbor(reader)

    value.multi_asset = multi_asset
    assert value.multi_asset is not None


def test_value_multi_asset_property_clear():
    """Test clearing multi_asset property."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)
    assert value.multi_asset is not None

    value.multi_asset = None
    assert value.multi_asset is None


def test_value_add_coin():
    """Test adding coin to a value."""
    value = Value.from_coin(1000000)
    value.add_coin(500000)
    assert value.coin == 1500000


def test_value_add_coin_overflow():
    """Test that adding coin with overflow wraps around."""
    value = Value.from_coin(9223372036854775807)
    value.add_coin(1)
    assert value.coin == -9223372036854775808


def test_value_subtract_coin():
    """Test subtracting coin from a value."""
    value = Value.from_coin(1500000)
    value.subtract_coin(500000)
    assert value.coin == 1000000


def test_value_subtract_coin_underflow():
    """Test that subtracting more coin than available results in negative value."""
    value = Value.from_coin(100)
    value.subtract_coin(200)
    assert value.coin == -100


def test_value_add_multi_asset():
    """Test adding multi-assets to a value."""
    value = Value.from_coin(1000000)

    reader = CborReader.from_hex(MULTI_ASSET_CBOR)
    multi_asset = MultiAsset.from_cbor(reader)

    value.add_multi_asset(multi_asset)
    assert value.multi_asset is not None


def test_value_subtract_multi_asset():
    """Test subtracting multi-assets from a value."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    reader2 = CborReader.from_hex(MULTI_ASSET_CBOR)
    multi_asset = MultiAsset.from_cbor(reader2)

    value.subtract_multi_asset(multi_asset)
    assert value.coin == 1000000


def test_value_add_asset():
    """Test adding a specific asset to a value."""
    value = Value.from_coin(1000000)
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = bytes.fromhex(ASSET_NAME_HEX_1)

    value.add_asset(policy_id, asset_name, 100)
    assert value.multi_asset is not None


def test_value_add_asset_with_id():
    """Test adding an asset using AssetId."""
    value = Value.from_coin(1000000)
    asset_id = AssetId.from_hex(POLICY_ID_HEX_1 + ASSET_NAME_HEX_1)

    value.add_asset_with_id(asset_id, 100)
    assert value.multi_asset is not None


def test_value_as_asset_map():
    """Test converting value to asset ID map."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    asset_map = value.as_asset_map()
    assert asset_map is not None
    assert len(asset_map) >= 1


def test_value_asset_count():
    """Test getting asset count."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    assert value.asset_count >= 1


def test_value_asset_count_zero():
    """Test asset count for zero value."""
    value = Value.zero()
    assert value.asset_count == 0


def test_value_is_zero():
    """Test checking if value is zero."""
    value = Value.zero()
    assert value.is_zero

    value.coin = 1
    assert not value.is_zero


def test_value_add():
    """Test adding two values together."""
    value1 = Value.from_coin(1000000)
    value2 = Value.from_coin(500000)

    result = value1 + value2
    assert result.coin == 1500000


def test_value_add_with_assets():
    """Test adding two values with assets."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR)
    value2 = Value.from_cbor(reader2)

    result = value1 + value2
    assert result.coin == 2000000


def test_value_subtract():
    """Test subtracting one value from another."""
    value1 = Value.from_coin(1500000)
    value2 = Value.from_coin(500000)

    result = value1 - value2
    assert result.coin == 1000000


def test_value_subtract_with_assets():
    """Test subtracting values with assets."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR)
    value2 = Value.from_cbor(reader2)

    result = value1 - value2
    assert result.coin == 0


def test_value_get_intersection():
    """Test getting intersection of assets between two values."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR)
    value2 = Value.from_cbor(reader2)

    intersection = value1.get_intersection(value2)
    assert intersection is not None


def test_value_get_intersection_count():
    """Test getting intersection count of assets between two values."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR)
    value2 = Value.from_cbor(reader2)

    count = value1.get_intersection_count(value2)
    assert count >= 0


def test_value_get_intersection_different_assets():
    """Test getting intersection when values have different assets."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR2)
    value2 = Value.from_cbor(reader2)

    intersection = value1.get_intersection(value2)
    assert intersection is not None


def test_value_equals():
    """Test equality of two values."""
    value1 = Value.from_coin(1000000)
    value2 = Value.from_coin(1000000)

    assert value1 == value2


def test_value_not_equals():
    """Test inequality of two values."""
    value1 = Value.from_coin(1000000)
    value2 = Value.from_coin(2000000)

    assert value1 != value2


def test_value_equals_with_assets():
    """Test equality of values with assets."""
    reader1 = CborReader.from_hex(CBOR)
    value1 = Value.from_cbor(reader1)

    reader2 = CborReader.from_hex(CBOR)
    value2 = Value.from_cbor(reader2)

    assert value1 == value2


def test_value_equals_different_types():
    """Test equality with different types returns NotImplemented."""
    value = Value.from_coin(1000000)
    assert value.__eq__("not a value") == NotImplemented


def test_value_bool():
    """Test boolean conversion of value."""
    value = Value.zero()
    assert not bool(value)

    value.coin = 1
    assert bool(value)


def test_value_repr():
    """Test string representation of value."""
    value = Value.from_coin(1000000)
    repr_str = repr(value)

    assert "Value" in repr_str
    assert "1000000" in repr_str


def test_value_to_cip116_json():
    """Test serializing value to CIP-116 JSON."""
    value = Value.from_coin(1000000)
    writer = JsonWriter()
    value.to_cip116_json(writer)

    json_str = writer.encode()
    assert json_str is not None
    assert "1000000" in json_str


def test_value_to_cip116_json_invalid_writer():
    """Test that to_cip116_json with invalid writer raises TypeError."""
    value = Value.from_coin(1000000)
    with pytest.raises(TypeError, match="writer must be a JsonWriter"):
        value.to_cip116_json("not a writer")


def test_value_to_cip116_json_with_assets():
    """Test serializing value with assets to CIP-116 JSON."""
    reader = CborReader.from_hex(CBOR)
    value = Value.from_cbor(reader)

    writer = JsonWriter()
    value.to_cip116_json(writer)

    json_str = writer.encode()
    assert json_str is not None


def test_value_context_manager():
    """Test using Value as a context manager."""
    with Value.from_coin(1000000) as value:
        assert value.coin == 1000000


def test_value_lifecycle():
    """Test Value lifecycle (creation and cleanup)."""
    value = Value.from_coin(1000000)
    assert value is not None
    del value


def test_value_roundtrip_cbor():
    """Test Value roundtrip through CBOR serialization."""
    original = Value.from_coin(1000000)

    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = bytes.fromhex(ASSET_NAME_HEX_1)
    original.add_asset(policy_id, asset_name, 100)

    writer = CborWriter()
    original.to_cbor(writer)
    cbor_hex = writer.to_hex()

    reader = CborReader.from_hex(cbor_hex)
    restored = Value.from_cbor(reader)

    assert original == restored


def test_value_roundtrip_dict():
    """Test Value roundtrip through dict conversion."""
    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = b"TOKEN"

    original_dict = [
        1500000,
        {
            policy_id: {
                asset_name: 100
            }
        }
    ]

    value = Value.from_dict(original_dict)
    result_dict = value.to_dict()

    assert result_dict[0] == original_dict[0]
    assert policy_id in result_dict[1]


def test_value_multiple_assets():
    """Test Value with multiple assets from different policies."""
    value = Value.from_coin(1000000)

    policy_id1 = bytes.fromhex(POLICY_ID_HEX_1)
    policy_id2 = bytes.fromhex(POLICY_ID_HEX_2)
    asset_name1 = bytes.fromhex(ASSET_NAME_HEX_1)
    asset_name2 = bytes.fromhex(ASSET_NAME_HEX_2)

    value.add_asset(policy_id1, asset_name1, 100)
    value.add_asset(policy_id2, asset_name2, 200)

    assert value.multi_asset is not None
    assert value.asset_count >= 3


def test_value_add_same_asset_twice():
    """Test adding the same asset twice accumulates the quantity."""
    value = Value.from_coin(1000000)

    policy_id = bytes.fromhex(POLICY_ID_HEX_1)
    asset_name = bytes.fromhex(ASSET_NAME_HEX_1)

    value.add_asset(policy_id, asset_name, 100)
    value.add_asset(policy_id, asset_name, 50)

    asset_map = value.as_asset_map()
    asset_id = AssetId.from_hex(POLICY_ID_HEX_1 + ASSET_NAME_HEX_1)
    quantity = asset_map.get(asset_id)

    assert quantity == 150


def test_value_zero_asset_count():
    """Test that zero value has asset count of 0."""
    value = Value.zero()
    assert value.asset_count == 0


def test_value_coin_only_asset_count():
    """Test that value with only coin has asset count of 1."""
    value = Value.from_coin(1000000)
    assert value.asset_count == 1
