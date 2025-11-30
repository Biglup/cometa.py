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
    AssetName,
    AssetNameList,
    AssetId,
    AssetIdList,
    AssetIdMap,
    AssetNameMap,
    MultiAsset,
    PolicyIdList,
    Blake2bHash,
    CborReader,
    CborWriter,
)


class TestAssetName:
    """Tests for the AssetName class."""

    def test_from_string(self):
        asset_name = AssetName.from_string("MyToken")
        assert asset_name.to_string() == "MyToken"

    def test_from_bytes(self):
        asset_name = AssetName.from_bytes(b"TestAsset")
        assert asset_name.to_bytes() == b"TestAsset"

    def test_from_hex(self):
        asset_name = AssetName.from_hex("4d79546f6b656e")
        assert asset_name.to_string() == "MyToken"

    def test_to_hex(self):
        asset_name = AssetName.from_string("MyToken")
        assert asset_name.to_hex() == "4d79546f6b656e"

    def test_equality(self):
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        name3 = AssetName.from_string("Other")
        assert name1 == name2
        assert name1 != name3

    def test_hash(self):
        name1 = AssetName.from_string("Token")
        name2 = AssetName.from_string("Token")
        assert hash(name1) == hash(name2)

    def test_len(self):
        asset_name = AssetName.from_string("Test")
        assert len(asset_name) == 4

    def test_repr(self):
        asset_name = AssetName.from_string("Token")
        assert "Token" in repr(asset_name)

    def test_cbor_roundtrip(self):
        original = AssetName.from_string("MyNFT")
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        restored = AssetName.from_cbor(reader)
        assert restored == original


class TestAssetId:
    """Tests for the AssetId class."""

    POLICY_ID = "00" * 28

    def test_new_asset_id(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("Token")
        asset_id = AssetId.new(policy_id, asset_name)
        assert not asset_id.is_lovelace

    def test_new_lovelace(self):
        lovelace = AssetId.new_lovelace()
        assert lovelace.is_lovelace

    def test_policy_id(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("Token")
        asset_id = AssetId.new(policy_id, asset_name)
        assert asset_id.policy_id is not None
        assert asset_id.policy_id.to_hex() == self.POLICY_ID

    def test_asset_name(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("MyToken")
        asset_id = AssetId.new(policy_id, asset_name)
        assert asset_id.asset_name is not None
        assert asset_id.asset_name.to_string() == "MyToken"

    def test_lovelace_policy_id_is_none(self):
        lovelace = AssetId.new_lovelace()
        assert lovelace.policy_id is None

    def test_lovelace_asset_name_is_none(self):
        lovelace = AssetId.new_lovelace()
        assert lovelace.asset_name is None

    def test_from_hex(self):
        policy_hex = self.POLICY_ID
        asset_name_hex = "4d79546f6b656e"
        asset_id = AssetId.from_hex(policy_hex + asset_name_hex)
        assert not asset_id.is_lovelace

    def test_equality(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        name = AssetName.from_string("Token")
        id1 = AssetId.new(policy_id, name)
        id2 = AssetId.new(policy_id, name)
        assert id1 == id2

    def test_str_lovelace(self):
        lovelace = AssetId.new_lovelace()
        assert str(lovelace) == "lovelace"


class TestAssetNameMap:
    """Tests for the AssetNameMap class."""

    def test_new_empty(self):
        asset_map = AssetNameMap()
        assert len(asset_map) == 0

    def test_insert_and_get(self):
        asset_map = AssetNameMap()
        name = AssetName.from_string("Token")
        asset_map.insert(name, 1000)
        assert asset_map.get(name) == 1000

    def test_len(self):
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("A"), 100)
        asset_map.insert(AssetName.from_string("B"), 200)
        assert len(asset_map) == 2

    def test_iteration(self):
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("A"), 100)
        asset_map.insert(AssetName.from_string("B"), 200)
        items = list(asset_map)
        assert len(items) == 2

    def test_contains(self):
        asset_map = AssetNameMap()
        name = AssetName.from_string("Token")
        asset_map.insert(name, 500)
        assert name in asset_map

    def test_add_operator(self):
        map1 = AssetNameMap()
        map1.insert(AssetName.from_string("A"), 100)
        map2 = AssetNameMap()
        map2.insert(AssetName.from_string("A"), 50)
        result = map1 + map2
        assert result.get(AssetName.from_string("A")) == 150

    def test_subtract_operator(self):
        map1 = AssetNameMap()
        map1.insert(AssetName.from_string("A"), 100)
        map2 = AssetNameMap()
        map2.insert(AssetName.from_string("A"), 30)
        result = map1 - map2
        assert result.get(AssetName.from_string("A")) == 70

    def test_cbor_roundtrip(self):
        original = AssetNameMap()
        original.insert(AssetName.from_string("Token"), 1000)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        restored = AssetNameMap.from_cbor(reader)
        assert len(restored) == 1

    def test_bracket_get_set(self):
        asset_map = AssetNameMap()
        name = AssetName.from_string("Token")
        asset_map[name] = 500
        assert asset_map[name] == 500

    def test_bool(self):
        asset_map = AssetNameMap()
        assert not asset_map  # Empty map is falsy
        asset_map.insert(AssetName.from_string("Token"), 100)
        assert asset_map  # Non-empty map is truthy

    def test_keys_values_items(self):
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("A"), 100)
        asset_map.insert(AssetName.from_string("B"), 200)
        keys = list(asset_map.keys())
        values = list(asset_map.values())
        items = list(asset_map.items())
        assert len(keys) == 2
        assert len(values) == 2
        assert len(items) == 2
        assert 100 in values
        assert 200 in values

    def test_iter_over_keys(self):
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("Token"), 100)
        # Iterating yields keys (like dict)
        keys = list(asset_map)
        assert len(keys) == 1
        assert keys[0].to_string() == "Token"


class TestMultiAsset:
    """Tests for the MultiAsset class."""

    POLICY_ID = "00" * 28

    def test_new_empty(self):
        multi_asset = MultiAsset()
        assert multi_asset.policy_count == 0

    def test_insert_assets(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("Token"), 100)
        multi_asset.insert_assets(policy_id, asset_map)
        assert multi_asset.policy_count == 1

    def test_get_assets(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("Token"), 100)
        multi_asset.insert_assets(policy_id, asset_map)
        retrieved = multi_asset.get_assets(policy_id)
        assert len(retrieved) == 1

    def test_get(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("Token")
        asset_map = AssetNameMap()
        asset_map.insert(asset_name, 500)
        multi_asset.insert_assets(policy_id, asset_map)
        assert multi_asset.get(policy_id, asset_name) == 500

    def test_set(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("Token")
        multi_asset.set(policy_id, asset_name, 1000)
        assert multi_asset.get(policy_id, asset_name) == 1000

    def test_add_operator(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        name = AssetName.from_string("Token")

        ma1 = MultiAsset()
        ma1.set(policy_id, name, 100)

        ma2 = MultiAsset()
        ma2.set(policy_id, name, 50)

        result = ma1 + ma2
        assert result.get(policy_id, name) == 150

    def test_subtract_operator(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        name = AssetName.from_string("Token")

        ma1 = MultiAsset()
        ma1.set(policy_id, name, 100)

        ma2 = MultiAsset()
        ma2.set(policy_id, name, 30)

        result = ma1 - ma2
        assert result.get(policy_id, name) == 70

    def test_cbor_roundtrip(self):
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        original = MultiAsset()
        original.set(policy_id, AssetName.from_string("Token"), 100)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = MultiAsset.from_cbor(reader)
        assert restored.policy_count == 1

    def test_bracket_get_set(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_map = AssetNameMap()
        asset_map.insert(AssetName.from_string("Token"), 100)
        multi_asset[policy_id] = asset_map
        retrieved = multi_asset[policy_id]
        assert len(retrieved) == 1

    def test_bool(self):
        multi_asset = MultiAsset()
        assert not multi_asset  # Empty is falsy
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        multi_asset.set(policy_id, AssetName.from_string("Token"), 100)
        assert multi_asset  # Non-empty is truthy

    def test_contains(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        multi_asset.set(policy_id, AssetName.from_string("Token"), 100)
        assert policy_id in multi_asset
        other_policy = Blake2bHash.from_hex("11" * 28)
        assert other_policy not in multi_asset

    def test_iter_over_policies(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        multi_asset.set(policy_id, AssetName.from_string("Token"), 100)
        # Iterating yields policy IDs (like dict)
        policies = list(multi_asset)
        assert len(policies) == 1
        assert policies[0].to_hex() == self.POLICY_ID

    def test_keys_values_items(self):
        multi_asset = MultiAsset()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        multi_asset.set(policy_id, AssetName.from_string("Token"), 100)
        keys = list(multi_asset.keys())
        values = list(multi_asset.values())
        items = list(multi_asset.items())
        assert len(keys) == 1
        assert len(values) == 1
        assert len(items) == 1
        # Values are AssetNameMaps
        assert len(values[0]) == 1

class TestAssetNameList:
    """Tests for the AssetNameList class."""

    def test_new_empty(self):
        name_list = AssetNameList()
        assert len(name_list) == 0

    def test_add_and_get(self):
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        assert len(name_list) == 1
        assert name_list.get(0).to_string() == "Token"

    def test_bracket_notation(self):
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("First"))
        name_list.add(AssetName.from_string("Second"))
        assert name_list[0].to_string() == "First"
        assert name_list[1].to_string() == "Second"

    def test_iteration(self):
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("A"))
        name_list.add(AssetName.from_string("B"))
        name_list.add(AssetName.from_string("C"))
        names = [n.to_string() for n in name_list]
        assert names == ["A", "B", "C"]

    def test_contains(self):
        name_list = AssetNameList()
        name = AssetName.from_string("Token")
        name_list.add(name)
        assert AssetName.from_string("Token") in name_list
        assert AssetName.from_string("Other") not in name_list

    def test_index_out_of_bounds(self):
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("Token"))
        with pytest.raises(IndexError):
            _ = name_list[5]

    def test_repr(self):
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("Token"))
        assert "len=1" in repr(name_list)

    def test_negative_index(self):
        name_list = AssetNameList()
        name_list.add(AssetName.from_string("First"))
        name_list.add(AssetName.from_string("Last"))
        assert name_list[-1].to_string() == "Last"

    def test_bool(self):
        name_list = AssetNameList()
        assert not name_list
        name_list.add(AssetName.from_string("Token"))
        assert name_list

    def test_append(self):
        name_list = AssetNameList()
        name_list.append(AssetName.from_string("Token"))
        assert len(name_list) == 1


class TestAssetIdList:
    """Tests for the AssetIdList class."""

    POLICY_ID = "00" * 28

    def test_new_empty(self):
        id_list = AssetIdList()
        assert len(id_list) == 0

    def test_add_and_get(self):
        id_list = AssetIdList()
        lovelace = AssetId.new_lovelace()
        id_list.add(lovelace)
        assert len(id_list) == 1
        assert id_list.get(0).is_lovelace

    def test_bracket_notation(self):
        id_list = AssetIdList()
        id_list.add(AssetId.new_lovelace())
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        asset_name = AssetName.from_string("Token")
        id_list.add(AssetId.new(policy_id, asset_name))
        assert id_list[0].is_lovelace
        assert not id_list[1].is_lovelace

    def test_iteration(self):
        id_list = AssetIdList()
        id_list.add(AssetId.new_lovelace())
        id_list.add(AssetId.new_lovelace())
        count = sum(1 for _ in id_list)
        assert count == 2

    def test_contains(self):
        id_list = AssetIdList()
        lovelace = AssetId.new_lovelace()
        id_list.add(lovelace)
        assert AssetId.new_lovelace() in id_list

    def test_index_out_of_bounds(self):
        id_list = AssetIdList()
        with pytest.raises(IndexError):
            _ = id_list[0]

    def test_repr(self):
        id_list = AssetIdList()
        assert "len=0" in repr(id_list)

    def test_negative_index(self):
        id_list = AssetIdList()
        id_list.add(AssetId.new_lovelace())
        policy_id = Blake2bHash.from_hex(self.POLICY_ID)
        id_list.add(AssetId.new(policy_id, AssetName.from_string("Token")))
        assert id_list[-1].asset_name.to_string() == "Token"

    def test_bool(self):
        id_list = AssetIdList()
        assert not id_list
        id_list.add(AssetId.new_lovelace())
        assert id_list

    def test_append(self):
        id_list = AssetIdList()
        id_list.append(AssetId.new_lovelace())
        assert len(id_list) == 1


class TestAssetIdMap:
    """Tests for the AssetIdMap class."""

    POLICY_ID = "00" * 28

    def test_new_empty(self):
        id_map = AssetIdMap()
        assert len(id_map) == 0

    def test_insert_and_get(self):
        id_map = AssetIdMap()
        lovelace = AssetId.new_lovelace()
        id_map.insert(lovelace, 1000000)
        assert id_map.get(lovelace) == 1000000

    def test_get_keys(self):
        id_map = AssetIdMap()
        lovelace = AssetId.new_lovelace()
        id_map.insert(lovelace, 1000000)
        keys = id_map.get_keys()
        assert len(keys) == 1
        assert keys[0].is_lovelace

    def test_get_key_at_and_value_at(self):
        id_map = AssetIdMap()
        lovelace = AssetId.new_lovelace()
        id_map.insert(lovelace, 2000000)
        key = id_map.get_key_at(0)
        value = id_map.get_value_at(0)
        assert key.is_lovelace
        assert value == 2000000

    def test_iteration(self):
        id_map = AssetIdMap()
        id_map.insert(AssetId.new_lovelace(), 1000000)
        # Iteration yields keys (like dict)
        keys = list(id_map)
        assert len(keys) == 1
        assert keys[0].is_lovelace

    def test_contains(self):
        id_map = AssetIdMap()
        lovelace = AssetId.new_lovelace()
        id_map.insert(lovelace, 500)
        assert lovelace in id_map

    def test_index_out_of_bounds(self):
        id_map = AssetIdMap()
        with pytest.raises(IndexError):
            _ = id_map.get_key_at(0)

    def test_repr(self):
        id_map = AssetIdMap()
        id_map.insert(AssetId.new_lovelace(), 100)
        assert "len=1" in repr(id_map)

    def test_equality(self):
        map1 = AssetIdMap()
        map1.insert(AssetId.new_lovelace(), 100)
        map2 = AssetIdMap()
        map2.insert(AssetId.new_lovelace(), 100)
        map3 = AssetIdMap()
        map3.insert(AssetId.new_lovelace(), 200)
        assert map1 == map2
        assert map1 != map3

    def test_add_operator(self):
        map1 = AssetIdMap()
        map1.insert(AssetId.new_lovelace(), 100)
        map2 = AssetIdMap()
        map2.insert(AssetId.new_lovelace(), 50)
        result = map1 + map2
        assert result.get(AssetId.new_lovelace()) == 150

    def test_subtract_operator(self):
        map1 = AssetIdMap()
        map1.insert(AssetId.new_lovelace(), 100)
        map2 = AssetIdMap()
        map2.insert(AssetId.new_lovelace(), 30)
        result = map1 - map2
        assert result.get(AssetId.new_lovelace()) == 70

    def test_bool(self):
        id_map = AssetIdMap()
        assert not id_map
        id_map.insert(AssetId.new_lovelace(), 100)
        assert id_map

    def test_bracket_get_set(self):
        id_map = AssetIdMap()
        lovelace = AssetId.new_lovelace()
        id_map[lovelace] = 1000000
        assert id_map[lovelace] == 1000000

    def test_keys_values_items(self):
        id_map = AssetIdMap()
        id_map.insert(AssetId.new_lovelace(), 1000000)
        keys = list(id_map.keys())
        values = list(id_map.values())
        items = list(id_map.items())
        assert len(keys) == 1
        assert len(values) == 1
        assert len(items) == 1
        assert values[0] == 1000000

    def test_iter_over_keys(self):
        id_map = AssetIdMap()
        id_map.insert(AssetId.new_lovelace(), 100)
        # Iterating over map should yield keys (like dict)
        keys = list(id_map)
        assert len(keys) == 1
        assert keys[0].is_lovelace


class TestPolicyIdList:
    """Tests for the PolicyIdList class."""

    POLICY_ID_1 = "00" * 28
    POLICY_ID_2 = "11" * 28

    def test_new_empty(self):
        policy_list = PolicyIdList()
        assert len(policy_list) == 0

    def test_add_and_get(self):
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID_1)
        policy_list.add(policy_id)
        assert len(policy_list) == 1
        assert policy_list.get(0).to_hex() == self.POLICY_ID_1

    def test_bracket_notation(self):
        policy_list = PolicyIdList()
        policy_list.add(Blake2bHash.from_hex(self.POLICY_ID_1))
        policy_list.add(Blake2bHash.from_hex(self.POLICY_ID_2))
        assert policy_list[0].to_hex() == self.POLICY_ID_1
        assert policy_list[1].to_hex() == self.POLICY_ID_2

    def test_iteration(self):
        policy_list = PolicyIdList()
        policy_list.add(Blake2bHash.from_hex(self.POLICY_ID_1))
        policy_list.add(Blake2bHash.from_hex(self.POLICY_ID_2))
        policies = [p.to_hex() for p in policy_list]
        assert self.POLICY_ID_1 in policies
        assert self.POLICY_ID_2 in policies

    def test_contains(self):
        policy_list = PolicyIdList()
        policy_id = Blake2bHash.from_hex(self.POLICY_ID_1)
        policy_list.add(policy_id)
        assert Blake2bHash.from_hex(self.POLICY_ID_1) in policy_list
        assert Blake2bHash.from_hex(self.POLICY_ID_2) not in policy_list

    def test_index_out_of_bounds(self):
        policy_list = PolicyIdList()
        with pytest.raises(IndexError):
            _ = policy_list[0]

    def test_repr(self):
        policy_list = PolicyIdList()
        assert "len=0" in repr(policy_list)
