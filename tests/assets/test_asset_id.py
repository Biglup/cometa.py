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
from cometa import AssetId, AssetName, Blake2bHash, CardanoError


ASSET_ID_HEX = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a736b7977616c6b6572"
POLICY_ID_HEX = "f0ff48bbb7bbe9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
POLICY_ID_BYTES = bytes([
    0xf0, 0xff, 0x48, 0xbb, 0xb7, 0xbb, 0xe9, 0xd5, 0x9a, 0x40, 0xf1, 0xce,
    0x90, 0xe9, 0xe9, 0xd0, 0xff, 0x50, 0x02, 0xec, 0x48, 0xf2, 0x32, 0xb4,
    0x9c, 0xa0, 0xfb, 0x9a
])
ASSET_ID_BYTES = bytes([
    0xf0, 0xff, 0x48, 0xbb, 0xb7, 0xbb, 0xe9, 0xd5, 0x9a, 0x40, 0xf1, 0xce,
    0x90, 0xe9, 0xe9, 0xd0, 0xff, 0x50, 0x02, 0xec, 0x48, 0xf2, 0x32, 0xb4,
    0x9c, 0xa0, 0xfb, 0x9a, 0x73, 0x6b, 0x79, 0x77, 0x61, 0x6c, 0x6b, 0x65, 0x72
])
INVALID_POLICY_ID_HEX = "e9d59a40f1ce90e9e9d0ff5002ec48f232b49ca0fb9a"
ASSET_NAME_STRING = "skywalker"


@pytest.fixture
def policy_id():
    """Create a valid policy ID for testing."""
    return Blake2bHash.from_hex(POLICY_ID_HEX)


@pytest.fixture
def asset_name():
    """Create a valid asset name for testing."""
    return AssetName.from_string(ASSET_NAME_STRING)


@pytest.fixture
def asset_id():
    """Create a default asset ID for testing."""
    return AssetId.from_hex(ASSET_ID_HEX)


@pytest.fixture
def lovelace_asset_id():
    """Create a Lovelace asset ID for testing."""
    return AssetId.new_lovelace()


class TestAssetIdNew:
    """Tests for AssetId.new() factory method."""

    def test_can_create_from_policy_and_name(self, policy_id, asset_name):
        """Test that AssetId can be created from policy ID and asset name."""
        asset_id = AssetId.new(policy_id, asset_name)
        assert asset_id is not None
        assert not asset_id.is_lovelace

    def test_policy_id_is_preserved(self, policy_id, asset_name):
        """Test that policy ID is preserved in created asset ID."""
        asset_id = AssetId.new(policy_id, asset_name)
        retrieved_policy_id = asset_id.policy_id
        assert retrieved_policy_id is not None
        assert retrieved_policy_id.to_hex() == POLICY_ID_HEX

    def test_asset_name_is_preserved(self, policy_id, asset_name):
        """Test that asset name is preserved in created asset ID."""
        asset_id = AssetId.new(policy_id, asset_name)
        retrieved_asset_name = asset_id.asset_name
        assert retrieved_asset_name is not None
        assert retrieved_asset_name.to_string() == ASSET_NAME_STRING

    def test_raises_error_for_none_policy_id(self, asset_name):
        """Test that None policy_id raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            AssetId.new(None, asset_name)

    def test_raises_error_for_none_asset_name(self, policy_id):
        """Test that None asset_name raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            AssetId.new(policy_id, None)

    def test_raises_error_for_invalid_policy_id_size(self, asset_name):
        """Test that invalid policy ID size raises an error."""
        invalid_policy_id = Blake2bHash.from_hex(INVALID_POLICY_ID_HEX)
        with pytest.raises(CardanoError):
            AssetId.new(invalid_policy_id, asset_name)


class TestAssetIdNewLovelace:
    """Tests for AssetId.new_lovelace() factory method."""

    def test_can_create_lovelace(self):
        """Test that Lovelace asset ID can be created."""
        lovelace = AssetId.new_lovelace()
        assert lovelace is not None

    def test_lovelace_is_identified_correctly(self):
        """Test that Lovelace asset ID is identified as Lovelace."""
        lovelace = AssetId.new_lovelace()
        assert lovelace.is_lovelace

    def test_lovelace_has_no_policy_id(self):
        """Test that Lovelace asset ID has no policy ID."""
        lovelace = AssetId.new_lovelace()
        assert lovelace.policy_id is None

    def test_lovelace_has_no_asset_name(self):
        """Test that Lovelace asset ID has no asset name."""
        lovelace = AssetId.new_lovelace()
        assert lovelace.asset_name is None

    def test_lovelace_string_representation(self):
        """Test that Lovelace asset ID has correct string representation."""
        lovelace = AssetId.new_lovelace()
        assert str(lovelace) == "lovelace"

    def test_lovelace_repr_representation(self):
        """Test that Lovelace asset ID has correct repr representation."""
        lovelace = AssetId.new_lovelace()
        assert repr(lovelace) == "AssetId(lovelace)"


class TestAssetIdFromBytes:
    """Tests for AssetId.from_bytes() factory method."""

    def test_can_create_from_bytes(self):
        """Test that AssetId can be created from bytes."""
        asset_id = AssetId.from_bytes(ASSET_ID_BYTES)
        assert asset_id is not None
        assert asset_id.to_bytes() == ASSET_ID_BYTES

    def test_can_create_from_bytearray(self):
        """Test that AssetId can be created from bytearray."""
        asset_id = AssetId.from_bytes(bytearray(ASSET_ID_BYTES))
        assert asset_id is not None
        assert asset_id.to_bytes() == ASSET_ID_BYTES

    def test_can_create_from_policy_id_only(self):
        """Test that AssetId can be created from policy ID only (empty asset name)."""
        asset_id = AssetId.from_bytes(POLICY_ID_BYTES)
        assert asset_id is not None
        assert not asset_id.is_lovelace
        assert len(asset_id.to_bytes()) == 28

    def test_raises_error_for_none_data(self):
        """Test that None data raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetId.from_bytes(None)

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raise an error."""
        with pytest.raises(CardanoError):
            AssetId.from_bytes(b"")

    def test_raises_error_for_insufficient_bytes(self):
        """Test that insufficient bytes raise an error."""
        with pytest.raises(CardanoError):
            AssetId.from_bytes(b"short")

    def test_raises_error_for_invalid_type(self):
        """Test that invalid data type raises an error."""
        with pytest.raises((CardanoError, TypeError)):
            AssetId.from_bytes("not bytes")


class TestAssetIdFromHex:
    """Tests for AssetId.from_hex() factory method."""

    def test_can_create_from_hex(self):
        """Test that AssetId can be created from hex string."""
        asset_id = AssetId.from_hex(ASSET_ID_HEX)
        assert asset_id is not None
        assert asset_id.to_hex() == ASSET_ID_HEX

    def test_can_create_from_uppercase_hex(self):
        """Test that AssetId can be created from uppercase hex."""
        asset_id = AssetId.from_hex(ASSET_ID_HEX.upper())
        assert asset_id is not None
        assert asset_id.to_hex().lower() == ASSET_ID_HEX.lower()

    def test_can_create_from_policy_id_hex_only(self):
        """Test that AssetId can be created from policy ID hex only."""
        asset_id = AssetId.from_hex(POLICY_ID_HEX)
        assert asset_id is not None
        assert not asset_id.is_lovelace

    def test_raises_error_for_none_hex(self):
        """Test that None hex string raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            AssetId.from_hex(None)

    def test_raises_error_for_empty_hex(self):
        """Test that empty hex string raises an error."""
        with pytest.raises(CardanoError):
            AssetId.from_hex("")

    def test_raises_error_for_odd_length_hex(self):
        """Test that odd-length hex string raises an error."""
        with pytest.raises(CardanoError):
            AssetId.from_hex(ASSET_ID_HEX[:-1])

    def test_raises_error_for_invalid_hex_characters(self):
        """Test that invalid hex characters raise an error."""
        with pytest.raises(CardanoError):
            AssetId.from_hex("gg" + ASSET_ID_HEX[2:])

    def test_raises_error_for_invalid_type(self):
        """Test that invalid hex type raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            AssetId.from_hex(12345)


class TestAssetIdToBytes:
    """Tests for AssetId.to_bytes() method."""

    def test_returns_correct_bytes(self, asset_id):
        """Test that to_bytes returns correct bytes."""
        assert asset_id.to_bytes() == ASSET_ID_BYTES

    def test_bytes_length_is_correct(self, asset_id):
        """Test that bytes length is correct."""
        asset_bytes = asset_id.to_bytes()
        assert len(asset_bytes) == len(ASSET_ID_BYTES)

    def test_round_trip_bytes(self):
        """Test that bytes round-trip works correctly."""
        asset_id1 = AssetId.from_bytes(ASSET_ID_BYTES)
        asset_bytes = asset_id1.to_bytes()
        asset_id2 = AssetId.from_bytes(asset_bytes)
        assert asset_id1.to_bytes() == asset_id2.to_bytes()


class TestAssetIdToHex:
    """Tests for AssetId.to_hex() method."""

    def test_returns_correct_hex(self, asset_id):
        """Test that to_hex returns correct hex string."""
        assert asset_id.to_hex() == ASSET_ID_HEX

    def test_hex_length_is_correct(self, asset_id):
        """Test that hex length is correct."""
        hex_string = asset_id.to_hex()
        assert len(hex_string) == len(ASSET_ID_HEX)

    def test_hex_is_lowercase(self, asset_id):
        """Test that hex string is lowercase."""
        hex_string = asset_id.to_hex()
        assert hex_string == hex_string.lower()

    def test_round_trip_hex(self):
        """Test that hex round-trip works correctly."""
        asset_id1 = AssetId.from_hex(ASSET_ID_HEX)
        hex_string = asset_id1.to_hex()
        asset_id2 = AssetId.from_hex(hex_string)
        assert asset_id1.to_hex() == asset_id2.to_hex()


class TestAssetIdIsLovelace:
    """Tests for AssetId.is_lovelace property."""

    def test_non_lovelace_asset_returns_false(self, asset_id):
        """Test that non-Lovelace asset ID returns False."""
        assert not asset_id.is_lovelace

    def test_lovelace_asset_returns_true(self, lovelace_asset_id):
        """Test that Lovelace asset ID returns True."""
        assert lovelace_asset_id.is_lovelace

    def test_created_asset_is_not_lovelace(self, policy_id, asset_name):
        """Test that created asset ID is not Lovelace."""
        asset_id = AssetId.new(policy_id, asset_name)
        assert not asset_id.is_lovelace


class TestAssetIdPolicyId:
    """Tests for AssetId.policy_id property."""

    def test_returns_policy_id_for_normal_asset(self, asset_id):
        """Test that policy_id returns correct policy ID for normal asset."""
        policy = asset_id.policy_id
        assert policy is not None
        assert policy.to_hex() == POLICY_ID_HEX

    def test_returns_none_for_lovelace(self, lovelace_asset_id):
        """Test that policy_id returns None for Lovelace."""
        assert lovelace_asset_id.policy_id is None

    def test_policy_id_is_correct_type(self, asset_id):
        """Test that policy_id returns Blake2bHash instance."""
        policy = asset_id.policy_id
        assert isinstance(policy, Blake2bHash)

    def test_policy_id_matches_original(self, policy_id, asset_name):
        """Test that retrieved policy ID matches original."""
        asset_id = AssetId.new(policy_id, asset_name)
        retrieved_policy = asset_id.policy_id
        assert retrieved_policy.to_hex() == policy_id.to_hex()


class TestAssetIdAssetName:
    """Tests for AssetId.asset_name property."""

    def test_returns_asset_name_for_normal_asset(self, asset_id):
        """Test that asset_name returns correct asset name for normal asset."""
        name = asset_id.asset_name
        assert name is not None
        assert name.to_string() == ASSET_NAME_STRING

    def test_returns_none_for_lovelace(self, lovelace_asset_id):
        """Test that asset_name returns None for Lovelace."""
        assert lovelace_asset_id.asset_name is None

    def test_asset_name_is_correct_type(self, asset_id):
        """Test that asset_name returns AssetName instance."""
        name = asset_id.asset_name
        assert isinstance(name, AssetName)

    def test_asset_name_matches_original(self, policy_id, asset_name):
        """Test that retrieved asset name matches original."""
        asset_id = AssetId.new(policy_id, asset_name)
        retrieved_name = asset_id.asset_name
        assert retrieved_name.to_string() == asset_name.to_string()


class TestAssetIdEquality:
    """Tests for AssetId.__eq__() method."""

    def test_same_asset_ids_are_equal(self):
        """Test that same asset IDs are equal."""
        asset_id1 = AssetId.from_hex(ASSET_ID_HEX)
        asset_id2 = AssetId.from_hex(ASSET_ID_HEX)
        assert asset_id1 == asset_id2

    def test_different_asset_ids_are_not_equal(self, asset_id, lovelace_asset_id):
        """Test that different asset IDs are not equal."""
        assert asset_id != lovelace_asset_id

    def test_lovelace_asset_ids_are_equal(self):
        """Test that Lovelace asset IDs are equal."""
        lovelace1 = AssetId.new_lovelace()
        lovelace2 = AssetId.new_lovelace()
        assert lovelace1 == lovelace2

    def test_equality_with_non_asset_id_returns_false(self, asset_id):
        """Test that equality with non-AssetId returns False."""
        assert asset_id != "not an asset id"
        assert asset_id != 12345
        assert asset_id != None

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric."""
        asset_id1 = AssetId.from_hex(ASSET_ID_HEX)
        asset_id2 = AssetId.from_hex(ASSET_ID_HEX)
        assert asset_id1 == asset_id2
        assert asset_id2 == asset_id1


class TestAssetIdHash:
    """Tests for AssetId.__hash__() method."""

    def test_can_be_hashed(self, asset_id):
        """Test that AssetId can be hashed."""
        hash_value = hash(asset_id)
        assert isinstance(hash_value, int)

    def test_same_asset_ids_have_same_hash(self):
        """Test that same asset IDs have same hash."""
        asset_id1 = AssetId.from_hex(ASSET_ID_HEX)
        asset_id2 = AssetId.from_hex(ASSET_ID_HEX)
        assert hash(asset_id1) == hash(asset_id2)

    def test_can_be_used_in_set(self):
        """Test that AssetId can be used in a set."""
        asset_id1 = AssetId.from_hex(ASSET_ID_HEX)
        asset_id2 = AssetId.from_hex(ASSET_ID_HEX)
        asset_set = {asset_id1, asset_id2}
        assert len(asset_set) == 1

    def test_can_be_used_as_dict_key(self, asset_id):
        """Test that AssetId can be used as a dict key."""
        asset_dict = {asset_id: "test_value"}
        assert asset_dict[asset_id] == "test_value"

    def test_lovelace_can_be_hashed(self, lovelace_asset_id):
        """Test that Lovelace asset ID can be hashed."""
        hash_value = hash(lovelace_asset_id)
        assert isinstance(hash_value, int)


class TestAssetIdStr:
    """Tests for AssetId.__str__() method."""

    def test_returns_hex_for_normal_asset(self, asset_id):
        """Test that str returns hex for normal asset."""
        assert str(asset_id) == ASSET_ID_HEX

    def test_returns_lovelace_for_lovelace_asset(self, lovelace_asset_id):
        """Test that str returns 'lovelace' for Lovelace asset."""
        assert str(lovelace_asset_id) == "lovelace"


class TestAssetIdRepr:
    """Tests for AssetId.__repr__() method."""

    def test_returns_truncated_hex_for_normal_asset(self, asset_id):
        """Test that repr returns truncated hex for normal asset."""
        repr_str = repr(asset_id)
        assert repr_str.startswith("AssetId(")
        assert "..." in repr_str

    def test_returns_lovelace_for_lovelace_asset(self, lovelace_asset_id):
        """Test that repr returns 'lovelace' for Lovelace asset."""
        assert repr(lovelace_asset_id) == "AssetId(lovelace)"


class TestAssetIdContextManager:
    """Tests for AssetId context manager protocol."""

    def test_can_be_used_as_context_manager(self, asset_id):
        """Test that AssetId can be used as a context manager."""
        with asset_id as ctx_asset_id:
            assert ctx_asset_id is asset_id

    def test_context_manager_returns_self(self, asset_id):
        """Test that context manager returns self."""
        with asset_id as ctx_asset_id:
            assert ctx_asset_id is asset_id
            assert ctx_asset_id.to_hex() == ASSET_ID_HEX
