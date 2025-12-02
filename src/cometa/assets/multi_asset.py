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

from __future__ import annotations
from typing import Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cryptography.blake2b_hash import Blake2bHash
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..json.json_writer import JsonWriter
from .asset_name import AssetName
from .asset_name_map import AssetNameMap
from .asset_id import AssetId


class MultiAsset:
    """
    Represents a collection of native assets in Cardano.

    MultiAsset maps policy IDs to asset name maps, allowing representation
    of multiple tokens across different minting policies. It's used in
    transaction outputs to specify token holdings.

    Example:
        >>> multi_asset = MultiAsset()
        >>> asset_map = AssetNameMap()
        >>> asset_map.insert(AssetName.from_string("Token"), 100)
        >>> multi_asset.insert_assets(policy_id, asset_map)
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_multi_asset_t**")
            err = lib.cardano_multi_asset_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create MultiAsset (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("MultiAsset: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_multi_asset_t**", self._ptr)
            lib.cardano_multi_asset_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MultiAsset:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"MultiAsset(policies={self.policy_count})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MultiAsset:
        """
        Deserializes a MultiAsset from CBOR data.

        Args:
            reader: A CborReader positioned at the multi-asset data.

        Returns:
            A new MultiAsset deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_multi_asset_t**")
        err = lib.cardano_multi_asset_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize MultiAsset from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def policy_count(self) -> int:
        """
        Returns the number of distinct policy IDs in this multi-asset.

        Returns:
            The number of unique policy IDs.
        """
        return int(lib.cardano_multi_asset_get_policy_count(self._ptr))

    def insert_assets(self, policy_id: Blake2bHash, assets: AssetNameMap) -> None:
        """
        Inserts or updates assets under a specific policy ID.

        Args:
            policy_id: The minting policy ID.
            assets: The asset name map with quantities.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_multi_asset_insert_assets(self._ptr, policy_id._ptr, assets._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert assets into MultiAsset (error code: {err})")

    def get_assets(self, policy_id: Blake2bHash) -> AssetNameMap:
        """
        Retrieves the assets under a specific policy ID.

        Args:
            policy_id: The minting policy ID to look up.

        Returns:
            The AssetNameMap for the specified policy.

        Raises:
            CardanoError: If the policy ID is not found or retrieval fails.
        """
        out = ffi.new("cardano_asset_name_map_t**")
        err = lib.cardano_multi_asset_get_assets(self._ptr, policy_id._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get assets from MultiAsset (error code: {err})")
        return AssetNameMap(out[0])

    def get(self, policy_id: Blake2bHash, asset_name: AssetName) -> int:
        """
        Retrieves the quantity of a specific asset.

        Args:
            policy_id: The minting policy ID.
            asset_name: The name of the asset.

        Returns:
            The quantity of the asset.

        Raises:
            CardanoError: If the asset is not found or retrieval fails.
        """
        value = ffi.new("int64_t*")
        err = lib.cardano_multi_asset_get(self._ptr, policy_id._ptr, asset_name._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to get asset from MultiAsset (error code: {err})")
        return int(value[0])

    def get_with_id(self, asset_id: AssetId) -> int:
        """
        Retrieves the quantity of an asset by its ID.

        Args:
            asset_id: The asset ID to look up.

        Returns:
            The quantity of the asset (0 if not present).

        Raises:
            CardanoError: If retrieval fails.
        """
        value = ffi.new("int64_t*")
        err = lib.cardano_multi_asset_get_with_id(self._ptr, asset_id._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to get asset by ID (error code: {err})")
        return int(value[0])

    def set(self, policy_id: Blake2bHash, asset_name: AssetName, value: int) -> None:
        """
        Sets the quantity of a specific asset.

        Args:
            policy_id: The minting policy ID.
            asset_name: The name of the asset.
            value: The new quantity.

        Raises:
            CardanoError: If the operation fails.
        """
        err = lib.cardano_multi_asset_set(self._ptr, policy_id._ptr, asset_name._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set asset in MultiAsset (error code: {err})")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the multi-asset to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_multi_asset_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize MultiAsset to CBOR (error code: {err})")

    def to_cip116_json(self, writer: JsonWriter) -> None:
        """
        Serializes this multi-asset to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_multi_asset_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize MultiAsset to CIP-116 JSON (error code: {err})")

    def add(self, other: MultiAsset) -> MultiAsset:
        """
        Combines two multi-assets by adding their quantities.

        Args:
            other: The other multi-asset to add.

        Returns:
            A new MultiAsset with combined quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_multi_asset_t**")
        err = lib.cardano_multi_asset_add(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to add MultiAssets (error code: {err})")
        return MultiAsset(out[0])

    def subtract(self, other: MultiAsset) -> MultiAsset:
        """
        Subtracts another multi-asset from this one.

        Args:
            other: The multi-asset to subtract.

        Returns:
            A new MultiAsset with subtracted quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_multi_asset_t**")
        err = lib.cardano_multi_asset_subtract(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to subtract MultiAssets (error code: {err})")
        return MultiAsset(out[0])

    def get_positive(self) -> MultiAsset:
        """
        Returns a new multi-asset containing only assets with positive quantities.

        Returns:
            A new MultiAsset with only positive quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_multi_asset_t**")
        err = lib.cardano_multi_asset_get_positive(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get positive MultiAsset (error code: {err})")
        return MultiAsset(out[0])

    def get_negative(self) -> MultiAsset:
        """
        Returns a new multi-asset containing only assets with negative quantities.

        Returns:
            A new MultiAsset with only negative quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_multi_asset_t**")
        err = lib.cardano_multi_asset_get_negative(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get negative MultiAsset (error code: {err})")
        return MultiAsset(out[0])

    def __eq__(self, other: object) -> bool:
        """Checks equality with another MultiAsset."""
        if not isinstance(other, MultiAsset):
            return False
        return bool(lib.cardano_multi_asset_equals(self._ptr, other._ptr))

    def __add__(self, other: MultiAsset) -> MultiAsset:
        """Adds two multi-assets using the + operator."""
        return self.add(other)

    def __sub__(self, other: MultiAsset) -> MultiAsset:
        """Subtracts a multi-asset using the - operator."""
        return self.subtract(other)

    def __len__(self) -> int:
        """Returns the number of distinct policy IDs."""
        return self.policy_count

    def __getitem__(self, key: Blake2bHash) -> AssetNameMap:
        """Gets asset map for a policy ID using bracket notation."""
        return self.get_assets(key)

    def __setitem__(self, key: Blake2bHash, value: AssetNameMap) -> None:
        """Sets assets for a policy ID using bracket notation."""
        self.insert_assets(key, value)

    def __bool__(self) -> bool:
        """Returns True if the multi-asset is not empty."""
        return self.policy_count > 0

    def __contains__(self, key: Blake2bHash) -> bool:
        """Checks if a policy ID is in the multi-asset."""
        try:
            self.get_assets(key)
            return True
        except CardanoError:
            return False

    def __iter__(self) -> Iterator[Blake2bHash]:
        """Iterates over all policy IDs (like Python dict)."""
        # Get the policy ID list
        out = ffi.new("cardano_policy_id_list_t**")
        err = lib.cardano_multi_asset_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get policy IDs from MultiAsset (error code: {err})")
        policy_list_ptr = out[0]
        try:
            length = lib.cardano_policy_id_list_get_length(policy_list_ptr)
            for i in range(length):
                hash_out = ffi.new("cardano_blake2b_hash_t**")
                err = lib.cardano_policy_id_list_get(policy_list_ptr, i, hash_out)
                if err != 0:
                    raise CardanoError(f"Failed to get policy ID at index {i} (error code: {err})")
                yield Blake2bHash(hash_out[0])
        finally:
            # Clean up the policy list
            ptr_ptr = ffi.new("cardano_policy_id_list_t**", policy_list_ptr)
            lib.cardano_policy_id_list_unref(ptr_ptr)

    def keys(self) -> Iterator[Blake2bHash]:
        """Returns an iterator over policy IDs (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[AssetNameMap]:
        """Returns an iterator over asset name maps (like Python dict)."""
        for policy_id in self:
            yield self.get_assets(policy_id)

    def items(self) -> Iterator[tuple[Blake2bHash, AssetNameMap]]:
        """Returns an iterator over (policy_id, assets) pairs (like Python dict)."""
        for policy_id in self:
            yield policy_id, self.get_assets(policy_id)
