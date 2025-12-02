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
from collections.abc import Mapping
from typing import Iterator, Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError
from .asset_id import AssetId
from .asset_id_list import AssetIdList


class AssetIdMap(Mapping["AssetId", "int"]):
    """
    Represents a map of asset IDs to their quantities.

    This collection type maps asset identifiers to coin amounts,
    useful for tracking asset balances across multiple tokens.

    Example:
        >>> asset_map = AssetIdMap()
        >>> asset_map.insert(AssetId.new_lovelace(), 1000000)
        >>> asset_map.get(AssetId.new_lovelace())
        1000000
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_asset_id_map_t**")
            err = lib.cardano_asset_id_map_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create AssetIdMap (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("AssetIdMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_asset_id_map_t**", self._ptr)
            lib.cardano_asset_id_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AssetIdMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"AssetIdMap(len={len(self)})"

    def insert(self, key: AssetId, value: int) -> None:
        """
        Inserts or updates an asset ID with its quantity.

        Args:
            key: The asset ID.
            value: The quantity (can be negative for burning).

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_asset_id_map_insert(self._ptr, key._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to insert into AssetIdMap (error code: {err})")

    def get(  # pylint: disable=arguments-differ
        self, key: AssetId, default: "int | None" = None
    ) -> "int | None":
        """
        Retrieves the quantity for a given asset ID.

        Args:
            key: The asset ID to look up.
            default: Value to return if key is not found. Defaults to None.

        Returns:
            The quantity associated with the asset ID, or default if not found.
        """
        value = ffi.new("int64_t*")
        err = lib.cardano_asset_id_map_get(self._ptr, key._ptr, value)
        if err != 0:
            return default
        return int(value[0])

    def get_keys(self) -> AssetIdList:
        """
        Retrieves all keys from the map.

        Returns:
            An AssetIdList containing all asset IDs in the map.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_asset_id_list_t**")
        err = lib.cardano_asset_id_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from AssetIdMap (error code: {err})")
        return AssetIdList(out[0])

    def get_key_at(self, index: int) -> AssetId:
        """
        Retrieves the asset ID at a specific index.

        Args:
            index: The index of the asset ID to retrieve.

        Returns:
            The AssetId at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        out = ffi.new("cardano_asset_id_t**")
        err = lib.cardano_asset_id_map_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get key at index {index} (error code: {err})")
        return AssetId(out[0])

    def get_value_at(self, index: int) -> int:
        """
        Retrieves the quantity at a specific index.

        Args:
            index: The index of the quantity to retrieve.

        Returns:
            The quantity at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        value = ffi.new("int64_t*")
        err = lib.cardano_asset_id_map_get_value_at(self._ptr, index, value)
        if err != 0:
            raise CardanoError(f"Failed to get value at index {index} (error code: {err})")
        return int(value[0])

    def get_key_value_at(self, index: int) -> tuple[AssetId, int]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple containing the AssetId and quantity at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        key_out = ffi.new("cardano_asset_id_t**")
        value_out = ffi.new("int64_t*")
        err = lib.cardano_asset_id_map_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (AssetId(key_out[0]), int(value_out[0]))

    def __len__(self) -> int:
        """Returns the number of entries in the map."""
        return int(lib.cardano_asset_id_map_get_length(self._ptr))

    def __iter__(self) -> Iterator[AssetId]:
        """Iterates over all keys (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i)

    def __contains__(self, item: AssetId) -> bool:
        """Checks if an asset ID is in the map."""
        return self.get(item) is not None

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __getitem__(self, key: AssetId) -> int:
        """Gets a quantity by asset ID using bracket notation."""
        return self.get(key)

    def __setitem__(self, key: AssetId, value: int) -> None:
        """Sets a quantity by asset ID using bracket notation."""
        self.insert(key, value)

    def keys(self) -> Iterator[AssetId]:
        """Returns an iterator over keys (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[int]:
        """Returns an iterator over values (like Python dict)."""
        for i in range(len(self)):
            yield self.get_value_at(i)

    def items(self) -> Iterator[Tuple[AssetId, int]]:
        """Returns an iterator over (key, value) pairs (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i), self.get_value_at(i)

    def __eq__(self, other: object) -> bool:
        """Checks equality with another AssetIdMap."""
        if not isinstance(other, AssetIdMap):
            return False
        return bool(lib.cardano_asset_id_map_equals(self._ptr, other._ptr))

    def __add__(self, other: AssetIdMap) -> AssetIdMap:
        """
        Adds two asset ID maps together.

        Creates a new map where quantities for matching keys are summed.

        Args:
            other: The map to add.

        Returns:
            A new AssetIdMap with combined quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_asset_id_map_t**")
        err = lib.cardano_asset_id_map_add(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to add AssetIdMaps (error code: {err})")
        return AssetIdMap(out[0])

    def __sub__(self, other: AssetIdMap) -> AssetIdMap:
        """
        Subtracts one asset ID map from another.

        Creates a new map where quantities for matching keys are subtracted.

        Args:
            other: The map to subtract.

        Returns:
            A new AssetIdMap with subtracted quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_asset_id_map_t**")
        err = lib.cardano_asset_id_map_subtract(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to subtract AssetIdMaps (error code: {err})")
        return AssetIdMap(out[0])
