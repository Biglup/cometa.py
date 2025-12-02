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
from typing import Iterator, Tuple, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..json.json_writer import JsonWriter
from .asset_name import AssetName

if TYPE_CHECKING:
    from .asset_name_list import AssetNameList


class AssetNameMap(Mapping["AssetName", "int"]):
    """
    Represents a map of asset names to their quantities.

    This collection type is used within Cardano's multi-asset structure to
    associate asset names with their amounts under a specific policy ID.
    The amounts can be positive or negative (for minting/burning).

    Example:
        >>> asset_map = AssetNameMap()
        >>> asset_map.insert(AssetName.from_string("Token1"), 1000)
        >>> asset_map.get(AssetName.from_string("Token1"))
        1000
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_asset_name_map_t**")
            err = lib.cardano_asset_name_map_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create AssetNameMap (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("AssetNameMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_asset_name_map_t**", self._ptr)
            lib.cardano_asset_name_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AssetNameMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"AssetNameMap(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> AssetNameMap:
        """
        Deserializes an AssetNameMap from CBOR data.

        Args:
            reader: A CborReader positioned at the asset name map data.

        Returns:
            A new AssetNameMap deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_asset_name_map_t**")
        err = lib.cardano_asset_name_map_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize AssetNameMap from CBOR (error code: {err})")
        return cls(out[0])

    def insert(self, key: AssetName, value: int) -> None:
        """
        Inserts or updates an asset name with its quantity.

        Args:
            key: The asset name.
            value: The quantity (can be negative for burning).

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_asset_name_map_insert(self._ptr, key._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to insert into AssetNameMap (error code: {err})")

    def get(  # pylint: disable=arguments-differ
        self, key: AssetName, default: "int | None" = None
    ) -> "int | None":
        """
        Retrieves the quantity for a given asset name.

        Args:
            key: The asset name to look up.
            default: Value to return if key is not found. Defaults to None.

        Returns:
            The quantity associated with the asset name, or default if not found.
        """
        value = ffi.new("int64_t*")
        err = lib.cardano_asset_name_map_get(self._ptr, key._ptr, value)
        if err != 0:
            return default
        return int(value[0])

    def get_key_at(self, index: int) -> AssetName:
        """
        Retrieves the asset name at a specific index.

        Args:
            index: The index of the asset name to retrieve.

        Returns:
            The AssetName at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        out = ffi.new("cardano_asset_name_t**")
        err = lib.cardano_asset_name_map_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get key at index {index} (error code: {err})")
        return AssetName(out[0])

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
        err = lib.cardano_asset_name_map_get_value_at(self._ptr, index, value)
        if err != 0:
            raise CardanoError(f"Failed to get value at index {index} (error code: {err})")
        return int(value[0])

    def get_key_value_at(self, index: int) -> tuple[AssetName, int]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple containing the AssetName and quantity at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        key_out = ffi.new("cardano_asset_name_t**")
        value_out = ffi.new("int64_t*")
        err = lib.cardano_asset_name_map_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (AssetName(key_out[0]), int(value_out[0]))

    def get_keys(self) -> AssetNameList:
        """
        Retrieves all keys (asset names) from the map.

        Returns:
            An AssetNameList containing all asset names in the map.

        Raises:
            CardanoError: If retrieval fails.
        """
        from .asset_name_list import AssetNameList

        out = ffi.new("cardano_asset_name_list_t**")
        err = lib.cardano_asset_name_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from AssetNameMap (error code: {err})")
        return AssetNameList(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the asset name map to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_asset_name_map_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize AssetNameMap to CBOR (error code: {err})")

    def to_cip116_json(self, writer: JsonWriter) -> None:
        """
        Serializes this asset name map to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_asset_name_map_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize AssetNameMap to CIP-116 JSON (error code: {err})")

    def add(self, other: AssetNameMap) -> AssetNameMap:
        """
        Combines two asset name maps by adding their quantities.

        Args:
            other: The other asset name map to add.

        Returns:
            A new AssetNameMap with combined quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_asset_name_map_t**")
        err = lib.cardano_asset_name_map_add(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to add AssetNameMaps (error code: {err})")
        return AssetNameMap(out[0])

    def subtract(self, other: AssetNameMap) -> AssetNameMap:
        """
        Subtracts another asset name map from this one.

        Args:
            other: The asset name map to subtract.

        Returns:
            A new AssetNameMap with subtracted quantities.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_asset_name_map_t**")
        err = lib.cardano_asset_name_map_subtract(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to subtract AssetNameMaps (error code: {err})")
        return AssetNameMap(out[0])

    def __len__(self) -> int:
        """Returns the number of entries in the map."""
        return int(lib.cardano_asset_name_map_get_length(self._ptr))

    def __iter__(self) -> Iterator[AssetName]:
        """Iterates over all keys (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i)

    def __getitem__(self, key: AssetName) -> int:
        """Gets a value by key using bracket notation."""
        return self.get(key)

    def __setitem__(self, key: AssetName, value: int) -> None:
        """Sets a value by key using bracket notation."""
        self.insert(key, value)

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __contains__(self, item: AssetName) -> bool:
        """Checks if an asset name is in the map."""
        return self.get(item) is not None

    def __eq__(self, other: object) -> bool:
        """Checks equality with another AssetNameMap."""
        if not isinstance(other, AssetNameMap):
            return False
        return bool(lib.cardano_asset_name_map_equals(self._ptr, other._ptr))

    def __add__(self, other: AssetNameMap) -> AssetNameMap:
        """Adds two asset name maps using the + operator."""
        return self.add(other)

    def __sub__(self, other: AssetNameMap) -> AssetNameMap:
        """Subtracts an asset name map using the - operator."""
        return self.subtract(other)

    def keys(self) -> Iterator[AssetName]:
        """Returns an iterator over keys (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[int]:
        """Returns an iterator over values (like Python dict)."""
        for i in range(len(self)):
            yield self.get_value_at(i)

    def items(self) -> Iterator[Tuple[AssetName, int]]:
        """Returns an iterator over (key, value) pairs (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i), self.get_value_at(i)
