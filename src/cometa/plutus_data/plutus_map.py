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
from typing import TYPE_CHECKING, Iterator, Union, Tuple, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from .plutus_data import PlutusData, PlutusDataLike
    from .plutus_list import PlutusList

class PlutusMap(Mapping["PlutusData", "PlutusData"]):
    """
    Represents a map of Plutus data to Plutus data.

    This class provides Pythonic dict-like operations for working with
    Plutus data maps on the Cardano blockchain. It supports native Python
    types (int, str, bytes) which are automatically converted to PlutusData.

    Example:
        >>> pmap = PlutusMap()
        >>> pmap["key1"] = 42              # str key, int value
        >>> pmap[1] = "value"              # int key, str value
        >>> pmap[b"\\x01"] = b"\\x02"        # bytes key, bytes value
        >>> len(pmap)
        3

        >>> # Dict-like operations
        >>> for key in pmap:
        ...     print(key.kind)
        >>> for key, value in pmap.items():
        ...     print(key, value)

        >>> # Check membership
        >>> "key1" in pmap
        True
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_map_t**")
            err = lib.cardano_plutus_map_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create PlutusMap (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_map_t**", self._ptr)
            lib.cardano_plutus_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusMap(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of key-value pairs in the map."""
        return int(lib.cardano_plutus_map_get_length(self._ptr))

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __eq__(self, other: object) -> bool:
        """Checks equality with another PlutusMap."""
        if not isinstance(other, PlutusMap):
            return False
        return bool(lib.cardano_plutus_map_equals(self._ptr, other._ptr))

    def __getitem__(self, key: "PlutusDataLike") -> "PlutusData":
        """
        Gets a value by key using bracket notation.

        Args:
            key: A PlutusData or native Python type (int, str, bytes).

        Returns:
            The PlutusData value associated with the key.

        Raises:
            KeyError: If the key is not found.
            CardanoError: If retrieval fails.
        """
        from .plutus_data import PlutusData
        key_data = PlutusData.to_plutus_data(key)
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_map_get(self._ptr, key_data._ptr, out)
        if err != 0:
            raise KeyError(key)
        if out[0] == ffi.NULL:
            raise KeyError(key)
        return PlutusData(out[0])

    def __setitem__(self, key: PlutusDataLike, value: PlutusDataLike) -> None:
        """
        Sets a value by key using bracket notation.

        Args:
            key: A PlutusData or native Python type (int, str, bytes).
            value: A PlutusData or native Python type (int, str, bytes).

        Raises:
            CardanoError: If the operation fails.
        """
        from .plutus_data import PlutusData
        key_data = PlutusData.to_plutus_data(key)
        value_data = PlutusData.to_plutus_data(value)
        self.insert(key_data, value_data)

    def __contains__(self, key: PlutusDataLike) -> bool:
        """
        Checks if a key is in the map.

        Args:
            key: A PlutusData or native Python type (int, str, bytes).

        Returns:
            True if the key exists in the map.
        """
        try:
            _ = self[key]
            return True
        except KeyError:
            return False

    def __iter__(self) -> Iterator["PlutusData"]:
        """Iterates over all keys in the map (like Python dict)."""
        yield from self.get_keys()

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusMap:
        """
        Deserializes a PlutusMap from CBOR data.

        Args:
            reader: A CborReader positioned at the map data.

        Returns:
            A new PlutusMap deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_map_t**")
        err = lib.cardano_plutus_map_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PlutusMap from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the map to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_plutus_map_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PlutusMap to CBOR (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can alter the data and invalidate existing signatures.
        """
        lib.cardano_plutus_map_clear_cbor_cache(self._ptr)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_plutus_map_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    def insert(self, key: "PlutusData", value: "PlutusData") -> None:
        """
        Inserts a key-value pair into the map.

        Args:
            key: The PlutusData key.
            value: The PlutusData value.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_plutus_map_insert(self._ptr, key._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert into PlutusMap (error code: {err})")

    def get(self, key: PlutusDataLike, default: Optional["PlutusData"] = None) -> Optional["PlutusData"]:
        """
        Gets a value by key, returning a default if not found.

        Args:
            key: A PlutusData or native Python type (int, str, bytes).
            default: Value to return if key is not found.

        Returns:
            The PlutusData value or the default.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def get_keys(self) -> "PlutusList":
        """
        Retrieves all keys from the map.

        Returns:
            A PlutusList containing all keys.

        Raises:
            CardanoError: If retrieval fails.
        """
        from .plutus_list import PlutusList
        out = ffi.new("cardano_plutus_list_t**")
        err = lib.cardano_plutus_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from PlutusMap (error code: {err})")
        return PlutusList(out[0])

    def get_values(self) -> "PlutusList":
        """
        Retrieves all values from the map.

        Returns:
            A PlutusList containing all values.

        Raises:
            CardanoError: If retrieval fails.
        """
        from .plutus_list import PlutusList
        out = ffi.new("cardano_plutus_list_t**")
        err = lib.cardano_plutus_map_get_values(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get values from PlutusMap (error code: {err})")
        return PlutusList(out[0])

    def keys(self) -> Iterator["PlutusData"]:
        """
        Returns an iterator over keys (like Python dict).

        Returns:
            An iterator over PlutusData keys.
        """
        return iter(self)

    def values(self) -> Iterator["PlutusData"]:
        """
        Returns an iterator over values (like Python dict).

        Returns:
            An iterator over PlutusData values.
        """
        yield from self.get_values()

    def items(self) -> Iterator[Tuple["PlutusData", "PlutusData"]]:
        """
        Returns an iterator over (key, value) pairs (like Python dict).

        Returns:
            An iterator over (PlutusData, PlutusData) tuples.
        """
        keys_list = self.get_keys()
        values_list = self.get_values()
        for i, key in enumerate(keys_list):
            yield key, values_list[i]

    def update(self, other: Union[PlutusMap, Mapping[PlutusDataLike, PlutusDataLike]]) -> None:
        """
        Updates the map with key-value pairs from another map or mapping.

        Args:
            other: Another PlutusMap or a mapping of PlutusData/native types.
        """
        if isinstance(other, PlutusMap):
            for key, value in other.items():
                self.insert(key, value)
        else:
            for key, value in other.items():
                self[key] = value

    def setdefault(self, key: PlutusDataLike, default: PlutusDataLike) -> "PlutusData":
        """
        Gets a value by key, inserting and returning default if not found.

        Args:
            key: A PlutusData or native Python type.
            default: Value to insert and return if key is not found.

        Returns:
            The existing value or the default.
        """
        from .plutus_data import PlutusData
        try:
            return self[key]
        except KeyError:
            default_data = PlutusData.to_plutus_data(default)
            self[key] = default_data
            return default_data

    def copy(self) -> PlutusMap:
        """
        Creates a shallow copy of this map.

        Returns:
            A new PlutusMap with the same key-value pairs.
        """
        result = PlutusMap()
        for key, value in self.items():
            result.insert(key, value)
        return result

    def pop(self, key: PlutusDataLike, *default) -> "PlutusData":
        """
        Note: Pop operation is not supported by the underlying C library.
        This method is provided for API completeness but will raise an error.

        Raises:
            NotImplementedError: Always raised as the C library doesn't support removal.
        """
        raise NotImplementedError("PlutusMap does not support removal operations")
