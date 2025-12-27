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
from typing import Iterator, Tuple, TYPE_CHECKING, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .metadatum import Metadatum

if TYPE_CHECKING:
    from .metadatum_list import MetadatumList

# Type alias for values that can be converted to Metadatum
MetadatumLike = Union[Metadatum, int, str, bytes, bytearray]


def _to_metadatum(value: MetadatumLike) -> Metadatum:
    """Convert a primitive value to a Metadatum."""
    if isinstance(value, Metadatum):
        return value
    if isinstance(value, int):
        return Metadatum.from_int(value)
    if isinstance(value, str):
        return Metadatum.from_string(value)
    if isinstance(value, (bytes, bytearray)):
        return Metadatum.from_bytes(value)
    raise TypeError(f"Cannot convert {type(value).__name__} to Metadatum")


class MetadatumMap(Mapping["Metadatum", "Metadatum"]):
    """
    Represents a map of metadatum keys to metadatum values.

    Both keys and values can be any valid metadatum type.
    Accepts Python primitives (int, str, bytes) directly for keys and values.

    Example:
        >>> meta_map = MetadatumMap()
        >>> meta_map["name"] = "Alice"        # str key and value
        >>> meta_map["age"] = 30              # str key, int value
        >>> meta_map[1] = b"\\xde\\xad"         # int key, bytes value
        >>> len(meta_map)
        3
        >>> "name" in meta_map
        True
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new MetadatumMap.

        Args:
            ptr: Optional FFI pointer to an existing map. If None, creates a new empty map.

        Raises:
            CardanoError: If map creation fails or if ptr is NULL.
        """
        if ptr is None:
            out = ffi.new("cardano_metadatum_map_t**")
            err = lib.cardano_metadatum_map_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create MetadatumMap (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("MetadatumMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the MetadatumMap by releasing its FFI resources."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_metadatum_map_t**", self._ptr)
            lib.cardano_metadatum_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MetadatumMap:
        """Enables use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cleans up when exiting context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the MetadatumMap."""
        return f"MetadatumMap(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MetadatumMap:
        """
        Deserializes a MetadatumMap from CBOR data.

        Args:
            reader: A CborReader positioned at the map data.

        Returns:
            A new MetadatumMap deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_metadatum_map_t**")
        err = lib.cardano_metadatum_map_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize MetadatumMap from CBOR (error code: {err})")
        return cls(out[0])

    def insert(self, key: MetadatumLike, value: MetadatumLike) -> None:
        """
        Inserts or updates a key-value pair.

        Args:
            key: The metadatum key. Can be a Metadatum or primitive (int, str, bytes).
            value: The metadatum value. Can be a Metadatum or primitive (int, str, bytes).

        Raises:
            CardanoError: If insertion fails.
            TypeError: If key or value cannot be converted to Metadatum.

        Example:
            >>> meta_map = MetadatumMap()
            >>> meta_map.insert("name", "Alice")
            >>> meta_map.insert(1, 42)
        """
        key_meta = _to_metadatum(key)
        value_meta = _to_metadatum(value)
        err = lib.cardano_metadatum_map_insert(self._ptr, key_meta._ptr, value_meta._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert into MetadatumMap (error code: {err})")

    def get(  # pylint: disable=arguments-differ
        self, key: MetadatumLike, default: "Metadatum | None" = None
    ) -> "Metadatum | None":
        """
        Retrieves the value for a given key.

        Args:
            key: The metadatum key to look up. Can be a Metadatum or primitive.
            default: Value to return if key is not found. Defaults to None.

        Returns:
            The Metadatum value associated with the key, or default if not found.

        Raises:
            TypeError: If key cannot be converted to Metadatum.
        """
        key_meta = _to_metadatum(key)
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_map_get(self._ptr, key_meta._ptr, out)
        if err != 0:
            return default
        return Metadatum(out[0])

    def get_at(self, index: int) -> Tuple[Metadatum, Metadatum]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the entry to retrieve.

        Returns:
            A tuple of (key, value) Metadatum objects at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for map of length {len(self)}")
        key_out = ffi.new("cardano_metadatum_t**")
        value_out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_map_get_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get entry at index {index} (error code: {err})")
        return Metadatum(key_out[0]), Metadatum(value_out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the metadatum map to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_metadatum_map_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize MetadatumMap to CBOR (error code: {err})")

    def __len__(self) -> int:
        """Returns the number of entries in the map."""
        return int(lib.cardano_metadatum_map_get_length(self._ptr))

    def __iter__(self) -> Iterator[Metadatum]:
        """Iterates over all keys (like Python dict)."""
        for i in range(len(self)):
            key, _ = self.get_at(i)
            yield key

    def __eq__(self, other: object) -> bool:
        """Checks equality with another MetadatumMap."""
        if not isinstance(other, MetadatumMap):
            return False
        return bool(lib.cardano_metadatum_map_equals(self._ptr, other._ptr))

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __getitem__(self, key: MetadatumLike) -> Metadatum:
        """Gets a value by key using bracket notation. Accepts primitives."""
        return self.get(key)

    def __setitem__(self, key: MetadatumLike, value: MetadatumLike) -> None:
        """Sets a value by key using bracket notation. Accepts primitives."""
        self.insert(key, value)

    def __contains__(self, key: MetadatumLike) -> bool:
        """Checks if a key is in the map. Accepts primitives."""
        return self.get(key) is not None

    def keys(self) -> Iterator[Metadatum]:
        """Returns an iterator over keys (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[Metadatum]:
        """Returns an iterator over values (like Python dict)."""
        for i in range(len(self)):
            _, value = self.get_at(i)
            yield value

    def items(self) -> Iterator[Tuple[Metadatum, Metadatum]]:
        """Returns an iterator over (key, value) pairs (like Python dict)."""
        for i in range(len(self)):
            yield self.get_at(i)

    def get_keys(self) -> MetadatumList:
        """
        Retrieves all keys from the map.

        Returns:
            A MetadatumList containing all keys in the map.

        Raises:
            CardanoError: If retrieval fails.
        """
        # Import here to avoid circular import
        from .metadatum_list import MetadatumList
        out = ffi.new("cardano_metadatum_list_t**")
        err = lib.cardano_metadatum_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from MetadatumMap (error code: {err})")
        return MetadatumList(out[0])

    def get_values(self) -> MetadatumList:
        """
        Retrieves all values from the map.

        Returns:
            A MetadatumList containing all values in the map.

        Raises:
            CardanoError: If retrieval fails.
        """
        # Import here to avoid circular import
        from .metadatum_list import MetadatumList
        out = ffi.new("cardano_metadatum_list_t**")
        err = lib.cardano_metadatum_map_get_values(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get values from MetadatumMap (error code: {err})")
        return MetadatumList(out[0])

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this metadatum map to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_metadatum_map_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
