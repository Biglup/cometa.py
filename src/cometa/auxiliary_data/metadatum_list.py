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
from collections.abc import Sequence
from typing import Iterable, Iterator, Optional, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .metadatum import Metadatum

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


class MetadatumList(Sequence["Metadatum"]):
    """
    Represents a list of metadatum values.

    Used to construct list-type metadata in transactions.
    Accepts Python primitives (int, str, bytes) directly.

    Example:
        >>> meta_list = MetadatumList()
        >>> meta_list.add(1)              # int
        >>> meta_list.add("hello")        # str
        >>> meta_list.add(b"\\xde\\xad")    # bytes
        >>> len(meta_list)
        3
        >>> 1 in meta_list
        True
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_metadatum_list_t**")
            err = lib.cardano_metadatum_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create MetadatumList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("MetadatumList: invalid handle")
            self._ptr = ptr

    @classmethod
    def from_list(cls, elements: Iterable[MetadatumLike]) -> MetadatumList:
        """
        Creates a MetadatumList from an iterable of metadatum values.

        Args:
            elements: An iterable of Metadatum objects or Python primitives
                     (int, str, bytes, bytearray).

        Returns:
            A new MetadatumList containing all the elements.

        Raises:
            CardanoError: If creation fails.
        """
        meta_list = cls()
        for element in elements:
            meta_list.add(element)
        return meta_list

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_metadatum_list_t**", self._ptr)
            lib.cardano_metadatum_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MetadatumList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"MetadatumList(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MetadatumList:
        """
        Deserializes a MetadatumList from CBOR data.

        Args:
            reader: A CborReader positioned at the list data.

        Returns:
            A new MetadatumList deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_metadatum_list_t**")
        err = lib.cardano_metadatum_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize MetadatumList from CBOR (error code: {err})")
        return cls(out[0])

    def add(self, element: MetadatumLike) -> None:
        """
        Adds a metadatum to the list.

        Args:
            element: The metadatum to add. Can be a Metadatum object or a
                     Python primitive (int, str, bytes, bytearray).

        Raises:
            CardanoError: If the operation fails.
            TypeError: If element cannot be converted to Metadatum.

        Example:
            >>> meta_list = MetadatumList()
            >>> meta_list.add(42)           # int
            >>> meta_list.add("hello")      # str
            >>> meta_list.add(b"\\xde\\xad")  # bytes
        """
        meta = _to_metadatum(element)
        err = lib.cardano_metadatum_list_add(self._ptr, meta._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to MetadatumList (error code: {err})")

    def get(self, index: int) -> Metadatum:
        """
        Retrieves a metadatum by index.

        Args:
            index: The index of the element to retrieve.

        Returns:
            The Metadatum at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from MetadatumList (error code: {err})")
        return Metadatum(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the metadatum list to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_metadatum_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize MetadatumList to CBOR (error code: {err})")

    def __len__(self) -> int:
        """Returns the number of elements in the list."""
        return int(lib.cardano_metadatum_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[Metadatum]:
        """Iterates over all metadatum values in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Metadatum:
        """Gets a metadatum by index using bracket notation. Supports negative indices."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __eq__(self, other: object) -> bool:
        """Checks equality with another MetadatumList."""
        if not isinstance(other, MetadatumList):
            return False
        return bool(lib.cardano_metadatum_list_equals(self._ptr, other._ptr))

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    def __contains__(self, item: MetadatumLike) -> bool:
        """Checks if a metadatum is in the list. Accepts primitives."""
        meta = _to_metadatum(item)
        for element in self:
            if element == meta:
                return True
        return False

    def append(self, element: MetadatumLike) -> None:
        """
        Appends a metadatum to the list.

        This is an alias for add() to match Python list semantics.

        Args:
            element: The metadatum to append. Can be a Metadatum object or a
                     Python primitive (int, str, bytes, bytearray).
        """
        self.add(element)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this metadatum list to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_metadatum_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def index(self, value: Metadatum, start: int = 0, stop: Optional[int] = None) -> int:
        """
        Returns the index of the first occurrence of value.

        Args:
            value: The value to search for.
            start: Start searching from this index.
            stop: Stop searching at this index.

        Returns:
            The index of the first occurrence.

        Raises:
            ValueError: If the value is not found.
        """
        if stop is None:
            stop = len(self)
        for i in range(start, stop):
            if self[i] == value:
                return i
        raise ValueError(f"{value!r} is not in list")

    def count(self, value: Metadatum) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[Metadatum]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
