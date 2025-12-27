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
from typing import TYPE_CHECKING, Iterable, Iterator, Union, overload

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from .plutus_data import PlutusData, PlutusDataLike

class PlutusList(Sequence["PlutusData"]):
    """
    Represents a list of Plutus data elements.

    This class provides Pythonic list-like operations for working with
    Plutus data lists on the Cardano blockchain. It supports native Python
    types (int, str, bytes) which are automatically converted to PlutusData.

    Example:
        >>> plist = PlutusList()
        >>> plist.append(42)           # int -> PlutusData
        >>> plist.append("hello")      # str -> PlutusData (UTF-8 bytes)
        >>> plist.append(b"\\x01\\x02") # bytes -> PlutusData
        >>> len(plist)
        3
        >>> plist[0].to_int()
        42

        >>> # Iteration
        >>> for item in plist:
        ...     print(item.kind)

        >>> # List-like operations
        >>> plist += [1, 2, 3]
        >>> 42 in plist  # Note: checks PlutusData equality
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new PlutusList instance.

        Args:
            ptr: Optional internal pointer for initialization from C library.

        Raises:
            CardanoError: If creation fails or pointer is invalid.
        """
        if ptr is None:
            out = ffi.new("cardano_plutus_list_t**")
            err = lib.cardano_plutus_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create PlutusList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the PlutusList by releasing underlying C resources."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_list_t**", self._ptr)
            lib.cardano_plutus_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusList:
        """Enables use of PlutusList as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exits the context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the PlutusList."""
        return f"PlutusList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of elements in the list."""
        return int(lib.cardano_plutus_list_get_length(self._ptr))

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    def __eq__(self, other: object) -> bool:
        """Checks equality with another PlutusList."""
        if not isinstance(other, PlutusList):
            return False
        return bool(lib.cardano_plutus_list_equals(self._ptr, other._ptr))

    @overload
    def __getitem__(self, index: int) -> "PlutusData": ...

    @overload
    def __getitem__(self, index: slice) -> list["PlutusData"]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union["PlutusData", list["PlutusData"]]:
        """
        Gets an element or slice from the list.

        Args:
            index: An integer index or slice.

        Returns:
            A single PlutusData if index is an int, or a list of PlutusData if slice.

        Raises:
            IndexError: If index is out of bounds.
        """
        if isinstance(index, slice):
            indices = range(*index.indices(len(self)))
            return [self._get_at(i) for i in indices]
        if index < 0:
            index = len(self) + index
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        return self._get_at(index)

    def _get_at(self, index: int) -> "PlutusData":
        """Internal method to get element at index."""
        from .plutus_data import PlutusData
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get element at index {index} (error code: {err})")
        return PlutusData(out[0])

    def __iter__(self) -> Iterator["PlutusData"]:
        """Iterates over all elements in the list."""
        for i in range(len(self)):
            yield self._get_at(i)

    def __reversed__(self) -> Iterator["PlutusData"]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self._get_at(i)

    def __contains__(self, item: "PlutusDataLike") -> bool:
        """
        Checks if an item is in the list.

        Args:
            item: A PlutusData or native Python type (int, str, bytes).

        Returns:
            True if the item is found in the list.
        """
        from .plutus_data import PlutusData
        search_data = PlutusData.to_plutus_data(item)
        for element in self:
            if element == search_data:
                return True
        return False

    def __add__(self, other: Union[PlutusList, Iterable]) -> PlutusList:
        """
        Concatenates this list with another list or iterable.

        Args:
            other: Another PlutusList or iterable of PlutusData/native types.

        Returns:
            A new PlutusList containing all elements from both lists.
        """
        result = PlutusList()
        for item in self:
            result.add(item)
        if isinstance(other, PlutusList):
            for item in other:
                result.add(item)
        else:
            for item in other:
                result.append(item)
        return result

    def __iadd__(self, other: Union[PlutusList, Iterable]) -> PlutusList:
        """
        Extends this list with another list or iterable in place.

        Args:
            other: Another PlutusList or iterable of PlutusData/native types.

        Returns:
            This PlutusList with elements added.
        """
        if isinstance(other, PlutusList):
            for item in other:
                self.add(item)
        else:
            for item in other:
                self.append(item)
        return self

    @classmethod
    def from_list(cls, elements: Iterable["PlutusDataLike"]) -> PlutusList:
        """
        Creates a PlutusList from an iterable of values.

        Args:
            elements: An iterable of PlutusData objects or Python primitives
                     (int, str, bytes).

        Returns:
            A new PlutusList containing all the elements.

        Raises:
            CardanoError: If creation fails.
        """
        plist = cls()
        for element in elements:
            plist.append(element)
        return plist

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusList:
        """
        Deserializes a PlutusList from CBOR data.

        Args:
            reader: A CborReader positioned at the list data.

        Returns:
            A new PlutusList deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_list_t**")
        err = lib.cardano_plutus_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PlutusList from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the list to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_plutus_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PlutusList to CBOR (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can alter the data and invalidate existing signatures.
        """
        lib.cardano_plutus_list_clear_cbor_cache(self._ptr)

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
        err = lib.cardano_plutus_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    def add(self, element: "PlutusData") -> None:
        """
        Adds a PlutusData element to the end of the list.

        Args:
            element: The PlutusData to add.

        Raises:
            CardanoError: If the operation fails.
        """
        err = lib.cardano_plutus_list_add(self._ptr, element._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add element to PlutusList (error code: {err})")

    def append(self, value: "PlutusDataLike") -> None:
        """
        Appends a value to the end of the list.

        This method accepts native Python types and converts them to PlutusData:
        - int -> Integer PlutusData
        - str -> Bytes PlutusData (UTF-8 encoded)
        - bytes -> Bytes PlutusData
        - PlutusData -> Used directly

        Args:
            value: The value to append.

        Raises:
            CardanoError: If the operation fails.
            TypeError: If the value type is not supported.
        """
        from .plutus_data import PlutusData
        data = PlutusData.to_plutus_data(value)
        self.add(data)

    def extend(self, values: Iterable["PlutusDataLike"]) -> None:
        """
        Extends the list with multiple values.

        Args:
            values: An iterable of values to append.
        """
        for value in values:
            self.append(value)

    def get(self, index: int) -> "PlutusData":
        """
        Retrieves the element at a specific index.

        Args:
            index: The index of the element to retrieve.

        Returns:
            The PlutusData at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        return self[index]

    def index(self, value: "PlutusDataLike", start: int = 0, stop: int = None) -> int:
        """
        Returns the index of the first occurrence of a value.

        Args:
            value: The value to search for.
            start: Start searching from this index.
            stop: Stop searching at this index.

        Returns:
            The index of the first occurrence.

        Raises:
            ValueError: If the value is not found.
        """
        from .plutus_data import PlutusData
        search_data = PlutusData.to_plutus_data(value)
        if stop is None:
            stop = len(self)
        for i in range(start, stop):
            if self._get_at(i) == search_data:
                return i
        raise ValueError("Value not found in PlutusList")

    def count(self, value: "PlutusDataLike") -> int:
        """
        Returns the number of occurrences of a value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        from .plutus_data import PlutusData
        search_data = PlutusData.to_plutus_data(value)
        return sum(1 for element in self if element == search_data)

    def copy(self) -> PlutusList:
        """
        Creates a shallow copy of this list.

        Returns:
            A new PlutusList with the same elements.
        """
        result = PlutusList()
        for item in self:
            result.add(item)
        return result
