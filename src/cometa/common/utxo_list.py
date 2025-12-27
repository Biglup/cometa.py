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

from typing import Iterator, Optional, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from .utxo import Utxo


class UtxoList(Sequence["Utxo"]):
    """
    Represents a list of UTxOs (Unspent Transaction Outputs).

    This class provides a collection interface for managing multiple UTxOs,
    supporting standard list operations like iteration, indexing, and slicing.

    Example:
        >>> from cometa import UtxoList, Utxo
        >>> utxo_list = UtxoList()
        >>> utxo_list.add(utxo)
        >>> print(len(utxo_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a UtxoList.

        Args:
            ptr: Optional FFI pointer to an existing cardano_utxo_list_t.
                 If None, creates a new empty list.

        Raises:
            CardanoError: If list creation fails or ptr is NULL.
        """
        if ptr is None:
            out = ffi.new("cardano_utxo_list_t**")
            err = lib.cardano_utxo_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create UtxoList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("UtxoList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """
        Cleans up the UtxoList by unreferencing the underlying C object.
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_utxo_list_t**", self._ptr)
            lib.cardano_utxo_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> UtxoList:
        """
        Enters the context manager, returning self.

        Returns:
            The UtxoList instance.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exits the context manager.

        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
        """

    def __repr__(self) -> str:
        """
        Returns a string representation of the UtxoList.

        Returns:
            A string showing the class name and length.
        """
        return f"UtxoList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of UTxOs in the list."""
        return int(lib.cardano_utxo_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[Utxo]:
        """Iterates over all UTxOs in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Utxo:
        """Gets a UTxO by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, utxos: list[Utxo]) -> UtxoList:
        """
        Creates a UtxoList from a Python list of Utxo objects.

        Args:
            utxos: A list of Utxo objects.

        Returns:
            A new UtxoList containing all the UTxOs.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> utxo_list = UtxoList.from_list([utxo1, utxo2, utxo3])
        """
        utxo_list = cls()
        for utxo in utxos:
            utxo_list.add(utxo)
        return utxo_list

    def add(self, utxo: Utxo) -> None:
        """
        Adds a UTxO to the end of the list.

        Args:
            utxo: The Utxo to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_utxo_list_add(self._ptr, utxo._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to UtxoList (error code: {err})")

    def get(self, index: int) -> Utxo:
        """
        Retrieves a UTxO at the specified index.

        Args:
            index: The index of the UTxO to retrieve.

        Returns:
            The Utxo at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_utxo_t**")
        err = lib.cardano_utxo_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from UtxoList (error code: {err})")
        return Utxo(out[0])

    def remove(self, utxo: Utxo) -> None:
        """
        Removes a specific UTxO from the list.

        Args:
            utxo: The Utxo to remove.

        Raises:
            CardanoError: If removal fails or UTxO not found.
        """
        err = lib.cardano_utxo_list_remove(self._ptr, utxo._ptr)
        if err != 0:
            raise CardanoError(f"Failed to remove from UtxoList (error code: {err})")

    def clear(self) -> None:
        """
        Removes all UTxOs from the list, leaving it empty.
        """
        lib.cardano_utxo_list_clear(self._ptr)

    def clone(self) -> UtxoList:
        """
        Creates a shallow clone of this UTxO list.

        The cloned list contains references to the same UTxO elements.
        The UTxO elements themselves are not duplicated.

        Returns:
            A new UtxoList containing the same elements.
        """
        ptr = lib.cardano_utxo_list_clone(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to clone UtxoList")
        return UtxoList(ptr)

    def concat(self, other: UtxoList) -> UtxoList:
        """
        Concatenates this list with another, returning a new list.

        Args:
            other: The UtxoList to concatenate with.

        Returns:
            A new UtxoList containing elements from both lists.
        """
        ptr = lib.cardano_utxo_list_concat(self._ptr, other._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to concatenate UtxoList")
        return UtxoList(ptr)

    def slice(self, start: int, end: int) -> UtxoList:
        """
        Extracts a portion of the list between the given indices.

        Args:
            start: Start index of the slice (inclusive).
            end: End index of the slice (exclusive).

        Returns:
            A new UtxoList containing the slice.
        """
        ptr = lib.cardano_utxo_list_slice(self._ptr, start, end)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to slice UtxoList")
        return UtxoList(ptr)

    def erase(self, start: int, delete_count: int = 1) -> UtxoList:
        """
        Removes elements from the list starting at a given index.

        This function removes delete_count elements from the list starting at the
        specified index and returns a new list containing the removed elements.
        The original list is modified in place.

        Args:
            start: The index at which to start removing elements. Supports negative
                   indices (e.g., -1 for the last element).
            delete_count: The number of elements to remove from the list starting
                         at start. If delete_count exceeds the number of elements
                         from start to the end, it will be adjusted to remove till
                         the end. Defaults to 1.

        Returns:
            A new UtxoList containing the removed elements.

        Raises:
            CardanoError: If the erase operation fails.

        Example:
            >>> utxo_list = UtxoList.from_list([utxo1, utxo2, utxo3])
            >>> removed = utxo_list.erase(1, 1)  # Remove second element
            >>> print(len(utxo_list))  # Now has 2 elements
            2
            >>> print(len(removed))  # Removed list has 1 element
            1
        """
        ptr = lib.cardano_utxo_list_erase(self._ptr, start, delete_count)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to erase from UtxoList")
        return UtxoList(ptr)

    def __add__(self, other: Union[UtxoList, list[Utxo]]) -> UtxoList:
        """
        Concatenates two UtxoLists using the + operator.

        Args:
            other: A UtxoList or Python list of Utxo objects to concatenate.

        Returns:
            A new UtxoList containing elements from both lists.
        """
        if isinstance(other, list):
            other = UtxoList.from_list(other)
        return self.concat(other)

    def index(self, value: Utxo, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: Utxo) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[Utxo]:
        """
        Returns an iterator that yields elements in reverse order.

        Returns:
            An iterator over the UTxOs in reverse order.
        """
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
