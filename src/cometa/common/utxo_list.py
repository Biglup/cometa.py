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

from typing import Iterator, List, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from .utxo import Utxo


class UtxoList:
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
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_utxo_list_t**", self._ptr)
            lib.cardano_utxo_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> UtxoList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
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
    def from_list(cls, utxos: List[Utxo]) -> UtxoList:
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

    def __add__(self, other: Union[UtxoList, List[Utxo]]) -> UtxoList:
        """Concatenates two UtxoLists using the + operator."""
        if isinstance(other, list):
            other = UtxoList.from_list(other)
        return self.concat(other)
