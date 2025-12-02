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
from typing import Iterable, Iterator, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError


class MetadatumLabelList(Sequence["int"]):
    """
    Represents a list of metadatum labels (unsigned 64-bit integers).

    Labels are used to identify metadata entries in transactions.
    Common labels include 721 for NFTs (CIP-25).

    Example:
        >>> label_list = MetadatumLabelList()
        >>> label_list.add(721)
        >>> label_list.add(674)
        >>> len(label_list)
        2
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_metadatum_label_list_t**")
            err = lib.cardano_metadatum_label_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create MetadatumLabelList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("MetadatumLabelList: invalid handle")
            self._ptr = ptr

    @classmethod
    def from_list(cls, labels: Iterable[int]) -> MetadatumLabelList:
        """
        Creates a MetadatumLabelList from an iterable of integers.

        Args:
            labels: An iterable of metadata labels (unsigned 64-bit integers).

        Returns:
            A new MetadatumLabelList containing all the labels.

        Raises:
            CardanoError: If creation fails.
        """
        label_list = cls()
        for label in labels:
            label_list.add(label)
        return label_list

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_metadatum_label_list_t**", self._ptr)
            lib.cardano_metadatum_label_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MetadatumLabelList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"MetadatumLabelList(len={len(self)})"

    def add(self, label: int) -> None:
        """
        Adds a label to the list.

        Args:
            label: The metadata label (unsigned 64-bit integer).

        Raises:
            CardanoError: If the operation fails.
        """
        err = lib.cardano_metadatum_label_list_add(self._ptr, label)
        if err != 0:
            raise CardanoError(f"Failed to add to MetadatumLabelList (error code: {err})")

    def get(self, index: int) -> int:
        """
        Retrieves a label by index.

        Args:
            index: The index of the element to retrieve.

        Returns:
            The label at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        label = ffi.new("uint64_t*")
        err = lib.cardano_metadatum_label_list_get(self._ptr, index, label)
        if err != 0:
            raise CardanoError(f"Failed to get from MetadatumLabelList (error code: {err})")
        return int(label[0])

    def __len__(self) -> int:
        """Returns the number of elements in the list."""
        return int(lib.cardano_metadatum_label_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[int]:
        """Iterates over all labels in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> int:
        """Gets a label by index using bracket notation. Supports negative indices."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __contains__(self, item: int) -> bool:
        """Checks if a label is in the list."""
        for label in self:
            if label == item:
                return True
        return False

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    def append(self, label: int) -> None:
        """
        Appends a label to the list.

        This is an alias for add() to match Python list semantics.

        Args:
            label: The metadata label to append.
        """
        self.add(label)
    def index(self, value: int, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: int) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[int]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
