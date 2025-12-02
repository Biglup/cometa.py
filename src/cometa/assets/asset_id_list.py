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
from .asset_id import AssetId


class AssetIdList(Sequence["AssetId"]):
    """
    Represents a list of asset identifiers.

    Example:
        >>> id_list = AssetIdList()
        >>> id_list.add(AssetId.new_lovelace())
        >>> len(id_list)
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_asset_id_list_t**")
            err = lib.cardano_asset_id_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create AssetIdList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("AssetIdList: invalid handle")
            self._ptr = ptr

    @classmethod
    def from_list(cls, ids: Iterable[AssetId]) -> AssetIdList:
        """
        Creates an AssetIdList from an iterable of AssetId objects.

        Args:
            ids: An iterable of AssetId objects.

        Returns:
            A new AssetIdList containing all the IDs.

        Raises:
            CardanoError: If creation fails.
        """
        id_list = cls()
        for asset_id in ids:
            id_list.add(asset_id)
        return id_list

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_asset_id_list_t**", self._ptr)
            lib.cardano_asset_id_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AssetIdList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"AssetIdList(len={len(self)})"

    def add(self, element: AssetId) -> None:
        """
        Adds an asset ID to the list.

        Args:
            element: The asset ID to add.

        Raises:
            CardanoError: If the operation fails.
        """
        err = lib.cardano_asset_id_list_add(self._ptr, element._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to AssetIdList (error code: {err})")

    def get(self, index: int) -> AssetId:
        """
        Retrieves an asset ID by index.

        Args:
            index: The index of the element to retrieve.

        Returns:
            The AssetId at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_asset_id_t**")
        err = lib.cardano_asset_id_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from AssetIdList (error code: {err})")
        return AssetId(out[0])

    def __len__(self) -> int:
        """Returns the number of elements in the list."""
        return int(lib.cardano_asset_id_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[AssetId]:
        """Iterates over all asset IDs in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> AssetId:
        """Gets an asset ID by index using bracket notation. Supports negative indices."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    def __contains__(self, item: AssetId) -> bool:
        """Checks if an asset ID is in the list."""
        for element in self:
            if element == item:
                return True
        return False

    def append(self, element: AssetId) -> None:
        """
        Appends an asset ID to the list.

        This is an alias for add() to match Python list semantics.

        Args:
            element: The asset ID to append.
        """
        self.add(element)

    def index(self, value: AssetId, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: AssetId) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[AssetId]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
