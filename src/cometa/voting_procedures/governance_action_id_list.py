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

from typing import Iterator, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..common import GovernanceActionId


class GovernanceActionIdList(Sequence["GovernanceActionId"]):
    """
    Represents a list of Governance Action IDs.

    This class provides a collection interface for managing multiple GovernanceActionIds,
    supporting standard list operations like iteration, indexing, and slicing.

    Example:
        >>> from cometa import GovernanceActionIdList, GovernanceActionId
        >>> action_id_list = GovernanceActionIdList()
        >>> action_id_list.add(action_id)
        >>> print(len(action_id_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_governance_action_id_list_t**")
            err = lib.cardano_governance_action_id_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create GovernanceActionIdList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("GovernanceActionIdList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_governance_action_id_list_t**", self._ptr)
            lib.cardano_governance_action_id_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> GovernanceActionIdList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"GovernanceActionIdList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of governance action IDs in the list."""
        return int(lib.cardano_governance_action_id_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[GovernanceActionId]:
        """Iterates over all governance action IDs in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> GovernanceActionId:
        """Gets a governance action ID by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """
        Returns True if the list is not empty.

        Returns:
            True if the list contains at least one element, False otherwise.
        """
        return len(self) > 0

    @classmethod
    def from_list(cls, action_ids: list[GovernanceActionId]) -> GovernanceActionIdList:
        """
        Creates a GovernanceActionIdList from a Python list of GovernanceActionId objects.

        Args:
            action_ids: A list of GovernanceActionId objects.

        Returns:
            A new GovernanceActionIdList containing all the governance action IDs.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> action_id_list = GovernanceActionIdList.from_list([action_id1, action_id2, action_id3])
        """
        action_id_list = cls()
        for action_id in action_ids:
            action_id_list.add(action_id)
        return action_id_list

    def add(self, action_id: GovernanceActionId) -> None:
        """
        Adds a governance action ID to the end of the list.

        Args:
            action_id: The GovernanceActionId to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_governance_action_id_list_add(self._ptr, action_id._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to GovernanceActionIdList (error code: {err})")

    def get(self, index: int) -> GovernanceActionId:
        """
        Retrieves a governance action ID at the specified index.

        Args:
            index: The index of the governance action ID to retrieve.

        Returns:
            The GovernanceActionId at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_governance_action_id_t**")
        err = lib.cardano_governance_action_id_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from GovernanceActionIdList (error code: {err})")
        return GovernanceActionId(out[0])

    def append(self, action_id: GovernanceActionId) -> None:
        """
        Appends a governance action ID to the end of the list (alias for add).

        Args:
            action_id: The GovernanceActionId to append.

        Raises:
            CardanoError: If appending fails.
        """
        self.add(action_id)

    def index(self, value: GovernanceActionId, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: GovernanceActionId) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[GovernanceActionId]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
