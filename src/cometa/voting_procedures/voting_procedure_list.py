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
from .voting_procedure import VotingProcedure


class VotingProcedureList(Sequence["VotingProcedure"]):
    """
    Represents a list of Voting Procedures.

    This class provides a collection interface for managing multiple VotingProcedures,
    supporting standard list operations like iteration, indexing, and slicing.

    Example:
        >>> from cometa import VotingProcedureList, VotingProcedure
        >>> procedure_list = VotingProcedureList()
        >>> procedure_list.add(procedure)
        >>> print(len(procedure_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_voting_procedure_list_t**")
            err = lib.cardano_voting_procedure_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create VotingProcedureList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("VotingProcedureList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_voting_procedure_list_t**", self._ptr)
            lib.cardano_voting_procedure_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> VotingProcedureList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"VotingProcedureList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of voting procedures in the list."""
        return int(lib.cardano_voting_procedure_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[VotingProcedure]:
        """Iterates over all voting procedures in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> VotingProcedure:
        """Gets a voting procedure by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, procedures: list[VotingProcedure]) -> VotingProcedureList:
        """
        Creates a VotingProcedureList from a Python list of VotingProcedure objects.

        Args:
            procedures: A list of VotingProcedure objects.

        Returns:
            A new VotingProcedureList containing all the voting procedures.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> procedure_list = VotingProcedureList.from_list([procedure1, procedure2, procedure3])
        """
        procedure_list = cls()
        for procedure in procedures:
            procedure_list.add(procedure)
        return procedure_list

    def add(self, procedure: VotingProcedure) -> None:
        """
        Adds a voting procedure to the end of the list.

        Args:
            procedure: The VotingProcedure to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_voting_procedure_list_add(self._ptr, procedure._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to VotingProcedureList (error code: {err})")

    def get(self, index: int) -> VotingProcedure:
        """
        Retrieves a voting procedure at the specified index.

        Args:
            index: The index of the voting procedure to retrieve.

        Returns:
            The VotingProcedure at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_voting_procedure_t**")
        err = lib.cardano_voting_procedure_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from VotingProcedureList (error code: {err})")
        return VotingProcedure(out[0])

    def append(self, procedure: VotingProcedure) -> None:
        """
        Appends a voting procedure to the end of the list (alias for add).

        Args:
            procedure: The VotingProcedure to append.

        Raises:
            CardanoError: If appending fails.
        """
        self.add(procedure)
    def index(self, value: VotingProcedure, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: VotingProcedure) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[VotingProcedure]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
