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
from .voter import Voter


class VoterList(Sequence["Voter"]):
    """
    Represents a list of Voters.

    This class provides a collection interface for managing multiple Voters,
    supporting standard list operations like iteration, indexing, and slicing.

    Example:
        >>> from cometa import VoterList, Voter
        >>> voter_list = VoterList()
        >>> voter_list.add(voter)
        >>> print(len(voter_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_voter_list_t**")
            err = lib.cardano_voter_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create VoterList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("VoterList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_voter_list_t**", self._ptr)
            lib.cardano_voter_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> VoterList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"VoterList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of voters in the list."""
        return int(lib.cardano_voter_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[Voter]:
        """Iterates over all voters in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Voter:
        """Gets a voter by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, voters: list[Voter]) -> VoterList:
        """
        Creates a VoterList from a Python list of Voter objects.

        Args:
            voters: A list of Voter objects.

        Returns:
            A new VoterList containing all the voters.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> voter_list = VoterList.from_list([voter1, voter2, voter3])
        """
        voter_list = cls()
        for voter in voters:
            voter_list.add(voter)
        return voter_list

    def add(self, voter: Voter) -> None:
        """
        Adds a voter to the end of the list.

        Args:
            voter: The Voter to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_voter_list_add(self._ptr, voter._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to VoterList (error code: {err})")

    def get(self, index: int) -> Voter:
        """
        Retrieves a voter at the specified index.

        Args:
            index: The index of the voter to retrieve.

        Returns:
            The Voter at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_voter_t**")
        err = lib.cardano_voter_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from VoterList (error code: {err})")
        return Voter(out[0])

    def append(self, voter: Voter) -> None:
        """
        Appends a voter to the end of the list (alias for add).

        Args:
            voter: The Voter to append.

        Raises:
            CardanoError: If appending fails.
        """
        self.add(voter)
    def index(self, value: Voter, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: Voter) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[Voter]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
