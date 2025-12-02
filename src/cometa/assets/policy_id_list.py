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
from ..cryptography.blake2b_hash import Blake2bHash


class PolicyIdList(Sequence["Blake2bHash"]):
    """
    Represents a list of policy IDs (Blake2b-224 hashes).

    Policy IDs are used to identify minting policies in Cardano.

    Example:
        >>> policy_list = PolicyIdList()
        >>> policy_list.add(Blake2bHash.from_hex("00" * 28))
        >>> len(policy_list)
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_blake2b_hash_set_t**")
            err = lib.cardano_blake2b_hash_set_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create PolicyIdList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PolicyIdList: invalid handle")
            self._ptr = ptr

    @classmethod
    def from_list(cls, policy_ids: Iterable[Blake2bHash]) -> PolicyIdList:
        """
        Creates a PolicyIdList from an iterable of Blake2bHash objects.

        Args:
            policy_ids: An iterable of Blake2bHash objects (policy IDs).

        Returns:
            A new PolicyIdList containing all the policy IDs.

        Raises:
            CardanoError: If creation fails.
        """
        policy_list = cls()
        for policy_id in policy_ids:
            policy_list.add(policy_id)
        return policy_list

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_blake2b_hash_set_t**", self._ptr)
            lib.cardano_blake2b_hash_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PolicyIdList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PolicyIdList(len={len(self)})"

    def add(self, element: Blake2bHash) -> None:
        """
        Adds a policy ID to the list.

        Args:
            element: The policy ID (Blake2b-224 hash) to add.

        Raises:
            CardanoError: If the operation fails.
        """
        err = lib.cardano_blake2b_hash_set_add(self._ptr, element._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to PolicyIdList (error code: {err})")

    def get(self, index: int) -> Blake2bHash:
        """
        Retrieves a policy ID by index.

        Args:
            index: The index of the element to retrieve.

        Returns:
            The policy ID (Blake2bHash) at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from PolicyIdList (error code: {err})")
        return Blake2bHash(out[0])

    def __len__(self) -> int:
        """Returns the number of elements in the list."""
        return int(lib.cardano_blake2b_hash_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[Blake2bHash]:
        """Iterates over all policy IDs in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Blake2bHash:
        """Gets a policy ID by index using bracket notation. Supports negative indices."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __contains__(self, item: Blake2bHash) -> bool:
        """Checks if a policy ID is in the list."""
        for policy_id in self:
            if policy_id == item:
                return True
        return False

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    def append(self, element: Blake2bHash) -> None:
        """
        Appends a policy ID to the list.

        This is an alias for add() to match Python list semantics.

        Args:
            element: The policy ID to append.
        """
        self.add(element)

    def index(self, value: Blake2bHash, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: Blake2bHash) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[Blake2bHash]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
