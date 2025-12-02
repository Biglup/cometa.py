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

from typing import TYPE_CHECKING, Iterator, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from ..address import RewardAddress


class RewardAddressList(Sequence["RewardAddress"]):
    """
    Represents a list of reward addresses.

    Reward addresses are used to distribute staking rewards in the Cardano
    proof-of-stake protocol.

    Example:
        >>> from cometa import RewardAddressList, RewardAddress
        >>> addr_list = RewardAddressList()
        >>> addr_list.add(RewardAddress.from_bech32("stake_test1..."))
        >>> len(addr_list)
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_reward_address_list_t**")
            err = lib.cardano_reward_address_list_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create RewardAddressList (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("RewardAddressList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_reward_address_list_t**", self._ptr)
            lib.cardano_reward_address_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> RewardAddressList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"RewardAddressList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of reward addresses in the list."""
        return int(lib.cardano_reward_address_list_get_length(self._ptr))

    def __iter__(self) -> Iterator["RewardAddress"]:
        """Iterates over all reward addresses in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> "RewardAddress":
        """Gets a reward address by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, addresses: list["RewardAddress"]) -> RewardAddressList:
        """
        Creates a RewardAddressList from a Python list of RewardAddress objects.

        Args:
            addresses: A list of RewardAddress objects.

        Returns:
            A new RewardAddressList containing all the addresses.

        Raises:
            CardanoError: If creation fails.
        """
        addr_list = cls()
        for addr in addresses:
            addr_list.add(addr)
        return addr_list

    def add(self, address: "RewardAddress") -> None:
        """
        Adds a reward address to the end of the list.

        Args:
            address: The RewardAddress to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_reward_address_list_add(self._ptr, address._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to RewardAddressList (error code: {err})")

    def get(self, index: int) -> "RewardAddress":
        """
        Retrieves a reward address at the specified index.

        Args:
            index: The index of the address to retrieve.

        Returns:
            The RewardAddress at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        from ..address import RewardAddress

        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for list of length {len(self)}")
        out = ffi.new("cardano_reward_address_t**")
        err = lib.cardano_reward_address_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from RewardAddressList (error code: {err})")
        return RewardAddress(out[0])

    def append(self, address: "RewardAddress") -> None:
        """
        Appends a reward address to the list.

        This is an alias for add() to match Python list semantics.

        Args:
            address: The RewardAddress to append.
        """
        self.add(address)
    def index(self, value: RewardAddress, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: RewardAddress) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[RewardAddress]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
