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
from collections.abc import Mapping

from typing import Iterator, Tuple, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from ..address.reward_address import RewardAddress
    from .reward_address_list import RewardAddressList


class WithdrawalMap(Mapping["RewardAddress", "int"]):
    """
    Represents a map of reward addresses to lovelace amounts.

    This collection type is used for staking reward withdrawals in Cardano
    transactions and treasury withdrawal governance actions.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_withdrawal_map_t**")
            err = lib.cardano_withdrawal_map_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create WithdrawalMap (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("WithdrawalMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_withdrawal_map_t**", self._ptr)
            lib.cardano_withdrawal_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> WithdrawalMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"WithdrawalMap(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> WithdrawalMap:
        """
        Deserializes a WithdrawalMap from CBOR data.

        Args:
            reader: A CborReader positioned at the withdrawal map data.

        Returns:
            A new WithdrawalMap deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_withdrawal_map_t**")
        err = lib.cardano_withdrawal_map_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize WithdrawalMap from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the withdrawal map to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_withdrawal_map_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize WithdrawalMap to CBOR (error code: {err})"
            )

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> WithdrawalMap:
        """
        Creates a WithdrawalMap from a dictionary mapping Bech32 addresses to amounts.

        Args:
            data: A dictionary where keys are Bech32-encoded reward addresses
                  (e.g., "stake1...") and values are amounts in lovelace.

        Returns:
            A new WithdrawalMap populated with the provided entries.

        Raises:
            CardanoError: If creation or insertion fails.

        Example:
            >>> withdrawals = WithdrawalMap.from_dict({
            ...     "stake_test1uq...": 1000000,
            ...     "stake_test1up...": 2000000
            ... })
        """
        withdrawal_map = cls()
        for address, amount in data.items():
            withdrawal_map.insert_ex(address, amount)
        return withdrawal_map

    def insert(self, key: RewardAddress, value: int) -> None:
        """
        Inserts or updates a reward address with its withdrawal amount.

        Args:
            key: The reward address.
            value: The amount in lovelace to withdraw.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_withdrawal_map_insert(self._ptr, key._ptr, value)
        if err != 0:
            raise CardanoError(
                f"Failed to insert into WithdrawalMap (error code: {err})"
            )

    def insert_ex(self, reward_address: str, value: int) -> None:
        """
        Inserts a withdrawal using a Bech32-encoded reward address string.

        Args:
            reward_address: Bech32-encoded reward address (e.g., "stake1...").
            value: The amount in lovelace to withdraw.

        Raises:
            CardanoError: If insertion fails.
        """
        addr_bytes = reward_address.encode("utf-8")
        err = lib.cardano_withdrawal_map_insert_ex(
            self._ptr, addr_bytes, len(addr_bytes), value
        )
        if err != 0:
            raise CardanoError(
                f"Failed to insert into WithdrawalMap (error code: {err})"
            )

    def get(  # pylint: disable=arguments-differ
        self, key: RewardAddress, default: "int | None" = None
    ) -> "int | None":
        """
        Retrieves the withdrawal amount for a given reward address.

        Args:
            key: The reward address to look up.
            default: Value to return if key is not found. Defaults to None.

        Returns:
            The withdrawal amount in lovelace, or default if not found.
        """
        value = ffi.new("uint64_t*")
        err = lib.cardano_withdrawal_map_get(self._ptr, key._ptr, value)
        if err != 0:
            return default
        return int(value[0])

    def get_key_at(self, index: int) -> RewardAddress:
        """
        Retrieves the reward address at a specific index.

        Args:
            index: The index of the reward address to retrieve.

        Returns:
            The RewardAddress at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        from ..address.reward_address import RewardAddress

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        out = ffi.new("cardano_reward_address_t**")
        err = lib.cardano_withdrawal_map_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get key at index {index} (error code: {err})")
        return RewardAddress(out[0])

    def get_value_at(self, index: int) -> int:
        """
        Retrieves the withdrawal amount at a specific index.

        Args:
            index: The index of the amount to retrieve.

        Returns:
            The withdrawal amount in lovelace at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        value = ffi.new("uint64_t*")
        err = lib.cardano_withdrawal_map_get_value_at(self._ptr, index, value)
        if err != 0:
            raise CardanoError(
                f"Failed to get value at index {index} (error code: {err})"
            )
        return int(value[0])

    def get_key_value_at(self, index: int) -> tuple[RewardAddress, int]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple containing the RewardAddress and withdrawal amount at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        from ..address.reward_address import RewardAddress

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        key_out = ffi.new("cardano_reward_address_t**")
        value_out = ffi.new("uint64_t*")
        err = lib.cardano_withdrawal_map_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (RewardAddress(key_out[0]), int(value_out[0]))

    def get_keys(self) -> RewardAddressList:
        """
        Retrieves all keys (reward addresses) from the map.

        Returns:
            A RewardAddressList containing all reward addresses in the map.

        Raises:
            CardanoError: If retrieval fails.
        """
        from ..common.reward_address_list import RewardAddressList

        out = ffi.new("cardano_reward_address_list_t**")
        err = lib.cardano_withdrawal_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from WithdrawalMap (error code: {err})")
        return RewardAddressList(out[0])

    def __len__(self) -> int:
        """Returns the number of entries in the map."""
        return int(lib.cardano_withdrawal_map_get_length(self._ptr))

    def __iter__(self) -> Iterator[RewardAddress]:
        """Iterates over all keys (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i)

    def __getitem__(self, key: RewardAddress) -> int:
        """Gets a value by key using bracket notation."""
        return self.get(key)

    def __setitem__(self, key: RewardAddress, value: int) -> None:
        """Sets a value by key using bracket notation."""
        self.insert(key, value)

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __contains__(self, item: RewardAddress) -> bool:
        """Checks if a reward address is in the map."""
        return self.get(item) is not None

    def keys(self) -> Iterator[RewardAddress]:
        """Returns an iterator over keys (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[int]:
        """Returns an iterator over values (like Python dict)."""
        for i in range(len(self)):
            yield self.get_value_at(i)

    def items(self) -> Iterator[Tuple[RewardAddress, int]]:
        """Returns an iterator over (key, value) pairs (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i), self.get_value_at(i)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_withdrawal_map_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
