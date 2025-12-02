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

from typing import Optional, Iterator, Tuple, TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError

if TYPE_CHECKING:
    from ...transaction_body import TransactionInput
    from ...witness_set import Redeemer


class InputToRedeemerMap(Mapping["TransactionInput", "Redeemer"]):
    """
    A map of transaction inputs to redeemers.

    This map associates specific references of inputs to redeemers in the witness set.
    Balancing the transaction can add additional inputs and this can make inputs change
    positions in the input set. Redeemers must be updated to point to the correct input.

    If you provide redeemers for any pre-selected input, you must specify this
    association in this map.

    Example:
        >>> from cometa.transaction_builder.balancing import InputToRedeemerMap
        >>> from cometa.transaction_body import TransactionInput
        >>> from cometa.witness_set import Redeemer
        >>>
        >>> input_map = InputToRedeemerMap.new()
        >>> input_map.insert(tx_input, redeemer)
        >>> print(f"Map contains {len(input_map)} entries")
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_input_to_redeemer_map_t**")
            err = lib.cardano_input_to_redeemer_map_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create InputToRedeemerMap (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("InputToRedeemerMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_input_to_redeemer_map_t**", self._ptr)
            lib.cardano_input_to_redeemer_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> InputToRedeemerMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"InputToRedeemerMap(length={len(self)})"

    def __len__(self) -> int:
        return int(lib.cardano_input_to_redeemer_map_get_length(self._ptr))

    def __iter__(self) -> Iterator["TransactionInput"]:
        """Iterate over keys (TransactionInputs)."""
        for i in range(len(self)):
            yield self.get_key_at(i)

    @classmethod
    def new(cls) -> InputToRedeemerMap:
        """
        Create a new empty InputToRedeemerMap.

        Returns:
            A new InputToRedeemerMap instance.

        Raises:
            CardanoError: If creation fails.
        """
        return cls()

    def insert(self, key: "TransactionInput", value: "Redeemer") -> None:
        """
        Insert a key-value pair into the map.

        Args:
            key: The transaction input to use as key.
            value: The redeemer to associate with the input.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_input_to_redeemer_map_insert(
            self._ptr, key._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to insert into InputToRedeemerMap (error code: {err})"
            )

    def __getitem__(self, key: "TransactionInput") -> "Redeemer":
        """
        Get the redeemer associated with a transaction input.

        Args:
            key: The transaction input to look up.

        Returns:
            The associated redeemer.

        Raises:
            KeyError: If key is not found.
            CardanoError: If lookup fails.
        """
        from ...witness_set import Redeemer

        redeemer_out = ffi.new("cardano_redeemer_t**")
        err = lib.cardano_input_to_redeemer_map_get(self._ptr, key._ptr, redeemer_out)
        if err != 0:
            raise KeyError(key)

        if redeemer_out[0] == ffi.NULL:
            raise KeyError(key)
        return Redeemer(redeemer_out[0])

    def get(self, key: "TransactionInput", default: Optional["Redeemer"] = None) -> Optional["Redeemer"]:
        """
        Get the redeemer associated with a transaction input.

        Args:
            key: The transaction input to look up.
            default: Value to return if key is not found.

        Returns:
            The associated redeemer, or default if not found.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def get_key_at(self, index: int) -> "TransactionInput":
        """
        Get the transaction input at the specified index.

        Args:
            index: The index of the key to retrieve.

        Returns:
            The TransactionInput at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        from ...transaction_body import TransactionInput

        input_out = ffi.new("cardano_transaction_input_t**")
        err = lib.cardano_input_to_redeemer_map_get_key_at(
            self._ptr, index, input_out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get key at index {index} (error code: {err})"
            )

        return TransactionInput(input_out[0])

    def get_value_at(self, index: int) -> "Redeemer":
        """
        Get the redeemer at the specified index.

        Args:
            index: The index of the value to retrieve.

        Returns:
            The Redeemer at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        from ...witness_set import Redeemer

        redeemer_out = ffi.new("cardano_redeemer_t**")
        err = lib.cardano_input_to_redeemer_map_get_value_at(
            self._ptr, index, redeemer_out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get value at index {index} (error code: {err})"
            )

        return Redeemer(redeemer_out[0])

    def get_key_value_at(
        self, index: int
    ) -> Tuple["TransactionInput", "Redeemer"]:
        """
        Get both the key and value at the specified index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple of (TransactionInput, Redeemer) at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        from ...transaction_body import TransactionInput
        from ...witness_set import Redeemer

        input_out = ffi.new("cardano_transaction_input_t**")
        redeemer_out = ffi.new("cardano_redeemer_t**")

        err = lib.cardano_input_to_redeemer_map_get_key_value_at(
            self._ptr, index, input_out, redeemer_out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get key-value at index {index} (error code: {err})"
            )

        return TransactionInput(input_out[0]), Redeemer(redeemer_out[0])

    def update_redeemer_index(
        self, tx_input: "TransactionInput", new_index: int
    ) -> None:
        """
        Update the index of a redeemer that matches the given input.

        If a matching redeemer is found, its index is updated. Otherwise,
        nothing happens.

        Args:
            tx_input: The input key to search for.
            new_index: The new index to assign to the redeemer.

        Raises:
            CardanoError: If update fails.
        """
        err = lib.cardano_input_to_redeemer_map_update_redeemer_index(
            self._ptr, tx_input._ptr, new_index
        )
        if err != 0:
            raise CardanoError(
                f"Failed to update redeemer index (error code: {err})"
            )

    def get_last_error(self) -> str:
        """
        Get the last error message recorded for this map.

        Returns:
            The last error message, or empty string if none.
        """
        result = lib.cardano_input_to_redeemer_map_get_last_error(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")
