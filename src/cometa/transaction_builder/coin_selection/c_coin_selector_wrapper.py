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

from typing import Optional, Union, List, Tuple, TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError

if TYPE_CHECKING:
    from ...common import UtxoList, Utxo
    from ...transaction_body import Value


class CCoinSelectorWrapper:
    """
    Wrapper around a C cardano_coin_selector_t* to use it from Python.

    This class allows using coin selectors created in C (e.g., LargeFirstCoinSelector)
    from Python code, providing a Python-friendly interface.

    Example:
        >>> # Using a C-based selector from Python
        >>> selector = LargeFirstCoinSelector.new()
        >>> selected, remaining = selector.select(available_utxos, target_value)
    """

    def __init__(self, ptr, owns_ref: bool = True) -> None:
        """
        Create a wrapper around a C coin selector pointer.

        Args:
            ptr: A cardano_coin_selector_t* pointer.
            owns_ref: If True, manage the pointer's lifecycle.

        Raises:
            CardanoError: If the pointer is NULL.
        """
        if ptr == ffi.NULL:
            raise CardanoError("CCoinSelectorWrapper: invalid handle")
        self._ptr = ptr
        self._owns_ref = owns_ref
        if owns_ref:
            lib.cardano_coin_selector_ref(ptr)

    def __del__(self) -> None:
        owns_ref = getattr(self, "_owns_ref", False)
        ptr = getattr(self, "_ptr", ffi.NULL)
        if owns_ref and ptr not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_coin_selector_t**", ptr)
            lib.cardano_coin_selector_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CCoinSelectorWrapper:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CCoinSelectorWrapper(name={self.get_name()})"

    @property
    def ptr(self):
        """Return the underlying cardano_coin_selector_t* pointer."""
        return self._ptr

    @property
    def name(self) -> str:
        """
        Get the name of the coin selector implementation.

        Returns:
            The coin selector's name string.
        """
        return self.get_name()

    def get_name(self) -> str:
        """
        Get the name of the coin selector implementation.

        Returns:
            The coin selector's name string.
        """
        result = lib.cardano_coin_selector_get_name(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")

    def select(
        self,
        pre_selected_utxo: Optional[Union["UtxoList", List["Utxo"]]],
        available_utxo: Union["UtxoList", List["Utxo"]],
        target: "Value",
    ) -> Tuple["UtxoList", "UtxoList"]:
        """
        Select UTXOs to satisfy the target value using the coin selection strategy.

        This method performs coin selection using the provided strategy, selecting
        UTXOs from the available UTXO set to meet the specified target value.

        Args:
            pre_selected_utxo: Optional set of pre-selected UTXOs to include in selection.
            available_utxo: List of available UTXOs to select from.
            target: The target value to be satisfied (in lovelace or multi-asset values).

        Returns:
            A tuple of (selected_utxos, remaining_utxos).

        Raises:
            CardanoError: If coin selection fails.

        Example:
            >>> selected, remaining = selector.select(None, available_utxos, target_value)
            >>> print(f"Selected {len(selected)} UTXOs")
        """
        from ...common.utxo_list import UtxoList

        if isinstance(available_utxo, list):
            available_utxo = UtxoList.from_list(available_utxo)

        pre_selected_ptr = ffi.NULL
        if pre_selected_utxo is not None:
            if isinstance(pre_selected_utxo, list):
                pre_selected_utxo = UtxoList.from_list(pre_selected_utxo)
            pre_selected_ptr = pre_selected_utxo._ptr

        selection_out = ffi.new("cardano_utxo_list_t**")
        remaining_out = ffi.new("cardano_utxo_list_t**")

        err = lib.cardano_coin_selector_select(
            self._ptr,
            pre_selected_ptr,
            available_utxo._ptr,
            target._ptr,
            selection_out,
            remaining_out,
        )
        if err != 0:
            raise CardanoError(
                f"Coin selection failed (error code: {err}): {self.get_last_error()}"
            )

        return UtxoList(selection_out[0]), UtxoList(remaining_out[0])

    def get_last_error(self) -> str:
        """
        Get the last error message recorded for this coin selector.

        Returns:
            The last error message, or empty string if none.
        """
        result = lib.cardano_coin_selector_get_last_error(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")
