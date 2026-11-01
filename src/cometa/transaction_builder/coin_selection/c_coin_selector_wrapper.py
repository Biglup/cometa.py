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
    from ...common import Utxo
    from ...common.utxo_list import UtxoList
    from ...address import Address
    from ...protocol_params import ProtocolParameters
    from .coin_selector import CoinSelectionRequest, CoinSelectionResult
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
        self, pre_selected_utxo: Optional[Union["UtxoList", List["Utxo"]]],
        available_utxo: Union["UtxoList", List["Utxo"]], target: "Value", *,
        change_address: "Address", protocol_params: "ProtocolParameters",
    ) -> Tuple["UtxoList", "UtxoList"]:
        """Select UTxOs using the network's change address and protocol parameters.

        Use ``select_with_context`` when explicit change outputs are also needed.
        """
        from .coin_selector import CoinSelectionRequest
        result = self.select_with_context(CoinSelectionRequest(
            available_utxo, target, change_address, protocol_params, pre_selected_utxo))
        return result.selection, result.remaining

    def select_with_context(self, request: "CoinSelectionRequest") -> "CoinSelectionResult":
        """Select UTxOs and construct change using a CoinSelectionRequest."""
        from ...common.utxo_list import UtxoList
        from ...transaction_body import TransactionOutputList
        from .coin_selector import CoinSelectionResult

        available = request.available_utxo
        if not isinstance(available, UtxoList):
            available = UtxoList.from_list(list(available))
        pre_selected = request.pre_selected_utxo
        if pre_selected is not None and not isinstance(pre_selected, UtxoList):
            pre_selected = UtxoList.from_list(list(pre_selected))
        outputs = None
        if request.outputs_to_cover is not None:
            outputs = TransactionOutputList.from_list(request.outputs_to_cover)
        native_request = ffi.new("cardano_coin_selection_request_t *")
        native_request.pre_selected_utxo = pre_selected._ptr if pre_selected is not None else ffi.NULL
        native_request.available_utxo = available._ptr
        native_request.target = request.target._ptr
        native_request.change_address = request.change_address._ptr
        native_request.protocol_params = request.protocol_params._ptr
        native_request.outputs_to_cover = outputs._ptr if outputs is not None else ffi.NULL
        selection = ffi.new("cardano_utxo_list_t **")
        remaining = ffi.new("cardano_utxo_list_t **")
        change = ffi.new("cardano_transaction_output_list_t **")
        err = lib.cardano_coin_selector_select(self._ptr, native_request, selection, remaining, change)
        if err:
            lib.cardano_utxo_list_unref(selection)
            lib.cardano_utxo_list_unref(remaining)
            lib.cardano_transaction_output_list_unref(change)
            raise CardanoError(f"Coin selection failed (error code: {err}): {self.get_last_error()}")
        changes = list(TransactionOutputList(change[0])) if change[0] != ffi.NULL else None
        return CoinSelectionResult(UtxoList(selection[0]), UtxoList(remaining[0]), changes)

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
