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

from typing import Optional, Union, List, TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError

if TYPE_CHECKING:
    from ...transaction import Transaction
    from ...common import UtxoList, Utxo
    from ...witness_set import RedeemerList


class CTxEvaluatorWrapper:
    """
    Wrapper around a C cardano_tx_evaluator_t* to use it from Python.

    This class allows using transaction evaluators created in C (e.g., from a provider)
    from Python code, providing a Python-friendly interface.

    Example:
        >>> # Using a C-based evaluator from Python
        >>> evaluator = CTxEvaluatorWrapper.from_provider(provider)
        >>> redeemers = evaluator.evaluate(transaction, additional_utxos)
    """

    def __init__(self, ptr, owns_ref: bool = True) -> None:
        """
        Create a wrapper around a C tx evaluator pointer.

        Args:
            ptr: A cardano_tx_evaluator_t* pointer.
            owns_ref: If True, manage the pointer's lifecycle.

        Raises:
            CardanoError: If the pointer is NULL.
        """
        if ptr == ffi.NULL:
            raise CardanoError("CTxEvaluatorWrapper: invalid handle")
        self._ptr = ptr
        self._owns_ref = owns_ref
        if owns_ref:
            lib.cardano_tx_evaluator_ref(ptr)

    def __del__(self) -> None:
        owns_ref = getattr(self, "_owns_ref", False)
        ptr = getattr(self, "_ptr", ffi.NULL)
        if owns_ref and ptr not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_tx_evaluator_t**", ptr)
            lib.cardano_tx_evaluator_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CTxEvaluatorWrapper:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CTxEvaluatorWrapper(name={self.get_name()})"

    @classmethod
    def from_provider(cls, provider) -> CTxEvaluatorWrapper:
        """
        Create a transaction evaluator from a provider.

        This creates an evaluator that uses the provider's evaluate_transaction
        method to compute execution units.

        Args:
            provider: A provider object (ProviderHandle or CProviderWrapper).

        Returns:
            A new CTxEvaluatorWrapper instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        """
        out = ffi.new("cardano_tx_evaluator_t**")

        # Get the C pointer from the provider
        provider_ptr = provider.ptr if hasattr(provider, "ptr") else provider._ptr

        err = lib.cardano_tx_evaluator_from_provider(provider_ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create tx evaluator from provider (error code: {err})"
            )

        # Don't increment ref, we take ownership from from_provider()
        instance = cls.__new__(cls)
        instance._ptr = out[0]
        instance._owns_ref = True
        return instance

    @property
    def ptr(self):
        """Return the underlying cardano_tx_evaluator_t* pointer."""
        return self._ptr

    @property
    def name(self) -> str:
        """
        Get the name of the evaluator implementation.

        Returns:
            The evaluator's name string.
        """
        return self.get_name()

    def get_name(self) -> str:
        """
        Get the name of the evaluator implementation.

        Returns:
            The evaluator's name string.
        """
        result = lib.cardano_tx_evaluator_get_name(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")

    def evaluate(
        self,
        transaction: "Transaction",
        additional_utxos: Optional[Union["UtxoList", List["Utxo"]]] = None,
    ) -> "RedeemerList":
        """
        Evaluate the execution units required for a transaction.

        This method calculates the execution units needed for a given transaction
        by using this evaluator. Evaluation considers any additional UTXOs required
        for the transaction and assigns appropriate redeemers based on the evaluation.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: Optional list of additional UTXOs needed for evaluation.

        Returns:
            A RedeemerList with computed execution units for each script.

        Raises:
            CardanoError: If evaluation fails.

        Example:
            >>> redeemers = evaluator.evaluate(tx, additional_utxos)
            >>> for redeemer in redeemers:
            ...     print(f"Tag: {redeemer.tag}, Index: {redeemer.index}")
        """
        from ...common.utxo_list import UtxoList
        from ...witness_set import RedeemerList

        additional_ptr = ffi.NULL
        if additional_utxos is not None:
            if isinstance(additional_utxos, list):
                additional_utxos = UtxoList.from_list(additional_utxos)
            additional_ptr = additional_utxos._ptr

        redeemers_out = ffi.new("cardano_redeemer_list_t**")
        err = lib.cardano_tx_evaluator_evaluate(
            self._ptr, transaction._ptr, additional_ptr, redeemers_out
        )
        if err != 0:
            raise CardanoError(
                f"Transaction evaluation failed (error code: {err}): "
                f"{self.get_last_error()}"
            )

        return RedeemerList(redeemers_out[0])

    def get_last_error(self) -> str:
        """
        Get the last error message recorded for this evaluator.

        Returns:
            The last error message, or empty string if none.
        """
        result = lib.cardano_tx_evaluator_get_last_error(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")
