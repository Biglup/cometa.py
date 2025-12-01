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


class TxEvaluator:
    """
    Transaction evaluator for Cardano.

    The TxEvaluator structure serves as the handle for managing the transaction
    evaluation process. It calculates the execution units required for Plutus
    scripts in a transaction.

    Example:
        >>> from cometa.transaction_builder.evaluation import TxEvaluator
        >>> evaluator = TxEvaluator(ptr)  # Created from provider or custom impl
        >>> redeemers = evaluator.evaluate(transaction, additional_utxos)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("TxEvaluator: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_tx_evaluator_t**", self._ptr)
            lib.cardano_tx_evaluator_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TxEvaluator:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TxEvaluator(name={self.name})"

    @property
    def name(self) -> str:
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
            raise CardanoError(f"Transaction evaluation failed (error code: {err})")

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
