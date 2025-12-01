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

from typing import Protocol, Union, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...transaction import Transaction
    from ...common import UtxoList, Utxo
    from ...witness_set import Redeemer


class TxEvaluatorProtocol(Protocol):
    """
    Protocol defining the interface for transaction evaluators.

    Transaction evaluators calculate the execution units required for Plutus
    scripts in a transaction. This is essential for determining accurate
    transaction fees when scripts are involved.

    Implement this protocol to create custom transaction evaluators
    (e.g., using Blockfrost, Koios, or local evaluation).

    Example:
        >>> class MyEvaluator:
        ...     def get_name(self) -> str:
        ...         return "MyEvaluator"
        ...
        ...     def evaluate(
        ...         self,
        ...         transaction: Transaction,
        ...         additional_utxos: List[Utxo],
        ...     ) -> List[Redeemer]:
        ...         # Custom evaluation logic
        ...         # Call external service, run local UPLC, etc.
        ...         return redeemers
    """

    def get_name(self) -> str:
        """
        Get the human-readable name of this evaluator.

        Returns:
            The evaluator name (e.g., "Blockfrost", "Koios", "Local").
        """

    def evaluate(
        self,
        transaction: "Transaction",
        additional_utxos: Union["UtxoList", List["Utxo"], None],
    ) -> List["Redeemer"]:
        """
        Evaluate the execution units required for a transaction.

        This method calculates the execution units needed for each Plutus
        script in the transaction.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: Optional additional UTXOs needed for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.

        Raises:
            Exception: If evaluation fails.
        """


# Alias for backwards compatibility
TxEvaluator = TxEvaluatorProtocol
