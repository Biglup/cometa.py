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

from typing import List, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..common.utxo_list import UtxoList
    from ..common.utxo import Utxo
    from ..witness_set import Redeemer
    from .provider import ProviderProtocol


class ProviderTxEvaluator:
    """
    Transaction evaluator that uses a provider's evaluation API.

    This evaluator wraps any Provider that implements ProviderProtocol and uses
    its evaluate_transaction method to compute execution units for Plutus scripts.
    It implements the TxEvaluatorProtocol interface.
    """

    def __init__(self, provider: "ProviderProtocol") -> None:
        """
        Creates a new ProviderTxEvaluator.

        Args:
            provider: Any provider implementing ProviderProtocol to use for evaluation.
        """
        self._provider = provider

    def get_name(self) -> str:
        """
        Get the human-readable name of this evaluator.

        Returns:
            The evaluator name (derived from the provider name).
        """
        return self._provider.get_name()

    @property
    def provider(self) -> "ProviderProtocol":
        """The Provider used by this evaluator."""
        return self._provider

    def evaluate(
        self,
        transaction: "Transaction",
        additional_utxos: Union["UtxoList", List["Utxo"], None],
    ) -> List["Redeemer"]:
        """
        Evaluate the execution units required for a transaction.

        This method uses the provider's evaluation API to calculate the
        execution units needed for each Plutus script in the transaction.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: Optional additional UTXOs needed for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.

        Raises:
            CardanoError: If evaluation fails.
        """
        tx_cbor_hex = transaction.serialize_to_cbor()
        return self._provider.evaluate_transaction(tx_cbor_hex, additional_utxos)
