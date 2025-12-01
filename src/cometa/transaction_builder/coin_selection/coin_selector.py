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

from typing import Protocol, Union, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ...common import UtxoList, Utxo
    from ...transaction_body import Value


class CoinSelectorProtocol(Protocol):
    """
    Protocol defining the interface for coin selection strategies.

    Coin selection is the process of selecting UTXOs (Unspent Transaction Outputs)
    to meet a target transaction value while optimizing for factors like:
    - Minimizing the number of inputs (to reduce fees)
    - Reducing dust (small UTXOs)
    - Optimizing change output size

    Implement this protocol to create custom coin selection strategies.

    Example:
        >>> class MyCustomSelector:
        ...     def get_name(self) -> str:
        ...         return "MyCustomSelector"
        ...
        ...     def select(
        ...         self,
        ...         pre_selected_utxo: List[Utxo],
        ...         available_utxo: List[Utxo],
        ...         target: Value,
        ...     ) -> Tuple[List[Utxo], List[Utxo]]:
        ...         # Custom selection logic
        ...         selected = []
        ...         remaining = list(available_utxo)
        ...         # ... selection algorithm ...
        ...         return selected, remaining
    """

    def get_name(self) -> str:
        """
        Get the human-readable name of this coin selector.

        Returns:
            The coin selector name (e.g., "LargeFirst", "RandomImprove").
        """

    def select(
        self,
        pre_selected_utxo: Union["UtxoList", List["Utxo"]],
        available_utxo: Union["UtxoList", List["Utxo"]],
        target: "Value",
    ) -> Tuple[List["Utxo"], List["Utxo"]]:
        """
        Select UTXOs to satisfy the target value.

        This method should implement the coin selection algorithm, choosing
        UTXOs from the available set to meet the target value.

        Args:
            pre_selected_utxo: UTXOs that must be included in the selection.
            available_utxo: Available UTXOs to choose from.
            target: The target value to satisfy (ADA and/or multi-assets).

        Returns:
            A tuple of (selected_utxos, remaining_utxos).

        Raises:
            Exception: If selection fails (e.g., insufficient funds).
        """


# Alias for backwards compatibility
CoinSelector = CoinSelectorProtocol
