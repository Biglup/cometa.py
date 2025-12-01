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

from ..._ffi import ffi, lib
from ...errors import CardanoError
from .coin_selector import CoinSelector


class LargeFirstCoinSelector(CoinSelector):
    """
    Coin selector using the "large first" strategy.

    In this strategy, UTXOs (Unspent Transaction Outputs) with larger amounts
    of assets are selected first to satisfy the target amount. This strategy
    can be more efficient for reducing the number of UTXOs involved in
    transactions, but may result in lower UTXO fragmentation.

    Example:
        >>> from cometa.transaction_builder.coin_selection import LargeFirstCoinSelector
        >>> selector = LargeFirstCoinSelector.new()
        >>> selected, remaining = selector.select(available_utxos, target_value)
        >>> print(f"Selected {len(selected)} UTXOs using largest-first strategy")
    """

    @classmethod
    def new(cls) -> LargeFirstCoinSelector:
        """
        Create a new coin selector using the "large first" strategy.

        Returns:
            A new LargeFirstCoinSelector instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> selector = LargeFirstCoinSelector.new()
        """
        out = ffi.new("cardano_coin_selector_t**")
        err = lib.cardano_large_first_coin_selector_new(out)
        if err != 0:
            raise CardanoError(
                f"Failed to create large first coin selector (error code: {err})"
            )
        return cls(out[0])
