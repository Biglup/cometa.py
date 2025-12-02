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

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError

if TYPE_CHECKING:
    from ...transaction import Transaction
    from ...protocol_params import ProtocolParameters


@dataclass
class ImplicitCoin:
    """
    Represents the implicit coin values in a transaction.

    Implicit coins are ADA values that are not explicitly present as inputs or
    outputs but affect the transaction balance. These include:
    - Withdrawals from reward accounts
    - Deposits for registrations (stake keys, pools, governance actions)
    - Reclaimed deposits from deregistrations

    Example:
        >>> from cometa.transaction_builder.balancing import compute_implicit_coin
        >>> implicit = compute_implicit_coin(tx, protocol_params)
        >>> print(f"Withdrawals: {implicit.withdrawals}")
        >>> print(f"Deposits: {implicit.deposits}")
        >>> print(f"Reclaimed: {implicit.reclaim_deposits}")
    """

    withdrawals: int
    """The total amount of reward withdrawals in lovelace."""
    deposits: int
    """The total amount of deposits required in lovelace."""
    reclaim_deposits: int
    """The total amount of deposits being reclaimed in lovelace."""

    @property
    def net_value(self) -> int:
        """
        Calculate the net implicit coin value.

        Returns:
            The net value: withdrawals + reclaim_deposits - deposits.
            Positive means the transaction gains ADA implicitly.
            Negative means the transaction loses ADA implicitly.
        """
        return self.withdrawals + self.reclaim_deposits - self.deposits


def compute_implicit_coin(
    transaction: "Transaction",
    protocol_params: "ProtocolParameters",
) -> ImplicitCoin:
    """
    Compute the implicit coin balance for a transaction.

    This function calculates the implicit coin values that affect the transaction
    balance but are not represented as explicit inputs or outputs. These include
    reward withdrawals, deposit requirements, and deposit reclaims.

    Args:
        transaction: The transaction to analyze.
        protocol_params: The protocol parameters needed for deposit calculations.

    Returns:
        An ImplicitCoin dataclass containing the computed values.

    Raises:
        CardanoError: If the computation fails.

    Example:
        >>> from cometa.transaction_builder.balancing import compute_implicit_coin
        >>> from cometa.protocol_params import ProtocolParameters
        >>>
        >>> # Assume tx is a transaction with withdrawals
        >>> implicit = compute_implicit_coin(tx, protocol_params)
        >>> print(f"Net implicit value: {implicit.net_value} lovelace")
    """
    implicit_coin = ffi.new("cardano_implicit_coin_t*")

    err = lib.cardano_compute_implicit_coin(
        transaction._ptr,
        protocol_params._ptr,
        implicit_coin,
    )
    if err != 0:
        raise CardanoError(f"Failed to compute implicit coin (error code: {err})")

    return ImplicitCoin(
        withdrawals=int(implicit_coin.withdrawals),
        deposits=int(implicit_coin.deposits),
        reclaim_deposits=int(implicit_coin.reclaim_deposits),
    )
