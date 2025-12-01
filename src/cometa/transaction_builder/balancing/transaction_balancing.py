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
    from ...protocol_params import ProtocolParameters
    from ...common import UtxoList, Utxo
    from ...address import Address
    from ..coin_selection import CoinSelector
    from ..evaluation import TxEvaluator
    from .input_to_redeemer_map import InputToRedeemerMap


# pylint: disable=too-many-locals
def balance_transaction(
    unbalanced_tx: "Transaction",
    protocol_params: "ProtocolParameters",
    change_address: "Address",
    available_utxo: Union["UtxoList", List["Utxo"]],
    coin_selector: "CoinSelector",
    foreign_signature_count: int = 0,
    reference_inputs: Optional[Union["UtxoList", List["Utxo"]]] = None,
    pre_selected_utxo: Optional[Union["UtxoList", List["Utxo"]]] = None,
    input_to_redeemer_map: Optional["InputToRedeemerMap"] = None,
    available_collateral_utxo: Optional[Union["UtxoList", List["Utxo"]]] = None,
    collateral_change_address: Optional["Address"] = None,
    evaluator: Optional["TxEvaluator"] = None,
) -> None:
    """
    Balance a Cardano transaction by adding necessary inputs and calculating change.

    This function balances an unbalanced transaction by:
    - Adding additional inputs if the transaction does not meet the required balance.
    - Computing the cost of script execution.
    - Calculating the change output to ensure the transaction has the correct total.
    - Adding collateral inputs if the transaction includes scripts.

    Args:
        unbalanced_tx: The transaction that needs balancing. Modified in-place.
        protocol_params: Protocol parameters for fee calculation and balancing.
        change_address: The address where any remaining balance (change) will be sent.
        available_utxo: Available UTXOs to select from if additional inputs are needed.
        coin_selector: The coin selector used for choosing appropriate UTXOs.
        foreign_signature_count: Number of expected extra signatures not in the transaction.
        reference_inputs: Resolved reference inputs already included in the transaction.
        pre_selected_utxo: UTXOs that must be included in the transaction inputs.
        input_to_redeemer_map: Map of inputs to redeemers for proper index updates.
        available_collateral_utxo: Available UTXOs for collateral if tx has scripts.
        collateral_change_address: Address for collateral change if applicable.
        evaluator: Transaction evaluator for determining script execution costs.

    Raises:
        CardanoError: If balancing fails.

    Example:
        >>> from cometa.transaction_builder.balancing import balance_transaction
        >>> from cometa.transaction_builder.coin_selection import LargeFirstCoinSelector
        >>>
        >>> selector = LargeFirstCoinSelector.new()
        >>> balance_transaction(
        ...     unbalanced_tx=tx,
        ...     protocol_params=params,
        ...     change_address=my_address,
        ...     available_utxo=my_utxos,
        ...     coin_selector=selector,
        ... )
        >>> # tx is now balanced
    """
    from ...common.utxo_list import UtxoList

    # Convert lists to UtxoList if needed
    if isinstance(available_utxo, list):
        available_utxo = UtxoList.from_list(available_utxo)

    ref_inputs_ptr = ffi.NULL
    if reference_inputs is not None:
        if isinstance(reference_inputs, list):
            reference_inputs = UtxoList.from_list(reference_inputs)
        ref_inputs_ptr = reference_inputs._ptr

    pre_selected_ptr = ffi.NULL
    if pre_selected_utxo is not None:
        if isinstance(pre_selected_utxo, list):
            pre_selected_utxo = UtxoList.from_list(pre_selected_utxo)
        pre_selected_ptr = pre_selected_utxo._ptr

    input_redeemer_ptr = ffi.NULL
    if input_to_redeemer_map is not None:
        input_redeemer_ptr = input_to_redeemer_map._ptr

    collateral_utxo_ptr = ffi.NULL
    if available_collateral_utxo is not None:
        if isinstance(available_collateral_utxo, list):
            available_collateral_utxo = UtxoList.from_list(available_collateral_utxo)
        collateral_utxo_ptr = available_collateral_utxo._ptr

    collateral_change_ptr = ffi.NULL
    if collateral_change_address is not None:
        collateral_change_ptr = collateral_change_address._ptr

    evaluator_ptr = ffi.NULL
    if evaluator is not None:
        evaluator_ptr = evaluator._ptr

    err = lib.cardano_balance_transaction(
        unbalanced_tx._ptr,
        foreign_signature_count,
        protocol_params._ptr,
        ref_inputs_ptr,
        pre_selected_ptr,
        input_redeemer_ptr,
        available_utxo._ptr,
        coin_selector._ptr,
        change_address._ptr,
        collateral_utxo_ptr,
        collateral_change_ptr,
        evaluator_ptr,
    )
    if err != 0:
        raise CardanoError(f"Failed to balance transaction (error code: {err})")


def is_transaction_balanced(
    transaction: "Transaction",
    resolved_inputs: Union["UtxoList", List["Utxo"]],
    protocol_params: "ProtocolParameters",
) -> bool:
    """
    Check whether a Cardano transaction is balanced.

    This function verifies if the specified transaction meets the balance requirements
    as per Cardano protocol rules. It considers the total inputs, outputs, fees, and
    execution costs.

    Args:
        transaction: The transaction to check.
        resolved_inputs: UTXOs that have been selected to cover outputs and fees.
        protocol_params: Protocol parameters for fee calculation.

    Returns:
        True if the transaction is balanced, False otherwise.

    Raises:
        CardanoError: If the balance check fails.

    Example:
        >>> from cometa.transaction_builder.balancing import is_transaction_balanced
        >>> if is_transaction_balanced(tx, resolved_utxos, params):
        ...     print("Transaction is balanced!")
        ... else:
        ...     print("Transaction needs balancing")
    """
    from ...common.utxo_list import UtxoList

    if isinstance(resolved_inputs, list):
        resolved_inputs = UtxoList.from_list(resolved_inputs)

    is_balanced_out = ffi.new("bool*")
    err = lib.cardano_is_transaction_balanced(
        transaction._ptr,
        resolved_inputs._ptr,
        protocol_params._ptr,
        is_balanced_out,
    )
    if err != 0:
        raise CardanoError(
            f"Failed to check if transaction is balanced (error code: {err})"
        )

    return bool(is_balanced_out[0])
