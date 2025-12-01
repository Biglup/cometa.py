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

from typing import Union, List, Optional, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..transaction_body import TransactionOutput
    from ..protocol_params import ProtocolParameters, ExUnitPrices
    from ..common import UtxoList, Utxo, UnitInterval, ExUnits
    from ..witness_set import RedeemerList
    from ..scripts import Script


def compute_transaction_fee(
    transaction: "Transaction",
    resolved_ref_inputs: Optional[Union["UtxoList", List["Utxo"]]] = None,
    protocol_params: Optional["ProtocolParameters"] = None,
) -> int:
    """
    Compute the minimum transaction fee.

    This function computes the minimum required transaction fee for the provided
    transaction, based on the resolved inputs and protocol parameters. The calculated
    fee considers factors such as the transaction size, execution units consumed by
    Plutus scripts, and size of included reference scripts.

    Args:
        transaction: The transaction to compute the fee for.
        resolved_ref_inputs: Resolved UTXOs that will be referenced by the transaction.
        protocol_params: Protocol parameters for fee calculation.

    Returns:
        The computed transaction fee in lovelace.

    Raises:
        CardanoError: If fee computation fails.

    Example:
        >>> from cometa import Transaction
        >>> from cometa.transaction_builder import compute_transaction_fee
        >>> tx = Transaction.from_cbor(...)
        >>> fee = compute_transaction_fee(tx, resolved_ref_inputs, params)
    """
    from ..common.utxo_list import UtxoList

    ref_inputs_ptr = ffi.NULL
    if resolved_ref_inputs is not None:
        if isinstance(resolved_ref_inputs, list):
            resolved_ref_inputs = UtxoList.from_list(resolved_ref_inputs)
        ref_inputs_ptr = resolved_ref_inputs._ptr

    params_ptr = ffi.NULL
    if protocol_params is not None:
        params_ptr = protocol_params._ptr

    fee_out = ffi.new("uint64_t*")
    err = lib.cardano_compute_transaction_fee(
        transaction._ptr, ref_inputs_ptr, params_ptr, fee_out
    )
    if err != 0:
        raise CardanoError(f"Failed to compute transaction fee (error code: {err})")

    return int(fee_out[0])


def compute_min_ada_required(
    output: "TransactionOutput",
    coins_per_utxo_byte: int,
) -> int:
    """
    Compute the minimum ADA required for a transaction output.

    This function calculates the minimum amount of ADA (in lovelace) that must be
    present in a UTXO, based on its size and the coins_per_utxo_byte parameter
    from the protocol.

    Args:
        output: The transaction output to calculate minimum ADA for.
        coins_per_utxo_byte: Protocol parameter specifying cost in lovelace per byte.

    Returns:
        The minimum ADA required in lovelace.

    Raises:
        CardanoError: If computation fails.

    Example:
        >>> from cometa.transaction_body import TransactionOutput
        >>> from cometa.transaction_builder import compute_min_ada_required
        >>> output = TransactionOutput.new(address, 0)
        >>> min_ada = compute_min_ada_required(output, 4310)
    """
    lovelace_out = ffi.new("uint64_t*")
    err = lib.cardano_compute_min_ada_required(
        output._ptr, coins_per_utxo_byte, lovelace_out
    )
    if err != 0:
        raise CardanoError(f"Failed to compute min ADA required (error code: {err})")

    return int(lovelace_out[0])


def compute_min_script_fee(
    transaction: "Transaction",
    prices: "ExUnitPrices",
    resolved_reference_inputs: Optional[Union["UtxoList", List["Utxo"]]] = None,
    coins_per_ref_script_byte: Optional["UnitInterval"] = None,
) -> int:
    """
    Compute the minimum fee required for a transaction with Plutus scripts.

    This function calculates the minimum fee required for a transaction that
    contains Plutus scripts. The fee is based on execution units, prices,
    and reference script sizes.

    Args:
        transaction: The transaction to calculate script fee for.
        prices: Prices for execution units (memory and steps).
        resolved_reference_inputs: Resolved UTXOs used by transaction reference inputs.
        coins_per_ref_script_byte: Cost per byte of reference scripts.

    Returns:
        The minimum script fee in lovelace.

    Raises:
        CardanoError: If computation fails.
    """
    from ..common.utxo_list import UtxoList

    ref_inputs_ptr = ffi.NULL
    if resolved_reference_inputs is not None:
        if isinstance(resolved_reference_inputs, list):
            resolved_reference_inputs = UtxoList.from_list(resolved_reference_inputs)
        ref_inputs_ptr = resolved_reference_inputs._ptr

    coins_per_byte_ptr = ffi.NULL
    if coins_per_ref_script_byte is not None:
        coins_per_byte_ptr = coins_per_ref_script_byte._ptr

    min_fee_out = ffi.new("uint64_t*")
    err = lib.cardano_compute_min_script_fee(
        transaction._ptr, prices._ptr, ref_inputs_ptr, coins_per_byte_ptr, min_fee_out
    )
    if err != 0:
        raise CardanoError(f"Failed to compute min script fee (error code: {err})")

    return int(min_fee_out[0])


def compute_min_fee_without_scripts(
    transaction: "Transaction",
    min_fee_constant: int,
    min_fee_coefficient: int,
) -> int:
    """
    Compute the minimum fee for a transaction without considering script costs.

    The fee is computed as:
        min_fee = min_fee_constant + (min_fee_coefficient * tx_size)

    where tx_size is the size of the transaction in bytes.

    Args:
        transaction: The transaction to calculate fee for.
        min_fee_constant: The constant fee factor (A) from protocol parameters.
        min_fee_coefficient: The fee-per-byte coefficient (B) from protocol parameters.

    Returns:
        The minimum fee in lovelace.

    Raises:
        CardanoError: If computation fails.

    Example:
        >>> fee = compute_min_fee_without_scripts(tx, 155381, 44)
    """
    min_fee_out = ffi.new("uint64_t*")
    err = lib.cardano_compute_min_fee_without_scripts(
        transaction._ptr, min_fee_constant, min_fee_coefficient, min_fee_out
    )
    if err != 0:
        raise CardanoError(
            f"Failed to compute min fee without scripts (error code: {err})"
        )

    return int(min_fee_out[0])


def compute_script_ref_fee(
    resolved_reference_inputs: Union["UtxoList", List["Utxo"]],
    coins_per_ref_script_byte: "UnitInterval",
) -> int:
    """
    Compute the script reference fee for transaction inputs.

    This function calculates the fee component contributed by reference scripts
    on the inputs of a transaction.

    Args:
        resolved_reference_inputs: Resolved reference inputs containing reference scripts.
        coins_per_ref_script_byte: Fee cost per byte of reference script data.

    Returns:
        The reference script fee in lovelace.

    Raises:
        CardanoError: If computation fails.
    """
    from ..common.utxo_list import UtxoList

    if isinstance(resolved_reference_inputs, list):
        resolved_reference_inputs = UtxoList.from_list(resolved_reference_inputs)

    script_ref_fee_out = ffi.new("uint64_t*")
    err = lib.cardano_compute_script_ref_fee(
        resolved_reference_inputs._ptr,
        coins_per_ref_script_byte._ptr,
        script_ref_fee_out,
    )
    if err != 0:
        raise CardanoError(f"Failed to compute script ref fee (error code: {err})")

    return int(script_ref_fee_out[0])


def get_total_ex_units_in_redeemers(redeemers: "RedeemerList") -> "ExUnits":
    """
    Compute the total execution units from a list of redeemers.

    This function aggregates the total execution units consumed by all redeemers.
    Execution units include both memory and CPU units.

    Args:
        redeemers: The list of redeemers to aggregate.

    Returns:
        The total execution units (memory and CPU).

    Raises:
        CardanoError: If computation fails.

    Example:
        >>> total_units = get_total_ex_units_in_redeemers(redeemer_list)
        >>> print(f"Memory: {total_units.mem}, Steps: {total_units.steps}")
    """
    from ..common.ex_units import ExUnits

    total_out = ffi.new("cardano_ex_units_t**")
    err = lib.cardano_get_total_ex_units_in_redeemers(redeemers._ptr, total_out)
    if err != 0:
        raise CardanoError(
            f"Failed to get total ex units in redeemers (error code: {err})"
        )

    return ExUnits(total_out[0])


def get_serialized_coin_size(lovelace: int) -> int:
    """
    Compute the serialized size of a given amount of lovelace.

    Args:
        lovelace: The amount of lovelace.

    Returns:
        The size in bytes required to serialize the lovelace amount.

    Raises:
        CardanoError: If computation fails.
    """
    size_out = ffi.new("size_t*")
    err = lib.cardano_get_serialized_coin_size(lovelace, size_out)
    if err != 0:
        raise CardanoError(f"Failed to get serialized coin size (error code: {err})")

    return int(size_out[0])


def get_serialized_output_size(output: "TransactionOutput") -> int:
    """
    Compute the serialized size of a transaction output.

    Args:
        output: The transaction output.

    Returns:
        The size in bytes required to serialize the output.

    Raises:
        CardanoError: If computation fails.
    """
    size_out = ffi.new("size_t*")
    err = lib.cardano_get_serialized_output_size(output._ptr, size_out)
    if err != 0:
        raise CardanoError(f"Failed to get serialized output size (error code: {err})")

    return int(size_out[0])


def get_serialized_script_size(script: "Script") -> int:
    """
    Compute the serialized size of a script.

    Args:
        script: The script object.

    Returns:
        The size in bytes required to serialize the script.

    Raises:
        CardanoError: If computation fails.
    """
    size_out = ffi.new("size_t*")
    err = lib.cardano_get_serialized_script_size(script._ptr, size_out)
    if err != 0:
        raise CardanoError(f"Failed to get serialized script size (error code: {err})")

    return int(size_out[0])


def get_serialized_transaction_size(transaction: "Transaction") -> int:
    """
    Compute the serialized size of a transaction.

    Args:
        transaction: The transaction object.

    Returns:
        The size in bytes required to serialize the transaction.

    Raises:
        CardanoError: If computation fails.

    Example:
        >>> tx_size = get_serialized_transaction_size(tx)
        >>> print(f"Transaction size: {tx_size} bytes")
    """
    size_out = ffi.new("size_t*")
    err = lib.cardano_get_serialized_transaction_size(transaction._ptr, size_out)
    if err != 0:
        raise CardanoError(
            f"Failed to get serialized transaction size (error code: {err})"
        )

    return int(size_out[0])
