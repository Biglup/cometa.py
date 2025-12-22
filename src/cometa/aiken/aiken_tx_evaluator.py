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

import json
from typing import List, Optional, Union, TYPE_CHECKING

from .._aiken_ffi import aiken_ffi, aiken_lib
from ..errors import CardanoError
from ..cbor import CborReader, CborWriter
from ..common.ex_units import ExUnits
from ..common.slot_config import SlotConfig

if TYPE_CHECKING:
    from ..transaction import Transaction
    from ..common.utxo_list import UtxoList
    from ..common.utxo import Utxo
    from ..witness_set import Redeemer
    from ..protocol_params import Costmdls
    from ..transaction_body import (
        TransactionInput,
        TransactionInputSet,
        TransactionOutputList,
        TransactionOutput,
    )

DEFAULT_MAX_TX_EX_UNITS_MEMORY = 14_000_000
DEFAULT_MAX_TX_EX_UNITS_CPU = 10_000_000_000

# Aiken seems to slightly underestimate the required resources,
# so we apply a safety factor to the results.
SAFETY_MARGIN = 1.025

class TxEvaluationError(CardanoError):
    """Exception raised when transaction evaluation fails."""


class AikenTxEvaluator:
    """
    Transaction evaluator using the Aiken UPLC evaluator.

    This evaluator calculates execution units for Plutus scripts using
    the Aiken library's phase-two validation. It implements the TxEvaluatorProtocol.

    Example:
        >>> from cometa.aiken import AikenTxEvaluator
        >>> from cometa import ExUnits, SlotConfig
        >>>
        >>> # Create evaluator with cost models (required for evaluation)
        >>> evaluator = AikenTxEvaluator(cost_models=cost_models)
        >>> redeemers = evaluator.evaluate(transaction, utxos)
        >>>
        >>> # For testnets or custom networks with custom budget
        >>> evaluator = AikenTxEvaluator(
        ...     cost_models=cost_models,
        ...     slot_config=SlotConfig.preview(),
        ...     max_tx_ex_units=ExUnits.new(28000000, 20000000000)
        ... )
        >>>
        >>> # Using protocol parameters for budget
        >>> evaluator = AikenTxEvaluator(
        ...     cost_models=protocol_params.cost_models,
        ...     slot_config=SlotConfig.preprod(),
        ...     max_tx_ex_units=protocol_params.max_tx_ex_units
        ... )
    """

    def __init__(
        self,
        cost_models: "Costmdls",
        slot_config: Optional[SlotConfig] = None,
        max_tx_ex_units: Optional[ExUnits] = None,
    ) -> None:
        """
        Creates a new AikenTxEvaluator.

        Args:
            cost_models: The cost models for script evaluation (required).
            slot_config: Slot configuration for the network. Defaults to mainnet.
            max_tx_ex_units: Maximum execution units for the transaction.
                Defaults to mainnet values (14M memory, 10B CPU steps).
                Can be obtained from protocol_params.max_tx_ex_units.
        """
        self._cost_models = cost_models
        self._slot_config = slot_config or SlotConfig.mainnet()
        self._max_tx_ex_units = max_tx_ex_units or ExUnits.new(
            DEFAULT_MAX_TX_EX_UNITS_MEMORY,
            DEFAULT_MAX_TX_EX_UNITS_CPU
        )

    def get_name(self) -> str:
        """
        Get the human-readable name of this evaluator.

        Returns:
            The evaluator name.
        """
        return "Aiken"

    @property
    def slot_config(self) -> SlotConfig:
        """The slot configuration used by this evaluator."""
        return self._slot_config

    @property
    def max_tx_ex_units(self) -> ExUnits:
        """The maximum transaction execution units used by this evaluator."""
        return self._max_tx_ex_units

    @property
    def cost_models(self) -> "Costmdls":
        """The cost models used by this evaluator."""
        return self._cost_models

    def evaluate(
        self,
        transaction: "Transaction",
        additional_utxos: Union["UtxoList", List["Utxo"], None],
    ) -> List["Redeemer"]:
        """
        Evaluate the execution units required for a transaction.

        This method calculates the execution units needed for each Plutus
        script in the transaction using the Aiken UPLC evaluator.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: UTXOs referenced by the transaction (inputs + reference inputs).

        Returns:
            A list of Redeemer objects with computed execution units.

        Raises:
            TxEvaluationError: If evaluation fails.
        """
        utxo_list = _prepare_utxos(additional_utxos)
        all_inputs = _collect_all_inputs(transaction)
        resolved_outputs = _resolve_outputs(all_inputs, utxo_list)

        result = self._call_eval_phase_two(
            transaction.serialize_to_cbor(),
            _serialize_inputs(all_inputs),
            _serialize_outputs(resolved_outputs),
            _serialize_cost_models(self._cost_models),
        )

        return _parse_result(result)

    def _call_eval_phase_two(
        self,
        tx_hex: str,
        inputs_hex: str,
        outputs_hex: str,
        cost_models_hex: str,
    ) -> dict:
        """Calls the native eval_phase_two function."""
        slot_config = aiken_ffi.new("SlotConfig*")
        slot_config.slot_length = self._slot_config.slot_length
        slot_config.zero_slot = self._slot_config.zero_slot
        slot_config.zero_time = self._slot_config.zero_time

        initial_budget = aiken_ffi.new("InitialBudget*")
        initial_budget.mem = int(self._max_tx_ex_units.memory / SAFETY_MARGIN)
        initial_budget.cpu = int(self._max_tx_ex_units.cpu_steps / SAFETY_MARGIN)

        # DEBUG
        result_ptr = aiken_lib.eval_phase_two(
            tx_hex.encode("utf-8") + b'\0',
            inputs_hex.encode("utf-8") + b'\0',
            outputs_hex.encode("utf-8") + b'\0',
            cost_models_hex.encode("utf-8") + b'\0',
            initial_budget,
            slot_config,
        )

        try:
            result_str = aiken_ffi.string(result_ptr)
            return json.loads(result_str)
        finally:
            aiken_lib.drop_char_pointer(result_ptr)


def _prepare_utxos(
    additional_utxos: Union["UtxoList", List["Utxo"], None]
) -> "UtxoList":
    """Converts additional_utxos to a UtxoList."""
    from ..common.utxo_list import UtxoList

    if additional_utxos is None:
        return UtxoList()
    if isinstance(additional_utxos, list):
        return UtxoList.from_list(additional_utxos)
    return additional_utxos


def _collect_all_inputs(transaction: "Transaction") -> "TransactionInputSet":
    """Collects all inputs including reference inputs."""
    from ..transaction_body import TransactionInputSet

    all_inputs = TransactionInputSet()

    for tx_input in transaction.body.inputs:
        all_inputs.add(tx_input)

    ref_inputs = transaction.body.reference_inputs
    if ref_inputs:
        for ref_input in ref_inputs:
            all_inputs.add(ref_input)

    return all_inputs


def _resolve_outputs(
    inputs: "TransactionInputSet",
    utxos: "UtxoList",
) -> "TransactionOutputList":
    """Resolves transaction inputs to their corresponding outputs."""
    from ..transaction_body import TransactionOutputList

    outputs = TransactionOutputList()

    for tx_input in inputs:
        output = _find_utxo_output(tx_input, utxos)
        outputs.add(output)

    return outputs


def _find_utxo_output(tx_input: "TransactionInput", utxos: "UtxoList") -> "TransactionOutput":
    """Finds the output for a given input from the UTXO set."""
    for utxo in utxos:
        if utxo.input.transaction_id == tx_input.transaction_id and utxo.input.index == tx_input.index:
            return utxo.output
    raise TxEvaluationError(
        f"Could not find UTXO for input: {tx_input.transaction_id.hex()}#{tx_input.index}"
    )


def _serialize_inputs(inputs: "TransactionInputSet") -> str:
    """Serializes inputs to CBOR hex as an array (Aiken expects array, not set)."""
    writer = CborWriter()
    writer.write_start_array(len(inputs))
    for tx_input in inputs:
        tx_input.to_cbor(writer)
    return writer.to_hex()


def _serialize_outputs(outputs: "TransactionOutputList") -> str:
    """Serializes outputs to CBOR hex."""
    writer = CborWriter()
    outputs.to_cbor(writer)
    return writer.to_hex()


def _serialize_cost_models(cost_models: "Costmdls") -> str:
    """Serializes cost models to CBOR hex."""
    writer = CborWriter()
    cost_models.to_cbor(writer)
    return writer.to_hex()


def _parse_result(result: dict) -> List["Redeemer"]:
    """Parses the evaluation result and returns redeemers."""
    from ..witness_set import RedeemerList

    status = result.get("status", "").upper()
    if status != "SUCCESS":
        error_msg = result.get("error", "Unknown evaluation error")
        raise TxEvaluationError(f"Transaction evaluation failed: {error_msg}")

    redeemer_cbor = result.get("redeemer_cbor", "")
    if not redeemer_cbor:
        return []

    reader = CborReader.from_hex(redeemer_cbor)
    redeemer_list = RedeemerList.from_cbor(reader)

    for redeemer in redeemer_list:
        if not redeemer.ex_units:
            continue
        redeemer.ex_units.memory = int(redeemer.ex_units.memory * SAFETY_MARGIN)
        redeemer.ex_units.cpu_steps = int(redeemer.ex_units.cpu_steps * SAFETY_MARGIN)

    return list(redeemer_list)
