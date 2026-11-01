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

from typing import Optional

from ..._ffi import ffi, lib
from ...common import SlotConfig
from ...protocol_params import Costmdls, ProtocolParameters
from ...errors import CardanoError
from .c_tx_evaluator_wrapper import CTxEvaluatorWrapper


class NativeTxEvaluator(CTxEvaluatorWrapper):
    """Evaluate Plutus scripts locally with cardano-c's virtual machine.

    Bind the network's slot configuration, cost models and protocol version.
    Transaction builders use this evaluator automatically.
    """

    def __init__(self, slot_config: SlotConfig, cost_models: Optional[Costmdls] = None,
                 *, protocol_major: int) -> None:
        config = ffi.new("cardano_slot_config_t *")
        config.zero_time = slot_config.zero_time
        config.zero_slot = slot_config.zero_slot
        config.slot_length = slot_config.slot_length
        out = ffi.new("cardano_tx_evaluator_t **")
        err = lib.cardano_tx_evaluator_new_native(
            config, cost_models._ptr if cost_models is not None else ffi.NULL,
            protocol_major, out)
        if err:
            raise CardanoError(f"Failed to create native evaluator (error code: {err})")
        super().__init__(out[0], owns_ref=False)
        self._owns_ref = True

    @classmethod
    def from_parameters(cls, protocol_params: ProtocolParameters,
                        slot_config: SlotConfig) -> NativeTxEvaluator:
        """Create an evaluator using the same network parameters as a builder."""
        return cls(slot_config, protocol_params.cost_models,
                   protocol_major=protocol_params.protocol_version.major)
