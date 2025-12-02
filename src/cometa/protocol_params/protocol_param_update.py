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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..buffer import Buffer
from ..common.unit_interval import UnitInterval
from ..common.protocol_version import ProtocolVersion
from ..common.ex_units import ExUnits
from .costmdls import Costmdls
from .ex_unit_prices import ExUnitPrices
from .pool_voting_thresholds import PoolVotingThresholds
from .drep_voting_thresholds import DRepVotingThresholds


class ProtocolParamUpdate:
    """
    Represents a proposed update to the protocol parameters.

    Unlike ProtocolParameters, this class allows optional values since
    an update proposal may only change specific parameters while leaving
    others unchanged.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ProtocolParamUpdate: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_protocol_param_update_t**", self._ptr)
            lib.cardano_protocol_param_update_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProtocolParamUpdate:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "ProtocolParamUpdate(...)"

    @classmethod
    def new(cls) -> ProtocolParamUpdate:
        """
        Creates a new empty ProtocolParamUpdate instance.

        Returns:
            A new ProtocolParamUpdate instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_protocol_param_update_t**")
        err = lib.cardano_protocol_param_update_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create ProtocolParamUpdate (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ProtocolParamUpdate:
        """
        Deserializes ProtocolParamUpdate from CBOR data.

        Args:
            reader: A CborReader positioned at the update data.

        Returns:
            A new ProtocolParamUpdate deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_protocol_param_update_t**")
        err = lib.cardano_protocol_param_update_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ProtocolParamUpdate from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the protocol param update to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_protocol_param_update_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ProtocolParamUpdate to CBOR (error code: {err})"
            )

    # Fee parameters

    @property
    def min_fee_a(self) -> Optional[int]:
        """Linear fee coefficient (a) for transaction fees."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_min_fee_a(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @min_fee_a.setter
    def min_fee_a(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_min_fee_a(self._ptr, ffi.new("uint64_t*", value))
        if err != 0:
            raise CardanoError(f"Failed to set min_fee_a (error code: {err})")

    @property
    def min_fee_b(self) -> Optional[int]:
        """Constant fee coefficient (b) for transaction fees."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_min_fee_b(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @min_fee_b.setter
    def min_fee_b(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_min_fee_b(self._ptr, ffi.new("uint64_t*", value))
        if err != 0:
            raise CardanoError(f"Failed to set min_fee_b (error code: {err})")

    # Size limits

    @property
    def max_block_body_size(self) -> Optional[int]:
        """Maximum block body size in bytes."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_block_body_size(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_block_body_size.setter
    def max_block_body_size(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_block_body_size(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_block_body_size (error code: {err})")

    @property
    def max_tx_size(self) -> Optional[int]:
        """Maximum transaction size in bytes."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_tx_size(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_tx_size.setter
    def max_tx_size(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_tx_size(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_tx_size (error code: {err})")

    @property
    def max_block_header_size(self) -> Optional[int]:
        """Maximum block header size in bytes."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_block_header_size(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_block_header_size.setter
    def max_block_header_size(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_block_header_size(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_block_header_size (error code: {err})")

    # Deposit parameters

    @property
    def key_deposit(self) -> Optional[int]:
        """Staking key registration deposit in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_key_deposit(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @key_deposit.setter
    def key_deposit(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_key_deposit(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set key_deposit (error code: {err})")

    @property
    def pool_deposit(self) -> Optional[int]:
        """Stake pool registration deposit in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_pool_deposit(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @pool_deposit.setter
    def pool_deposit(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_pool_deposit(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set pool_deposit (error code: {err})")

    # Pool parameters

    @property
    def max_epoch(self) -> Optional[int]:
        """Maximum pool retirement epoch bounds."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_epoch(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_epoch.setter
    def max_epoch(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_epoch(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_epoch (error code: {err})")

    @property
    def n_opt(self) -> Optional[int]:
        """Desired number of stake pools (k parameter)."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_n_opt(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @n_opt.setter
    def n_opt(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_n_opt(self._ptr, ffi.new("uint64_t*", value))
        if err != 0:
            raise CardanoError(f"Failed to set n_opt (error code: {err})")

    @property
    def pool_pledge_influence(self) -> Optional[UnitInterval]:
        """Pool pledge influence factor (a0)."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_protocol_param_update_get_pool_pledge_influence(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return UnitInterval(out[0])

    @pool_pledge_influence.setter
    def pool_pledge_influence(self, value: Optional[UnitInterval]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_pool_pledge_influence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pool_pledge_influence (error code: {err})")

    @property
    def expansion_rate(self) -> Optional[UnitInterval]:
        """Monetary expansion rate (rho)."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_protocol_param_update_get_expansion_rate(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return UnitInterval(out[0])

    @expansion_rate.setter
    def expansion_rate(self, value: Optional[UnitInterval]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_expansion_rate(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set expansion_rate (error code: {err})")

    @property
    def treasury_growth_rate(self) -> Optional[UnitInterval]:
        """Treasury growth rate (tau)."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_protocol_param_update_get_treasury_growth_rate(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return UnitInterval(out[0])

    @treasury_growth_rate.setter
    def treasury_growth_rate(self, value: Optional[UnitInterval]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_treasury_growth_rate(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set treasury_growth_rate (error code: {err})")

    @property
    def d(self) -> Optional[UnitInterval]:  # pylint: disable=invalid-name
        """Decentralization parameter (deprecated in Babbage)."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_protocol_param_update_get_d(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return UnitInterval(out[0])

    @d.setter
    def d(self, value: Optional[UnitInterval]) -> None:  # pylint: disable=invalid-name
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_d(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set d (error code: {err})")

    @property
    def extra_entropy(self) -> Optional[Buffer]:
        """Extra entropy for leader selection (deprecated)."""
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_protocol_param_update_get_extra_entropy(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return Buffer(out[0])

    @extra_entropy.setter
    def extra_entropy(self, value: Optional[Buffer]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_extra_entropy(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set extra_entropy (error code: {err})")

    @property
    def protocol_version(self) -> Optional[ProtocolVersion]:
        """Current protocol version."""
        out = ffi.new("cardano_protocol_version_t**")
        err = lib.cardano_protocol_param_update_get_protocol_version(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ProtocolVersion(out[0])

    @protocol_version.setter
    def protocol_version(self, value: Optional[ProtocolVersion]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_protocol_version(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set protocol_version (error code: {err})")

    @property
    def min_pool_cost(self) -> Optional[int]:
        """Minimum pool cost in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_min_pool_cost(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @min_pool_cost.setter
    def min_pool_cost(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_min_pool_cost(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set min_pool_cost (error code: {err})")

    # UTXO parameters

    @property
    def ada_per_utxo_byte(self) -> Optional[int]:
        """Lovelaces per UTXO byte (coins per UTxO word)."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_ada_per_utxo_byte(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @ada_per_utxo_byte.setter
    def ada_per_utxo_byte(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_ada_per_utxo_byte(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set ada_per_utxo_byte (error code: {err})")

    # Plutus parameters

    @property
    def cost_models(self) -> Optional[Costmdls]:
        """Cost models for Plutus script execution."""
        out = ffi.new("cardano_costmdls_t**")
        err = lib.cardano_protocol_param_update_get_cost_models(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return Costmdls(out[0])

    @cost_models.setter
    def cost_models(self, value: Optional[Costmdls]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_cost_models(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set cost_models (error code: {err})")

    @property
    def execution_costs(self) -> Optional[ExUnitPrices]:
        """Execution unit prices for Plutus scripts."""
        out = ffi.new("cardano_ex_unit_prices_t**")
        err = lib.cardano_protocol_param_update_get_execution_costs(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ExUnitPrices(out[0])

    @execution_costs.setter
    def execution_costs(self, value: Optional[ExUnitPrices]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_execution_costs(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set execution_costs (error code: {err})")

    @property
    def max_tx_ex_units(self) -> Optional[ExUnits]:
        """Maximum execution units per transaction."""
        out = ffi.new("cardano_ex_units_t**")
        err = lib.cardano_protocol_param_update_get_max_tx_ex_units(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ExUnits(out[0])

    @max_tx_ex_units.setter
    def max_tx_ex_units(self, value: Optional[ExUnits]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_tx_ex_units(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set max_tx_ex_units (error code: {err})")

    @property
    def max_block_ex_units(self) -> Optional[ExUnits]:
        """Maximum execution units per block."""
        out = ffi.new("cardano_ex_units_t**")
        err = lib.cardano_protocol_param_update_get_max_block_ex_units(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ExUnits(out[0])

    @max_block_ex_units.setter
    def max_block_ex_units(self, value: Optional[ExUnits]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_block_ex_units(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set max_block_ex_units (error code: {err})")

    @property
    def max_value_size(self) -> Optional[int]:
        """Maximum value size in bytes."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_value_size(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_value_size.setter
    def max_value_size(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_value_size(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_value_size (error code: {err})")

    @property
    def collateral_percentage(self) -> Optional[int]:
        """Collateral percentage required for Plutus scripts."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_collateral_percentage(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @collateral_percentage.setter
    def collateral_percentage(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_collateral_percentage(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set collateral_percentage (error code: {err})")

    @property
    def max_collateral_inputs(self) -> Optional[int]:
        """Maximum number of collateral inputs."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_max_collateral_inputs(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @max_collateral_inputs.setter
    def max_collateral_inputs(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_max_collateral_inputs(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set max_collateral_inputs (error code: {err})")

    # Governance parameters (Conway era)

    @property
    def pool_voting_thresholds(self) -> Optional[PoolVotingThresholds]:
        """Voting thresholds for stake pool operators."""
        out = ffi.new("cardano_pool_voting_thresholds_t**")
        err = lib.cardano_protocol_param_update_get_pool_voting_thresholds(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return PoolVotingThresholds(out[0])

    @pool_voting_thresholds.setter
    def pool_voting_thresholds(self, value: Optional[PoolVotingThresholds]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_pool_voting_thresholds(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pool_voting_thresholds (error code: {err})")

    @property
    def drep_voting_thresholds(self) -> Optional[DRepVotingThresholds]:
        """Voting thresholds for DReps."""
        out = ffi.new("cardano_drep_voting_thresholds_t**")
        err = lib.cardano_protocol_param_update_get_drep_voting_thresholds(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return DRepVotingThresholds(out[0])

    @drep_voting_thresholds.setter
    def drep_voting_thresholds(self, value: Optional[DRepVotingThresholds]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_drep_voting_thresholds(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set drep_voting_thresholds (error code: {err})")

    @property
    def min_committee_size(self) -> Optional[int]:
        """Minimum constitutional committee size."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_min_committee_size(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @min_committee_size.setter
    def min_committee_size(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_min_committee_size(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set min_committee_size (error code: {err})")

    @property
    def committee_term_limit(self) -> Optional[int]:
        """Committee member term limit in epochs."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_committee_term_limit(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @committee_term_limit.setter
    def committee_term_limit(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_committee_term_limit(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set committee_term_limit (error code: {err})")

    @property
    def governance_action_validity_period(self) -> Optional[int]:
        """Governance action validity period in epochs."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_governance_action_validity_period(
            self._ptr, out
        )
        if err != 0:
            return None
        return int(out[0])

    @governance_action_validity_period.setter
    def governance_action_validity_period(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_governance_action_validity_period(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set governance_action_validity_period (error code: {err})"
            )

    @property
    def governance_action_deposit(self) -> Optional[int]:
        """Governance action deposit in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_governance_action_deposit(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @governance_action_deposit.setter
    def governance_action_deposit(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_governance_action_deposit(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set governance_action_deposit (error code: {err})")

    @property
    def drep_deposit(self) -> Optional[int]:
        """DRep registration deposit in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_drep_deposit(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @drep_deposit.setter
    def drep_deposit(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_drep_deposit(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set drep_deposit (error code: {err})")

    @property
    def drep_inactivity_period(self) -> Optional[int]:
        """DRep inactivity period in epochs."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_protocol_param_update_get_drep_inactivity_period(self._ptr, out)
        if err != 0:
            return None
        return int(out[0])

    @drep_inactivity_period.setter
    def drep_inactivity_period(self, value: Optional[int]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_drep_inactivity_period(
            self._ptr, ffi.new("uint64_t*", value)
        )
        if err != 0:
            raise CardanoError(f"Failed to set drep_inactivity_period (error code: {err})")

    @property
    def ref_script_cost_per_byte(self) -> Optional[UnitInterval]:
        """Reference script cost per byte."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_protocol_param_update_get_ref_script_cost_per_byte(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return UnitInterval(out[0])

    @ref_script_cost_per_byte.setter
    def ref_script_cost_per_byte(self, value: Optional[UnitInterval]) -> None:
        if value is None:
            return
        err = lib.cardano_protocol_param_update_set_ref_script_cost_per_byte(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set ref_script_cost_per_byte (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_protocol_param_update_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
