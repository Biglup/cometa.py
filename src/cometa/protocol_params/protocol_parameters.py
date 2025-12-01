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
from ..buffer import Buffer
from ..common.unit_interval import UnitInterval
from ..common.protocol_version import ProtocolVersion
from ..common.ex_units import ExUnits
from .costmdls import Costmdls
from .ex_unit_prices import ExUnitPrices
from .pool_voting_thresholds import PoolVotingThresholds
from .drep_voting_thresholds import DRepVotingThresholds


# pylint: disable=too-many-instance-attributes
class ProtocolParameters:
    """
    Protocol parameters that govern the Cardano network.

    Protocol parameters define various aspects of the network including
    transaction fees, block sizes, staking parameters, and governance
    thresholds.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ProtocolParameters: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_protocol_parameters_t**", self._ptr)
            lib.cardano_protocol_parameters_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProtocolParameters:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "ProtocolParameters(...)"

    @classmethod
    def new(cls) -> ProtocolParameters:
        """
        Creates a new empty ProtocolParameters instance.

        Returns:
            A new ProtocolParameters instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_protocol_parameters_t**")
        err = lib.cardano_protocol_parameters_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create ProtocolParameters (error code: {err})")
        return cls(out[0])

    # Fee parameters

    @property
    def min_fee_a(self) -> int:
        """
        Linear fee coefficient (a) for transaction fees.

        The minimum fee is calculated as: min_fee = a * tx_size + b
        """
        return int(lib.cardano_protocol_parameters_get_min_fee_a(self._ptr))

    @min_fee_a.setter
    def min_fee_a(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_min_fee_a(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set min_fee_a (error code: {err})")

    @property
    def min_fee_b(self) -> int:
        """
        Constant fee coefficient (b) for transaction fees.

        The minimum fee is calculated as: min_fee = a * tx_size + b
        """
        return int(lib.cardano_protocol_parameters_get_min_fee_b(self._ptr))

    @min_fee_b.setter
    def min_fee_b(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_min_fee_b(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set min_fee_b (error code: {err})")

    # Size limits

    @property
    def max_block_body_size(self) -> int:
        """Maximum block body size in bytes."""
        return int(lib.cardano_protocol_parameters_get_max_block_body_size(self._ptr))

    @max_block_body_size.setter
    def max_block_body_size(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_block_body_size(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_block_body_size (error code: {err})")

    @property
    def max_tx_size(self) -> int:
        """Maximum transaction size in bytes."""
        return int(lib.cardano_protocol_parameters_get_max_tx_size(self._ptr))

    @max_tx_size.setter
    def max_tx_size(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_tx_size(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_tx_size (error code: {err})")

    @property
    def max_block_header_size(self) -> int:
        """Maximum block header size in bytes."""
        return int(lib.cardano_protocol_parameters_get_max_block_header_size(self._ptr))

    @max_block_header_size.setter
    def max_block_header_size(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_block_header_size(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_block_header_size (error code: {err})")

    # Deposit parameters

    @property
    def key_deposit(self) -> int:
        """Staking key registration deposit in lovelaces."""
        return int(lib.cardano_protocol_parameters_get_key_deposit(self._ptr))

    @key_deposit.setter
    def key_deposit(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_key_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set key_deposit (error code: {err})")

    @property
    def pool_deposit(self) -> int:
        """Stake pool registration deposit in lovelaces."""
        return int(lib.cardano_protocol_parameters_get_pool_deposit(self._ptr))

    @pool_deposit.setter
    def pool_deposit(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_pool_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set pool_deposit (error code: {err})")

    # Pool parameters

    @property
    def max_epoch(self) -> int:
        """Maximum pool retirement epoch bounds."""
        return int(lib.cardano_protocol_parameters_get_max_epoch(self._ptr))

    @max_epoch.setter
    def max_epoch(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_epoch(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_epoch (error code: {err})")

    @property
    def n_opt(self) -> int:
        """Desired number of stake pools (k parameter)."""
        return int(lib.cardano_protocol_parameters_get_n_opt(self._ptr))

    @n_opt.setter
    def n_opt(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_n_opt(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set n_opt (error code: {err})")

    @property
    def pool_pledge_influence(self) -> Optional[UnitInterval]:
        """Pool pledge influence factor (a0)."""
        ptr = lib.cardano_protocol_parameters_get_pool_pledge_influence(self._ptr)
        if ptr == ffi.NULL:
            return None
        return UnitInterval(ptr)

    @pool_pledge_influence.setter
    def pool_pledge_influence(self, value: UnitInterval) -> None:
        err = lib.cardano_protocol_parameters_set_pool_pledge_influence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pool_pledge_influence (error code: {err})")

    @property
    def expansion_rate(self) -> Optional[UnitInterval]:
        """Monetary expansion rate (rho)."""
        ptr = lib.cardano_protocol_parameters_get_expansion_rate(self._ptr)
        if ptr == ffi.NULL:
            return None
        return UnitInterval(ptr)

    @expansion_rate.setter
    def expansion_rate(self, value: UnitInterval) -> None:
        err = lib.cardano_protocol_parameters_set_expansion_rate(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set expansion_rate (error code: {err})")

    @property
    def treasury_growth_rate(self) -> Optional[UnitInterval]:
        """Treasury growth rate (tau)."""
        ptr = lib.cardano_protocol_parameters_get_treasury_growth_rate(self._ptr)
        if ptr == ffi.NULL:
            return None
        return UnitInterval(ptr)

    @treasury_growth_rate.setter
    def treasury_growth_rate(self, value: UnitInterval) -> None:
        err = lib.cardano_protocol_parameters_set_treasury_growth_rate(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set treasury_growth_rate (error code: {err})")

    @property
    def d(self) -> Optional[UnitInterval]:  # pylint: disable=invalid-name
        """Decentralization parameter (deprecated in Babbage)."""
        ptr = lib.cardano_protocol_parameters_get_d(self._ptr)
        if ptr == ffi.NULL:
            return None
        return UnitInterval(ptr)

    @d.setter
    def d(self, value: UnitInterval) -> None:  # pylint: disable=invalid-name
        err = lib.cardano_protocol_parameters_set_d(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set d (error code: {err})")

    @property
    def extra_entropy(self) -> Optional[Buffer]:
        """Extra entropy for leader selection (deprecated)."""
        ptr = lib.cardano_protocol_parameters_get_extra_entropy(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Buffer(ptr)

    @extra_entropy.setter
    def extra_entropy(self, value: Buffer) -> None:
        err = lib.cardano_protocol_parameters_set_extra_entropy(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set extra_entropy (error code: {err})")

    @property
    def protocol_version(self) -> Optional[ProtocolVersion]:
        """Current protocol version."""
        ptr = lib.cardano_protocol_parameters_get_protocol_version(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ProtocolVersion(ptr)

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion) -> None:
        err = lib.cardano_protocol_parameters_set_protocol_version(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set protocol_version (error code: {err})")

    @property
    def min_pool_cost(self) -> int:
        """Minimum pool cost in lovelaces."""
        return int(lib.cardano_protocol_parameters_get_min_pool_cost(self._ptr))

    @min_pool_cost.setter
    def min_pool_cost(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_min_pool_cost(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set min_pool_cost (error code: {err})")

    # UTXO parameters

    @property
    def ada_per_utxo_byte(self) -> int:
        """Lovelaces per UTXO byte (coins per UTxO word)."""
        return int(lib.cardano_protocol_parameters_get_ada_per_utxo_byte(self._ptr))

    @ada_per_utxo_byte.setter
    def ada_per_utxo_byte(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_ada_per_utxo_byte(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set ada_per_utxo_byte (error code: {err})")

    # Plutus parameters

    @property
    def cost_models(self) -> Optional[Costmdls]:
        """Cost models for Plutus script execution."""
        ptr = lib.cardano_protocol_parameters_get_cost_models(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Costmdls(ptr)

    @cost_models.setter
    def cost_models(self, value: Costmdls) -> None:
        err = lib.cardano_protocol_parameters_set_cost_models(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set cost_models (error code: {err})")

    @property
    def execution_costs(self) -> Optional[ExUnitPrices]:
        """Execution unit prices for Plutus scripts."""
        ptr = lib.cardano_protocol_parameters_get_execution_costs(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ExUnitPrices(ptr)

    @execution_costs.setter
    def execution_costs(self, value: ExUnitPrices) -> None:
        err = lib.cardano_protocol_parameters_set_execution_costs(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set execution_costs (error code: {err})")

    @property
    def max_tx_ex_units(self) -> Optional[ExUnits]:
        """Maximum execution units per transaction."""
        ptr = lib.cardano_protocol_parameters_get_max_tx_ex_units(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ExUnits(ptr)

    @max_tx_ex_units.setter
    def max_tx_ex_units(self, value: ExUnits) -> None:
        err = lib.cardano_protocol_parameters_set_max_tx_ex_units(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set max_tx_ex_units (error code: {err})")

    @property
    def max_block_ex_units(self) -> Optional[ExUnits]:
        """Maximum execution units per block."""
        ptr = lib.cardano_protocol_parameters_get_max_block_ex_units(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ExUnits(ptr)

    @max_block_ex_units.setter
    def max_block_ex_units(self, value: ExUnits) -> None:
        err = lib.cardano_protocol_parameters_set_max_block_ex_units(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set max_block_ex_units (error code: {err})")

    @property
    def max_value_size(self) -> int:
        """Maximum value size in bytes."""
        return int(lib.cardano_protocol_parameters_get_max_value_size(self._ptr))

    @max_value_size.setter
    def max_value_size(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_value_size(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_value_size (error code: {err})")

    @property
    def collateral_percentage(self) -> int:
        """Collateral percentage required for Plutus scripts."""
        return int(lib.cardano_protocol_parameters_get_collateral_percentage(self._ptr))

    @collateral_percentage.setter
    def collateral_percentage(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_collateral_percentage(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set collateral_percentage (error code: {err})")

    @property
    def max_collateral_inputs(self) -> int:
        """Maximum number of collateral inputs."""
        return int(lib.cardano_protocol_parameters_get_max_collateral_inputs(self._ptr))

    @max_collateral_inputs.setter
    def max_collateral_inputs(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_max_collateral_inputs(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set max_collateral_inputs (error code: {err})")

    # Governance parameters (Conway era)

    @property
    def pool_voting_thresholds(self) -> Optional[PoolVotingThresholds]:
        """Voting thresholds for stake pool operators."""
        ptr = lib.cardano_protocol_parameters_get_pool_voting_thresholds(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PoolVotingThresholds(ptr)

    @pool_voting_thresholds.setter
    def pool_voting_thresholds(self, value: PoolVotingThresholds) -> None:
        err = lib.cardano_protocol_parameters_set_pool_voting_thresholds(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pool_voting_thresholds (error code: {err})")

    @property
    def drep_voting_thresholds(self) -> Optional[DRepVotingThresholds]:
        """Voting thresholds for DReps."""
        ptr = lib.cardano_protocol_parameters_get_drep_voting_thresholds(self._ptr)
        if ptr == ffi.NULL:
            return None
        return DRepVotingThresholds(ptr)

    @drep_voting_thresholds.setter
    def drep_voting_thresholds(self, value: DRepVotingThresholds) -> None:
        err = lib.cardano_protocol_parameters_set_drep_voting_thresholds(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set drep_voting_thresholds (error code: {err})")

    @property
    def min_committee_size(self) -> int:
        """Minimum constitutional committee size."""
        return int(lib.cardano_protocol_parameters_get_min_committee_size(self._ptr))

    @min_committee_size.setter
    def min_committee_size(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_min_committee_size(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set min_committee_size (error code: {err})")

    @property
    def committee_term_limit(self) -> int:
        """Committee member term limit in epochs."""
        return int(lib.cardano_protocol_parameters_get_committee_term_limit(self._ptr))

    @committee_term_limit.setter
    def committee_term_limit(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_committee_term_limit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set committee_term_limit (error code: {err})")

    @property
    def governance_action_validity_period(self) -> int:
        """Governance action validity period in epochs."""
        return int(lib.cardano_protocol_parameters_get_governance_action_validity_period(self._ptr))

    @governance_action_validity_period.setter
    def governance_action_validity_period(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_governance_action_validity_period(self._ptr, value)
        if err != 0:
            raise CardanoError(
                f"Failed to set governance_action_validity_period (error code: {err})"
            )

    @property
    def governance_action_deposit(self) -> int:
        """Governance action deposit in lovelaces."""
        return int(lib.cardano_protocol_parameters_get_governance_action_deposit(self._ptr))

    @governance_action_deposit.setter
    def governance_action_deposit(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_governance_action_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set governance_action_deposit (error code: {err})")

    @property
    def drep_deposit(self) -> int:
        """DRep registration deposit in lovelaces."""
        return int(lib.cardano_protocol_parameters_get_drep_deposit(self._ptr))

    @drep_deposit.setter
    def drep_deposit(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_drep_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set drep_deposit (error code: {err})")

    @property
    def drep_inactivity_period(self) -> int:
        """DRep inactivity period in epochs."""
        return int(lib.cardano_protocol_parameters_get_drep_inactivity_period(self._ptr))

    @drep_inactivity_period.setter
    def drep_inactivity_period(self, value: int) -> None:
        err = lib.cardano_protocol_parameters_set_drep_inactivity_period(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set drep_inactivity_period (error code: {err})")

    @property
    def ref_script_cost_per_byte(self) -> Optional[UnitInterval]:
        """Reference script cost per byte."""
        ptr = lib.cardano_protocol_parameters_get_ref_script_cost_per_byte(self._ptr)
        if ptr == ffi.NULL:
            return None
        return UnitInterval(ptr)

    @ref_script_cost_per_byte.setter
    def ref_script_cost_per_byte(self, value: UnitInterval) -> None:
        err = lib.cardano_protocol_parameters_set_ref_script_cost_per_byte(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set ref_script_cost_per_byte (error code: {err})")
