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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.unit_interval import UnitInterval


class DRepVotingThresholds:
    """
    Voting thresholds for Delegated Representatives (DReps) in governance actions.

    Different governance actions have different ratification requirements.
    These thresholds specify the percentage of the total active voting stake
    that must be met by DReps who vote Yes for approval.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("DRepVotingThresholds: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_drep_voting_thresholds_t**", self._ptr)
            lib.cardano_drep_voting_thresholds_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> DRepVotingThresholds:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "DRepVotingThresholds(...)"

    @classmethod
    def new(
        cls,
        motion_no_confidence: UnitInterval,
        committee_normal: UnitInterval,
        committee_no_confidence: UnitInterval,
        update_constitution: UnitInterval,
        hard_fork_initiation: UnitInterval,
        pp_network_group: UnitInterval,
        pp_economic_group: UnitInterval,
        pp_technical_group: UnitInterval,
        pp_governance_group: UnitInterval,
        treasury_withdrawal: UnitInterval,
    ) -> DRepVotingThresholds:
        """
        Creates a new DRepVotingThresholds instance.

        Args:
            motion_no_confidence: Threshold for motion of no-confidence.
            committee_normal: Threshold for electing committee in confidence state.
            committee_no_confidence: Threshold for electing committee in no-confidence state.
            update_constitution: Threshold for constitutional updates.
            hard_fork_initiation: Threshold for hard fork initiation.
            pp_network_group: Threshold for network group parameter updates.
            pp_economic_group: Threshold for economic group parameter updates.
            pp_technical_group: Threshold for technical group parameter updates.
            pp_governance_group: Threshold for governance group parameter updates.
            treasury_withdrawal: Threshold for treasury withdrawals.

        Returns:
            A new DRepVotingThresholds instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_drep_voting_thresholds_t**")
        err = lib.cardano_drep_voting_thresholds_new(
            motion_no_confidence._ptr,
            committee_normal._ptr,
            committee_no_confidence._ptr,
            update_constitution._ptr,
            hard_fork_initiation._ptr,
            pp_network_group._ptr,
            pp_economic_group._ptr,
            pp_technical_group._ptr,
            pp_governance_group._ptr,
            treasury_withdrawal._ptr,
            out,
        )
        if err != 0:
            raise CardanoError(f"Failed to create DRepVotingThresholds (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> DRepVotingThresholds:
        """
        Deserializes DRepVotingThresholds from CBOR data.

        Args:
            reader: A CborReader positioned at the thresholds data.

        Returns:
            A new DRepVotingThresholds deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_drep_voting_thresholds_t**")
        err = lib.cardano_drep_voting_thresholds_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize DRepVotingThresholds from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the thresholds to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_drep_voting_thresholds_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize DRepVotingThresholds to CBOR (error code: {err})"
            )

    @property
    def motion_no_confidence(self) -> UnitInterval:
        """Threshold for motion of no-confidence."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_motion_no_confidence(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get motion_no_confidence (error code: {err})")
        return UnitInterval(out[0])

    @motion_no_confidence.setter
    def motion_no_confidence(self, value: UnitInterval) -> None:
        """Sets the threshold for motion of no-confidence."""
        err = lib.cardano_drep_voting_thresholds_set_motion_no_confidence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set motion_no_confidence (error code: {err})")

    @property
    def committee_normal(self) -> UnitInterval:
        """Threshold for electing committee when in confidence state."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_committee_normal(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get committee_normal (error code: {err})")
        return UnitInterval(out[0])

    @committee_normal.setter
    def committee_normal(self, value: UnitInterval) -> None:
        """Sets the threshold for electing committee when in confidence state."""
        err = lib.cardano_drep_voting_thresholds_set_committee_normal(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set committee_normal (error code: {err})")

    @property
    def committee_no_confidence(self) -> UnitInterval:
        """Threshold for electing committee when in no-confidence state."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_committee_no_confidence(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get committee_no_confidence (error code: {err})")
        return UnitInterval(out[0])

    @committee_no_confidence.setter
    def committee_no_confidence(self, value: UnitInterval) -> None:
        """Sets the threshold for electing committee when in no-confidence state."""
        err = lib.cardano_drep_voting_thresholds_set_committee_no_confidence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set committee_no_confidence (error code: {err})")

    @property
    def update_constitution(self) -> UnitInterval:
        """Threshold for constitutional updates."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_update_constitution(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get update_constitution (error code: {err})")
        return UnitInterval(out[0])

    @update_constitution.setter
    def update_constitution(self, value: UnitInterval) -> None:
        """Sets the threshold for constitutional updates."""
        err = lib.cardano_drep_voting_thresholds_set_update_constitution(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set update_constitution (error code: {err})")

    @property
    def hard_fork_initiation(self) -> UnitInterval:
        """Threshold for hard fork initiation."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_hard_fork_initiation(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get hard_fork_initiation (error code: {err})")
        return UnitInterval(out[0])

    @hard_fork_initiation.setter
    def hard_fork_initiation(self, value: UnitInterval) -> None:
        """Sets the threshold for hard fork initiation."""
        err = lib.cardano_drep_voting_thresholds_set_hard_fork_initiation(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set hard_fork_initiation (error code: {err})")

    @property
    def pp_network_group(self) -> UnitInterval:
        """Threshold for network group parameter updates."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_pp_network_group(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pp_network_group (error code: {err})")
        return UnitInterval(out[0])

    @pp_network_group.setter
    def pp_network_group(self, value: UnitInterval) -> None:
        """Sets the threshold for network group parameter updates."""
        err = lib.cardano_drep_voting_thresholds_set_pp_network_group(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pp_network_group (error code: {err})")

    @property
    def pp_economic_group(self) -> UnitInterval:
        """Threshold for economic group parameter updates."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_pp_economic_group(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pp_economic_group (error code: {err})")
        return UnitInterval(out[0])

    @pp_economic_group.setter
    def pp_economic_group(self, value: UnitInterval) -> None:
        """Sets the threshold for economic group parameter updates."""
        err = lib.cardano_drep_voting_thresholds_set_pp_economic_group(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pp_economic_group (error code: {err})")

    @property
    def pp_technical_group(self) -> UnitInterval:
        """Threshold for technical group parameter updates."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_pp_technical_group(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pp_technical_group (error code: {err})")
        return UnitInterval(out[0])

    @pp_technical_group.setter
    def pp_technical_group(self, value: UnitInterval) -> None:
        """Sets the threshold for technical group parameter updates."""
        err = lib.cardano_drep_voting_thresholds_set_pp_technical_group(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pp_technical_group (error code: {err})")

    @property
    def pp_governance_group(self) -> UnitInterval:
        """Threshold for governance group parameter updates."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_pp_governance_group(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pp_governance_group (error code: {err})")
        return UnitInterval(out[0])

    @pp_governance_group.setter
    def pp_governance_group(self, value: UnitInterval) -> None:
        """Sets the threshold for governance group parameter updates."""
        err = lib.cardano_drep_voting_thresholds_set_pp_governance_group(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pp_governance_group (error code: {err})")

    @property
    def treasury_withdrawal(self) -> UnitInterval:
        """Threshold for treasury withdrawals."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_drep_voting_thresholds_get_treasury_withdrawal(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get treasury_withdrawal (error code: {err})")
        return UnitInterval(out[0])

    @treasury_withdrawal.setter
    def treasury_withdrawal(self, value: UnitInterval) -> None:
        """Sets the threshold for treasury withdrawals."""
        err = lib.cardano_drep_voting_thresholds_set_treasury_withdrawal(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set treasury_withdrawal (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this DRep voting thresholds to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_drep_voting_thresholds_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
