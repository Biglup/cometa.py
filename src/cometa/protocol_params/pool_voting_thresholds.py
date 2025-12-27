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


class PoolVotingThresholds:
    """
    Voting thresholds for stake pool operators (SPOs) in governance actions.

    Different governance actions have different ratification requirements.
    These thresholds specify the percentage of stake held by all stake pools
    that must be met by the SPOs who vote Yes for approval.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PoolVotingThresholds: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_pool_voting_thresholds_t**", self._ptr)
            lib.cardano_pool_voting_thresholds_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PoolVotingThresholds:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "PoolVotingThresholds(...)"

    @classmethod
    def new(
        cls,
        motion_no_confidence: UnitInterval,
        committee_normal: UnitInterval,
        committee_no_confidence: UnitInterval,
        hard_fork_initiation: UnitInterval,
        security_relevant_param: UnitInterval,
    ) -> PoolVotingThresholds:
        """
        Creates a new PoolVotingThresholds instance.

        Args:
            motion_no_confidence: Threshold for motion of no-confidence.
            committee_normal: Threshold for electing committee in confidence state.
            committee_no_confidence: Threshold for electing committee in no-confidence state.
            hard_fork_initiation: Threshold for hard fork initiation.
            security_relevant_param: Threshold for security-relevant parameter changes.

        Returns:
            A new PoolVotingThresholds instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_pool_voting_thresholds_t**")
        err = lib.cardano_pool_voting_thresholds_new(
            motion_no_confidence._ptr,
            committee_normal._ptr,
            committee_no_confidence._ptr,
            hard_fork_initiation._ptr,
            security_relevant_param._ptr,
            out,
        )
        if err != 0:
            raise CardanoError(f"Failed to create PoolVotingThresholds (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PoolVotingThresholds:
        """
        Deserializes PoolVotingThresholds from CBOR data.

        Args:
            reader: A CborReader positioned at the thresholds data.

        Returns:
            A new PoolVotingThresholds deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_pool_voting_thresholds_t**")
        err = lib.cardano_pool_voting_thresholds_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PoolVotingThresholds from CBOR (error code: {err})"
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
        err = lib.cardano_pool_voting_thresholds_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PoolVotingThresholds to CBOR (error code: {err})"
            )

    @property
    def motion_no_confidence(self) -> UnitInterval:
        """Threshold for motion of no-confidence."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_voting_thresholds_get_motion_no_confidence(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get motion_no_confidence (error code: {err})")
        return UnitInterval(out[0])

    @motion_no_confidence.setter
    def motion_no_confidence(self, value: UnitInterval) -> None:
        """Sets the threshold for motion of no-confidence."""
        err = lib.cardano_pool_voting_thresholds_set_motion_no_confidence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set motion_no_confidence (error code: {err})")

    @property
    def committee_normal(self) -> UnitInterval:
        """Threshold for electing committee when in confidence state."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_voting_thresholds_get_committee_normal(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get committee_normal (error code: {err})")
        return UnitInterval(out[0])

    @committee_normal.setter
    def committee_normal(self, value: UnitInterval) -> None:
        """Sets the threshold for electing committee when in confidence state."""
        err = lib.cardano_pool_voting_thresholds_set_committee_normal(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set committee_normal (error code: {err})")

    @property
    def committee_no_confidence(self) -> UnitInterval:
        """Threshold for electing committee when in no-confidence state."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_voting_thresholds_get_committee_no_confidence(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get committee_no_confidence (error code: {err})")
        return UnitInterval(out[0])

    @committee_no_confidence.setter
    def committee_no_confidence(self, value: UnitInterval) -> None:
        """Sets the threshold for electing committee when in no-confidence state."""
        err = lib.cardano_pool_voting_thresholds_set_committee_no_confidence(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set committee_no_confidence (error code: {err})")

    @property
    def hard_fork_initiation(self) -> UnitInterval:
        """Threshold for hard fork initiation."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_voting_thresholds_get_hard_fork_initiation(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get hard_fork_initiation (error code: {err})")
        return UnitInterval(out[0])

    @hard_fork_initiation.setter
    def hard_fork_initiation(self, value: UnitInterval) -> None:
        """Sets the threshold for hard fork initiation."""
        err = lib.cardano_pool_voting_thresholds_set_hard_fork_initiation(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set hard_fork_initiation (error code: {err})")

    @property
    def security_relevant_param(self) -> UnitInterval:
        """Threshold for security-relevant parameter changes."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_voting_thresholds_get_security_relevant_param(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get security_relevant_param (error code: {err})")
        return UnitInterval(out[0])

    @security_relevant_param.setter
    def security_relevant_param(self, value: UnitInterval) -> None:
        """Sets the threshold for security-relevant parameter changes."""
        err = lib.cardano_pool_voting_thresholds_set_security_relevant_param(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set security_relevant_param (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this pool voting thresholds to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_pool_voting_thresholds_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
