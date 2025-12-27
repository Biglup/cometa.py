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
from ..common.governance_action_id import GovernanceActionId
from ..cryptography.blake2b_hash import Blake2bHash
from ..protocol_params.protocol_param_update import ProtocolParamUpdate


class ParameterChangeAction:
    """
    Represents a parameter change governance action.

    This action proposes updates to one or more updatable protocol parameters,
    excluding changes to major protocol versions (i.e., "hard forks").
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ParameterChangeAction: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_parameter_change_action_t**", self._ptr)
            lib.cardano_parameter_change_action_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ParameterChangeAction:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "ParameterChangeAction(...)"

    @classmethod
    def new(
        cls,
        protocol_param_update: ProtocolParamUpdate,
        governance_action_id: Optional[GovernanceActionId] = None,
        policy_hash: Optional[Blake2bHash] = None,
    ) -> ParameterChangeAction:
        """
        Creates a new parameter change action.

        Args:
            protocol_param_update: The proposed protocol parameter updates.
            governance_action_id: Optional ID of a previous governance action
                                 that this action depends on.
            policy_hash: Optional guardrails policy hash.

        Returns:
            A new ParameterChangeAction instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_parameter_change_action_t**")
        gov_id_ptr = (
            governance_action_id._ptr if governance_action_id is not None else ffi.NULL
        )
        policy_ptr = policy_hash._ptr if policy_hash is not None else ffi.NULL
        err = lib.cardano_parameter_change_action_new(
            protocol_param_update._ptr, gov_id_ptr, policy_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ParameterChangeAction (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ParameterChangeAction:
        """
        Deserializes a ParameterChangeAction from CBOR data.

        Args:
            reader: A CborReader positioned at the action data.

        Returns:
            A new ParameterChangeAction deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_parameter_change_action_t**")
        err = lib.cardano_parameter_change_action_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ParameterChangeAction from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the action to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_parameter_change_action_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ParameterChangeAction to CBOR (error code: {err})"
            )

    @property
    def protocol_param_update(self) -> ProtocolParamUpdate:
        """
        The proposed protocol parameter updates.

        Returns:
            The ProtocolParamUpdate.
        """
        ptr = lib.cardano_parameter_change_action_get_protocol_param_update(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get protocol param update")
        lib.cardano_protocol_param_update_ref(ptr)
        return ProtocolParamUpdate(ptr)

    @protocol_param_update.setter
    def protocol_param_update(self, value: ProtocolParamUpdate) -> None:
        """
        Sets the protocol parameter update.

        Args:
            value: The ProtocolParamUpdate to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_parameter_change_action_set_protocol_param_update(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set protocol param update (error code: {err})"
            )

    @property
    def policy_hash(self) -> Optional[Blake2bHash]:
        """
        The optional guardrails policy hash.

        Returns:
            The Blake2bHash if present, None otherwise.
        """
        ptr = lib.cardano_parameter_change_action_get_policy_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @policy_hash.setter
    def policy_hash(self, value: Optional[Blake2bHash]) -> None:
        """
        Sets the policy hash.

        Args:
            value: The Blake2bHash to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        policy_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_parameter_change_action_set_policy_hash(
            self._ptr, policy_ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set policy hash (error code: {err})")

    @property
    def governance_action_id(self) -> Optional[GovernanceActionId]:
        """
        The optional governance action ID that this action depends on.

        Returns:
            The GovernanceActionId if present, None otherwise.
        """
        ptr = lib.cardano_parameter_change_action_get_governance_action_id(self._ptr)
        if ptr == ffi.NULL:
            return None
        lib.cardano_governance_action_id_ref(ptr)
        return GovernanceActionId(ptr)

    @governance_action_id.setter
    def governance_action_id(self, value: Optional[GovernanceActionId]) -> None:
        """
        Sets the governance action ID.

        Args:
            value: The GovernanceActionId to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        gov_id_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_parameter_change_action_set_governance_action_id(
            self._ptr, gov_id_ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set governance action ID (error code: {err})"
            )

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
        err = lib.cardano_parameter_change_action_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
