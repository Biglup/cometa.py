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
from ..common.protocol_version import ProtocolVersion
from ..common.governance_action_id import GovernanceActionId


class HardForkInitiationAction:
    """
    Represents a hard fork initiation governance action.

    This action initiates a non-backwards compatible upgrade of the network.
    It requires a preceding software update and specifies the target protocol
    version for the hard fork.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("HardForkInitiationAction: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_hard_fork_initiation_action_t**", self._ptr)
            lib.cardano_hard_fork_initiation_action_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> HardForkInitiationAction:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        pv = self.protocol_version # pylint: disable=invalid-name
        return f"HardForkInitiationAction(version={pv.major}.{pv.minor})"

    @classmethod
    def new(
        cls,
        protocol_version: ProtocolVersion,
        governance_action_id: Optional[GovernanceActionId] = None,
    ) -> HardForkInitiationAction:
        """
        Creates a new hard fork initiation action.

        Args:
            protocol_version: The target protocol version for the hard fork.
            governance_action_id: Optional ID of a previous governance action
                                 that this action depends on.

        Returns:
            A new HardForkInitiationAction instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_hard_fork_initiation_action_t**")
        gov_id_ptr = (
            governance_action_id._ptr if governance_action_id is not None else ffi.NULL
        )
        err = lib.cardano_hard_fork_initiation_action_new(
            protocol_version._ptr, gov_id_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create HardForkInitiationAction (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> HardForkInitiationAction:
        """
        Deserializes a HardForkInitiationAction from CBOR data.

        Args:
            reader: A CborReader positioned at the action data.

        Returns:
            A new HardForkInitiationAction deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_hard_fork_initiation_action_t**")
        err = lib.cardano_hard_fork_initiation_action_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize HardForkInitiationAction from CBOR (error code: {err})"
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
        err = lib.cardano_hard_fork_initiation_action_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize HardForkInitiationAction to CBOR (error code: {err})"
            )

    @property
    def protocol_version(self) -> ProtocolVersion:
        """
        The target protocol version for the hard fork.

        Returns:
            The ProtocolVersion.
        """
        ptr = lib.cardano_hard_fork_initiation_action_get_protocol_version(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get protocol version")
        lib.cardano_protocol_version_ref(ptr)
        return ProtocolVersion(ptr)

    @protocol_version.setter
    def protocol_version(self, value: ProtocolVersion) -> None:
        """
        Sets the target protocol version.

        Args:
            value: The ProtocolVersion to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_hard_fork_initiation_action_set_protocol_version(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set protocol version (error code: {err})")

    @property
    def governance_action_id(self) -> Optional[GovernanceActionId]:
        """
        The optional governance action ID that this action depends on.

        Returns:
            The GovernanceActionId if present, None otherwise.
        """
        ptr = lib.cardano_hard_fork_initiation_action_get_governance_action_id(
            self._ptr
        )
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
        err = lib.cardano_hard_fork_initiation_action_set_governance_action_id(
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
        err = lib.cardano_hard_fork_initiation_action_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
