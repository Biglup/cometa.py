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

from typing import Optional, Union, List

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.governance_action_id import GovernanceActionId
from ..common.unit_interval import UnitInterval
from ..common.credential import Credential
from .credential_set import CredentialSet
from .committee_members_map import CommitteeMembersMap


class UpdateCommitteeAction:
    """
    Represents an update committee governance action.

    This action modifies the composition of the constitutional committee,
    its signature threshold, or its terms of operation. It can add or remove
    members and update the quorum threshold.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("UpdateCommitteeAction: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_update_committee_action_t**", self._ptr)
            lib.cardano_update_committee_action_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> UpdateCommitteeAction:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "UpdateCommitteeAction(...)"

    @classmethod
    def new(
        cls,
        members_to_be_removed: Union[CredentialSet, List[Credential]],
        members_to_be_added: CommitteeMembersMap,
        new_quorum: UnitInterval,
        governance_action_id: Optional[GovernanceActionId] = None,
    ) -> UpdateCommitteeAction:
        """
        Creates a new update committee action.

        Args:
            members_to_be_removed: Credentials of committee members to remove.
                Can be a CredentialSet or a Python list of Credential objects.
            members_to_be_added: Map of new committee member credentials to term epochs.
            new_quorum: The new quorum threshold for the committee.
            governance_action_id: Optional ID of a previous governance action
                                 that this action depends on.

        Returns:
            A new UpdateCommitteeAction instance.

        Raises:
            CardanoError: If creation fails.
        """
        if isinstance(members_to_be_removed, list):
            members_to_be_removed = CredentialSet.from_list(members_to_be_removed)
        out = ffi.new("cardano_update_committee_action_t**")
        gov_id_ptr = (
            governance_action_id._ptr if governance_action_id is not None else ffi.NULL
        )
        err = lib.cardano_update_committee_action_new(
            members_to_be_removed._ptr,
            members_to_be_added._ptr,
            new_quorum._ptr,
            gov_id_ptr,
            out,
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create UpdateCommitteeAction (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> UpdateCommitteeAction:
        """
        Deserializes an UpdateCommitteeAction from CBOR data.

        Args:
            reader: A CborReader positioned at the action data.

        Returns:
            A new UpdateCommitteeAction deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_update_committee_action_t**")
        err = lib.cardano_update_committee_action_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize UpdateCommitteeAction from CBOR (error code: {err})"
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
        err = lib.cardano_update_committee_action_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize UpdateCommitteeAction to CBOR (error code: {err})"
            )

    @property
    def members_to_be_removed(self) -> CredentialSet:
        """
        The set of committee members to be removed.

        Returns:
            The CredentialSet of members to remove.
        """
        ptr = lib.cardano_update_committee_action_get_members_to_be_removed(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get members to be removed")
        lib.cardano_credential_set_ref(ptr)
        return CredentialSet(ptr)

    @members_to_be_removed.setter
    def members_to_be_removed(self, value: Union[CredentialSet, List[Credential]]) -> None:
        """
        Sets the members to be removed.

        Args:
            value: The CredentialSet or a Python list of Credential objects to set.

        Raises:
            CardanoError: If setting fails.
        """
        if isinstance(value, list):
            value = CredentialSet.from_list(value)
        err = lib.cardano_update_committee_action_set_members_to_be_removed(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set members to be removed (error code: {err})"
            )

    @property
    def members_to_be_added(self) -> CommitteeMembersMap:
        """
        The map of committee members to be added.

        Returns:
            The CommitteeMembersMap of members to add.
        """
        ptr = lib.cardano_update_committee_action_get_members_to_be_added(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get members to be added")
        lib.cardano_committee_members_map_ref(ptr)
        return CommitteeMembersMap(ptr)

    @members_to_be_added.setter
    def members_to_be_added(self, value: CommitteeMembersMap) -> None:
        """
        Sets the members to be added.

        Args:
            value: The CommitteeMembersMap to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_update_committee_action_set_members_to_be_added(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set members to be added (error code: {err})")

    @property
    def quorum(self) -> UnitInterval:
        """
        The quorum threshold for the committee.

        Returns:
            The UnitInterval representing the quorum.
        """
        ptr = lib.cardano_update_committee_action_get_quorum(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get quorum")
        lib.cardano_unit_interval_ref(ptr)
        return UnitInterval(ptr)

    @quorum.setter
    def quorum(self, value: UnitInterval) -> None:
        """
        Sets the quorum threshold.

        Args:
            value: The UnitInterval to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_update_committee_action_set_quorum(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set quorum (error code: {err})")

    @property
    def governance_action_id(self) -> Optional[GovernanceActionId]:
        """
        The optional governance action ID that this action depends on.

        Returns:
            The GovernanceActionId if present, None otherwise.
        """
        ptr = lib.cardano_update_committee_action_get_governance_action_id(self._ptr)
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
        err = lib.cardano_update_committee_action_set_governance_action_id(
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
        err = lib.cardano_update_committee_action_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
