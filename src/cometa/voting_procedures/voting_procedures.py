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
from typing import Iterator, List, Optional, Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.governance_action_id import GovernanceActionId
from .voter import Voter
from .voting_procedure import VotingProcedure


class VotingProcedures:
    """
    Represents a map of voting procedures in the Cardano governance system.

    This collection maps (Voter, GovernanceActionId) pairs to VotingProcedure objects.
    It provides a dict-like interface for managing voting procedures.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("VotingProcedures: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_voting_procedures_t**", self._ptr)
            lib.cardano_voting_procedures_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> VotingProcedures:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        voters = self.get_voters()
        return f"VotingProcedures(voters={len(voters)})"

    @classmethod
    def new(cls) -> VotingProcedures:
        """
        Creates a new empty VotingProcedures map.

        Returns:
            A new empty VotingProcedures instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_voting_procedures_t**")
        err = lib.cardano_voting_procedures_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create VotingProcedures (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> VotingProcedures:
        """
        Deserializes VotingProcedures from CBOR data.

        Args:
            reader: A CborReader positioned at the voting procedures data.

        Returns:
            A new VotingProcedures deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_voting_procedures_t**")
        err = lib.cardano_voting_procedures_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize VotingProcedures from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the voting procedures to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_voting_procedures_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize VotingProcedures to CBOR (error code: {err})")

    def insert(
        self,
        voter: Voter,
        governance_action_id: GovernanceActionId,
        procedure: VotingProcedure,
    ) -> None:
        """
        Inserts a voting procedure for a specific voter and governance action.

        Args:
            voter: The voter casting the vote.
            governance_action_id: The governance action being voted on.
            procedure: The voting procedure containing the vote and optional anchor.

        Raises:
            CardanoError: If insertion fails.

        Example:
            >>> procedures = VotingProcedures.new()
            >>> procedures.insert(voter, action_id, VotingProcedure.new(Vote.YES))
        """
        err = lib.cardano_voting_procedures_insert(
            self._ptr, voter._ptr, governance_action_id._ptr, procedure._ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to insert voting procedure (error code: {err})")

    def get(
        self, voter: Voter, governance_action_id: GovernanceActionId
    ) -> Optional[VotingProcedure]:
        """
        Retrieves a voting procedure for a specific voter and governance action.

        Args:
            voter: The voter who cast the vote.
            governance_action_id: The governance action that was voted on.

        Returns:
            The VotingProcedure if found, None otherwise.
        """
        proc_ptr = lib.cardano_voting_procedures_get(
            self._ptr, voter._ptr, governance_action_id._ptr
        )
        if proc_ptr == ffi.NULL:
            return None
        return VotingProcedure(proc_ptr)

    def __setitem__(
        self,
        key: Tuple[Voter, GovernanceActionId],
        value: VotingProcedure,
    ) -> None:
        """
        Sets a voting procedure using dict-like syntax.

        Args:
            key: A tuple of (Voter, GovernanceActionId).
            value: The VotingProcedure to store.

        Example:
            >>> procedures[voter, action_id] = VotingProcedure.new(Vote.YES)
        """
        voter, action_id = key
        self.insert(voter, action_id, value)

    def __getitem__(
        self, key: Tuple[Voter, GovernanceActionId]
    ) -> VotingProcedure:
        """
        Gets a voting procedure using dict-like syntax.

        Args:
            key: A tuple of (Voter, GovernanceActionId).

        Returns:
            The VotingProcedure.

        Raises:
            KeyError: If the key is not found.

        Example:
            >>> procedure = procedures[voter, action_id]
        """
        voter, action_id = key
        result = self.get(voter, action_id)
        if result is None:
            raise KeyError("No voting procedure found for voter and action ID")
        return result

    def get_voters(self) -> List[Voter]:
        """
        Returns a list of all voters in this collection.

        Returns:
            A list of Voter objects.
        """
        out = ffi.new("cardano_voter_list_t**")
        err = lib.cardano_voting_procedures_get_voters(self._ptr, out)
        if err != 0:
            return []
        if out[0] == ffi.NULL:
            return []

        voter_list_ptr = out[0]
        length = lib.cardano_voter_list_get_length(voter_list_ptr)
        voters = []
        for i in range(length):
            voter_out = ffi.new("cardano_voter_t**")
            err = lib.cardano_voter_list_get(voter_list_ptr, i, voter_out)
            if err == 0 and voter_out[0] != ffi.NULL:
                voters.append(Voter(voter_out[0]))

        # Unref the list
        list_ptr_ptr = ffi.new("cardano_voter_list_t**", voter_list_ptr)
        lib.cardano_voter_list_unref(list_ptr_ptr)

        return voters

    def get_governance_action_ids_by_voter(
        self, voter: Voter
    ) -> List[GovernanceActionId]:
        """
        Returns a list of governance action IDs for a specific voter.

        Args:
            voter: The voter to get action IDs for.

        Returns:
            A list of GovernanceActionId objects.
        """
        out = ffi.new("cardano_governance_action_id_list_t**")
        err = lib.cardano_voting_procedures_get_governance_ids_by_voter(
            self._ptr, voter._ptr, out
        )
        if err != 0:
            return []
        if out[0] == ffi.NULL:
            return []

        action_list_ptr = out[0]
        length = lib.cardano_governance_action_id_list_get_length(action_list_ptr)
        action_ids = []
        for i in range(length):
            action_out = ffi.new("cardano_governance_action_id_t**")
            err = lib.cardano_governance_action_id_list_get(action_list_ptr, i, action_out)
            if err == 0 and action_out[0] != ffi.NULL:
                action_ids.append(GovernanceActionId(action_out[0]))

        # Unref the list
        list_ptr_ptr = ffi.new("cardano_governance_action_id_list_t**", action_list_ptr)
        lib.cardano_governance_action_id_list_unref(list_ptr_ptr)

        return action_ids

    def items(self) -> Iterator[Tuple[Voter, GovernanceActionId, VotingProcedure]]:
        """
        Iterates over all (voter, governance_action_id, voting_procedure) tuples.

        Returns:
            An iterator over tuples of (Voter, GovernanceActionId, VotingProcedure).
        """
        for voter in self.get_voters():
            for action_id in self.get_governance_action_ids_by_voter(voter):
                procedure = self.get(voter, action_id)
                if procedure is not None:
                    yield (voter, action_id, procedure)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_voting_procedures_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
