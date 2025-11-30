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
from ..common.anchor import Anchor
from .vote import Vote


class VotingProcedure:
    """
    Represents a voting procedure in the Cardano governance system.

    A voting procedure consists of:
    - A vote (Yes, No, or Abstain)
    - An optional anchor that links the vote to arbitrary off-chain JSON metadata
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("VotingProcedure: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_voting_procedure_t**", self._ptr)
            lib.cardano_voting_procedure_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> VotingProcedure:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        anchor = self.anchor
        if anchor:
            return f"VotingProcedure(vote={self.vote.name}, anchor={anchor.url!r})"
        return f"VotingProcedure(vote={self.vote.name})"

    @classmethod
    def new(cls, vote: Vote, anchor: Optional[Anchor] = None) -> VotingProcedure:
        """
        Creates a new voting procedure.

        Args:
            vote: The vote choice (YES, NO, or ABSTAIN).
            anchor: Optional anchor linking to off-chain metadata.

        Returns:
            A new VotingProcedure instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> procedure = VotingProcedure.new(Vote.YES)
            >>> procedure = VotingProcedure.new(Vote.NO, anchor=my_anchor)
        """
        out = ffi.new("cardano_voting_procedure_t**")
        anchor_ptr = anchor._ptr if anchor is not None else ffi.NULL
        err = lib.cardano_voting_procedure_new(int(vote), anchor_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create VotingProcedure (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> VotingProcedure:
        """
        Deserializes a VotingProcedure from CBOR data.

        Args:
            reader: A CborReader positioned at the voting procedure data.

        Returns:
            A new VotingProcedure deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_voting_procedure_t**")
        err = lib.cardano_voting_procedure_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize VotingProcedure from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the voting procedure to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_voting_procedure_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize VotingProcedure to CBOR (error code: {err})")

    @property
    def vote(self) -> Vote:
        """Returns the vote choice."""
        return Vote(lib.cardano_voting_procedure_get_vote(self._ptr))

    @vote.setter
    def vote(self, value: Vote) -> None:
        """Sets the vote choice."""
        err = lib.cardano_voting_procedure_set_vote(self._ptr, int(value))
        if err != 0:
            raise CardanoError(f"Failed to set vote (error code: {err})")

    @property
    def anchor(self) -> Optional[Anchor]:
        """Returns the anchor, or None if not set."""
        anchor_ptr = lib.cardano_voting_procedure_get_anchor(self._ptr)
        if anchor_ptr == ffi.NULL:
            return None
        return Anchor(anchor_ptr)

    @anchor.setter
    def anchor(self, value: Optional[Anchor]) -> None:
        """Sets or clears the anchor."""
        anchor_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_voting_procedure_set_anchor(self._ptr, anchor_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set anchor (error code: {err})")
