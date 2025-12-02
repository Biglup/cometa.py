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
from collections.abc import Set

from typing import Iterable, Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .proposal_procedure import ProposalProcedure


class ProposalProcedureSet(Set["ProposalProcedure"]):
    """
    Represents a set of proposal procedures.

    This collection type is used in transaction bodies to hold multiple
    governance proposal procedures.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_proposal_procedure_set_t**")
            err = lib.cardano_proposal_procedure_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create ProposalProcedureSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("ProposalProcedureSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_proposal_procedure_set_t**", self._ptr)
            lib.cardano_proposal_procedure_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProposalProcedureSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ProposalProcedureSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ProposalProcedureSet:
        """
        Deserializes a ProposalProcedureSet from CBOR data.

        Args:
            reader: A CborReader positioned at the proposal procedure set data.

        Returns:
            A new ProposalProcedureSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_proposal_procedure_set_t**")
        err = lib.cardano_proposal_procedure_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ProposalProcedureSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, proposals: Iterable[ProposalProcedure]) -> ProposalProcedureSet:
        """
        Creates a ProposalProcedureSet from an iterable of ProposalProcedure objects.

        Args:
            proposals: An iterable of ProposalProcedure objects.

        Returns:
            A new ProposalProcedureSet containing all the proposals.

        Raises:
            CardanoError: If creation fails.
        """
        proposal_set = cls()
        for proposal in proposals:
            proposal_set.add(proposal)
        return proposal_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the proposal procedure set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_proposal_procedure_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ProposalProcedureSet to CBOR (error code: {err})"
            )

    def add(self, proposal: ProposalProcedure) -> None:
        """
        Adds a proposal procedure to the set.

        Args:
            proposal: The ProposalProcedure to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_proposal_procedure_set_add(self._ptr, proposal._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to ProposalProcedureSet (error code: {err})"
            )

    def get(self, index: int) -> ProposalProcedure:
        """
        Retrieves a proposal procedure at the specified index.

        Args:
            index: The index of the proposal procedure to retrieve.

        Returns:
            The ProposalProcedure at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from ProposalProcedureSet (error code: {err})"
            )
        return ProposalProcedure(out[0])

    def __len__(self) -> int:
        """Returns the number of proposal procedures in the set."""
        return int(lib.cardano_proposal_procedure_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[ProposalProcedure]:
        """Iterates over all proposal procedures in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> ProposalProcedure:
        """Gets a proposal procedure by index using bracket notation."""
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the set is not empty."""
        return len(self) > 0

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
        err = lib.cardano_proposal_procedure_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[ProposalProcedure]") -> bool:
        """
        Returns True if the set has no elements in common with other.

        Args:
            other: Another iterable to compare with.

        Returns:
            True if the sets are disjoint.
        """
        for item in other:
            if item in self:
                return False
        return True
