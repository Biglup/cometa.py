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

from typing import Iterator, Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.credential import Credential
from ..common.unit_interval import UnitInterval
from .credential_set import CredentialSet


class Committee:
    """
    Represents the constitutional committee.

    The constitutional committee represents a set of individuals or entities
    (each associated with a pair of Ed25519 credentials) that are collectively
    responsible for ensuring that the Constitution is respected.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Committee: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_committee_t**", self._ptr)
            lib.cardano_committee_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Committee:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "Committee(...)"

    @classmethod
    def new(cls, quorum_threshold: UnitInterval) -> Committee:
        """
        Creates a new constitutional committee.

        Args:
            quorum_threshold: The minimum percentage of committee members
                             required to participate in a vote for it to be valid.

        Returns:
            A new Committee instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_committee_t**")
        err = lib.cardano_committee_new(quorum_threshold._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Committee (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Committee:
        """
        Deserializes a Committee from CBOR data.

        Args:
            reader: A CborReader positioned at the committee data.

        Returns:
            A new Committee deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_committee_t**")
        err = lib.cardano_committee_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Committee from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the committee to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_committee_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Committee to CBOR (error code: {err})"
            )

    @property
    def quorum_threshold(self) -> UnitInterval:
        """
        The quorum threshold for the committee.

        Returns:
            The UnitInterval representing the minimum voting percentage.
        """
        ptr = lib.cardano_committee_get_quorum_threshold(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get quorum threshold")
        lib.cardano_unit_interval_ref(ptr)
        return UnitInterval(ptr)

    @quorum_threshold.setter
    def quorum_threshold(self, value: UnitInterval) -> None:
        """
        Sets the quorum threshold.

        Args:
            value: The UnitInterval to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_committee_set_quorum_threshold(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set quorum threshold (error code: {err})")

    def members_keys(self) -> CredentialSet:
        """
        Retrieves all member credentials.

        Returns:
            A CredentialSet containing all committee member credentials.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_credential_set_t**")
        err = lib.cardano_committee_members_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get member keys (error code: {err})")
        return CredentialSet(out[0])

    def add_member(self, credential: Credential, epoch: int) -> None:
        """
        Adds a member to the committee.

        Args:
            credential: The credential of the member to add.
            epoch: The epoch when the member's term expires.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_committee_add_member(self._ptr, credential._ptr, epoch)
        if err != 0:
            raise CardanoError(f"Failed to add member (error code: {err})")

    def get_member_epoch(self, credential: Credential) -> int:
        """
        Gets the term epoch for a specific member.

        Args:
            credential: The credential of the member to look up.

        Returns:
            The epoch when the member's term expires, or 0 if not found.
        """
        return int(lib.cardano_committee_get_member_epoch(self._ptr, credential._ptr))

    def get_key_at(self, index: int) -> Credential:
        """
        Retrieves the credential at a specific index.

        Args:
            index: The index of the credential to retrieve.

        Returns:
            The Credential at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_committee_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get key at index {index} (error code: {err})")
        return Credential(out[0])

    def get_value_at(self, index: int) -> int:
        """
        Retrieves the term epoch at a specific index.

        Args:
            index: The index of the epoch to retrieve.

        Returns:
            The term epoch at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        value = ffi.new("uint64_t*")
        err = lib.cardano_committee_get_value_at(self._ptr, index, value)
        if err != 0:
            raise CardanoError(
                f"Failed to get value at index {index} (error code: {err})"
            )
        return int(value[0])

    def get_key_value_at(self, index: int) -> tuple[Credential, int]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple containing the Credential and term epoch at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        key_out = ffi.new("cardano_credential_t**")
        value_out = ffi.new("uint64_t*")
        err = lib.cardano_committee_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (Credential(key_out[0]), int(value_out[0]))

    def __iter__(self) -> Iterator[Credential]:
        """Iterates over all member credentials."""
        keys = self.members_keys()
        for i in range(len(keys)):
            yield keys.get(i)

    def items(self) -> Iterator[Tuple[Credential, int]]:
        """Returns an iterator over (credential, epoch) pairs."""
        keys = self.members_keys()
        for i in range(len(keys)):
            cred = keys.get(i)
            epoch = self.get_member_epoch(cred)
            yield cred, epoch
