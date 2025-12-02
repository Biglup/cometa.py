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
from collections.abc import Mapping

from typing import Iterator, Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.credential import Credential
from .credential_set import CredentialSet


class CommitteeMembersMap(Mapping["Credential", "int"]):
    """
    Represents a map of committee member credentials to their term epochs.

    This collection type is used in governance actions to specify
    committee members and when their terms expire.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_committee_members_map_t**")
            err = lib.cardano_committee_members_map_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create CommitteeMembersMap (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("CommitteeMembersMap: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_committee_members_map_t**", self._ptr)
            lib.cardano_committee_members_map_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CommitteeMembersMap:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CommitteeMembersMap(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> CommitteeMembersMap:
        """
        Deserializes a CommitteeMembersMap from CBOR data.

        Args:
            reader: A CborReader positioned at the committee members map data.

        Returns:
            A new CommitteeMembersMap deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_committee_members_map_t**")
        err = lib.cardano_committee_members_map_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize CommitteeMembersMap from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the committee members map to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_committee_members_map_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize CommitteeMembersMap to CBOR (error code: {err})"
            )

    def insert(self, key: Credential, value: int) -> None:
        """
        Inserts or updates a committee member credential with its term epoch.

        Args:
            key: The credential of the committee member.
            value: The epoch when the member's term expires.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_committee_members_map_insert(self._ptr, key._ptr, value)
        if err != 0:
            raise CardanoError(
                f"Failed to insert into CommitteeMembersMap (error code: {err})"
            )

    def get(  # pylint: disable=arguments-differ
        self, key: Credential, default: "int | None" = None
    ) -> "int | None":
        """
        Retrieves the term epoch for a given committee member credential.

        Args:
            key: The credential to look up.
            default: Value to return if key is not found. Defaults to None.

        Returns:
            The epoch when the member's term expires, or default if not found.
        """
        value = ffi.new("uint64_t*")
        err = lib.cardano_committee_members_map_get(self._ptr, key._ptr, value)
        if err != 0:
            return default
        return int(value[0])

    def get_keys(self) -> CredentialSet:
        """
        Retrieves all keys (credentials) from the map.

        Returns:
            A CredentialSet containing all committee member credentials.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_credential_set_t**")
        err = lib.cardano_committee_members_map_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get keys from CommitteeMembersMap (error code: {err})"
            )
        return CredentialSet(out[0])

    def get_key_at(self, index: int) -> Credential:
        """
        Retrieves the credential at a specific index.

        Args:
            index: The index of the credential to retrieve.

        Returns:
            The Credential at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_committee_members_map_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get key at index {index} (error code: {err})"
            )
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
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        value = ffi.new("uint64_t*")
        err = lib.cardano_committee_members_map_get_value_at(self._ptr, index, value)
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
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for map of length {len(self)}"
            )
        key_out = ffi.new("cardano_credential_t**")
        value_out = ffi.new("uint64_t*")
        err = lib.cardano_committee_members_map_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (Credential(key_out[0]), int(value_out[0]))

    def __len__(self) -> int:
        """Returns the number of entries in the map."""
        return int(lib.cardano_committee_members_map_get_length(self._ptr))

    def __iter__(self) -> Iterator[Credential]:
        """Iterates over all keys (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i)

    def __getitem__(self, key: Credential) -> int:
        """Gets a value by key using bracket notation."""
        return self.get(key)

    def __setitem__(self, key: Credential, value: int) -> None:
        """Sets a value by key using bracket notation."""
        self.insert(key, value)

    def __bool__(self) -> bool:
        """Returns True if the map is not empty."""
        return len(self) > 0

    def __contains__(self, item: Credential) -> bool:
        """Checks if a credential is in the map."""
        return self.get(item) is not None

    def keys(self) -> Iterator[Credential]:
        """Returns an iterator over keys (like Python dict)."""
        return iter(self)

    def values(self) -> Iterator[int]:
        """Returns an iterator over values (like Python dict)."""
        for i in range(len(self)):
            yield self.get_value_at(i)

    def items(self) -> Iterator[Tuple[Credential, int]]:
        """Returns an iterator over (key, value) pairs (like Python dict)."""
        for i in range(len(self)):
            yield self.get_key_at(i), self.get_value_at(i)

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
        err = lib.cardano_committee_members_map_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
