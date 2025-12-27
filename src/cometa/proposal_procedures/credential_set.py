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
from ..common.credential import Credential


class CredentialSet(Set["Credential"]):
    """
    Represents a set of credentials.

    This collection type is used in governance actions to specify
    sets of committee member credentials that should be added or removed.
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new CredentialSet.

        Args:
            ptr: Optional internal pointer to an existing credential set.
                If None, creates a new empty set.

        Raises:
            CardanoError: If initialization fails or ptr is invalid.
        """
        if ptr is None:
            out = ffi.new("cardano_credential_set_t**")
            err = lib.cardano_credential_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create CredentialSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("CredentialSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the credential set by releasing its resources."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_credential_set_t**", self._ptr)
            lib.cardano_credential_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CredentialSet:
        """Enters the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exits the context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the credential set."""
        return f"CredentialSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> CredentialSet:
        """
        Deserializes a CredentialSet from CBOR data.

        Args:
            reader: A CborReader positioned at the credential set data.

        Returns:
            A new CredentialSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_credential_set_t**")
        err = lib.cardano_credential_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize CredentialSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, credentials: Iterable[Credential]) -> CredentialSet:
        """
        Creates a CredentialSet from an iterable of Credential objects.

        Args:
            credentials: An iterable of Credential objects.

        Returns:
            A new CredentialSet containing all the credentials.

        Raises:
            CardanoError: If creation fails.
        """
        cred_set = cls()
        for cred in credentials:
            cred_set.add(cred)
        return cred_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the credential set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_credential_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize CredentialSet to CBOR (error code: {err})"
            )

    def add(self, credential: Credential) -> None:
        """
        Adds a credential to the set.

        Args:
            credential: The credential to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_credential_set_add(self._ptr, credential._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to CredentialSet (error code: {err})"
            )

    def get(self, index: int) -> Credential:
        """
        Retrieves a credential at the specified index.

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
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_credential_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from CredentialSet (error code: {err})"
            )
        return Credential(out[0])

    def __len__(self) -> int:
        """Returns the number of credentials in the set."""
        return int(lib.cardano_credential_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[Credential]:
        """Iterates over all credentials in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Credential:
        """Gets a credential by index using bracket notation."""
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
        err = lib.cardano_credential_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[Credential]") -> bool:
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
