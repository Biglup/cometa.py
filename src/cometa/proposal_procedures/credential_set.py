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

from typing import Iterator, Iterable

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.credential import Credential


class CredentialSet:
    """
    Represents a set of credentials.

    This collection type is used in governance actions to specify
    sets of committee member credentials that should be added or removed.
    """

    def __init__(self, ptr=None) -> None:
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
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_credential_set_t**", self._ptr)
            lib.cardano_credential_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CredentialSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
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
