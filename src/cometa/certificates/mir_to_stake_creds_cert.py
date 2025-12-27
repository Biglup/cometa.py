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
from .mir_cert_pot_type import MirCertPotType


class MirToStakeCredsCert:
    """
    Represents a Move Instantaneous Reward (MIR) certificate for transferring funds to stake credentials.

    This certificate is used to transfer rewards to a specified set of stake credentials
    from either the reserve or treasury pot.
    """

    def __init__(self, ptr) -> None:
        """
        Initializes a MirToStakeCredsCert from a C pointer.

        Args:
            ptr: The C pointer to the certificate object.

        Raises:
            CardanoError: If the pointer is NULL.
        """
        if ptr == ffi.NULL:
            raise CardanoError("MirToStakeCredsCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the certificate when the object is destroyed."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_mir_to_stake_creds_cert_t**", self._ptr)
            lib.cardano_mir_to_stake_creds_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MirToStakeCredsCert:
        """Enters the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exits the context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the certificate."""
        return f"MirToStakeCredsCert(pot={self.pot.name}, size={len(self)})"

    def __len__(self) -> int:
        """Returns the number of credential-to-amount mappings."""
        return int(lib.cardano_mir_to_stake_creds_cert_get_size(self._ptr))

    def __iter__(self) -> Iterator[Tuple[Credential, int]]:
        """Iterates over credential-to-amount mappings."""
        for i in range(len(self)):
            yield self.get_key_value_at(i)

    @classmethod
    def new(cls, pot_type: MirCertPotType) -> MirToStakeCredsCert:
        """
        Creates a new MIR to stake credentials certificate.

        Args:
            pot_type: The accounting pot from which funds will be drawn.

        Returns:
            A new MirToStakeCredsCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_mir_to_stake_creds_cert_t**")
        err = lib.cardano_mir_to_stake_creds_cert_new(pot_type.value, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create MirToStakeCredsCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MirToStakeCredsCert:
        """
        Deserializes a MirToStakeCredsCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new MirToStakeCredsCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_mir_to_stake_creds_cert_t**")
        err = lib.cardano_mir_to_stake_creds_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize MirToStakeCredsCert from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the certificate to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_mir_to_stake_creds_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize MirToStakeCredsCert to CBOR (error code: {err})"
            )

    @property
    def pot(self) -> MirCertPotType:
        """
        The accounting pot from which funds are drawn.

        Returns:
            The MirCertPotType indicating the source pot.
        """
        out = ffi.new("cardano_mir_cert_pot_type_t*")
        err = lib.cardano_mir_to_stake_creds_cert_get_pot(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pot type (error code: {err})")
        return MirCertPotType(out[0])

    @pot.setter
    def pot(self, value: MirCertPotType) -> None:
        """
        Sets the accounting pot from which funds are drawn.

        Args:
            value: The MirCertPotType to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_mir_to_stake_creds_cert_set_pot(self._ptr, value.value)
        if err != 0:
            raise CardanoError(f"Failed to set pot type (error code: {err})")

    def insert(self, credential: Credential, amount: int) -> None:
        """
        Inserts a credential-to-amount mapping.

        Args:
            credential: The stake credential to receive the reward.
            amount: The amount of ADA (in lovelace) to transfer.

        Raises:
            CardanoError: If the insertion fails.
        """
        err = lib.cardano_mir_to_stake_creds_cert_insert(
            self._ptr, credential._ptr, amount
        )
        if err != 0:
            raise CardanoError(f"Failed to insert credential mapping (error code: {err})")

    def get_key_at(self, index: int) -> Credential:
        """
        Retrieves the credential at the specified index.

        Args:
            index: The index of the credential to retrieve.

        Returns:
            The Credential at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_mir_to_stake_creds_cert_get_key_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get credential at index {index} (error code: {err})")
        return Credential(out[0])

    def get_value_at(self, index: int) -> int:
        """
        Retrieves the amount at the specified index.

        Args:
            index: The index of the amount to retrieve.

        Returns:
            The amount in lovelace.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("uint64_t*")
        err = lib.cardano_mir_to_stake_creds_cert_get_value_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get amount at index {index} (error code: {err})")
        return int(out[0])

    def get_key_value_at(self, index: int) -> Tuple[Credential, int]:
        """
        Retrieves both the credential and amount at the specified index.

        Args:
            index: The index of the mapping to retrieve.

        Returns:
            A tuple of (Credential, amount).

        Raises:
            CardanoError: If retrieval fails.
        """
        cred_out = ffi.new("cardano_credential_t**")
        amount_out = ffi.new("uint64_t*")
        err = lib.cardano_mir_to_stake_creds_cert_get_key_value_at(
            self._ptr, index, cred_out, amount_out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get key-value at index {index} (error code: {err})"
            )
        return Credential(cred_out[0]), int(amount_out[0])

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this certificate to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_mir_to_stake_creds_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
