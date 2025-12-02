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

from typing import TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .mir_cert_type import MirCertType

if TYPE_CHECKING:
    from .mir_to_pot_cert import MirToPotCert
    from .mir_to_stake_creds_cert import MirToStakeCredsCert


class MirCert:
    """
    Represents a Move Instantaneous Reward (MIR) certificate.

    This certificate facilitates an instantaneous transfer of rewards within the system.
    It can either move funds between accounting pots (reserve/treasury) or transfer
    rewards to a specified set of stake credentials.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("MirCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_mir_cert_t**", self._ptr)
            lib.cardano_mir_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MirCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"MirCert(type={self.cert_type.name})"

    @classmethod
    def new_to_other_pot(cls, to_other_pot_cert: MirToPotCert) -> MirCert:
        """
        Creates a MIR certificate for transferring funds to another accounting pot.

        Args:
            to_other_pot_cert: A MirToPotCert specifying the pot transfer details.

        Returns:
            A new MirCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_mir_cert_t**")
        err = lib.cardano_mir_cert_new_to_other_pot(to_other_pot_cert._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create MirCert to other pot (error code: {err})")
        return cls(out[0])

    @classmethod
    def new_to_stake_creds(cls, to_stake_creds_cert: MirToStakeCredsCert) -> MirCert:
        """
        Creates a MIR certificate for transferring funds to stake credentials.

        Args:
            to_stake_creds_cert: A MirToStakeCredsCert specifying the stake credential transfers.

        Returns:
            A new MirCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_mir_cert_t**")
        err = lib.cardano_mir_cert_new_to_stake_creds(to_stake_creds_cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create MirCert to stake creds (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MirCert:
        """
        Deserializes a MirCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new MirCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_mir_cert_t**")
        err = lib.cardano_mir_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize MirCert from CBOR (error code: {err})"
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
        err = lib.cardano_mir_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize MirCert to CBOR (error code: {err})"
            )

    @property
    def cert_type(self) -> MirCertType:
        """
        The type of this MIR certificate.

        Returns:
            The MirCertType indicating whether this is a pot transfer or stake credentials transfer.
        """
        out = ffi.new("cardano_mir_cert_type_t*")
        err = lib.cardano_mir_cert_get_type(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get MIR cert type (error code: {err})")
        return MirCertType(out[0])

    def as_to_other_pot(self) -> MirToPotCert:
        """
        Retrieves this certificate as a MirToPotCert.

        Returns:
            The underlying MirToPotCert.

        Raises:
            CardanoError: If this certificate is not a pot transfer type.
        """
        from .mir_to_pot_cert import MirToPotCert

        out = ffi.new("cardano_mir_to_pot_cert_t**")
        err = lib.cardano_mir_cert_as_to_other_pot(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get MirCert as to_other_pot (error code: {err})"
            )
        return MirToPotCert(out[0])

    def as_to_stake_creds(self) -> MirToStakeCredsCert:
        """
        Retrieves this certificate as a MirToStakeCredsCert.

        Returns:
            The underlying MirToStakeCredsCert.

        Raises:
            CardanoError: If this certificate is not a stake credentials transfer type.
        """
        from .mir_to_stake_creds_cert import MirToStakeCredsCert

        out = ffi.new("cardano_mir_to_stake_creds_cert_t**")
        err = lib.cardano_mir_cert_as_to_stake_creds(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get MirCert as to_stake_creds (error code: {err})"
            )
        return MirToStakeCredsCert(out[0])

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
        err = lib.cardano_mir_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
