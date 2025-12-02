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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .mir_cert_pot_type import MirCertPotType


class MirToPotCert:
    """
    Represents a Move Instantaneous Reward (MIR) certificate for transferring funds between pots.

    This certificate is used to transfer a specified amount of ADA from one accounting pot
    (reserve or treasury) to the other pot.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("MirToPotCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_mir_to_pot_cert_t**", self._ptr)
            lib.cardano_mir_to_pot_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> MirToPotCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"MirToPotCert(pot={self.pot.name}, amount={self.amount})"

    @classmethod
    def new(cls, pot_type: MirCertPotType, amount: int) -> MirToPotCert:
        """
        Creates a new MIR to pot certificate.

        Args:
            pot_type: The accounting pot from which funds will be drawn.
            amount: The amount of ADA to be transferred.

        Returns:
            A new MirToPotCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_mir_to_pot_cert_t**")
        err = lib.cardano_mir_to_pot_cert_new(pot_type.value, amount, out)
        if err != 0:
            raise CardanoError(f"Failed to create MirToPotCert (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> MirToPotCert:
        """
        Deserializes a MirToPotCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new MirToPotCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_mir_to_pot_cert_t**")
        err = lib.cardano_mir_to_pot_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize MirToPotCert from CBOR (error code: {err})"
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
        err = lib.cardano_mir_to_pot_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize MirToPotCert to CBOR (error code: {err})"
            )

    @property
    def pot(self) -> MirCertPotType:
        """
        The accounting pot from which funds are drawn.

        Returns:
            The MirCertPotType indicating the source pot.
        """
        out = ffi.new("cardano_mir_cert_pot_type_t*")
        err = lib.cardano_mir_to_pot_cert_get_pot(self._ptr, out)
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
        err = lib.cardano_mir_to_pot_cert_set_pot(self._ptr, value.value)
        if err != 0:
            raise CardanoError(f"Failed to set pot type (error code: {err})")

    @property
    def amount(self) -> int:
        """
        The amount of ADA to be transferred.

        Returns:
            The amount in lovelace.
        """
        out = ffi.new("uint64_t*")
        err = lib.cardano_mir_to_pot_cert_get_amount(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get amount (error code: {err})")
        return int(out[0])

    @amount.setter
    def amount(self, value: int) -> None:
        """
        Sets the amount of ADA to be transferred.

        Args:
            value: The amount in lovelace.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_mir_to_pot_cert_set_amount(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set amount (error code: {err})")

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
        err = lib.cardano_mir_to_pot_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
