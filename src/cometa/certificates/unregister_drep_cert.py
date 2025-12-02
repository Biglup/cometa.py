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
from ..common.credential import Credential


class UnregisterDRepCert:
    """
    Represents a DRep unregistration certificate.

    This certificate is used when a Delegated Representative (DRep) wants to
    unregister and receive their deposit back.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("UnregisterDRepCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_unregister_drep_cert_t**", self._ptr)
            lib.cardano_unregister_drep_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> UnregisterDRepCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"UnregisterDRepCert(deposit={self.deposit})"

    @classmethod
    def new(cls, credential: Credential, deposit: int) -> UnregisterDRepCert:
        """
        Creates a new DRep unregistration certificate.

        Args:
            credential: The DRep credential to unregister.
            deposit: The deposit amount to be refunded (in lovelace).

        Returns:
            A new UnregisterDRepCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_unregister_drep_cert_t**")
        err = lib.cardano_unregister_drep_cert_new(credential._ptr, deposit, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create UnregisterDRepCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> UnregisterDRepCert:
        """
        Deserializes an UnregisterDRepCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new UnregisterDRepCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_unregister_drep_cert_t**")
        err = lib.cardano_unregister_drep_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize UnregisterDRepCert from CBOR (error code: {err})"
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
        err = lib.cardano_unregister_drep_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize UnregisterDRepCert to CBOR (error code: {err})"
            )

    @property
    def credential(self) -> Credential:
        """
        The DRep credential being unregistered.

        Returns:
            The Credential for the DRep.
        """
        ptr = lib.cardano_unregister_drep_cert_get_credential(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get credential")
        lib.cardano_credential_ref(ptr)
        return Credential(ptr)

    @credential.setter
    def credential(self, value: Credential) -> None:
        """
        Sets the DRep credential.

        Args:
            value: The Credential to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_unregister_drep_cert_set_credential(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set credential (error code: {err})")

    @property
    def deposit(self) -> int:
        """
        The deposit amount to be refunded (in lovelace).

        Returns:
            The deposit amount.
        """
        return int(lib.cardano_unregister_drep_cert_get_deposit(self._ptr))

    @deposit.setter
    def deposit(self, value: int) -> None:
        """
        Sets the deposit amount.

        Args:
            value: The deposit amount in lovelace.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_unregister_drep_cert_set_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set deposit (error code: {err})")

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
        err = lib.cardano_unregister_drep_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
