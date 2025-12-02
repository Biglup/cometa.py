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
from ..common.credential import Credential
from ..common.anchor import Anchor


class RegisterDRepCert:
    """
    Represents a DRep registration certificate.

    This certificate is used to register a new Delegated Representative (DRep)
    who can participate in governance by voting on proposals.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("RegisterDRepCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_register_drep_cert_t**", self._ptr)
            lib.cardano_register_drep_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> RegisterDRepCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"RegisterDRepCert(deposit={self.deposit})"

    @classmethod
    def new(
        cls,
        drep_credential: Credential,
        deposit: int,
        anchor: Optional[Anchor] = None,
    ) -> RegisterDRepCert:
        """
        Creates a new DRep registration certificate.

        Args:
            drep_credential: The DRep credential to register.
            deposit: The deposit amount in lovelace.
            anchor: Optional anchor with DRep metadata.

        Returns:
            A new RegisterDRepCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_register_drep_cert_t**")
        anchor_ptr = anchor._ptr if anchor is not None else ffi.NULL
        err = lib.cardano_register_drep_cert_new(
            drep_credential._ptr, deposit, anchor_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create RegisterDRepCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> RegisterDRepCert:
        """
        Deserializes a RegisterDRepCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new RegisterDRepCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_register_drep_cert_t**")
        err = lib.cardano_register_drep_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize RegisterDRepCert from CBOR (error code: {err})"
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
        err = lib.cardano_register_drep_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize RegisterDRepCert to CBOR (error code: {err})"
            )

    @property
    def credential(self) -> Credential:
        """
        The DRep credential being registered.

        Returns:
            The Credential for the DRep.
        """
        ptr = lib.cardano_register_drep_cert_get_credential(self._ptr)
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
        err = lib.cardano_register_drep_cert_set_credential(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set credential (error code: {err})")

    @property
    def deposit(self) -> int:
        """
        The deposit amount in lovelace.

        Returns:
            The deposit amount.
        """
        return int(lib.cardano_register_drep_cert_get_deposit(self._ptr))

    @deposit.setter
    def deposit(self, value: int) -> None:
        """
        Sets the deposit amount.

        Args:
            value: The deposit amount in lovelace.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_register_drep_cert_set_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set deposit (error code: {err})")

    @property
    def anchor(self) -> Optional[Anchor]:
        """
        The optional anchor with DRep metadata.

        Returns:
            The Anchor if present, None otherwise.
        """
        ptr = lib.cardano_register_drep_cert_get_anchor(self._ptr)
        if ptr == ffi.NULL:
            return None
        lib.cardano_anchor_ref(ptr)
        return Anchor(ptr)

    @anchor.setter
    def anchor(self, value: Optional[Anchor]) -> None:
        """
        Sets the anchor.

        Args:
            value: The Anchor to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        anchor_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_register_drep_cert_set_anchor(self._ptr, anchor_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set anchor (error code: {err})")

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
        err = lib.cardano_register_drep_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
