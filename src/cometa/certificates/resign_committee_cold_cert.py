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


class ResignCommitteeColdCert:
    """
    Represents a committee cold key resignation certificate.

    This certificate is used when a constitutional committee member wants to resign
    from their position.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ResignCommitteeColdCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_resign_committee_cold_cert_t**", self._ptr)
            lib.cardano_resign_committee_cold_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ResignCommitteeColdCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "ResignCommitteeColdCert(...)"

    @classmethod
    def new(
        cls, committee_cold_cred: Credential, anchor: Optional[Anchor] = None
    ) -> ResignCommitteeColdCert:
        """
        Creates a new committee cold key resignation certificate.

        Args:
            committee_cold_cred: The committee cold credential to resign.
            anchor: Optional anchor with resignation metadata.

        Returns:
            A new ResignCommitteeColdCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_resign_committee_cold_cert_t**")
        anchor_ptr = anchor._ptr if anchor is not None else ffi.NULL
        err = lib.cardano_resign_committee_cold_cert_new(
            committee_cold_cred._ptr, anchor_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ResignCommitteeColdCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ResignCommitteeColdCert:
        """
        Deserializes a ResignCommitteeColdCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new ResignCommitteeColdCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_resign_committee_cold_cert_t**")
        err = lib.cardano_resign_committee_cold_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ResignCommitteeColdCert from CBOR (error code: {err})"
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
        err = lib.cardano_resign_committee_cold_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ResignCommitteeColdCert to CBOR (error code: {err})"
            )

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
        err = lib.cardano_resign_committee_cold_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    @property
    def committee_cold_credential(self) -> Credential:
        """
        The committee cold credential being resigned.

        Returns:
            The Credential for the committee cold key.
        """
        ptr = lib.cardano_resign_committee_cold_cert_get_credential(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get committee cold credential")
        lib.cardano_credential_ref(ptr)
        return Credential(ptr)

    @committee_cold_credential.setter
    def committee_cold_credential(self, value: Credential) -> None:
        """
        Sets the committee cold credential.

        Args:
            value: The Credential to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_resign_committee_cold_cert_set_credential(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set committee cold credential (error code: {err})"
            )

    @property
    def anchor(self) -> Optional[Anchor]:
        """
        The optional anchor with resignation metadata.

        Returns:
            The Anchor if present, None otherwise.
        """
        ptr = lib.cardano_resign_committee_cold_cert_get_anchor(self._ptr)
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
        err = lib.cardano_resign_committee_cold_cert_set_anchor(self._ptr, anchor_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set anchor (error code: {err})")
