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


class AuthCommitteeHotCert:
    """
    Represents a committee hot key authorization certificate.

    This certificate is used to authorize a hot key for a constitutional committee member.
    The hot key is used for voting, while the cold key remains secure offline.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("AuthCommitteeHotCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_auth_committee_hot_cert_t**", self._ptr)
            lib.cardano_auth_committee_hot_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AuthCommitteeHotCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "AuthCommitteeHotCert(...)"

    @classmethod
    def new(
        cls, committee_cold_cred: Credential, committee_hot_cred: Credential
    ) -> AuthCommitteeHotCert:
        """
        Creates a new committee hot key authorization certificate.

        Args:
            committee_cold_cred: The committee cold credential.
            committee_hot_cred: The committee hot credential to authorize.

        Returns:
            A new AuthCommitteeHotCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_auth_committee_hot_cert_t**")
        err = lib.cardano_auth_committee_hot_cert_new(
            committee_cold_cred._ptr, committee_hot_cred._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create AuthCommitteeHotCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> AuthCommitteeHotCert:
        """
        Deserializes an AuthCommitteeHotCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new AuthCommitteeHotCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_auth_committee_hot_cert_t**")
        err = lib.cardano_auth_committee_hot_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize AuthCommitteeHotCert from CBOR (error code: {err})"
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
        err = lib.cardano_auth_committee_hot_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize AuthCommitteeHotCert to CBOR (error code: {err})"
            )

    @property
    def committee_cold_credential(self) -> Credential:
        """
        The committee cold credential.

        Returns:
            The Credential for the committee cold key.
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_auth_committee_hot_cert_get_cold_cred(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get committee cold credential (error code: {err})"
            )
        return Credential(out[0])

    @committee_cold_credential.setter
    def committee_cold_credential(self, value: Credential) -> None:
        """
        Sets the committee cold credential.

        Args:
            value: The Credential to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_auth_committee_hot_cert_set_cold_cred(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set committee cold credential (error code: {err})"
            )

    @property
    def committee_hot_credential(self) -> Credential:
        """
        The committee hot credential.

        Returns:
            The Credential for the committee hot key.
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_auth_committee_hot_cert_get_hot_cred(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get committee hot credential (error code: {err})"
            )
        return Credential(out[0])

    @committee_hot_credential.setter
    def committee_hot_credential(self, value: Credential) -> None:
        """
        Sets the committee hot credential.

        Args:
            value: The Credential to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_auth_committee_hot_cert_set_hot_cred(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set committee hot credential (error code: {err})"
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
        err = lib.cardano_auth_committee_hot_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
