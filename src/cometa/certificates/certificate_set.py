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

from typing import Iterable, Iterator, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .certificate import Certificate, CertificateUnion


class CertificateSet(Set["Certificate"]):
    """
    Represents a set of Cardano certificates.

    This is a collection type that holds multiple Certificate objects.
    It is typically used within transactions to include multiple certificate
    operations in a single transaction.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("CertificateSet: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_certificate_set_t**", self._ptr)
            lib.cardano_certificate_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CertificateSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CertificateSet(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of certificates in the set."""
        return int(lib.cardano_certificate_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[Certificate]:
        """Iterates over the certificates in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Certificate:
        """Gets a certificate at the specified index."""
        if index < 0:
            index = len(self) + index
        if index < 0 or index >= len(self):
            raise IndexError("CertificateSet index out of range")
        return self.get(index)

    @classmethod
    def new(cls) -> CertificateSet:
        """
        Creates a new empty certificate set.

        Returns:
            A new CertificateSet instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_certificate_set_t**")
        err = lib.cardano_certificate_set_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create CertificateSet (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> CertificateSet:
        """
        Deserializes a CertificateSet from CBOR data.

        Args:
            reader: A CborReader positioned at the set data.

        Returns:
            A new CertificateSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_certificate_set_t**")
        err = lib.cardano_certificate_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize CertificateSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, certificates: Iterable[Union[Certificate, CertificateUnion]]) -> CertificateSet:
        """
        Creates a CertificateSet from an iterable of Certificate objects.

        Args:
            certificates: An iterable of Certificate or specific certificate type objects.

        Returns:
            A new CertificateSet containing all the certificates.

        Raises:
            CardanoError: If creation fails.
        """
        cert_set = cls.new()
        for cert in certificates:
            cert_set.add(cert)
        return cert_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the certificate set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_certificate_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize CertificateSet to CBOR (error code: {err})"
            )

    def get(self, index: int) -> Certificate:
        """
        Gets the certificate at the specified index.

        Args:
            index: The index of the certificate to retrieve.

        Returns:
            The Certificate at the specified index.

        Raises:
            CardanoError: If retrieval fails.
        """
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get certificate at index {index} (error code: {err})"
            )
        return Certificate(out[0])

    def add(self, certificate: Union[Certificate, CertificateUnion]) -> None:
        """
        Adds a certificate to the set.

        Args:
            certificate: The Certificate to add. Can be either a Certificate instance
                        or any specific certificate type (e.g., StakeRegistrationCert),
                        which will be automatically converted.

        Raises:
            CardanoError: If adding fails.

        Example:
            >>> cert_set = CertificateSet.new()
            >>> stake_reg = StakeRegistrationCert.new(credential)
            >>> cert_set.add(stake_reg)  # Automatic conversion
        """
        # Convert to Certificate if needed
        if not isinstance(certificate, Certificate):
            certificate = Certificate(certificate)
        err = lib.cardano_certificate_set_add(self._ptr, certificate._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add certificate to set (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this certificate set to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_certificate_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[Certificate]") -> bool:
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
