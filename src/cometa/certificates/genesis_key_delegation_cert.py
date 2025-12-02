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
from ..cryptography.blake2b_hash import Blake2bHash


class GenesisKeyDelegationCert:
    """
    Represents a genesis key delegation certificate.

    This certificate is used in the Shelley era to delegate genesis keys.
    It is a legacy certificate type not used in later eras.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("GenesisKeyDelegationCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_genesis_key_delegation_cert_t**", self._ptr)
            lib.cardano_genesis_key_delegation_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> GenesisKeyDelegationCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "GenesisKeyDelegationCert(...)"

    @classmethod
    def new(
        cls,
        genesis_hash: Blake2bHash,
        genesis_delegate_hash: Blake2bHash,
        vrf_key_hash: Blake2bHash,
    ) -> GenesisKeyDelegationCert:
        """
        Creates a new genesis key delegation certificate.

        Args:
            genesis_hash: The hash of the genesis key.
            genesis_delegate_hash: The hash of the genesis delegate key.
            vrf_key_hash: The hash of the VRF key.

        Returns:
            A new GenesisKeyDelegationCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_genesis_key_delegation_cert_t**")
        err = lib.cardano_genesis_key_delegation_cert_new(
            genesis_hash._ptr, genesis_delegate_hash._ptr, vrf_key_hash._ptr, out
        )
        if err != 0:
            raise CardanoError(f"Failed to create GenesisKeyDelegationCert (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> GenesisKeyDelegationCert:
        """
        Deserializes a GenesisKeyDelegationCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new GenesisKeyDelegationCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_genesis_key_delegation_cert_t**")
        err = lib.cardano_genesis_key_delegation_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize GenesisKeyDelegationCert from CBOR (error code: {err})"
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
        err = lib.cardano_genesis_key_delegation_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize GenesisKeyDelegationCert to CBOR (error code: {err})"
            )

    @property
    def genesis_hash(self) -> Blake2bHash:
        """
        The hash of the genesis key.

        Returns:
            The Blake2bHash of the genesis key.
        """
        ptr = lib.cardano_genesis_key_delegation_cert_get_genesis_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get genesis hash")
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @genesis_hash.setter
    def genesis_hash(self, value: Blake2bHash) -> None:
        """
        Sets the genesis hash.

        Args:
            value: The Blake2bHash of the genesis key.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_genesis_key_delegation_cert_set_genesis_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set genesis hash (error code: {err})")

    @property
    def genesis_delegate_hash(self) -> Blake2bHash:
        """
        The hash of the genesis delegate key.

        Returns:
            The Blake2bHash of the genesis delegate key.
        """
        ptr = lib.cardano_genesis_key_delegation_cert_get_genesis_delegate_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get genesis delegate hash")
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @genesis_delegate_hash.setter
    def genesis_delegate_hash(self, value: Blake2bHash) -> None:
        """
        Sets the genesis delegate hash.

        Args:
            value: The Blake2bHash of the genesis delegate key.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_genesis_key_delegation_cert_set_genesis_delegate_hash(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set genesis delegate hash (error code: {err})")

    @property
    def vrf_key_hash(self) -> Blake2bHash:
        """
        The hash of the VRF key.

        Returns:
            The Blake2bHash of the VRF key.
        """
        ptr = lib.cardano_genesis_key_delegation_cert_get_vrf_key_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get VRF key hash")
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @vrf_key_hash.setter
    def vrf_key_hash(self, value: Blake2bHash) -> None:
        """
        Sets the VRF key hash.

        Args:
            value: The Blake2bHash of the VRF key.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_genesis_key_delegation_cert_set_vrf_key_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set VRF key hash (error code: {err})")

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
        err = lib.cardano_genesis_key_delegation_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
