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
from ..pool_params.pool_params import PoolParams


class PoolRegistrationCert:
    """
    Represents a pool registration certificate.

    This certificate is used to register a new stake pool on the Cardano blockchain.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PoolRegistrationCert: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_pool_registration_cert_t**", self._ptr)
            lib.cardano_pool_registration_cert_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PoolRegistrationCert:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "PoolRegistrationCert(...)"

    @classmethod
    def new(cls, params: PoolParams) -> PoolRegistrationCert:
        """
        Creates a new pool registration certificate.

        Args:
            params: The pool parameters for the new pool.

        Returns:
            A new PoolRegistrationCert instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_pool_registration_cert_t**")
        err = lib.cardano_pool_registration_cert_new(params._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PoolRegistrationCert (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PoolRegistrationCert:
        """
        Deserializes a PoolRegistrationCert from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new PoolRegistrationCert deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_pool_registration_cert_t**")
        err = lib.cardano_pool_registration_cert_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PoolRegistrationCert from CBOR (error code: {err})"
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
        err = lib.cardano_pool_registration_cert_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PoolRegistrationCert to CBOR (error code: {err})"
            )

    @property
    def params(self) -> PoolParams:
        """
        The pool parameters.

        Returns:
            The PoolParams for this registration.
        """
        out = ffi.new("cardano_pool_params_t**")
        err = lib.cardano_pool_registration_cert_get_params(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            raise CardanoError(f"Failed to get pool params (error code: {err})")
        lib.cardano_pool_params_ref(out[0])
        return PoolParams(out[0])

    @params.setter
    def params(self, value: PoolParams) -> None:
        """
        Sets the pool parameters.

        Args:
            value: The PoolParams to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_pool_registration_cert_set_params(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set pool params (error code: {err})")

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
        err = lib.cardano_pool_registration_cert_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
