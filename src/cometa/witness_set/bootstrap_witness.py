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


class BootstrapWitness:
    """
    Represents a bootstrap witness for Byron-era addresses.

    Bootstrap witnesses are used to sign transactions that spend from
    Byron-era addresses. They include additional information beyond
    just the public key and signature, such as the chain code and
    address attributes.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("BootstrapWitness: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_bootstrap_witness_t**", self._ptr)
            lib.cardano_bootstrap_witness_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> BootstrapWitness:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "BootstrapWitness(...)"

    @classmethod
    def new(
        cls,
        vkey: bytes,
        signature: bytes,
        chain_code: bytes,
        attributes: bytes,
    ) -> BootstrapWitness:
        """
        Creates a new bootstrap witness.

        Args:
            vkey: The verification key (32 bytes for Ed25519).
            signature: The signature (64 bytes for Ed25519).
            chain_code: The chain code (32 bytes).
            attributes: The address attributes (CBOR encoded).

        Returns:
            A new BootstrapWitness instance.

        Raises:
            CardanoError: If creation fails.
        """
        vkey_ptr = ffi.new("cardano_ed25519_public_key_t**")
        if lib.cardano_ed25519_public_key_from_bytes(vkey, len(vkey), vkey_ptr) != 0:
            raise CardanoError("Failed to create public key")

        sig_ptr = ffi.new("cardano_ed25519_signature_t**")
        if lib.cardano_ed25519_signature_from_bytes(signature, len(signature), sig_ptr) != 0:
            lib.cardano_ed25519_public_key_unref(vkey_ptr)
            raise CardanoError("Failed to create signature")

        chain_code_ptr = lib.cardano_buffer_new_from(
            ffi.from_buffer("byte_t[]", chain_code), len(chain_code)
        )
        if chain_code_ptr == ffi.NULL:
            lib.cardano_ed25519_public_key_unref(vkey_ptr)
            lib.cardano_ed25519_signature_unref(sig_ptr)
            raise CardanoError("Failed to create chain code buffer")

        attr_ptr = lib.cardano_buffer_new_from(
            ffi.from_buffer("byte_t[]", attributes), len(attributes)
        )
        if attr_ptr == ffi.NULL:
            lib.cardano_ed25519_public_key_unref(vkey_ptr)
            lib.cardano_ed25519_signature_unref(sig_ptr)
            lib.cardano_buffer_unref(ffi.new("cardano_buffer_t**", chain_code_ptr))
            raise CardanoError("Failed to create attributes buffer")

        out = ffi.new("cardano_bootstrap_witness_t**")
        err = lib.cardano_bootstrap_witness_new(
            vkey_ptr[0], sig_ptr[0], chain_code_ptr, attr_ptr, out
        )

        lib.cardano_ed25519_public_key_unref(vkey_ptr)
        lib.cardano_ed25519_signature_unref(sig_ptr)
        lib.cardano_buffer_unref(ffi.new("cardano_buffer_t**", chain_code_ptr))
        lib.cardano_buffer_unref(ffi.new("cardano_buffer_t**", attr_ptr))

        if err != 0:
            raise CardanoError(f"Failed to create BootstrapWitness (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> BootstrapWitness:
        """
        Deserializes a BootstrapWitness from CBOR data.

        Args:
            reader: A CborReader positioned at the witness data.

        Returns:
            A new BootstrapWitness deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_bootstrap_witness_t**")
        err = lib.cardano_bootstrap_witness_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize BootstrapWitness from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the witness to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_bootstrap_witness_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize BootstrapWitness to CBOR (error code: {err})"
            )

    @property
    def vkey(self) -> bytes:
        """
        The verification key (public key).

        Returns:
            The 32-byte Ed25519 public key.
        """
        ptr = lib.cardano_bootstrap_witness_get_vkey(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get vkey")
        lib.cardano_ed25519_public_key_ref(ptr)

        data_ptr = lib.cardano_ed25519_public_key_get_data(ptr)
        size = lib.cardano_ed25519_public_key_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        pk_ptr = ffi.new("cardano_ed25519_public_key_t**", ptr)
        lib.cardano_ed25519_public_key_unref(pk_ptr)

        return result

    @vkey.setter
    def vkey(self, value: bytes) -> None:
        """
        Sets the verification key.

        Args:
            value: The 32-byte Ed25519 public key.

        Raises:
            CardanoError: If setting fails.
        """
        vkey_ptr = ffi.new("cardano_ed25519_public_key_t**")
        err = lib.cardano_ed25519_public_key_from_bytes(value, len(value), vkey_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create public key (error code: {err})")

        err = lib.cardano_bootstrap_witness_set_vkey(self._ptr, vkey_ptr[0])
        lib.cardano_ed25519_public_key_unref(vkey_ptr)

        if err != 0:
            raise CardanoError(f"Failed to set vkey (error code: {err})")

    @property
    def signature(self) -> bytes:
        """
        The signature.

        Returns:
            The 64-byte Ed25519 signature.
        """
        ptr = lib.cardano_bootstrap_witness_get_signature(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get signature")
        lib.cardano_ed25519_signature_ref(ptr)

        data_ptr = lib.cardano_ed25519_signature_get_data(ptr)
        size = lib.cardano_ed25519_signature_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        sig_ptr = ffi.new("cardano_ed25519_signature_t**", ptr)
        lib.cardano_ed25519_signature_unref(sig_ptr)

        return result

    @signature.setter
    def signature(self, value: bytes) -> None:
        """
        Sets the signature.

        Args:
            value: The 64-byte Ed25519 signature.

        Raises:
            CardanoError: If setting fails.
        """
        sig_ptr = ffi.new("cardano_ed25519_signature_t**")
        err = lib.cardano_ed25519_signature_from_bytes(value, len(value), sig_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create signature (error code: {err})")

        err = lib.cardano_bootstrap_witness_set_signature(self._ptr, sig_ptr[0])
        lib.cardano_ed25519_signature_unref(sig_ptr)

        if err != 0:
            raise CardanoError(f"Failed to set signature (error code: {err})")

    @property
    def chain_code(self) -> bytes:
        """
        The chain code for key derivation.

        Returns:
            The 32-byte chain code.
        """
        ptr = lib.cardano_bootstrap_witness_get_chain_code(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get chain_code")
        lib.cardano_buffer_ref(ptr)

        data_ptr = lib.cardano_buffer_get_data(ptr)
        size = lib.cardano_buffer_get_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        buf_ptr = ffi.new("cardano_buffer_t**", ptr)
        lib.cardano_buffer_unref(buf_ptr)

        return result

    @chain_code.setter
    def chain_code(self, value: bytes) -> None:
        """
        Sets the chain code.

        Args:
            value: The 32-byte chain code.

        Raises:
            CardanoError: If setting fails.
        """
        buf_ptr = lib.cardano_buffer_new_from(ffi.from_buffer("byte_t[]", value), len(value))
        if buf_ptr == ffi.NULL:
            raise CardanoError("Failed to create buffer")

        err = lib.cardano_bootstrap_witness_set_chain_code(self._ptr, buf_ptr)
        lib.cardano_buffer_unref(ffi.new("cardano_buffer_t**", buf_ptr))

        if err != 0:
            raise CardanoError(f"Failed to set chain_code (error code: {err})")

    @property
    def attributes(self) -> bytes:
        """
        The address attributes (CBOR encoded).

        Returns:
            The attributes bytes.
        """
        ptr = lib.cardano_bootstrap_witness_get_attributes(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get attributes")
        lib.cardano_buffer_ref(ptr)

        data_ptr = lib.cardano_buffer_get_data(ptr)
        size = lib.cardano_buffer_get_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        buf_ptr = ffi.new("cardano_buffer_t**", ptr)
        lib.cardano_buffer_unref(buf_ptr)

        return result

    @attributes.setter
    def attributes(self, value: bytes) -> None:
        """
        Sets the address attributes.

        Args:
            value: The attributes bytes (CBOR encoded).

        Raises:
            CardanoError: If setting fails.
        """
        buf_ptr = lib.cardano_buffer_new_from(ffi.from_buffer("byte_t[]", value), len(value))
        if buf_ptr == ffi.NULL:
            raise CardanoError("Failed to create buffer")

        err = lib.cardano_bootstrap_witness_set_attributes(self._ptr, buf_ptr)
        lib.cardano_buffer_unref(ffi.new("cardano_buffer_t**", buf_ptr))

        if err != 0:
            raise CardanoError(f"Failed to set attributes (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_bootstrap_witness_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
