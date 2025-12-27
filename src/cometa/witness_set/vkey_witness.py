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


class VkeyWitness:
    """
    Represents a verification key witness in a Cardano transaction.

    A VKey witness consists of a verification key (public key) and a signature
    that proves the owner of the corresponding private key has authorized
    the transaction.

    This is the standard way to sign transactions in Cardano - the private key
    signs the transaction body hash, and the witness contains both the public
    key and the signature for verification.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("VkeyWitness: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_vkey_witness_t**", self._ptr)
            lib.cardano_vkey_witness_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> VkeyWitness:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "VkeyWitness(...)"

    @classmethod
    def new(cls, vkey: bytes, signature: bytes) -> VkeyWitness:
        """
        Creates a new VKey witness from raw bytes.

        Args:
            vkey: The verification key (32 bytes for Ed25519).
            signature: The signature (64 bytes for Ed25519).

        Returns:
            A new VkeyWitness instance.

        Raises:
            CardanoError: If creation fails.
        """
        # Create ed25519_public_key
        vkey_ptr = ffi.new("cardano_ed25519_public_key_t**")
        err = lib.cardano_ed25519_public_key_from_bytes(vkey, len(vkey), vkey_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create public key (error code: {err})")

        # Create ed25519_signature
        sig_ptr = ffi.new("cardano_ed25519_signature_t**")
        err = lib.cardano_ed25519_signature_from_bytes(signature, len(signature), sig_ptr)
        if err != 0:
            # Clean up vkey
            lib.cardano_ed25519_public_key_unref(vkey_ptr)
            raise CardanoError(f"Failed to create signature (error code: {err})")

        # Create witness
        out = ffi.new("cardano_vkey_witness_t**")
        err = lib.cardano_vkey_witness_new(vkey_ptr[0], sig_ptr[0], out)

        # Clean up intermediate objects
        lib.cardano_ed25519_public_key_unref(vkey_ptr)
        lib.cardano_ed25519_signature_unref(sig_ptr)

        if err != 0:
            raise CardanoError(f"Failed to create VkeyWitness (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> VkeyWitness:
        """
        Deserializes a VkeyWitness from CBOR data.

        Args:
            reader: A CborReader positioned at the witness data.

        Returns:
            A new VkeyWitness deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_vkey_witness_t**")
        err = lib.cardano_vkey_witness_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize VkeyWitness from CBOR (error code: {err})"
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
        err = lib.cardano_vkey_witness_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize VkeyWitness to CBOR (error code: {err})"
            )

    @property
    def vkey(self) -> bytes:
        """
        The verification key (public key).

        Returns:
            The 32-byte Ed25519 public key.
        """
        ptr = lib.cardano_vkey_witness_get_vkey(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get vkey")
        lib.cardano_ed25519_public_key_ref(ptr)

        # Get the bytes
        data_ptr = lib.cardano_ed25519_public_key_get_data(ptr)
        size = lib.cardano_ed25519_public_key_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        # Clean up
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

        err = lib.cardano_vkey_witness_set_vkey(self._ptr, vkey_ptr[0])
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
        ptr = lib.cardano_vkey_witness_get_signature(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get signature")
        lib.cardano_ed25519_signature_ref(ptr)

        # Get the bytes
        data_ptr = lib.cardano_ed25519_signature_get_data(ptr)
        size = lib.cardano_ed25519_signature_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        # Clean up
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

        err = lib.cardano_vkey_witness_set_signature(self._ptr, sig_ptr[0])
        lib.cardano_ed25519_signature_unref(sig_ptr)

        if err != 0:
            raise CardanoError(f"Failed to set signature (error code: {err})")

    def has_public_key(self, vkey: bytes) -> bool:
        """
        Checks if this witness contains a specific public key.

        Args:
            vkey: The 32-byte Ed25519 public key to check for.

        Returns:
            True if the witness contains this public key, False otherwise.

        Raises:
            CardanoError: If the check fails.
        """
        vkey_ptr = ffi.new("cardano_ed25519_public_key_t**")
        err = lib.cardano_ed25519_public_key_from_bytes(vkey, len(vkey), vkey_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create public key (error code: {err})")

        result = lib.cardano_vkey_witness_has_public_key(self._ptr, vkey_ptr[0])
        lib.cardano_ed25519_public_key_unref(vkey_ptr)

        return bool(result)

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
        err = lib.cardano_vkey_witness_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
