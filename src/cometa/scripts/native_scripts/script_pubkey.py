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

from .native_script import NativeScript
from ..._ffi import ffi, lib
from ...errors import CardanoError
from ...cbor.cbor_reader import CborReader
from ...cbor.cbor_writer import CborWriter


class ScriptPubkey:
    """
    Represents a public key script (signature requirement).

    This script evaluates to true if the transaction includes a valid key
    witness where the witness verification key hashes to the given hash.
    In other words, this checks that the transaction is signed by a particular
    key, identified by its verification key hash.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ScriptPubkey: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_script_pubkey_t**", self._ptr)
            lib.cardano_script_pubkey_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ScriptPubkey:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ScriptPubkey(key_hash={self.key_hash.hex()})"

    @classmethod
    def new(cls, key_hash: bytes) -> ScriptPubkey:
        """
        Creates a new public key script.

        Args:
            key_hash: The 28-byte Blake2b hash of the verification key.

        Returns:
            A new ScriptPubkey instance.

        Raises:
            CardanoError: If creation fails.
        """
        # Create blake2b_hash from bytes
        hash_ptr = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_from_bytes(key_hash, len(key_hash), hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create key hash (error code: {err})")

        out = ffi.new("cardano_script_pubkey_t**")
        err = lib.cardano_script_pubkey_new(hash_ptr[0], out)

        # Clean up hash
        lib.cardano_blake2b_hash_unref(hash_ptr)

        if err != 0:
            raise CardanoError(f"Failed to create ScriptPubkey (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ScriptPubkey:
        """
        Deserializes a ScriptPubkey from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new ScriptPubkey deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_script_pubkey_t**")
        err = lib.cardano_script_pubkey_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ScriptPubkey from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the script to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_script_pubkey_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ScriptPubkey to CBOR (error code: {err})"
            )

    @property
    def key_hash(self) -> bytes:
        """
        The verification key hash that must sign the transaction.

        Returns:
            The 28-byte Blake2b hash.
        """
        hash_ptr = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_script_pubkey_get_key_hash(self._ptr, hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to get key hash (error code: {err})")

        data_ptr = lib.cardano_blake2b_hash_get_data(hash_ptr[0])
        size = lib.cardano_blake2b_hash_get_bytes_size(hash_ptr[0])
        result = bytes(ffi.buffer(data_ptr, size))

        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    @property
    def hash(self) -> bytes:
        """
        The hash of this native script.

        Returns:
            The 28-byte Blake2b hash.
        """
        native = NativeScript.from_pubkey(self)
        ptr = lib.cardano_native_script_get_hash(native._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    def __eq__(self, other: object) -> bool:
        """Checks equality with another ScriptPubkey."""
        if not isinstance(other, ScriptPubkey):
            return NotImplemented
        return bool(lib.cardano_script_pubkey_equals(self._ptr, other._ptr))
