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

from ..._ffi import ffi, lib
from ...errors import CardanoError
from ...cbor.cbor_reader import CborReader
from ...cbor.cbor_writer import CborWriter


class PlutusV2Script:
    """
    Represents a Plutus V2 script.

    Plutus scripts are pieces of code that implement pure functions with True or
    False outputs. These functions take several inputs such as Datum, Redeemer
    and the transaction context to decide whether an output can be spent or not.

    V2 was introduced in the Vasil hard fork. The main changes were to the
    ScriptContext which was extended to include:
    - The full "redeemers" structure
    - Reference inputs (CIP-31)
    - Inline datums (CIP-32)
    - Reference scripts (CIP-33)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PlutusV2Script: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v2_script_t**", self._ptr)
            lib.cardano_plutus_v2_script_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV2Script:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV2Script(hash={self.hash.hex()})"

    @classmethod
    def new(cls, script_bytes: bytes) -> PlutusV2Script:
        """
        Creates a new PlutusV2Script from raw bytes.

        Args:
            script_bytes: The compiled Plutus script bytes.

        Returns:
            A new PlutusV2Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_plutus_v2_script_new_bytes(
            script_bytes, len(script_bytes), out
        )
        if err != 0:
            raise CardanoError(f"Failed to create PlutusV2Script (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> PlutusV2Script:
        """
        Creates a new PlutusV2Script from a hexadecimal string.

        Args:
            hex_string: The compiled Plutus script as a hex string.

        Returns:
            A new PlutusV2Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        hex_bytes = hex_string.encode("utf-8")
        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_plutus_v2_script_new_bytes_from_hex(
            hex_bytes, len(hex_bytes), out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create PlutusV2Script from hex (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusV2Script:
        """
        Deserializes a PlutusV2Script from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new PlutusV2Script deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_plutus_v2_script_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PlutusV2Script from CBOR (error code: {err})"
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
        err = lib.cardano_plutus_v2_script_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusV2Script to CBOR (error code: {err})"
            )

    @property
    def hash(self) -> bytes:
        """
        The hash of this script.

        Returns:
            The 28-byte Blake2b hash of the script.
        """
        ptr = lib.cardano_plutus_v2_script_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    @property
    def raw_bytes(self) -> bytes:
        """
        The raw bytes of the compiled script.

        Returns:
            The raw script bytes.
        """
        buf_ptr = ffi.new("cardano_buffer_t**")
        err = lib.cardano_plutus_v2_script_to_raw_bytes(self._ptr, buf_ptr)
        if err != 0:
            raise CardanoError(f"Failed to get raw bytes (error code: {err})")

        data_ptr = lib.cardano_buffer_get_data(buf_ptr[0])
        size = lib.cardano_buffer_get_size(buf_ptr[0])
        result = bytes(ffi.buffer(data_ptr, size))

        lib.cardano_buffer_unref(buf_ptr)

        return result

    def __eq__(self, other: object) -> bool:
        """Checks equality with another PlutusV2Script."""
        if not isinstance(other, PlutusV2Script):
            return NotImplemented
        return bool(lib.cardano_plutus_v2_script_equals(self._ptr, other._ptr))
