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


class ScriptInvalidAfter:
    """
    Represents a time-lock script that expires at a slot.

    This script evaluates to true if the upper bound of the transaction validity
    interval is a slot number Y, and X <= Y (the slot number in this script).
    This guarantees that the transaction is included in a slot < X.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ScriptInvalidAfter: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_script_invalid_after_t**", self._ptr)
            lib.cardano_script_invalid_after_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ScriptInvalidAfter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ScriptInvalidAfter(slot={self.slot})"

    @classmethod
    def new(cls, slot: int) -> ScriptInvalidAfter:
        """
        Creates a new ScriptInvalidAfter with the given slot number.

        Args:
            slot: The slot number representing the upper bound of validity.

        Returns:
            A new ScriptInvalidAfter instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_script_invalid_after_t**")
        err = lib.cardano_script_invalid_after_new(slot, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create ScriptInvalidAfter (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ScriptInvalidAfter:
        """
        Deserializes a ScriptInvalidAfter from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new ScriptInvalidAfter deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_script_invalid_after_t**")
        err = lib.cardano_script_invalid_after_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ScriptInvalidAfter from CBOR (error code: {err})"
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
        err = lib.cardano_script_invalid_after_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ScriptInvalidAfter to CBOR (error code: {err})"
            )

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ...json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_script_invalid_after_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    @property
    def slot(self) -> int:
        """
        The slot number representing the upper bound of validity.

        Returns:
            The slot number.
        """
        slot_out = ffi.new("uint64_t*")
        err = lib.cardano_script_invalid_after_get_slot(self._ptr, slot_out)
        if err != 0:
            raise CardanoError(f"Failed to get slot (error code: {err})")
        return int(slot_out[0])

    @slot.setter
    def slot(self, value: int) -> None:
        """
        Sets the slot number.

        Args:
            value: The slot number.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_script_invalid_after_set_slot(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set slot (error code: {err})")

    @property
    def hash(self) -> bytes:
        """
        The hash of this native script.

        Returns:
            The 28-byte Blake2b hash.
        """
        native = NativeScript.from_invalid_after(self)
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
        """Checks equality with another ScriptInvalidAfter."""
        if not isinstance(other, ScriptInvalidAfter):
            return NotImplemented
        return bool(lib.cardano_script_invalid_after_equals(self._ptr, other._ptr))
