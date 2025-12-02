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

from typing import Union, List

from .native_script import NativeScript
from ..._ffi import ffi, lib
from ...errors import CardanoError
from ...cbor.cbor_reader import CborReader
from ...cbor.cbor_writer import CborWriter
from .native_script_list import NativeScriptList, NativeScriptLike


class ScriptAll:
    """
    Represents a script that requires all sub-scripts to evaluate to true.

    This script evaluates to true if all the sub-scripts evaluate to true.
    If the list of sub-scripts is empty, this script evaluates to true.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ScriptAll: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_script_all_t**", self._ptr)
            lib.cardano_script_all_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ScriptAll:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ScriptAll(len={len(self)})"

    @classmethod
    def new(cls, scripts: Union[NativeScriptList, List[NativeScriptLike]]) -> ScriptAll:
        """
        Creates a new ScriptAll with the given sub-scripts.

        Args:
            scripts: The list of native scripts that must all evaluate to true.
                Can be a NativeScriptList or a Python list of native scripts.

        Returns:
            A new ScriptAll instance.

        Raises:
            CardanoError: If creation fails.
        """
        if isinstance(scripts, list):
            scripts = NativeScriptList.from_list(scripts)
        out = ffi.new("cardano_script_all_t**")
        err = lib.cardano_script_all_new(scripts._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create ScriptAll (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ScriptAll:
        """
        Deserializes a ScriptAll from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new ScriptAll deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_script_all_t**")
        err = lib.cardano_script_all_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ScriptAll from CBOR (error code: {err})"
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
        err = lib.cardano_script_all_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ScriptAll to CBOR (error code: {err})"
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
        err = lib.cardano_script_all_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    @property
    def scripts(self) -> NativeScriptList:
        """
        The list of sub-scripts.

        Returns:
            The NativeScriptList containing all sub-scripts.
        """
        out = ffi.new("cardano_native_script_list_t**")
        err = lib.cardano_script_all_get_scripts(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get scripts (error code: {err})")
        return NativeScriptList(out[0])

    @scripts.setter
    def scripts(self, value: Union[NativeScriptList, List[NativeScriptLike]]) -> None:
        """
        Sets the list of sub-scripts.

        Args:
            value: The NativeScriptList or a Python list of native scripts to set.

        Raises:
            CardanoError: If setting fails.
        """
        if isinstance(value, list):
            value = NativeScriptList.from_list(value)
        err = lib.cardano_script_all_set_scripts(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set scripts (error code: {err})")

    @property
    def hash(self) -> bytes:
        """
        The hash of this native script.

        Returns:
            The 28-byte Blake2b hash.
        """
        native = NativeScript.from_all(self)
        ptr = lib.cardano_native_script_get_hash(native._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    def __len__(self) -> int:
        """Returns the number of sub-scripts."""
        return int(lib.cardano_script_all_get_length(self._ptr))

    def __eq__(self, other: object) -> bool:
        """Checks equality with another ScriptAll."""
        if not isinstance(other, ScriptAll):
            return NotImplemented
        return bool(lib.cardano_script_all_equals(self._ptr, other._ptr))
