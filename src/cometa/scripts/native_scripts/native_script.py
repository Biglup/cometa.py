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

from typing import TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError
from ...cbor.cbor_reader import CborReader
from ...cbor.cbor_writer import CborWriter
from .native_script_type import NativeScriptType

if TYPE_CHECKING:
    from .script_pubkey import ScriptPubkey
    from .script_all import ScriptAll
    from .script_any import ScriptAny
    from .script_n_of_k import ScriptNOfK
    from .script_invalid_before import ScriptInvalidBefore
    from .script_invalid_after import ScriptInvalidAfter


class NativeScript:
    """
    Represents a native script in Cardano.

    Native scripts form an expression tree where the evaluation produces either
    true or false. They support signature requirements, time-locks, and boolean
    combinations (all, any, n-of-k).

    Note that native scripts are recursive. There are no constraints on nesting
    or size, except that imposed by the overall transaction size limit.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("NativeScript: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_native_script_t**", self._ptr)
            lib.cardano_native_script_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> NativeScript:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"NativeScript(type={self.script_type.name})"

    @classmethod
    def from_pubkey(cls, script_pubkey: ScriptPubkey) -> NativeScript:
        """
        Creates a NativeScript from a ScriptPubkey.

        Args:
            script_pubkey: The ScriptPubkey to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_pubkey(script_pubkey._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from pubkey (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_all(cls, script_all: ScriptAll) -> NativeScript:
        """
        Creates a NativeScript from a ScriptAll.

        Args:
            script_all: The ScriptAll to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_all(script_all._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from all (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_any(cls, script_any: ScriptAny) -> NativeScript:
        """
        Creates a NativeScript from a ScriptAny.

        Args:
            script_any: The ScriptAny to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_any(script_any._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from any (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_n_of_k(cls, script_n_of_k: ScriptNOfK) -> NativeScript:
        """
        Creates a NativeScript from a ScriptNOfK.

        Args:
            script_n_of_k: The ScriptNOfK to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_n_of_k(script_n_of_k._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from n_of_k (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_invalid_before(cls, script: ScriptInvalidBefore) -> NativeScript:
        """
        Creates a NativeScript from a ScriptInvalidBefore.

        Args:
            script: The ScriptInvalidBefore to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_invalid_before(script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from invalid_before (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_invalid_after(cls, script: ScriptInvalidAfter) -> NativeScript:
        """
        Creates a NativeScript from a ScriptInvalidAfter.

        Args:
            script: The ScriptInvalidAfter to wrap.

        Returns:
            A new NativeScript instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_new_invalid_after(script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create NativeScript from invalid_after (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> NativeScript:
        """
        Deserializes a NativeScript from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new NativeScript deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize NativeScript from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_json(cls, json: str) -> NativeScript:
        """
        Creates a NativeScript from a JSON string.

        Args:
            json: A JSON string containing the native script data.

        Returns:
            A new NativeScript deserialized from the JSON.

        Raises:
            CardanoError: If deserialization fails.
        """
        json_bytes = json.encode("utf-8")
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_from_json(json_bytes, len(json_bytes), out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize NativeScript from JSON (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the native script to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_native_script_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize NativeScript to CBOR (error code: {err})"
            )

    @property
    def script_type(self) -> NativeScriptType:
        """
        The type of this native script.

        Returns:
            The NativeScriptType value.
        """
        type_out = ffi.new("cardano_native_script_type_t*")
        err = lib.cardano_native_script_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get script type (error code: {err})")
        return NativeScriptType(type_out[0])

    @property
    def hash(self) -> bytes:
        """
        The hash of this native script.

        Returns:
            The 28-byte Blake2b hash.
        """
        ptr = lib.cardano_native_script_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    def to_pubkey(self) -> ScriptPubkey:
        """
        Converts this native script to a ScriptPubkey.

        Returns:
            The ScriptPubkey if this script is a pubkey script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_pubkey import ScriptPubkey

        out = ffi.new("cardano_script_pubkey_t**")
        err = lib.cardano_native_script_to_pubkey(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to pubkey (error code: {err})")
        return ScriptPubkey(out[0])

    def to_all(self) -> ScriptAll:
        """
        Converts this native script to a ScriptAll.

        Returns:
            The ScriptAll if this script is an all script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_all import ScriptAll

        out = ffi.new("cardano_script_all_t**")
        err = lib.cardano_native_script_to_all(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to all (error code: {err})")
        return ScriptAll(out[0])

    def to_any(self) -> ScriptAny:
        """
        Converts this native script to a ScriptAny.

        Returns:
            The ScriptAny if this script is an any script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_any import ScriptAny

        out = ffi.new("cardano_script_any_t**")
        err = lib.cardano_native_script_to_any(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to any (error code: {err})")
        return ScriptAny(out[0])

    def to_n_of_k(self) -> ScriptNOfK:
        """
        Converts this native script to a ScriptNOfK.

        Returns:
            The ScriptNOfK if this script is an n-of-k script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_n_of_k import ScriptNOfK

        out = ffi.new("cardano_script_n_of_k_t**")
        err = lib.cardano_native_script_to_n_of_k(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to n_of_k (error code: {err})")
        return ScriptNOfK(out[0])

    def to_invalid_before(self) -> ScriptInvalidBefore:
        """
        Converts this native script to a ScriptInvalidBefore.

        Returns:
            The ScriptInvalidBefore if this script is an invalid_before script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_invalid_before import ScriptInvalidBefore

        out = ffi.new("cardano_script_invalid_before_t**")
        err = lib.cardano_native_script_to_invalid_before(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to invalid_before (error code: {err})"
            )
        return ScriptInvalidBefore(out[0])

    def to_invalid_after(self) -> ScriptInvalidAfter:
        """
        Converts this native script to a ScriptInvalidAfter.

        Returns:
            The ScriptInvalidAfter if this script is an invalid_after script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .script_invalid_after import ScriptInvalidAfter

        out = ffi.new("cardano_script_invalid_after_t**")
        err = lib.cardano_native_script_to_invalid_after(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to invalid_after (error code: {err})"
            )
        return ScriptInvalidAfter(out[0])

    def __eq__(self, other: object) -> bool:
        """Checks equality with another NativeScript."""
        if not isinstance(other, NativeScript):
            return NotImplemented
        return bool(lib.cardano_native_script_equals(self._ptr, other._ptr))
