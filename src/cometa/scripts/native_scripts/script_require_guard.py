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


from ...common import Credential


class ScriptRequireGuard:
    """Native script requiring a credential in this transaction level's guard set."""

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ScriptRequireGuard: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_script_require_guard_t**", self._ptr)
            lib.cardano_script_require_guard_unref(ptr_ptr)
            self._ptr = ffi.NULL

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ScriptRequireGuard:
        """
        Deserializes a ScriptRequireGuard from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new ScriptRequireGuard deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_script_require_guard_t**")
        err = lib.cardano_script_require_guard_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ScriptRequireGuard from CBOR (error code: {err})"
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
        err = lib.cardano_script_require_guard_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ScriptRequireGuard to CBOR (error code: {err})"
            )

    @property
    def hash(self) -> bytes:
        """
        The hash of this native script.

        Returns:
            The 28-byte Blake2b hash.
        """
        native = NativeScript.from_require_guard(self)
        ptr = lib.cardano_native_script_get_hash(native._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    @classmethod
    def new(cls, credential: Credential) -> ScriptRequireGuard:
        """Create a guard requirement for a key or script credential."""
        out = ffi.new("cardano_script_require_guard_t **")
        err = lib.cardano_script_require_guard_new(credential._ptr, out)
        if err:
            raise CardanoError(f"Failed to create guard script (error code: {err})")
        return cls(out[0])

    @property
    def credential(self) -> Credential:
        """The credential required in the guard set."""
        out = ffi.new("cardano_credential_t **")
        err = lib.cardano_script_require_guard_get_credential(self._ptr, out)
        if err:
            raise CardanoError(f"Failed to read guard credential (error code: {err})")
        return Credential(out[0])
