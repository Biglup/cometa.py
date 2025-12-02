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

from typing import TYPE_CHECKING, Union, Any

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .script_language import ScriptLanguage

if TYPE_CHECKING:
    from .native_scripts.native_script import NativeScript
    from .native_scripts.script_pubkey import ScriptPubkey
    from .native_scripts.script_all import ScriptAll
    from .native_scripts.script_any import ScriptAny
    from .native_scripts.script_n_of_k import ScriptNOfK
    from .native_scripts.script_invalid_before import ScriptInvalidBefore
    from .native_scripts.script_invalid_after import ScriptInvalidAfter
    from .plutus_scripts.plutus_v1_script import PlutusV1Script
    from .plutus_scripts.plutus_v2_script import PlutusV2Script
    from .plutus_scripts.plutus_v3_script import PlutusV3Script

    NativeScriptLike = Union[
        NativeScript,
        ScriptPubkey,
        ScriptAll,
        ScriptAny,
        ScriptNOfK,
        ScriptInvalidBefore,
        ScriptInvalidAfter,
    ]

    ScriptLike = Union[
        NativeScript,
        ScriptPubkey,
        ScriptAll,
        ScriptAny,
        ScriptNOfK,
        ScriptInvalidBefore,
        ScriptInvalidAfter,
        PlutusV1Script,
        PlutusV2Script,
        PlutusV3Script,
    ]

    PlutusScriptLike = Union[
        PlutusV1Script,
        PlutusV2Script,
        PlutusV3Script,
    ]
else:
    # At runtime, we use Any to avoid circular imports
    NativeScriptLike = Any # pylint: disable=invalid-name
    ScriptLike = Any  # pylint: disable=invalid-name
    PlutusScriptLike = Any  # pylint: disable=invalid-name

class Script:
    """
    Represents a script in Cardano.

    A script is a program that decides whether the transaction that spends
    the output is authorized to do so. Scripts can be native scripts or
    Plutus scripts (V1, V2, or V3).
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Script: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_script_t**", self._ptr)
            lib.cardano_script_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Script:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Script(language={self.language.name}, hash={self.hash.hex()})"

    @classmethod
    def from_native(cls, native_script: NativeScriptLike) -> Script:
        """
        Creates a Script from a NativeScript.

        Args:
            native_script: The NativeScript to wrap.

        Returns:
            A new Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        from .native_scripts.native_script import NativeScript
        from .native_scripts.script_pubkey import ScriptPubkey
        from .native_scripts.script_all import ScriptAll
        from .native_scripts.script_any import ScriptAny
        from .native_scripts.script_n_of_k import ScriptNOfK
        from .native_scripts.script_invalid_before import ScriptInvalidBefore
        from .native_scripts.script_invalid_after import ScriptInvalidAfter

        # Convert specific script types to NativeScript
        if isinstance(native_script, ScriptPubkey):
            native_script = NativeScript.from_pubkey(native_script)
        elif isinstance(native_script, ScriptAll):
            native_script = NativeScript.from_all(native_script)
        elif isinstance(native_script, ScriptAny):
            native_script = NativeScript.from_any(native_script)
        elif isinstance(native_script, ScriptNOfK):
            native_script = NativeScript.from_n_of_k(native_script)
        elif isinstance(native_script, ScriptInvalidBefore):
            native_script = NativeScript.from_invalid_before(native_script)
        elif isinstance(native_script, ScriptInvalidAfter):
            native_script = NativeScript.from_invalid_after(native_script)
        else:
            if not isinstance(native_script, NativeScript):
                raise TypeError(
                    f"Expected NativeScript or native script type, got {type(native_script).__name__}"
                )

        out = ffi.new("cardano_script_t**")
        err = lib.cardano_script_new_native(native_script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Script from native (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_plutus_v1(cls, plutus_v1_script: PlutusV1Script) -> Script:
        """
        Creates a Script from a PlutusV1Script.

        Args:
            plutus_v1_script: The PlutusV1Script to wrap.

        Returns:
            A new Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_script_t**")
        err = lib.cardano_script_new_plutus_v1(plutus_v1_script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Script from Plutus V1 (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_plutus_v2(cls, plutus_v2_script: PlutusV2Script) -> Script:
        """
        Creates a Script from a PlutusV2Script.

        Args:
            plutus_v2_script: The PlutusV2Script to wrap.

        Returns:
            A new Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_script_t**")
        err = lib.cardano_script_new_plutus_v2(plutus_v2_script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Script from Plutus V2 (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_plutus_v3(cls, plutus_v3_script: PlutusV3Script) -> Script:
        """
        Creates a Script from a PlutusV3Script.

        Args:
            plutus_v3_script: The PlutusV3Script to wrap.

        Returns:
            A new Script instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_script_t**")
        err = lib.cardano_script_new_plutus_v3(plutus_v3_script._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Script from Plutus V3 (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Script:
        """
        Deserializes a Script from CBOR data.

        Args:
            reader: A CborReader positioned at the script data.

        Returns:
            A new Script deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_script_t**")
        err = lib.cardano_script_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Script from CBOR (error code: {err})"
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
        err = lib.cardano_script_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Script to CBOR (error code: {err})"
            )

    @property
    def language(self) -> ScriptLanguage:
        """
        The language of this script.

        Returns:
            The ScriptLanguage value.
        """
        lang_out = ffi.new("cardano_script_language_t*")
        err = lib.cardano_script_get_language(self._ptr, lang_out)
        if err != 0:
            raise CardanoError(f"Failed to get language (error code: {err})")
        return ScriptLanguage(lang_out[0])

    @property
    def hash(self) -> bytes:
        """
        The hash of this script.

        Returns:
            The 28-byte Blake2b hash of the script.
        """
        ptr = lib.cardano_script_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get script hash")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    def to_native(self) -> NativeScript:
        """
        Converts this script to a NativeScript.

        Returns:
            The NativeScript if this is a native script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .native_scripts.native_script import NativeScript

        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_script_to_native(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to native (error code: {err})")
        return NativeScript(out[0])

    def to_plutus_v1(self) -> PlutusV1Script:
        """
        Converts this script to a PlutusV1Script.

        Returns:
            The PlutusV1Script if this is a Plutus V1 script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .plutus_scripts.plutus_v1_script import PlutusV1Script

        out = ffi.new("cardano_plutus_v1_script_t**")
        err = lib.cardano_script_to_plutus_v1(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to Plutus V1 (error code: {err})")
        return PlutusV1Script(out[0])

    def to_plutus_v2(self) -> PlutusV2Script:
        """
        Converts this script to a PlutusV2Script.

        Returns:
            The PlutusV2Script if this is a Plutus V2 script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .plutus_scripts.plutus_v2_script import PlutusV2Script

        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_script_to_plutus_v2(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to Plutus V2 (error code: {err})")
        return PlutusV2Script(out[0])

    def to_plutus_v3(self) -> PlutusV3Script:
        """
        Converts this script to a PlutusV3Script.

        Returns:
            The PlutusV3Script if this is a Plutus V3 script.

        Raises:
            CardanoError: If conversion fails or type mismatch.
        """
        from .plutus_scripts.plutus_v3_script import PlutusV3Script

        out = ffi.new("cardano_plutus_v3_script_t**")
        err = lib.cardano_script_to_plutus_v3(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to Plutus V3 (error code: {err})")
        return PlutusV3Script(out[0])

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Script."""
        if not isinstance(other, Script):
            return NotImplemented
        return bool(lib.cardano_script_equals(self._ptr, other._ptr))
