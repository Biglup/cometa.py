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
from collections.abc import Set

from typing import TYPE_CHECKING, Iterable, Iterator, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from ..scripts.native_scripts.native_script import NativeScript
    from ..scripts.native_scripts.script_pubkey import ScriptPubkey
    from ..scripts.native_scripts.script_all import ScriptAll
    from ..scripts.native_scripts.script_any import ScriptAny
    from ..scripts.native_scripts.script_n_of_k import ScriptNOfK
    from ..scripts.native_scripts.script_invalid_before import ScriptInvalidBefore
    from ..scripts.native_scripts.script_invalid_after import ScriptInvalidAfter

    NativeScriptLike = Union[
        NativeScript,
        ScriptPubkey,
        ScriptAll,
        ScriptAny,
        ScriptNOfK,
        ScriptInvalidBefore,
        ScriptInvalidAfter,
    ]


class NativeScriptSet(Set["NativeScript"]):
    """
    Represents a set of native scripts.

    Native scripts form an expression tree and evaluate to either true or false.
    They are used in Cardano to define spending conditions including multi-signature
    scripts, time-locks, and other types of scripts.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_native_script_set_t**")
            err = lib.cardano_native_script_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create NativeScriptSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("NativeScriptSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_native_script_set_t**", self._ptr)
            lib.cardano_native_script_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> NativeScriptSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"NativeScriptSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> NativeScriptSet:
        """
        Deserializes a NativeScriptSet from CBOR data.

        Args:
            reader: A CborReader positioned at the script set data.

        Returns:
            A new NativeScriptSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_native_script_set_t**")
        err = lib.cardano_native_script_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize NativeScriptSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, scripts: Iterable[NativeScriptLike]) -> NativeScriptSet:
        """
        Creates a NativeScriptSet from an iterable of native script objects.

        Args:
            scripts: An iterable of NativeScript or native script type objects.

        Returns:
            A new NativeScriptSet containing all the scripts.

        Raises:
            CardanoError: If creation fails.
        """
        script_set = cls()
        for script in scripts:
            script_set.add(script)
        return script_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the script set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_native_script_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize NativeScriptSet to CBOR (error code: {err})"
            )

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_native_script_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_native_script_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def add(self, script: NativeScriptLike) -> None:
        """
        Adds a native script to the set.

        Args:
            script: The script to add. Can be a NativeScript or any specific
                native script type (ScriptPubkey, ScriptAll, ScriptAny,
                ScriptNOfK, ScriptInvalidBefore, ScriptInvalidAfter).

        Raises:
            CardanoError: If addition fails.
            TypeError: If the script type is not supported.
        """
        from ..scripts.native_scripts.native_script import NativeScript
        from ..scripts.native_scripts.script_pubkey import ScriptPubkey
        from ..scripts.native_scripts.script_all import ScriptAll
        from ..scripts.native_scripts.script_any import ScriptAny
        from ..scripts.native_scripts.script_n_of_k import ScriptNOfK
        from ..scripts.native_scripts.script_invalid_before import ScriptInvalidBefore
        from ..scripts.native_scripts.script_invalid_after import ScriptInvalidAfter

        # Convert specific script types to NativeScript
        if isinstance(script, NativeScript):
            native_script = script
        elif isinstance(script, ScriptPubkey):
            native_script = NativeScript.from_pubkey(script)
        elif isinstance(script, ScriptAll):
            native_script = NativeScript.from_all(script)
        elif isinstance(script, ScriptAny):
            native_script = NativeScript.from_any(script)
        elif isinstance(script, ScriptNOfK):
            native_script = NativeScript.from_n_of_k(script)
        elif isinstance(script, ScriptInvalidBefore):
            native_script = NativeScript.from_invalid_before(script)
        elif isinstance(script, ScriptInvalidAfter):
            native_script = NativeScript.from_invalid_after(script)
        else:
            raise TypeError(
                f"Expected NativeScript or native script type, got {type(script).__name__}"
            )

        err = lib.cardano_native_script_set_add(self._ptr, native_script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to NativeScriptSet (error code: {err})"
            )

    def get(self, index: int) -> NativeScript:
        """
        Retrieves a native script at the specified index.

        Args:
            index: The index of the script to retrieve.

        Returns:
            The NativeScript at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        from ..scripts.native_scripts.native_script import NativeScript

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from NativeScriptSet (error code: {err})"
            )
        return NativeScript(out[0])

    def __len__(self) -> int:
        """Returns the number of scripts in the set."""
        return int(lib.cardano_native_script_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[NativeScript]:
        """Iterates over all scripts in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> NativeScript:
        """Gets a script by index using bracket notation."""
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the set is not empty."""
        return len(self) > 0

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
        err = lib.cardano_native_script_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[NativeScript]") -> bool:
        """
        Returns True if the set has no elements in common with other.

        Args:
            other: Another iterable to compare with.

        Returns:
            True if the sets are disjoint.
        """
        for item in other:
            if item in self:
                return False
        return True
