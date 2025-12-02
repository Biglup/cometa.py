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
from collections.abc import Sequence

from typing import TYPE_CHECKING, Any, Iterable, Iterator, Optional, Union

from ..._ffi import ffi, lib
from ...errors import CardanoError
from ...cbor.cbor_reader import CborReader
from ...cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from .native_script import NativeScript
    from .script_pubkey import ScriptPubkey
    from .script_all import ScriptAll
    from .script_any import ScriptAny
    from .script_n_of_k import ScriptNOfK
    from .script_invalid_before import ScriptInvalidBefore
    from .script_invalid_after import ScriptInvalidAfter

    NativeScriptLike = Union[
        NativeScript,
        ScriptPubkey,
        ScriptAll,
        ScriptAny,
        ScriptNOfK,
        ScriptInvalidBefore,
        ScriptInvalidAfter,
    ]
else:
    # At runtime, we use Any to avoid circular imports
    NativeScriptLike = Any # pylint: disable=invalid-name


class NativeScriptList(Sequence["NativeScript"]):
    """
    Represents a list of native scripts.

    Native scripts form an expression tree and evaluate to either true or false.
    This list is used for script_all, script_any, and script_n_of_k constructs.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_native_script_list_t**")
            err = lib.cardano_native_script_list_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create NativeScriptList (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("NativeScriptList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_native_script_list_t**", self._ptr)
            lib.cardano_native_script_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> NativeScriptList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"NativeScriptList(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> NativeScriptList:
        """
        Deserializes a NativeScriptList from CBOR data.

        Args:
            reader: A CborReader positioned at the script list data.

        Returns:
            A new NativeScriptList deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_native_script_list_t**")
        err = lib.cardano_native_script_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize NativeScriptList from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, scripts: Iterable[NativeScriptLike]) -> NativeScriptList:
        """
        Creates a NativeScriptList from an iterable of native script objects.

        Args:
            scripts: An iterable of NativeScript or native script type objects.

        Returns:
            A new NativeScriptList containing all the scripts.

        Raises:
            CardanoError: If creation fails.
        """
        script_list = cls()
        for script in scripts:
            script_list.add(script)
        return script_list

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the script list to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_native_script_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize NativeScriptList to CBOR (error code: {err})"
            )

    def add(self, script: NativeScriptLike) -> None:
        """
        Adds a native script to the list.

        Args:
            script: The script to add. Can be a NativeScript or any specific
                native script type (ScriptPubkey, ScriptAll, ScriptAny,
                ScriptNOfK, ScriptInvalidBefore, ScriptInvalidAfter).

        Raises:
            CardanoError: If addition fails.
            TypeError: If the script type is not supported.
        """
        from .native_script import NativeScript
        from .script_pubkey import ScriptPubkey
        from .script_all import ScriptAll
        from .script_any import ScriptAny
        from .script_n_of_k import ScriptNOfK
        from .script_invalid_before import ScriptInvalidBefore
        from .script_invalid_after import ScriptInvalidAfter

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

        err = lib.cardano_native_script_list_add(self._ptr, native_script._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to NativeScriptList (error code: {err})")

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
        from .native_script import NativeScript

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for list of length {len(self)}"
            )
        out = ffi.new("cardano_native_script_t**")
        err = lib.cardano_native_script_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from NativeScriptList (error code: {err})"
            )
        return NativeScript(out[0])

    def __len__(self) -> int:
        """Returns the number of scripts in the list."""
        return int(lib.cardano_native_script_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[NativeScript]:
        """Iterates over all scripts in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> NativeScript:
        """Gets a script by index using bracket notation."""
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0
    def index(self, value: NativeScript, start: int = 0, stop: Optional[int] = None) -> int:
        """
        Returns the index of the first occurrence of value.

        Args:
            value: The value to search for.
            start: Start searching from this index.
            stop: Stop searching at this index.

        Returns:
            The index of the first occurrence.

        Raises:
            ValueError: If the value is not found.
        """
        if stop is None:
            stop = len(self)
        for i in range(start, stop):
            if self[i] == value:
                return i
        raise ValueError(f"{value!r} is not in list")

    def count(self, value: NativeScript) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[NativeScript]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
