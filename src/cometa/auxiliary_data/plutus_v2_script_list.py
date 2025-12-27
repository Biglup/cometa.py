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

from typing import Iterator, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..scripts.plutus_scripts.plutus_v2_script import PlutusV2Script


class PlutusV2ScriptList(Sequence["PlutusV2Script"]):
    """
    Represents a list of Plutus V2 scripts.

    Plutus scripts are pieces of code that implement pure functions with True or
    False outputs. These functions take several inputs such as Datum, Redeemer
    and the transaction context to decide whether an output can be spent or not.

    V2 was introduced in the Vasil hard fork.

    The main changes in V2 of Plutus were to the interface to scripts. The ScriptContext
    was extended to include the following information:
    - The full "redeemers" structure, which contains all the redeemers used in the transaction
    - Reference inputs in the transaction (proposed in CIP-31)
    - Inline datums in the transaction (proposed in CIP-32)
    - Reference scripts in the transaction (proposed in CIP-33)

    Example:
        >>> from cometa import PlutusV2ScriptList
        >>> script_list = PlutusV2ScriptList()
        >>> script_list.add(script)
        >>> print(len(script_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_v2_script_list_t**")
            err = lib.cardano_plutus_v2_script_list_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusV2ScriptList (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusV2ScriptList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v2_script_list_t**", self._ptr)
            lib.cardano_plutus_v2_script_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV2ScriptList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV2ScriptList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of Plutus V2 scripts in the list."""
        return int(lib.cardano_plutus_v2_script_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusV2Script]:
        """Iterates over all Plutus V2 scripts in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusV2Script:
        """Gets a Plutus V2 script by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, scripts: list[PlutusV2Script]) -> PlutusV2ScriptList:
        """
        Creates a PlutusV2ScriptList from a Python list of PlutusV2Script objects.

        Args:
            scripts: A list of PlutusV2Script objects.

        Returns:
            A new PlutusV2ScriptList containing all the scripts.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> script_list = PlutusV2ScriptList.from_list([script1, script2, script3])
        """
        script_list = cls()
        for script in scripts:
            script_list.add(script)
        return script_list

    @classmethod
    def from_cbor(cls, cbor_hex: str) -> PlutusV2ScriptList:
        """
        Creates a PlutusV2ScriptList from a CBOR hex string.

        Args:
            cbor_hex: A hex-encoded CBOR string.

        Returns:
            A new PlutusV2ScriptList decoded from the CBOR.

        Raises:
            CardanoError: If decoding fails.

        Example:
            >>> script_list = PlutusV2ScriptList.from_cbor("82...")
        """
        from ..cbor.cbor_reader import CborReader

        reader = CborReader.from_hex(cbor_hex)
        out = ffi.new("cardano_plutus_v2_script_list_t**")
        err = lib.cardano_plutus_v2_script_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to decode PlutusV2ScriptList from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self) -> str:
        """
        Serializes the PlutusV2ScriptList to CBOR format.

        Returns:
            A hex-encoded CBOR string.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> cbor_hex = script_list.to_cbor()
        """
        from ..cbor.cbor_writer import CborWriter

        writer = CborWriter()
        err = lib.cardano_plutus_v2_script_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to encode PlutusV2ScriptList to CBOR (error code: {err})"
            )
        return writer.to_hex()

    def to_cip116_json(self, writer) -> None:
        """
        Serializes the PlutusV2ScriptList to CIP-116 JSON format.

        Writes a JSON array where each element is a Plutus V2 script object.
        This function emits the surrounding array brackets. Keys in each element
        are emitted in stable order: "language", then "bytes".

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa import JsonWriter, JsonFormat
            >>> writer = JsonWriter(JsonFormat.COMPACT)
            >>> script_list.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        from ..json.json_writer import JsonWriter

        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")

        err = lib.cardano_plutus_v2_script_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to encode PlutusV2ScriptList to CIP-116 JSON (error code: {err})"
            )

    def add(self, script: PlutusV2Script) -> None:
        """
        Adds a Plutus V2 script to the end of the list.

        Args:
            script: The PlutusV2Script to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_v2_script_list_add(self._ptr, script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to PlutusV2ScriptList (error code: {err})"
            )

    def get(self, index: int) -> PlutusV2Script:
        """
        Retrieves a Plutus V2 script at the specified index.

        Args:
            index: The index of the script to retrieve.

        Returns:
            The PlutusV2Script at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for list of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_plutus_v2_script_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from PlutusV2ScriptList (error code: {err})"
            )
        return PlutusV2Script(out[0])

    def append(self, script: PlutusV2Script) -> None:
        """
        Appends a Plutus V2 script to the end of the list.

        This is an alias for add() to provide a more Pythonic interface.

        Args:
            script: The PlutusV2Script to append.

        Raises:
            CardanoError: If addition fails.
        """
        self.add(script)
    def index(self, value: PlutusV2Script, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: PlutusV2Script) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[PlutusV2Script]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
