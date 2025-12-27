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
from ..scripts.plutus_scripts.plutus_v1_script import PlutusV1Script


class PlutusV1ScriptList(Sequence["PlutusV1Script"]):
    """
    Represents a list of Plutus V1 scripts.

    Plutus scripts are pieces of code that implement pure functions with True or
    False outputs. These functions take several inputs such as Datum, Redeemer
    and the transaction context to decide whether an output can be spent or not.

    V1 was the initial version of Plutus, introduced in the Alonzo hard fork.

    Example:
        >>> from cometa import PlutusV1ScriptList
        >>> script_list = PlutusV1ScriptList()
        >>> script_list.add(script)
        >>> print(len(script_list))
        1
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_v1_script_list_t**")
            err = lib.cardano_plutus_v1_script_list_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusV1ScriptList (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusV1ScriptList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v1_script_list_t**", self._ptr)
            lib.cardano_plutus_v1_script_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV1ScriptList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV1ScriptList(len={len(self)})"

    def __len__(self) -> int:
        """Returns the number of Plutus V1 scripts in the list."""
        return int(lib.cardano_plutus_v1_script_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusV1Script]:
        """Iterates over all Plutus V1 scripts in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusV1Script:
        """Gets a Plutus V1 script by index using bracket notation."""
        if index < 0:
            index = len(self) + index
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
        return len(self) > 0

    @classmethod
    def from_list(cls, scripts: list[PlutusV1Script]) -> PlutusV1ScriptList:
        """
        Creates a PlutusV1ScriptList from a Python list of PlutusV1Script objects.

        Args:
            scripts: A list of PlutusV1Script objects.

        Returns:
            A new PlutusV1ScriptList containing all the scripts.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> script_list = PlutusV1ScriptList.from_list([script1, script2, script3])
        """
        script_list = cls()
        for script in scripts:
            script_list.add(script)
        return script_list

    @classmethod
    def from_cbor(cls, cbor_hex: str) -> PlutusV1ScriptList:
        """
        Creates a PlutusV1ScriptList from a CBOR hex string.

        Args:
            cbor_hex: A hex-encoded CBOR string.

        Returns:
            A new PlutusV1ScriptList decoded from the CBOR.

        Raises:
            CardanoError: If decoding fails.

        Example:
            >>> script_list = PlutusV1ScriptList.from_cbor("82...")
        """
        from ..cbor.cbor_reader import CborReader

        reader = CborReader.from_hex(cbor_hex)
        out = ffi.new("cardano_plutus_v1_script_list_t**")
        err = lib.cardano_plutus_v1_script_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to decode PlutusV1ScriptList from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self) -> str:
        """
        Serializes the PlutusV1ScriptList to CBOR format.

        Returns:
            A hex-encoded CBOR string.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> cbor_hex = script_list.to_cbor()
        """
        from ..cbor.cbor_writer import CborWriter

        writer = CborWriter()
        err = lib.cardano_plutus_v1_script_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to encode PlutusV1ScriptList to CBOR (error code: {err})"
            )
        return writer.to_hex()

    def add(self, script: PlutusV1Script) -> None:
        """
        Adds a Plutus V1 script to the end of the list.

        Args:
            script: The PlutusV1Script to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_v1_script_list_add(self._ptr, script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to PlutusV1ScriptList (error code: {err})"
            )

    def get(self, index: int) -> PlutusV1Script:
        """
        Retrieves a Plutus V1 script at the specified index.

        Args:
            index: The index of the script to retrieve.

        Returns:
            The PlutusV1Script at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for list of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_v1_script_t**")
        err = lib.cardano_plutus_v1_script_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from PlutusV1ScriptList (error code: {err})"
            )
        return PlutusV1Script(out[0])

    def to_cip116_json(self, writer) -> None:
        """
        Serializes the PlutusV1ScriptList to CIP-116 JSON format.

        Writes a JSON array where each element is a Plutus v1 script object with the shape:
        [
          { "language": "plutus_v1", "bytes": "<hex-bytes>" },
          { "language": "plutus_v1", "bytes": "<hex-bytes>" }
        ]

        This method emits the surrounding array brackets ([and ]). It does not write a
        property name; if you need this list as a field value inside another object, write the
        property name first and then call this method.

        Args:
            writer: A JsonWriter instance where the JSON will be written.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa import JsonWriter, JsonFormat
            >>> writer = JsonWriter(JsonFormat.COMPACT)
            >>> script_list.to_cip116_json(writer)
        """
        err = lib.cardano_plutus_v1_script_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusV1ScriptList to CIP-116 JSON (error code: {err})"
            )

    def append(self, script: PlutusV1Script) -> None:
        """
        Appends a Plutus V1 script to the end of the list.

        This is an alias for add() to provide a more Pythonic interface.

        Args:
            script: The PlutusV1Script to append.

        Raises:
            CardanoError: If addition fails.
        """
        self.add(script)
    def index(self, value: PlutusV1Script, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: PlutusV1Script) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[PlutusV1Script]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
