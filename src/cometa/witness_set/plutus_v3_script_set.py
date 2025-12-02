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

from typing import TYPE_CHECKING, Iterable, Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter

if TYPE_CHECKING:
    from ..scripts.plutus_scripts.plutus_v3_script import PlutusV3Script


class PlutusV3ScriptSet(Set["PlutusV3Script"]):
    """
    Represents a set of Plutus V3 scripts.

    Plutus V3 scripts are smart contracts introduced in the Conway hard fork.
    V3 scripts support governance features and have additional built-in functions
    for working with the new governance mechanisms.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_v3_script_set_t**")
            err = lib.cardano_plutus_v3_script_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusV3ScriptSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusV3ScriptSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v3_script_set_t**", self._ptr)
            lib.cardano_plutus_v3_script_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV3ScriptSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV3ScriptSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusV3ScriptSet:
        """
        Deserializes a PlutusV3ScriptSet from CBOR data.

        Args:
            reader: A CborReader positioned at the script set data.

        Returns:
            A new PlutusV3ScriptSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_v3_script_set_t**")
        err = lib.cardano_plutus_v3_script_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PlutusV3ScriptSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, scripts: Iterable[PlutusV3Script]) -> PlutusV3ScriptSet:
        """
        Creates a PlutusV3ScriptSet from an iterable of PlutusV3Script objects.

        Args:
            scripts: An iterable of PlutusV3Script objects.

        Returns:
            A new PlutusV3ScriptSet containing all the scripts.

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
        err = lib.cardano_plutus_v3_script_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusV3ScriptSet to CBOR (error code: {err})"
            )

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_plutus_v3_script_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_plutus_v3_script_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def add(self, script: PlutusV3Script) -> None:
        """
        Adds a Plutus V3 script to the set.

        Args:
            script: The PlutusV3Script to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_v3_script_set_add(self._ptr, script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to PlutusV3ScriptSet (error code: {err})"
            )

    def get(self, index: int) -> PlutusV3Script:
        """
        Retrieves a Plutus V3 script at the specified index.

        Args:
            index: The index of the script to retrieve.

        Returns:
            The PlutusV3Script at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        from ..scripts.plutus_scripts.plutus_v3_script import PlutusV3Script

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_v3_script_t**")
        err = lib.cardano_plutus_v3_script_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from PlutusV3ScriptSet (error code: {err})"
            )
        return PlutusV3Script(out[0])

    def __len__(self) -> int:
        """Returns the number of scripts in the set."""
        return int(lib.cardano_plutus_v3_script_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusV3Script]:
        """Iterates over all scripts in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusV3Script:
        """Gets a script by index using bracket notation."""
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the set is not empty."""
        return len(self) > 0
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[PlutusV3Script]") -> bool:
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
