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
    from ..scripts.plutus_scripts.plutus_v1_script import PlutusV1Script


class PlutusV1ScriptSet(Set["PlutusV1Script"]):
    """
    Represents a set of Plutus V1 scripts.

    Plutus V1 scripts are smart contracts that implement pure functions with
    True or False outputs. V1 was the initial version of Plutus, introduced
    in the Alonzo hard fork.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_v1_script_set_t**")
            err = lib.cardano_plutus_v1_script_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusV1ScriptSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusV1ScriptSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v1_script_set_t**", self._ptr)
            lib.cardano_plutus_v1_script_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV1ScriptSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV1ScriptSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusV1ScriptSet:
        """
        Deserializes a PlutusV1ScriptSet from CBOR data.

        Args:
            reader: A CborReader positioned at the script set data.

        Returns:
            A new PlutusV1ScriptSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_v1_script_set_t**")
        err = lib.cardano_plutus_v1_script_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PlutusV1ScriptSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, scripts: Iterable[PlutusV1Script]) -> PlutusV1ScriptSet:
        """
        Creates a PlutusV1ScriptSet from an iterable of PlutusV1Script objects.

        Args:
            scripts: An iterable of PlutusV1Script objects.

        Returns:
            A new PlutusV1ScriptSet containing all the scripts.

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
        err = lib.cardano_plutus_v1_script_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusV1ScriptSet to CBOR (error code: {err})"
            )

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_plutus_v1_script_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_plutus_v1_script_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def add(self, script: PlutusV1Script) -> None:
        """
        Adds a Plutus V1 script to the set.

        Args:
            script: The PlutusV1Script to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_v1_script_set_add(self._ptr, script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to PlutusV1ScriptSet (error code: {err})"
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
        from ..scripts.plutus_scripts.plutus_v1_script import PlutusV1Script

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_v1_script_t**")
        err = lib.cardano_plutus_v1_script_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from PlutusV1ScriptSet (error code: {err})"
            )
        return PlutusV1Script(out[0])

    def __len__(self) -> int:
        """Returns the number of scripts in the set."""
        return int(lib.cardano_plutus_v1_script_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusV1Script]:
        """Iterates over all scripts in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusV1Script:
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

    def isdisjoint(self, other: "Iterable[PlutusV1Script]") -> bool:
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
