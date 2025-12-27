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
    from ..scripts.plutus_scripts.plutus_v2_script import PlutusV2Script


class PlutusV2ScriptSet(Set["PlutusV2Script"]):
    """
    Represents a set of Plutus V2 scripts.

    Plutus V2 scripts are smart contracts introduced in the Vasil hard fork.
    V2 scripts have access to reference inputs, inline datums, and reference
    scripts, making them more efficient than V1 scripts.
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new PlutusV2ScriptSet.

        Args:
            ptr: Optional FFI pointer to an existing script set. If None, creates a new set.

        Raises:
            CardanoError: If creation fails or if ptr is NULL.
        """
        if ptr is None:
            out = ffi.new("cardano_plutus_v2_script_set_t**")
            err = lib.cardano_plutus_v2_script_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusV2ScriptSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusV2ScriptSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_v2_script_set_t**", self._ptr)
            lib.cardano_plutus_v2_script_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusV2ScriptSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusV2ScriptSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusV2ScriptSet:
        """
        Deserializes a PlutusV2ScriptSet from CBOR data.

        Args:
            reader: A CborReader positioned at the script set data.

        Returns:
            A new PlutusV2ScriptSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_v2_script_set_t**")
        err = lib.cardano_plutus_v2_script_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PlutusV2ScriptSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, scripts: Iterable[PlutusV2Script]) -> PlutusV2ScriptSet:
        """
        Creates a PlutusV2ScriptSet from an iterable of PlutusV2Script objects.

        Args:
            scripts: An iterable of PlutusV2Script objects.

        Returns:
            A new PlutusV2ScriptSet containing all the scripts.

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
        err = lib.cardano_plutus_v2_script_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusV2ScriptSet to CBOR (error code: {err})"
            )

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_plutus_v2_script_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_plutus_v2_script_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def add(self, script: PlutusV2Script) -> None:
        """
        Adds a Plutus V2 script to the set.

        Args:
            script: The PlutusV2Script to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_v2_script_set_add(self._ptr, script._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to PlutusV2ScriptSet (error code: {err})"
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
        from ..scripts.plutus_scripts.plutus_v2_script import PlutusV2Script

        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_v2_script_t**")
        err = lib.cardano_plutus_v2_script_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from PlutusV2ScriptSet (error code: {err})"
            )
        return PlutusV2Script(out[0])

    def __len__(self) -> int:
        """Returns the number of scripts in the set."""
        return int(lib.cardano_plutus_v2_script_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusV2Script]:
        """Iterates over all scripts in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusV2Script:
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

    def isdisjoint(self, other: "Iterable[PlutusV2Script]") -> bool:
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
