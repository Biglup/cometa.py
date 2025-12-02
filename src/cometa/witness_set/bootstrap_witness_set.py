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

from typing import Iterable, Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .bootstrap_witness import BootstrapWitness


class BootstrapWitnessSet(Set["BootstrapWitness"]):
    """
    Represents a set of bootstrap witnesses.

    This collection type is used in transaction witness sets to hold all
    bootstrap witnesses required for Byron-era address spending.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_bootstrap_witness_set_t**")
            err = lib.cardano_bootstrap_witness_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create BootstrapWitnessSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("BootstrapWitnessSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_bootstrap_witness_set_t**", self._ptr)
            lib.cardano_bootstrap_witness_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> BootstrapWitnessSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"BootstrapWitnessSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> BootstrapWitnessSet:
        """
        Deserializes a BootstrapWitnessSet from CBOR data.

        Args:
            reader: A CborReader positioned at the witness set data.

        Returns:
            A new BootstrapWitnessSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_bootstrap_witness_set_t**")
        err = lib.cardano_bootstrap_witness_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize BootstrapWitnessSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, witnesses: Iterable[BootstrapWitness]) -> BootstrapWitnessSet:
        """
        Creates a BootstrapWitnessSet from an iterable of BootstrapWitness objects.

        Args:
            witnesses: An iterable of BootstrapWitness objects.

        Returns:
            A new BootstrapWitnessSet containing all the witnesses.

        Raises:
            CardanoError: If creation fails.
        """
        witness_set = cls()
        for witness in witnesses:
            witness_set.add(witness)
        return witness_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the witness set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_bootstrap_witness_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize BootstrapWitnessSet to CBOR (error code: {err})"
            )

    def add(self, witness: BootstrapWitness) -> None:
        """
        Adds a bootstrap witness to the set.

        Args:
            witness: The BootstrapWitness to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_bootstrap_witness_set_add(self._ptr, witness._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to BootstrapWitnessSet (error code: {err})"
            )

    def get(self, index: int) -> BootstrapWitness:
        """
        Retrieves a bootstrap witness at the specified index.

        Args:
            index: The index of the witness to retrieve.

        Returns:
            The BootstrapWitness at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_bootstrap_witness_t**")
        err = lib.cardano_bootstrap_witness_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from BootstrapWitnessSet (error code: {err})"
            )
        return BootstrapWitness(out[0])

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_bootstrap_witness_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_bootstrap_witness_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def __len__(self) -> int:
        """Returns the number of witnesses in the set."""
        return int(lib.cardano_bootstrap_witness_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[BootstrapWitness]:
        """Iterates over all witnesses in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> BootstrapWitness:
        """Gets a witness by index using bracket notation."""
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
        err = lib.cardano_bootstrap_witness_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[BootstrapWitness]") -> bool:
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
