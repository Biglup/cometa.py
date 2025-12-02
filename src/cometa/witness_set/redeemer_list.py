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

from typing import Iterable, Iterator, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .redeemer import Redeemer
from .redeemer_tag import RedeemerTag


class RedeemerList(Sequence["Redeemer"]):
    """
    Represents a list of redeemers.

    This collection type is used in transaction witness sets to hold all
    redeemers required for script validation.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_redeemer_list_t**")
            err = lib.cardano_redeemer_list_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create RedeemerList (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("RedeemerList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_redeemer_list_t**", self._ptr)
            lib.cardano_redeemer_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> RedeemerList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"RedeemerList(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> RedeemerList:
        """
        Deserializes a RedeemerList from CBOR data.

        Args:
            reader: A CborReader positioned at the redeemer list data.

        Returns:
            A new RedeemerList deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_redeemer_list_t**")
        err = lib.cardano_redeemer_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize RedeemerList from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, redeemers: Iterable[Redeemer]) -> RedeemerList:
        """
        Creates a RedeemerList from an iterable of Redeemer objects.

        Args:
            redeemers: An iterable of Redeemer objects.

        Returns:
            A new RedeemerList containing all the redeemers.

        Raises:
            CardanoError: If creation fails.
        """
        redeemer_list = cls()
        for redeemer in redeemers:
            redeemer_list.add(redeemer)
        return redeemer_list

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the redeemer list to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_redeemer_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize RedeemerList to CBOR (error code: {err})"
            )

    def add(self, redeemer: Redeemer) -> None:
        """
        Adds a redeemer to the list.

        Args:
            redeemer: The Redeemer to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_redeemer_list_add(self._ptr, redeemer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to RedeemerList (error code: {err})")

    def get(self, index: int) -> Redeemer:
        """
        Retrieves a redeemer at the specified index.

        Args:
            index: The index of the redeemer to retrieve.

        Returns:
            The Redeemer at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for list of length {len(self)}"
            )
        out = ffi.new("cardano_redeemer_t**")
        err = lib.cardano_redeemer_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from RedeemerList (error code: {err})")
        return Redeemer(out[0])

    def set_ex_units(
        self, tag: RedeemerTag, index: int, mem: int, steps: int
    ) -> None:
        """
        Sets the execution units for a specific redeemer.

        Args:
            tag: The redeemer tag type.
            index: The index of the redeemer.
            mem: The memory units.
            steps: The step units.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_redeemer_list_set_ex_units(
            self._ptr, int(tag), index, mem, steps
        )
        if err != 0:
            raise CardanoError(
                f"Failed to set ex_units on RedeemerList (error code: {err})"
            )

    def clone(self) -> RedeemerList:
        """
        Creates a deep copy of this redeemer list.

        Returns:
            A new RedeemerList that is a deep copy.

        Raises:
            CardanoError: If cloning fails.
        """
        out = ffi.new("cardano_redeemer_list_t**")
        err = lib.cardano_redeemer_list_clone(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to clone RedeemerList (error code: {err})")
        return RedeemerList(out[0])

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        This is useful when you have modified the list after it was created
        from CBOR and you want to ensure that the next serialization reflects
        the current state rather than using the original cached CBOR.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can invalidate existing signatures.
        """
        lib.cardano_redeemer_list_clear_cbor_cache(self._ptr)

    def __len__(self) -> int:
        """Returns the number of redeemers in the list."""
        return int(lib.cardano_redeemer_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[Redeemer]:
        """Iterates over all redeemers in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> Redeemer:
        """Gets a redeemer by index using bracket notation."""
        return self.get(index)

    def __bool__(self) -> bool:
        """Returns True if the list is not empty."""
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
        err = lib.cardano_redeemer_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def index(self, value: Redeemer, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: Redeemer) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[Redeemer]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
