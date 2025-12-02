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
from ..plutus_data.plutus_data import PlutusData


class PlutusDataSet(Set["PlutusData"]):
    """
    Represents a set of Plutus data.

    Plutus data is used in Plutus scripts to carry additional information
    during script execution. The datum is a piece of data attached to UTXOs
    that scripts can use to validate transactions.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_plutus_data_set_t**")
            err = lib.cardano_plutus_data_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create PlutusDataSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("PlutusDataSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_data_set_t**", self._ptr)
            lib.cardano_plutus_data_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusDataSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusDataSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusDataSet:
        """
        Deserializes a PlutusDataSet from CBOR data.

        Args:
            reader: A CborReader positioned at the data set.

        Returns:
            A new PlutusDataSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_data_set_t**")
        err = lib.cardano_plutus_data_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize PlutusDataSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, data_items: Iterable[PlutusData]) -> PlutusDataSet:
        """
        Creates a PlutusDataSet from an iterable of PlutusData objects.

        Args:
            data_items: An iterable of PlutusData objects.

        Returns:
            A new PlutusDataSet containing all the data items.

        Raises:
            CardanoError: If creation fails.
        """
        data_set = cls()
        for data in data_items:
            data_set.add(data)
        return data_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the data set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_plutus_data_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize PlutusDataSet to CBOR (error code: {err})"
            )

    def add(self, data: PlutusData) -> None:
        """
        Adds Plutus data to the set.

        Args:
            data: The PlutusData to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_plutus_data_set_add(self._ptr, data._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add to PlutusDataSet (error code: {err})")

    def get(self, index: int) -> PlutusData:
        """
        Retrieves Plutus data at the specified index.

        Args:
            index: The index of the data to retrieve.

        Returns:
            The PlutusData at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get from PlutusDataSet (error code: {err})")
        return PlutusData(out[0])

    @property
    def use_tag(self) -> bool:
        """
        Whether the set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False for legacy array encoding.
        """
        return bool(lib.cardano_plutus_data_set_get_use_tag(self._ptr))

    @use_tag.setter
    def use_tag(self, value: bool) -> None:
        """
        Sets whether to use Conway era tagged encoding.

        Args:
            value: True for tagged encoding, False for legacy array encoding.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_plutus_data_set_set_use_tag(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set use_tag (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        This is useful when you have modified the set after it was created
        from CBOR and you want to ensure that the next serialization reflects
        the current state rather than using the original cached CBOR.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can invalidate existing signatures.
        """
        lib.cardano_plutus_data_set_clear_cbor_cache(self._ptr)

    def __len__(self) -> int:
        """Returns the number of data items in the set."""
        return int(lib.cardano_plutus_data_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[PlutusData]:
        """Iterates over all data items in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> PlutusData:
        """Gets data by index using bracket notation."""
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
        err = lib.cardano_plutus_data_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[PlutusData]") -> bool:
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
