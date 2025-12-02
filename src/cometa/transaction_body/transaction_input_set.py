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
from .transaction_input import TransactionInput


class TransactionInputSet(Set["TransactionInput"]):
    """
    Represents an ordered set of transaction inputs.

    Transaction inputs are unique references to UTXOs being spent.
    The set maintains ordering and prevents duplicates.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_transaction_input_set_t**")
            err = lib.cardano_transaction_input_set_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create TransactionInputSet (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("TransactionInputSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_input_set_t**", self._ptr)
            lib.cardano_transaction_input_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionInputSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TransactionInputSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionInputSet:
        """
        Deserializes a TransactionInputSet from CBOR data.

        Args:
            reader: A CborReader positioned at the input set data.

        Returns:
            A new TransactionInputSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_transaction_input_set_t**")
        err = lib.cardano_transaction_input_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionInputSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, inputs: Iterable[TransactionInput]) -> TransactionInputSet:
        """
        Creates a TransactionInputSet from an iterable of TransactionInput objects.

        Args:
            inputs: An iterable of TransactionInput objects.

        Returns:
            A new TransactionInputSet containing all the inputs.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> input1 = TransactionInput.from_hex(tx_hash1, 0)
            >>> input2 = TransactionInput.from_hex(tx_hash2, 1)
            >>> input_set = TransactionInputSet.from_list([input1, input2])
        """
        input_set = cls()
        for tx_input in inputs:
            input_set.add(tx_input)
        return input_set

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the input set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_transaction_input_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionInputSet to CBOR (error code: {err})"
            )

    def add(self, tx_input: TransactionInput) -> None:
        """
        Adds a transaction input to the set.

        Args:
            tx_input: The TransactionInput to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_transaction_input_set_add(self._ptr, tx_input._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to TransactionInputSet (error code: {err})"
            )

    def get(self, index: int) -> TransactionInput:
        """
        Retrieves a transaction input at the specified index.

        Args:
            index: The index of the input to retrieve.

        Returns:
            The TransactionInput at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for set of length {len(self)}"
            )
        out = ffi.new("cardano_transaction_input_t**")
        err = lib.cardano_transaction_input_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from TransactionInputSet (error code: {err})"
            )
        return TransactionInput(out[0])

    @property
    def is_tagged(self) -> bool:
        """
        Whether this set uses Conway era tagged encoding.

        Returns:
            True if using tagged encoding, False otherwise.
        """
        return bool(lib.cardano_transaction_input_set_is_tagged(self._ptr))

    def __len__(self) -> int:
        """Returns the number of inputs in the set."""
        return int(lib.cardano_transaction_input_set_get_length(self._ptr))

    def __iter__(self) -> Iterator[TransactionInput]:
        """Iterates over all inputs in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> TransactionInput:
        """Gets an input by index using bracket notation."""
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
        err = lib.cardano_transaction_input_set_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def __contains__(self, item: object) -> bool:
        """Checks if an item is in the set."""
        for element in self:
            if element == item:
                return True
        return False

    def isdisjoint(self, other: "Iterable[TransactionInput]") -> bool:
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
