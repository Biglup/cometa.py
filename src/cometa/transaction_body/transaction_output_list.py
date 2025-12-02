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
from .transaction_output import TransactionOutput


class TransactionOutputList(Sequence["TransactionOutput"]):
    """
    Represents an ordered list of transaction outputs.

    Transaction outputs specify where funds are sent in a transaction,
    including the recipient address and the value being transferred.
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_transaction_output_list_t**")
            err = lib.cardano_transaction_output_list_new(out)
            if err != 0:
                raise CardanoError(
                    f"Failed to create TransactionOutputList (error code: {err})"
                )
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("TransactionOutputList: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_output_list_t**", self._ptr)
            lib.cardano_transaction_output_list_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionOutputList:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TransactionOutputList(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionOutputList:
        """
        Deserializes a TransactionOutputList from CBOR data.

        Args:
            reader: A CborReader positioned at the output list data.

        Returns:
            A new TransactionOutputList deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_transaction_output_list_t**")
        err = lib.cardano_transaction_output_list_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionOutputList from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_list(cls, outputs: Iterable[TransactionOutput]) -> TransactionOutputList:
        """
        Creates a TransactionOutputList from an iterable of TransactionOutput objects.

        Args:
            outputs: An iterable of TransactionOutput objects.

        Returns:
            A new TransactionOutputList containing all the outputs.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> output1 = TransactionOutput.new(address1, 1000000)
            >>> output2 = TransactionOutput.new(address2, 2000000)
            >>> output_list = TransactionOutputList.from_list([output1, output2])
        """
        output_list = cls()
        for output in outputs:
            output_list.add(output)
        return output_list

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the output list to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_transaction_output_list_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionOutputList to CBOR (error code: {err})"
            )

    def add(self, output: TransactionOutput) -> None:
        """
        Adds a transaction output to the list.

        Args:
            output: The TransactionOutput to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_transaction_output_list_add(self._ptr, output._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to add to TransactionOutputList (error code: {err})"
            )

    def get(self, index: int) -> TransactionOutput:
        """
        Retrieves a transaction output at the specified index.

        Args:
            index: The index of the output to retrieve.

        Returns:
            The TransactionOutput at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(
                f"Index {index} out of range for list of length {len(self)}"
            )
        out = ffi.new("cardano_transaction_output_t**")
        err = lib.cardano_transaction_output_list_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get from TransactionOutputList (error code: {err})"
            )
        return TransactionOutput(out[0])

    def __len__(self) -> int:
        """Returns the number of outputs in the list."""
        return int(lib.cardano_transaction_output_list_get_length(self._ptr))

    def __iter__(self) -> Iterator[TransactionOutput]:
        """Iterates over all outputs in the list."""
        for i in range(len(self)):
            yield self.get(i)

    def __getitem__(self, index: int) -> TransactionOutput:
        """Gets an output by index using bracket notation."""
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
        err = lib.cardano_transaction_output_list_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
    def index(self, value: TransactionOutput, start: int = 0, stop: Optional[int] = None) -> int:
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

    def count(self, value: TransactionOutput) -> int:
        """
        Returns the number of occurrences of value.

        Args:
            value: The value to count.

        Returns:
            The number of occurrences.
        """
        return sum(1 for item in self if item == value)

    def __reversed__(self) -> Iterator[TransactionOutput]:
        """Iterates over elements in reverse order."""
        for i in range(len(self) - 1, -1, -1):
            yield self[i]
