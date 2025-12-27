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
from typing import Iterator, Tuple, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .metadatum import Metadatum

if TYPE_CHECKING:
    from .metadatum_label_list import MetadatumLabelList


class TransactionMetadata:
    """
    Represents transaction metadata as a map of labels to metadatum values.

    Transaction metadata in Cardano is organized as a map where keys are
    unsigned 64-bit integers (labels) and values are Metadatum objects.
    Common labels include 721 for NFT metadata (CIP-25).

    Example:
        >>> metadata = TransactionMetadata()
        >>> metadata.insert(721, Metadatum.from_string("NFT metadata"))
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new TransactionMetadata instance.

        Args:
            ptr: Optional FFI pointer to an existing transaction metadata object.
                If None, creates a new empty transaction metadata.

        Raises:
            CardanoError: If creation fails or ptr is NULL.
        """
        if ptr is None:
            out = ffi.new("cardano_transaction_metadata_t**")
            err = lib.cardano_transaction_metadata_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create TransactionMetadata (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("TransactionMetadata: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the TransactionMetadata by releasing the underlying C resources."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_metadata_t**", self._ptr)
            lib.cardano_transaction_metadata_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionMetadata:
        """Enters the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exits the context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the TransactionMetadata."""
        return f"TransactionMetadata(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionMetadata:
        """
        Deserializes TransactionMetadata from CBOR data.

        Args:
            reader: A CborReader positioned at the metadata data.

        Returns:
            A new TransactionMetadata deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_transaction_metadata_t**")
        err = lib.cardano_transaction_metadata_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionMetadata from CBOR (error code: {err})"
            )
        return cls(out[0])

    def insert(self, label: int, value: Metadatum) -> None:
        """
        Inserts or updates a metadatum entry with the given label.

        Args:
            label: The metadata label (unsigned 64-bit integer).
            value: The metadatum value to associate with the label.

        Raises:
            CardanoError: If insertion fails.

        Example:
            >>> metadata.insert(721, nft_metadatum)
        """
        err = lib.cardano_transaction_metadata_insert(self._ptr, label, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert into TransactionMetadata (error code: {err})")

    def get(self, label: int) -> Metadatum:
        """
        Retrieves the metadatum associated with a label.

        Args:
            label: The metadata label to look up.

        Returns:
            The Metadatum associated with the label.

        Raises:
            CardanoError: If the label is not found or retrieval fails.

        Example:
            >>> nft_meta = metadata.get(721)
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_transaction_metadata_get(self._ptr, label, out)
        if err != 0:
            raise CardanoError(f"Failed to get from TransactionMetadata (error code: {err})")
        return Metadatum(out[0])

    def get_key_at(self, index: int) -> int:
        """
        Retrieves the label at a specific index.

        Args:
            index: The index of the label to retrieve.

        Returns:
            The label at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for metadata of length {len(self)}")
        label = ffi.new("uint64_t*")
        err = lib.cardano_transaction_metadata_get_key_at(self._ptr, index, label)
        if err != 0:
            raise CardanoError(f"Failed to get key at index {index} (error code: {err})")
        return int(label[0])

    def get_value_at(self, index: int) -> Metadatum:
        """
        Retrieves the metadatum at a specific index.

        Args:
            index: The index of the metadatum to retrieve.

        Returns:
            The Metadatum at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for metadata of length {len(self)}")
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_transaction_metadata_get_value_at(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get value at index {index} (error code: {err})")
        return Metadatum(out[0])

    def get_key_value_at(self, index: int) -> tuple[int, Metadatum]:
        """
        Retrieves the key-value pair at a specific index.

        Args:
            index: The index of the key-value pair to retrieve.

        Returns:
            A tuple containing the label (int) and Metadatum at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for metadata of length {len(self)}")
        key_out = ffi.new("uint64_t*")
        value_out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_transaction_metadata_get_key_value_at(self._ptr, index, key_out, value_out)
        if err != 0:
            raise CardanoError(f"Failed to get key-value at index {index} (error code: {err})")
        return (int(key_out[0]), Metadatum(value_out[0]))

    def get_keys(self) -> MetadatumLabelList:
        """
        Retrieves all keys (labels) from the metadata.

        Returns:
            A MetadatumLabelList containing all labels in the metadata.

        Raises:
            CardanoError: If retrieval fails.
        """
        from .metadatum_label_list import MetadatumLabelList

        out = ffi.new("cardano_metadatum_label_list_t**")
        err = lib.cardano_transaction_metadata_get_keys(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get keys from TransactionMetadata (error code: {err})")
        return MetadatumLabelList(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the transaction metadata to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_transaction_metadata_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionMetadata to CBOR (error code: {err})"
            )

    def __len__(self) -> int:
        """Returns the number of metadata entries."""
        return int(lib.cardano_transaction_metadata_get_length(self._ptr))

    def __iter__(self) -> Iterator[Tuple[int, Metadatum]]:
        """Iterates over all (label, metadatum) pairs."""
        for i in range(len(self)):
            yield self.get_key_at(i), self.get_value_at(i)

    def __contains__(self, label: int) -> bool:
        """Checks if a label exists in the metadata."""
        try:
            self.get(label)
            return True
        except CardanoError:
            return False

    def __getitem__(self, label: int) -> Metadatum:
        """Gets a metadatum by label using bracket notation."""
        return self.get(label)

    def __setitem__(self, label: int, value: Metadatum) -> None:
        """Sets a metadatum by label using bracket notation."""
        self.insert(label, value)

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
        err = lib.cardano_transaction_metadata_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
