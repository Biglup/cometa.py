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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter


class TransactionInput:
    """
    Represents a reference to an unspent transaction output (UTXO) being spent.

    A transaction input consists of:
    - Transaction ID: The hash of the transaction containing the UTXO
    - Index: The index of the output within that transaction
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("TransactionInput: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_input_t**", self._ptr)
            lib.cardano_transaction_input_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionInput:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TransactionInput(id={self.transaction_id.hex()}, index={self.index})"

    @classmethod
    def new(cls, transaction_id: bytes, index: int) -> TransactionInput:
        """
        Creates a new TransactionInput.

        Args:
            transaction_id: The 32-byte transaction hash.
            index: The output index within the transaction.

        Returns:
            A new TransactionInput instance.

        Raises:
            CardanoError: If creation fails.
        """
        # Create blake2b_hash from transaction_id
        hash_ptr = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_from_bytes(
            transaction_id, len(transaction_id), hash_ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to create transaction ID hash (error code: {err})")

        out = ffi.new("cardano_transaction_input_t**")
        err = lib.cardano_transaction_input_new(hash_ptr[0], index, out)

        lib.cardano_blake2b_hash_unref(hash_ptr)

        if err != 0:
            raise CardanoError(f"Failed to create TransactionInput (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, transaction_id_hex: str, index: int) -> TransactionInput:
        """
        Creates a new TransactionInput from a hex-encoded transaction ID.

        Args:
            transaction_id_hex: The transaction hash as a hex string.
            index: The output index within the transaction.

        Returns:
            A new TransactionInput instance.

        Raises:
            CardanoError: If creation fails.
        """
        hex_bytes = transaction_id_hex.encode("utf-8")
        out = ffi.new("cardano_transaction_input_t**")
        err = lib.cardano_transaction_input_from_hex(
            hex_bytes, len(hex_bytes), index, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create TransactionInput from hex (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionInput:
        """
        Deserializes a TransactionInput from CBOR data.

        Args:
            reader: A CborReader positioned at the input data.

        Returns:
            A new TransactionInput deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_transaction_input_t**")
        err = lib.cardano_transaction_input_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionInput from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the transaction input to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_transaction_input_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionInput to CBOR (error code: {err})"
            )

    def to_cip116_json(self, writer) -> None:
        """
        Serializes this transaction input to CIP-116 JSON format.

        CIP-116 defines a standard JSON representation for Cardano transactions.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa.json import JsonWriter
            >>> input = TransactionInput.from_hex(tx_hash, 0)
            >>> writer = JsonWriter()
            >>> input.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_transaction_input_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize TransactionInput to CIP-116 JSON (error code: {err})")

    @property
    def transaction_id(self) -> bytes:
        """
        The transaction ID (hash of the transaction containing the UTXO).

        Returns:
            The 32-byte transaction hash.
        """
        ptr = lib.cardano_transaction_input_get_id(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction ID")

        data_ptr = lib.cardano_blake2b_hash_get_data(ptr)
        size = lib.cardano_blake2b_hash_get_bytes_size(ptr)
        result = bytes(ffi.buffer(data_ptr, size))

        hash_ptr = ffi.new("cardano_blake2b_hash_t**", ptr)
        lib.cardano_blake2b_hash_unref(hash_ptr)

        return result

    @transaction_id.setter
    def transaction_id(self, value: bytes) -> None:
        """
        Sets the transaction ID.

        Args:
            value: The 32-byte transaction hash.

        Raises:
            CardanoError: If setting fails.
        """
        hash_ptr = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_from_bytes(value, len(value), hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create transaction ID hash (error code: {err})")

        err = lib.cardano_transaction_input_set_id(self._ptr, hash_ptr[0])
        lib.cardano_blake2b_hash_unref(hash_ptr)

        if err != 0:
            raise CardanoError(f"Failed to set transaction ID (error code: {err})")

    @property
    def index(self) -> int:
        """
        The output index within the transaction.

        Returns:
            The output index.
        """
        return int(lib.cardano_transaction_input_get_index(self._ptr))

    @index.setter
    def index(self, value: int) -> None:
        """
        Sets the output index.

        Args:
            value: The output index.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_input_set_index(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set index (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another TransactionInput."""
        if not isinstance(other, TransactionInput):
            return NotImplemented
        return bool(lib.cardano_transaction_input_equals(self._ptr, other._ptr))

    def __lt__(self, other: TransactionInput) -> bool:
        """Compares this input with another for ordering."""
        if not isinstance(other, TransactionInput):
            return NotImplemented
        return lib.cardano_transaction_input_compare(self._ptr, other._ptr) < 0

    def __hash__(self) -> int:
        """Returns hash for use in sets and dicts."""
        return hash((self.transaction_id, self.index))
