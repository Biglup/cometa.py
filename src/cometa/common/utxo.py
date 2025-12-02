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


class Utxo:
    """
    Represents an Unspent Transaction Output (UTxO).

    A UTxO links a transaction input to its corresponding output, representing
    spendable value in the Cardano blockchain. UTxOs are fundamental to Cardano's
    accounting model and are used as inputs in new transactions.

    Example:
        >>> from cometa import Utxo, TransactionInput, TransactionOutput, Address
        >>> tx_input = TransactionInput.from_hex("abc123...", 0)
        >>> address = Address.from_string("addr_test1...")
        >>> tx_output = TransactionOutput.new(address, 1000000)
        >>> utxo = Utxo.new(tx_input, tx_output)
        >>> print(utxo.input.index)
        0
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            raise CardanoError("Utxo cannot be created directly. Use Utxo.new() instead.")
        if ptr == ffi.NULL:
            raise CardanoError("Utxo: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_utxo_t**", self._ptr)
            lib.cardano_utxo_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Utxo:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Utxo(input={self.input!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Utxo):
            return False
        return bool(lib.cardano_utxo_equals(self._ptr, other._ptr))

    @classmethod
    def new(cls, tx_input: "TransactionInput", tx_output: "TransactionOutput") -> Utxo:
        """
        Creates a new UTXO by associating a transaction input with its
        corresponding transaction output.

        Args:
            tx_input: The transaction input representing the source of the UTXO.
            tx_output: The transaction output representing the value and recipient.

        Returns:
            A new Utxo instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> utxo = Utxo.new(tx_input, tx_output)
        """
        out = ffi.new("cardano_utxo_t**")
        err = lib.cardano_utxo_new(tx_input._ptr, tx_output._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Utxo (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Utxo:
        """
        Deserializes a Utxo from CBOR data.

        Args:
            reader: A CborReader positioned at the UTXO data.

        Returns:
            A new Utxo instance deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_utxo_t**")
        err = lib.cardano_utxo_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Utxo from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the UTXO to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_utxo_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Utxo to CBOR (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Converts this object to CIP-116 compliant JSON representation.

        CIP-116 defines a standard JSON format for Cardano data structures.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If conversion fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_utxo_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    @property
    def input(self) -> "TransactionInput":
        """
        Gets the transaction input associated with this UTXO.

        Returns:
            The TransactionInput representing the source of the UTXO.
        """
        from ..transaction_body.transaction_input import TransactionInput

        ptr = lib.cardano_utxo_get_input(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get UTXO input")
        return TransactionInput(ptr)

    @input.setter
    def input(self, value: "TransactionInput") -> None:
        """
        Sets the transaction input for this UTXO.

        Args:
            value: The TransactionInput to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_utxo_set_input(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set UTXO input (error code: {err})")

    @property
    def output(self) -> "TransactionOutput":
        """
        Gets the transaction output associated with this UTXO.

        Returns:
            The TransactionOutput representing the value and recipient.
        """
        from ..transaction_body.transaction_output import TransactionOutput

        ptr = lib.cardano_utxo_get_output(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get UTXO output")
        return TransactionOutput(ptr)

    @output.setter
    def output(self, value: "TransactionOutput") -> None:
        """
        Sets the transaction output for this UTXO.

        Args:
            value: The TransactionOutput to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_utxo_set_output(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set UTXO output (error code: {err})")
