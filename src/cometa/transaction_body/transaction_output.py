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

from typing import Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..address.address import Address
from ..common.datum import Datum
from ..scripts.script import Script
from .value import Value


class TransactionOutput:
    """
    Represents an output of a Cardano transaction.

    A transaction output consists of:
    - Address: The recipient address (can be a payment key hash or script hash)
    - Value: The amount of ADA (in lovelace) and any multi-assets
    - Datum: Optional state data for Plutus scripts
    - Script reference: Optional reference to a script in another output
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("TransactionOutput: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_output_t**", self._ptr)
            lib.cardano_transaction_output_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionOutput:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TransactionOutput(address={self.address}, value={self.value})"

    @classmethod
    def new(cls, address: Address, amount: int) -> TransactionOutput:
        """
        Creates a new TransactionOutput with the given address and ADA amount.

        Args:
            address: The recipient address.
            amount: The amount in lovelace.

        Returns:
            A new TransactionOutput instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_transaction_output_t**")
        err = lib.cardano_transaction_output_new(address._ptr, amount, out)
        if err != 0:
            raise CardanoError(f"Failed to create TransactionOutput (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionOutput:
        """
        Deserializes a TransactionOutput from CBOR data.

        Args:
            reader: A CborReader positioned at the output data.

        Returns:
            A new TransactionOutput deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_transaction_output_t**")
        err = lib.cardano_transaction_output_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionOutput from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the transaction output to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_transaction_output_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionOutput to CBOR (error code: {err})"
            )

    def to_cip116_json(self, writer) -> None:
        """
        Serializes this transaction output to CIP-116 JSON format.

        CIP-116 defines a standard JSON representation for Cardano transactions.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa.json import JsonWriter
            >>> output = TransactionOutput.new(address, 1000000)
            >>> writer = JsonWriter()
            >>> output.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_transaction_output_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize TransactionOutput to CIP-116 JSON (error code: {err})")

    @property
    def address(self) -> Address:
        """
        The recipient address for this output.

        Returns:
            The Address where funds are sent.
        """
        ptr = lib.cardano_transaction_output_get_address(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get address")
        return Address(ptr)

    @address.setter
    def address(self, value: Address) -> None:
        """
        Sets the recipient address.

        Args:
            value: The Address to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_output_set_address(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set address (error code: {err})")

    @property
    def value(self) -> Value:
        """
        The value (ADA and multi-assets) held by this output.

        Returns:
            The Value contained in the output.
        """
        ptr = lib.cardano_transaction_output_get_value(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get value")
        return Value(ptr)

    @value.setter
    def value(self, val: Value) -> None:
        """
        Sets the value for this output.

        Args:
            val: The Value to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_output_set_value(self._ptr, val._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set value (error code: {err})")

    @property
    def datum(self) -> Optional[Datum]:
        """
        The optional datum associated with this output.

        A datum is state data used by Plutus scripts to dictate
        transaction validity based on script logic.

        Returns:
            The Datum if present, None otherwise.
        """
        ptr = lib.cardano_transaction_output_get_datum(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Datum(ptr)

    @datum.setter
    def datum(self, value: Optional[Datum]) -> None:
        """
        Sets or clears the datum for this output.

        Args:
            value: The Datum to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        datum_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_output_set_datum(self._ptr, datum_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set datum (error code: {err})")

    @property
    def script_ref(self) -> Optional[Script]:
        """
        The optional script reference in this output.

        Script references allow transactions to refer to scripts included
        in other outputs, reducing transaction size by not including
        the script directly.

        Returns:
            The Script if present, None otherwise.
        """
        ptr = lib.cardano_transaction_output_get_script_ref(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Script(ptr)

    @script_ref.setter
    def script_ref(self, value: Optional[Script]) -> None:
        """
        Sets or clears the script reference for this output.

        Args:
            value: The Script to set as reference, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        script_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_output_set_script_ref(self._ptr, script_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set script_ref (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another TransactionOutput."""
        if not isinstance(other, TransactionOutput):
            return NotImplemented
        return bool(lib.cardano_transaction_output_equals(self._ptr, other._ptr))
