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

from typing import Optional, TYPE_CHECKING

from ..json import JsonFormat, JsonWriter
from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..cryptography.blake2b_hash import Blake2bHash
from ..transaction_body.transaction_body import TransactionBody
from ..witness_set.witness_set import WitnessSet
from ..auxiliary_data.auxiliary_data import AuxiliaryData

if TYPE_CHECKING:
    from ..cryptography.blake2b_hash_set import Blake2bHashSet
    from ..common.utxo_list import UtxoList


class Transaction:
    """
    Represents a complete Cardano transaction.

    A transaction is a record of value transfer between addresses on the network.
    It consists of:
    - Body: The core transaction data (inputs, outputs, fees, etc.)
    - Witness set: Cryptographic signatures and other witness data
    - Auxiliary data: Optional metadata
    - Is valid: Flag indicating expected Plutus script validation result
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Transaction: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_t**", self._ptr)
            lib.cardano_transaction_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Transaction:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Transaction(id={self.id.to_hex()[:16]}...)"

    @classmethod
    def new(
        cls,
        body: TransactionBody,
        witness_set: WitnessSet,
        auxiliary_data: Optional[AuxiliaryData] = None,
    ) -> Transaction:
        """
        Creates a new Transaction.

        Args:
            body: The transaction body containing inputs, outputs, and fees.
            witness_set: The witness set containing signatures and other witness data.
            auxiliary_data: Optional auxiliary data (metadata, governance info).

        Returns:
            A new Transaction instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_transaction_t**")
        aux_ptr = auxiliary_data._ptr if auxiliary_data is not None else ffi.NULL
        err = lib.cardano_transaction_new(body._ptr, witness_set._ptr, aux_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Transaction (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Transaction:
        """
        Deserializes a Transaction from CBOR data.

        Args:
            reader: A CborReader positioned at the transaction data.

        Returns:
            A new Transaction deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.

        Note:
            The original CBOR encoding is cached internally to preserve
            the exact representation and avoid invalidating signatures
            when re-serializing.
        """
        out = ffi.new("cardano_transaction_t**")
        err = lib.cardano_transaction_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Transaction from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the transaction to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Note:
            If this transaction was created from CBOR, the cached
            original encoding is used to preserve the exact representation.
        """
        err = lib.cardano_transaction_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Transaction to CBOR (error code: {err})"
            )

    def serialize_to_cbor(self) -> str:
        """
        Serializes the transaction to a CBOR hex string.

        Returns:
            A hex string representing the serialized CBOR data.

        Raises:
            CardanoError: If serialization fails.

        Note:
            If this transaction was created from CBOR, the cached
            original encoding is used to preserve the exact representation.
        """
        writer = CborWriter()
        self.to_cbor(writer)
        return writer.to_hex()

    def serialize_to_json(self) -> str:
        """
        Serializes the transaction to a JSON string.

        Returns:
            A JSON string representing the transaction.

        Raises:
            CardanoError: If serialization fails.
        """
        json_writer = JsonWriter(JsonFormat.PRETTY)
        self.to_cip116_json(json_writer)
        return json_writer.encode()

    def to_dict(self) -> dict:
        """
        Converts the transaction to a dictionary representation (follows CIP-116).

        Returns:
            A dictionary representing the transaction.

        Raises:
            CardanoError: If serialization fails.
        """
        import json

        json_str = self.serialize_to_json()
        return json.loads(json_str)

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        After calling this, to_cbor will serialize the transaction
        fresh rather than using the cached original encoding.

        Warning:
            This may change the binary representation and alter the
            transaction hash, invalidating any existing signatures.
        """
        lib.cardano_transaction_clear_cbor_cache(self._ptr)

    def to_cip116_json(self, writer) -> None:
        """
        Serializes this transaction to CIP-116 JSON format.

        CIP-116 defines a standard JSON representation for Cardano transactions.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa.json import JsonWriter
            >>> tx = Transaction.new(body, witness_set)
            >>> writer = JsonWriter()
            >>> tx.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_transaction_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Transaction to CIP-116 JSON (error code: {err})")

    @property
    def id(self) -> Blake2bHash: # ignore pylint: disable=invalid-name
        """
        The transaction ID (Blake2b-256 hash of the transaction body).

        This hash uniquely identifies the transaction on the blockchain.

        Returns:
            The transaction ID as a Blake2bHash.
        """
        ptr = lib.cardano_transaction_get_id(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction ID")
        return Blake2bHash(ptr)

    @property
    def body(self) -> TransactionBody:
        """
        The transaction body containing core transaction data.

        Returns:
            The TransactionBody.
        """
        ptr = lib.cardano_transaction_get_body(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction body")
        return TransactionBody(ptr)

    @body.setter
    def body(self, value: TransactionBody) -> None:
        """
        Sets the transaction body.

        Args:
            value: The TransactionBody to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_set_body(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set body (error code: {err})")

    @property
    def witness_set(self) -> WitnessSet:
        """
        The witness set containing signatures and witness data.

        Returns:
            The WitnessSet.
        """
        ptr = lib.cardano_transaction_get_witness_set(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get witness set")
        return WitnessSet(ptr)

    @witness_set.setter
    def witness_set(self, value: WitnessSet) -> None:
        """
        Sets the witness set.

        Args:
            value: The WitnessSet to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_set_witness_set(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set witness_set (error code: {err})")

    @property
    def auxiliary_data(self) -> Optional[AuxiliaryData]:
        """
        The optional auxiliary data (metadata, governance info).

        Returns:
            The AuxiliaryData if present, None otherwise.
        """
        ptr = lib.cardano_transaction_get_auxiliary_data(self._ptr)
        if ptr == ffi.NULL:
            return None
        return AuxiliaryData(ptr)

    @auxiliary_data.setter
    def auxiliary_data(self, value: Optional[AuxiliaryData]) -> None:
        """
        Sets or clears the auxiliary data.

        Args:
            value: The AuxiliaryData to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        aux_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_set_auxiliary_data(self._ptr, aux_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set auxiliary_data (error code: {err})")

    @property
    def is_valid(self) -> bool:
        """
        Whether the transaction is expected to pass Plutus script validation.

        A transaction with this flag set to False is expected to fail
        validation, but can still be submitted to the blockchain.

        Returns:
            True if expected to pass validation, False otherwise.
        """
        return bool(lib.cardano_transaction_get_is_valid(self._ptr))

    @is_valid.setter
    def is_valid(self, value: bool) -> None:
        """
        Sets the expected validation result flag.

        Args:
            value: True if expected to pass validation, False otherwise.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_set_is_valid(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set is_valid (error code: {err})")

    def has_script_data(self) -> bool:
        """
        Checks if this transaction contains script data.

        Script data includes redeemers or datums required for
        transactions involving Plutus scripts.

        Returns:
            True if the transaction contains script data, False otherwise.
        """
        return bool(lib.cardano_transaction_has_script_data(self._ptr))

    def apply_vkey_witnesses(self, vkey_witnesses) -> None:
        """
        Applies verification key witnesses to this transaction.

        Args:
            vkey_witnesses: A VkeyWitnessSet containing the witnesses to apply.

        Raises:
            CardanoError: If applying witnesses fails.
        """
        err = lib.cardano_transaction_apply_vkey_witnesses(
            self._ptr, vkey_witnesses._ptr
        )
        if err != 0:
            raise CardanoError(
                f"Failed to apply vkey witnesses (error code: {err})"
            )

    def get_unique_signers(
        self, resolved_inputs: Optional["UtxoList"] = None
    ) -> "Blake2bHashSet":
        """
        Extracts the unique set of public key hashes required to sign this transaction.

        This method computes the required signers by analyzing the transaction body
        and an optional list of resolved input UTxOs.

        Args:
            resolved_inputs: An optional UtxoList containing the resolved UTxOs
                that are spent by the transaction. If None or empty, the function
                won't resolve signers from inputs or collateral inputs. If provided,
                they must account for all inputs and collateral inputs in the
                transaction or the function will fail.

        Returns:
            A Blake2bHashSet containing the unique public key hashes (signers)
            required to authorize the transaction.

        Raises:
            CardanoError: If computing the unique signers fails.

        Example:
            >>> from cometa import Transaction, UtxoList, CborReader
            >>> tx = Transaction.from_cbor(CborReader.from_hex(tx_cbor_hex))
            >>> signers = tx.get_unique_signers(resolved_utxos)
            >>> for signer in signers:
            ...     print(signer.to_hex())
        """
        from ..cryptography.blake2b_hash_set import Blake2bHashSet

        out = ffi.new("cardano_blake2b_hash_set_t**")
        inputs_ptr = resolved_inputs._ptr if resolved_inputs is not None else ffi.NULL
        err = lib.cardano_transaction_get_unique_signers(self._ptr, inputs_ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get unique signers from transaction (error code: {err})"
            )
        return Blake2bHashSet(out[0])
