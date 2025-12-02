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
from typing import Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cryptography.blake2b_hash import Blake2bHash
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter


class GovernanceActionId:
    """
    Represents a unique identifier for a governance action on the Cardano blockchain.

    Each governance action accepted on-chain is assigned a unique identifier consisting of:
    - The transaction hash of the transaction that created it
    - The index within the transaction body pointing to the governance action

    This identifier is used to reference specific governance actions in voting,
    ratification, and other governance-related operations.

    Example:
        >>> gov_id = GovernanceActionId.from_hash_hex("00" * 32, 0)
        >>> gov_id.index
        0
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("GovernanceActionId: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_governance_action_id_t**", self._ptr)
            lib.cardano_governance_action_id_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> GovernanceActionId:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"GovernanceActionId(index={self.index})"

    @classmethod
    def new(cls, transaction_hash: Blake2bHash, index: int) -> GovernanceActionId:
        """
        Creates a new governance action ID from a transaction hash and index.

        Args:
            transaction_hash: The Blake2b hash of the transaction containing the action.
            index: The index within the transaction body pointing to the governance action.

        Returns:
            A new GovernanceActionId instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> tx_hash = Blake2bHash.from_hex("00" * 32)
            >>> gov_id = GovernanceActionId.new(tx_hash, 0)
        """
        out = ffi.new("cardano_governance_action_id_t**")
        err = lib.cardano_governance_action_id_new(transaction_hash._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to create GovernanceActionId (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bech32(cls, bech32_string: str) -> GovernanceActionId:
        """
        Creates a governance action ID from a Bech32-encoded string (CIP-129 format).

        Args:
            bech32_string: The Bech32-encoded governance action ID string.

        Returns:
            A new GovernanceActionId instance.

        Raises:
            CardanoError: If parsing fails.

        Example:
            >>> gov_id = GovernanceActionId.from_bech32("gov_action1...")
        """
        out = ffi.new("cardano_governance_action_id_t**")
        data = bech32_string.encode("utf-8")
        err = lib.cardano_governance_action_id_from_bech32(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to parse GovernanceActionId from Bech32 (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hash_hex(cls, hex_string: str, index: int) -> GovernanceActionId:
        """
        Creates a governance action ID from a hexadecimal transaction hash string.

        Args:
            hex_string: The transaction hash as a hexadecimal string.
            index: The index within the transaction body.

        Returns:
            A new GovernanceActionId instance.

        Raises:
            CardanoError: If creation fails or hash is invalid.

        Example:
            >>> gov_id = GovernanceActionId.from_hash_hex("abcd1234" * 8, 1)
        """
        out = ffi.new("cardano_governance_action_id_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_governance_action_id_from_hash_hex(hex_bytes, len(hex_bytes), index, out)
        if err != 0:
            raise CardanoError(f"Failed to create GovernanceActionId from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hash_bytes(cls, data: Union[bytes, bytearray], index: int) -> GovernanceActionId:
        """
        Creates a governance action ID from raw transaction hash bytes.

        Args:
            data: The transaction hash as raw bytes.
            index: The index within the transaction body.

        Returns:
            A new GovernanceActionId instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> gov_id = GovernanceActionId.from_hash_bytes(bytes(32), 0)
        """
        out = ffi.new("cardano_governance_action_id_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_governance_action_id_from_hash_bytes(c_data, len(data), index, out)
        if err != 0:
            raise CardanoError(f"Failed to create GovernanceActionId from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> GovernanceActionId:
        """
        Deserializes a GovernanceActionId from CBOR data.

        Args:
            reader: A CborReader positioned at the governance action ID data.

        Returns:
            A new GovernanceActionId deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_governance_action_id_t**")
        err = lib.cardano_governance_action_id_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize GovernanceActionId from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def transaction_hash(self) -> Blake2bHash:
        """Returns the transaction hash associated with this governance action ID."""
        ptr = lib.cardano_governance_action_id_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction hash")
        return Blake2bHash(ptr)

    @transaction_hash.setter
    def transaction_hash(self, value: Blake2bHash) -> None:
        """Sets the transaction hash for this governance action ID."""
        err = lib.cardano_governance_action_id_set_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set transaction hash (error code: {err})")

    @property
    def index(self) -> int:
        """Returns the index within the transaction body."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_governance_action_id_get_index(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get index (error code: {err})")
        return int(out[0])

    @index.setter
    def index(self, value: int) -> None:
        """Sets the index within the transaction body."""
        err = lib.cardano_governance_action_id_set_index(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set index (error code: {err})")

    @property
    def hash_hex(self) -> str:
        """Returns the transaction hash as a hexadecimal string."""
        hex_ptr = lib.cardano_governance_action_id_get_hash_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    @property
    def hash_bytes(self) -> bytes:
        """Returns the transaction hash as raw bytes."""
        size = lib.cardano_governance_action_id_get_hash_bytes_size(self._ptr)
        if size == 0:
            return b""
        data = lib.cardano_governance_action_id_get_hash_bytes(self._ptr)
        if data == ffi.NULL:
            return b""
        return bytes(ffi.buffer(data, size))

    def to_bech32(self) -> str:
        """
        Returns the CIP-129 Bech32 string representation.

        Returns:
            The governance action ID as a Bech32-encoded string.

        Raises:
            CardanoError: If conversion fails.
        """
        size = lib.cardano_governance_action_id_get_bech32_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_governance_action_id_to_bech32(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert to Bech32 (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the governance action ID to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_governance_action_id_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize GovernanceActionId to CBOR (error code: {err})")

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
        err = lib.cardano_governance_action_id_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another GovernanceActionId."""
        if not isinstance(other, GovernanceActionId):
            return False
        return lib.cardano_governance_action_id_equals(self._ptr, other._ptr)

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.hash_bytes, self.index))

    def __str__(self) -> str:
        """Returns the Bech32 string representation."""
        str_ptr = lib.cardano_governance_action_id_get_string(self._ptr)
        if str_ptr == ffi.NULL:
            return ""
        return ffi.string(str_ptr).decode("utf-8")
