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
from typing import Optional, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from .datum_type import DatumType
from ..cryptography.blake2b_hash import Blake2bHash
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..plutus_data.plutus_data import PlutusData


class Datum:
    """
    Represents a piece of data attached to a UTxO for Plutus script interaction.

    Datums act as state for UTxOs, allowing Plutus scripts to perform complex
    logic based on stored data when the UTxO is being spent. There are two types:

    - DATA_HASH: A hash reference to off-chain datum data
    - INLINE_DATA: The actual Plutus data stored directly on-chain

    Example:
        >>> datum = Datum.from_data_hash_hex("00" * 32)
        >>> datum.datum_type
        DatumType.DATA_HASH
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Datum: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_datum_t**", self._ptr)
            lib.cardano_datum_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Datum:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Datum(type={self.datum_type.name})"

    @classmethod
    def from_data_hash(cls, hash_value: Blake2bHash) -> Datum:
        """
        Creates a datum from a Blake2b hash reference.

        Args:
            hash_value: The Blake2b hash of the datum data.

        Returns:
            A new Datum instance with type DATA_HASH.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> hash_val = Blake2bHash.from_hex("00" * 32)
            >>> datum = Datum.from_data_hash(hash_val)
        """
        out = ffi.new("cardano_datum_t**")
        err = lib.cardano_datum_new_data_hash(hash_value._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Datum from hash (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_data_hash_hex(cls, hex_string: str) -> Datum:
        """
        Creates a datum from a hexadecimal hash string.

        Args:
            hex_string: The hash as a hexadecimal string.

        Returns:
            A new Datum instance with type DATA_HASH.

        Raises:
            CardanoError: If creation fails or hash is invalid.

        Example:
            >>> datum = Datum.from_data_hash_hex("abcd1234" * 8)
        """
        out = ffi.new("cardano_datum_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_datum_new_data_hash_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Datum from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_data_hash_bytes(cls, data: Union[bytes, bytearray]) -> Datum:
        """
        Creates a datum from raw hash bytes.

        Args:
            data: The hash as raw bytes.

        Returns:
            A new Datum instance with type DATA_HASH.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> datum = Datum.from_data_hash_bytes(bytes(32))
        """
        out = ffi.new("cardano_datum_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_datum_new_data_hash_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Datum from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_inline_data(cls, data) -> Datum:
        """
        Creates a datum from inline Plutus data.

        Args:
            data: The Plutus data to store inline (PlutusData instance).

        Returns:
            A new Datum instance with type INLINE_DATA.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> plutus_data = PlutusData.from_int(42)
            >>> datum = Datum.from_inline_data(plutus_data)
        """
        out = ffi.new("cardano_datum_t**")
        err = lib.cardano_datum_new_inline_data(data._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Datum from inline data (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Datum:
        """
        Deserializes a Datum from CBOR data.

        Args:
            reader: A CborReader positioned at the datum data.

        Returns:
            A new Datum deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_datum_t**")
        err = lib.cardano_datum_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Datum from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def datum_type(self) -> DatumType:
        """Returns the type of this datum (DATA_HASH or INLINE_DATA)."""
        type_out = ffi.new("cardano_datum_type_t*")
        err = lib.cardano_datum_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get datum type (error code: {err})")
        return DatumType(type_out[0])

    @property
    def data_hash(self) -> Optional[Blake2bHash]:
        """
        Returns the hash associated with this datum.

        Returns None if this is an inline datum without a hash.
        """
        ptr = lib.cardano_datum_get_data_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)

    @data_hash.setter
    def data_hash(self, value: Blake2bHash) -> None:
        """Sets the data hash for this datum."""
        err = lib.cardano_datum_set_data_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set data hash (error code: {err})")

    @property
    def data_hash_hex(self) -> str:
        """Returns the data hash as a hexadecimal string."""
        hex_ptr = lib.cardano_datum_get_data_hash_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    @property
    def data_hash_bytes(self) -> bytes:
        """Returns the data hash as raw bytes."""
        size = lib.cardano_datum_get_data_hash_bytes_size(self._ptr)
        if size == 0:
            return b""
        data = lib.cardano_datum_get_data_hash_bytes(self._ptr)
        if data == ffi.NULL:
            return b""
        return bytes(ffi.buffer(data, size))

    def get_inline_data(self):
        """
        Returns the inline Plutus data if this is an inline datum.

        Returns None if this is a data hash datum.

        Note: This method requires the PlutusData module to be available.
        Import PlutusData from cometa.plutus_data before calling this method.

        Raises:
            ImportError: If PlutusData module is not available.
        """
        ptr = lib.cardano_datum_get_inline_data(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PlutusData(ptr)

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the datum to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_datum_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Datum to CBOR (error code: {err})")

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
        err = lib.cardano_datum_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Datum."""
        if not isinstance(other, Datum):
            return False
        return lib.cardano_datum_equals(self._ptr, other._ptr)

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.datum_type, self.data_hash_bytes))

    def __str__(self) -> str:
        """Returns a string representation of the datum."""
        if self.datum_type == DatumType.DATA_HASH:
            hash_hex = self.data_hash_hex
            if hash_hex:
                return f"DatumHash({hash_hex[:16]}...)"
            return "DatumHash()"
        return f"InlineDatum(type={self.datum_type.name})"
