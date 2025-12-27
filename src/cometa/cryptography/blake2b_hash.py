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
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter


class Blake2bHash:
    """
    Represents a BLAKE2b cryptographic hash.

    BLAKE2b is a cryptographic hash function used throughout Cardano for
    transaction identification, address generation, and cryptographic verification.

    Common hash sizes:
        - 28 bytes (224 bits): Used for credentials and key hashes
        - 32 bytes (256 bits): Used for transaction IDs and script hashes
    """

    def __init__(self, ptr) -> None:
        """
        Internal constructor.
        Use class methods like `compute`, `from_bytes`, `from_hex`, or `from_cbor` instead.
        """
        if ptr == ffi.NULL:
            raise CardanoError("Blake2bHash: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        """
        Destructor to release the underlying C object.
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_blake2b_hash_t**", self._ptr)
            lib.cardano_blake2b_hash_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Blake2bHash:
        """
        Context manager entry (no-op).
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Context manager exit (no-op).
        """

    def __repr__(self) -> str:
        """
        Returns a developer-friendly string representation.
        """
        return f"Blake2bHash({self.to_hex()})"

    @classmethod
    def compute(cls, data: Union[bytes, bytearray], hash_size: int = 32) -> Blake2bHash:
        """
        Computes a BLAKE2b hash of the given data.

        Args:
            data: The input data to hash.
            hash_size: The desired hash length in bytes (e.g., 28 or 32).

        Returns:
            A new Blake2bHash containing the computed hash.

        Raises:
            CardanoError: If the hash computation fails.

        Example:
            >>> hash = Blake2bHash.compute(b"hello world", hash_size=32)
            >>> len(hash)
            32
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_blake2b_compute_hash(c_data, len(data), hash_size, out)
        if err != 0:
            raise CardanoError(f"Failed to compute BLAKE2b hash (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Blake2bHash:
        """
        Creates a Blake2bHash from raw hash bytes.

        Args:
            data: The raw hash bytes.

        Returns:
            A new Blake2bHash containing the provided bytes.

        Raises:
            CardanoError: If the hash creation fails.

        Example:
            >>> hash = Blake2bHash.from_bytes(bytes(32))
            >>> len(hash)
            32
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_blake2b_hash_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Blake2bHash from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Blake2bHash:
        """
        Creates a Blake2bHash from a hexadecimal string.

        Args:
            hex_string: The hexadecimal representation of the hash.

        Returns:
            A new Blake2bHash containing the decoded bytes.

        Raises:
            CardanoError: If the hex string is invalid.

        Example:
            >>> hash = Blake2bHash.from_hex("00" * 32)
            >>> len(hash)
            32
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_blake2b_hash_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Blake2bHash from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Blake2bHash:
        """
        Deserializes a Blake2bHash from CBOR data.

        Args:
            reader: A CborReader positioned at the hash data.

        Returns:
            A new Blake2bHash deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Blake2bHash from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def size(self) -> int:
        """Returns the size of the hash in bytes."""
        return int(lib.cardano_blake2b_hash_get_bytes_size(self._ptr))

    def to_bytes(self) -> bytes:
        """
        Returns the raw hash bytes.

        Returns:
            The hash as a bytes object.

        Example:
            >>> hash = Blake2bHash.from_hex("00" * 32)
            >>> hash.to_bytes() == bytes(32)
            True
        """
        size = self.size
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_blake2b_hash_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert Blake2bHash to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_hex(self) -> str:
        """
        Returns the hexadecimal string representation of the hash.

        Returns:
            The hash as a lowercase hexadecimal string.

        Example:
            >>> hash = Blake2bHash.from_bytes(bytes(32))
            >>> hash.to_hex()
            '0000000000000000000000000000000000000000000000000000000000000000'
        """
        size = lib.cardano_blake2b_hash_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_blake2b_hash_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert Blake2bHash to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the hash to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_blake2b_hash_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Blake2bHash to CBOR (error code: {err})")

    def compare(self, other: Blake2bHash) -> int:
        """
        Compares this hash with another hash.

        Args:
            other: The hash to compare with.

        Returns:
            A negative value if this hash is less than other,
            zero if they are equal,
            a positive value if this hash is greater than other.
        """
        return int(lib.cardano_blake2b_hash_compare(self._ptr, other._ptr))

    def __len__(self) -> int:
        """Returns the size of the hash in bytes."""
        return self.size

    def __bytes__(self) -> bytes:
        """Returns the raw hash bytes."""
        return self.to_bytes()

    def __str__(self) -> str:
        """Returns the hexadecimal string representation."""
        return self.to_hex()

    def __hash__(self) -> int:
        """Returns a Python hash of this object for use in sets and dicts."""
        return hash(self.to_bytes())

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Blake2bHash."""
        if not isinstance(other, Blake2bHash):
            return False
        return bool(lib.cardano_blake2b_hash_equals(self._ptr, other._ptr))

    def __lt__(self, other: Blake2bHash) -> bool:
        """Less than comparison."""
        return self.compare(other) < 0

    def __le__(self, other: Blake2bHash) -> bool:
        """Less than or equal comparison."""
        return self.compare(other) <= 0

    def __gt__(self, other: Blake2bHash) -> bool:
        """Greater than comparison."""
        return self.compare(other) > 0

    def __ge__(self, other: Blake2bHash) -> bool:
        """Greater than or equal comparison."""
        return self.compare(other) >= 0
