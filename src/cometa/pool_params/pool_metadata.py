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
from ..cryptography.blake2b_hash import Blake2bHash


class PoolMetadata:
    """
    Represents pool metadata for a Cardano stake pool.

    Pool metadata includes a URL pointing to a JSON file containing pool information
    and a Blake2b-256 hash of that file for integrity verification.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PoolMetadata: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_pool_metadata_t**", self._ptr)
            lib.cardano_pool_metadata_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PoolMetadata:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PoolMetadata(url={self.url!r}, hash={self.hash.to_hex()!r})"

    def __str__(self) -> str:
        return self.url

    @classmethod
    def new(cls, url: str, metadata_hash: Blake2bHash) -> PoolMetadata:
        """
        Creates a new pool metadata object.

        Args:
            url: The URL pointing to the pool metadata JSON file.
            metadata_hash: The Blake2b-256 hash of the metadata file.

        Returns:
            A new PoolMetadata instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> hash = Blake2bHash.from_hex("00" * 32)
            >>> metadata = PoolMetadata.new("https://example.com/pool.json", hash)
        """
        out = ffi.new("cardano_pool_metadata_t**")
        url_bytes = url.encode("utf-8")
        err = lib.cardano_pool_metadata_new(url_bytes, len(url_bytes), metadata_hash._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PoolMetadata (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hash_hex(cls, url: str, hash_hex: str) -> PoolMetadata:
        """
        Creates a new pool metadata object from a URL and hex-encoded hash.

        Args:
            url: The URL pointing to the pool metadata JSON file.
            hash_hex: The Blake2b-256 hash as a hexadecimal string.

        Returns:
            A new PoolMetadata instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> metadata = PoolMetadata.from_hash_hex(
            ...     "https://example.com/pool.json",
            ...     "00" * 32
            ... )
        """
        out = ffi.new("cardano_pool_metadata_t**")
        url_bytes = url.encode("utf-8")
        hash_bytes = hash_hex.encode("utf-8")
        err = lib.cardano_pool_metadata_from_hash_hex(
            url_bytes, len(url_bytes), hash_bytes, len(hash_bytes), out
        )
        if err != 0:
            raise CardanoError(f"Failed to create PoolMetadata from hash hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PoolMetadata:
        """
        Deserializes a PoolMetadata from CBOR data.

        Args:
            reader: A CborReader positioned at the pool metadata data.

        Returns:
            A new PoolMetadata deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_pool_metadata_t**")
        err = lib.cardano_pool_metadata_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PoolMetadata from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the pool metadata to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_pool_metadata_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PoolMetadata to CBOR (error code: {err})")

    @property
    def url(self) -> str:
        """Returns the metadata URL."""
        url_ptr = lib.cardano_pool_metadata_get_url(self._ptr)
        if url_ptr == ffi.NULL:
            return ""
        return ffi.string(url_ptr).decode("utf-8")

    @url.setter
    def url(self, value: str) -> None:
        """Sets the metadata URL."""
        url_bytes = value.encode("utf-8")
        err = lib.cardano_pool_metadata_set_url(url_bytes, len(url_bytes), self._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set URL (error code: {err})")

    @property
    def hash(self) -> Blake2bHash:
        """Returns the metadata hash."""
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_pool_metadata_get_hash(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get hash (error code: {err})")
        return Blake2bHash(out[0])

    @hash.setter
    def hash(self, value: Blake2bHash) -> None:
        """Sets the metadata hash."""
        err = lib.cardano_pool_metadata_set_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set hash (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this pool metadata to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_pool_metadata_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
