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


class Anchor:
    """
    Represents an anchor for off-chain metadata in Cardano governance.

    An anchor is a pair of:
    - A URL pointing to a JSON payload of metadata
    - A Blake2b-256 hash of the contents at that URL

    Anchors are used throughout Cardano's governance system to reference off-chain
    metadata while maintaining on-chain integrity through hash verification:

    - Governance actions: Justification and context for proposals
    - DRep registration: Optional metadata about the DRep
    - Votes: Supporting information for voting decisions
    - Constitution: Reference to the constitution document
    - Treasury withdrawals: Justification for withdrawal requests

    The hash should be computed as the Blake2b-256 hash of the raw bytes received
    from the URL, ensuring there are no ambiguities in verification.

    Note: The on-chain rules do not validate the URL or verify the hash against
    actual content. Client applications must perform verification when fetching
    content from the provided URL. If the hash doesn't match, the metadata should
    be considered invalid.

    Example:
        >>> anchor = Anchor.from_hash_hex(
        ...     "https://example.com/metadata.json",
        ...     "abc123..." * 2  # 32-byte hash as hex
        ... )
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Anchor: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_anchor_t**", self._ptr)
            lib.cardano_anchor_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Anchor:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Anchor(url={self.url!r})"

    @classmethod
    def new(cls, url: str, hash_value: Blake2bHash) -> Anchor:
        """
        Creates a new anchor with a URL and hash.

        Args:
            url: The URL pointing to the metadata JSON.
            hash_value: The Blake2b hash of the metadata content.

        Returns:
            A new Anchor instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> hash_val = Blake2bHash.from_hex("00" * 32)
            >>> anchor = Anchor.new("https://example.com/meta.json", hash_val)
        """
        out = ffi.new("cardano_anchor_t**")
        url_bytes = url.encode("utf-8")
        err = lib.cardano_anchor_new(url_bytes, len(url_bytes), hash_value._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Anchor (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hash_hex(cls, url: str, hash_hex: str) -> Anchor:
        """
        Creates an anchor from a URL and hexadecimal hash string.

        Args:
            url: The URL pointing to the metadata JSON.
            hash_hex: The hash as a hexadecimal string.

        Returns:
            A new Anchor instance.

        Raises:
            CardanoError: If creation fails or hash is invalid.

        Example:
            >>> anchor = Anchor.from_hash_hex(
            ...     "https://example.com/meta.json",
            ...     "abcd1234" * 8
            ... )
        """
        out = ffi.new("cardano_anchor_t**")
        url_bytes = url.encode("utf-8")
        hex_bytes = hash_hex.encode("utf-8")
        err = lib.cardano_anchor_from_hash_hex(
            url_bytes, len(url_bytes), hex_bytes, len(hex_bytes), out
        )
        if err != 0:
            raise CardanoError(f"Failed to create Anchor from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hash_bytes(cls, url: str, hash_bytes: Union[bytes, bytearray]) -> Anchor:
        """
        Creates an anchor from a URL and raw hash bytes.

        Args:
            url: The URL pointing to the metadata JSON.
            hash_bytes: The hash as raw bytes.

        Returns:
            A new Anchor instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> anchor = Anchor.from_hash_bytes(
            ...     "https://example.com/meta.json",
            ...     bytes(32)
            ... )
        """
        out = ffi.new("cardano_anchor_t**")
        url_bytes = url.encode("utf-8")
        c_data = ffi.from_buffer("byte_t[]", hash_bytes)
        err = lib.cardano_anchor_from_hash_bytes(
            url_bytes, len(url_bytes), c_data, len(hash_bytes), out
        )
        if err != 0:
            raise CardanoError(f"Failed to create Anchor from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Anchor:
        """
        Deserializes an Anchor from CBOR data.

        Args:
            reader: A CborReader positioned at the anchor data.

        Returns:
            A new Anchor deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_anchor_t**")
        err = lib.cardano_anchor_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Anchor from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def url(self) -> str:
        """Returns the URL associated with this anchor."""
        url_ptr = lib.cardano_anchor_get_url(self._ptr)
        if url_ptr == ffi.NULL:
            return ""
        return ffi.string(url_ptr).decode("utf-8")

    @url.setter
    def url(self, value: str) -> None:
        """Sets the URL for this anchor."""
        url_bytes = value.encode("utf-8")
        err = lib.cardano_anchor_set_url(self._ptr, url_bytes, len(url_bytes))
        if err != 0:
            raise CardanoError(f"Failed to set URL (error code: {err})")

    @property
    def hash(self) -> Blake2bHash:
        """Returns the hash associated with this anchor."""
        ptr = lib.cardano_anchor_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get anchor hash")
        return Blake2bHash(ptr)

    @hash.setter
    def hash(self, value: Blake2bHash) -> None:
        """Sets the hash for this anchor."""
        err = lib.cardano_anchor_set_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set hash (error code: {err})")

    @property
    def hash_hex(self) -> str:
        """Returns the hash as a hexadecimal string."""
        hex_ptr = lib.cardano_anchor_get_hash_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    @property
    def hash_bytes(self) -> bytes:
        """Returns the hash as raw bytes."""
        size = lib.cardano_anchor_get_hash_bytes_size(self._ptr)
        if size == 0:
            return b""
        data = lib.cardano_anchor_get_hash_bytes(self._ptr)
        if data == ffi.NULL:
            return b""
        return bytes(ffi.buffer(data, size))

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the anchor to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_anchor_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Anchor to CBOR (error code: {err})")

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
        err = lib.cardano_anchor_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Anchor."""
        if not isinstance(other, Anchor):
            return False
        return self.url == other.url and self.hash_bytes == other.hash_bytes

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.url, self.hash_bytes))

    def __str__(self) -> str:
        """Returns a string representation of the anchor."""
        return f"{self.url} ({self.hash_hex[:16]}...)"
