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
from ..json.json_writer import JsonWriter


class AssetName:
    """
    Represents a native asset name in the Cardano blockchain.

    Asset names in Cardano are arbitrary byte strings (up to 32 bytes) used to
    uniquely identify assets within a minting policy. They can represent
    human-readable names or arbitrary binary data.

    Example:
        >>> asset_name = AssetName.from_string("MyToken")
        >>> asset_name.to_string()
        'MyToken'
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("AssetName: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_asset_name_t**", self._ptr)
            lib.cardano_asset_name_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AssetName:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        name_str = self.to_string()
        if name_str:
            return f"AssetName({name_str!r})"
        return f"AssetName({self.to_hex()})"

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> AssetName:
        """
        Creates an asset name from raw bytes.

        Args:
            data: The asset name as raw bytes (max 32 bytes).

        Returns:
            A new AssetName instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> asset_name = AssetName.from_bytes(b"MyToken")
        """
        out = ffi.new("cardano_asset_name_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_asset_name_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetName from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> AssetName:
        """
        Creates an asset name from a hexadecimal string.

        Args:
            hex_string: The asset name as a hexadecimal string.

        Returns:
            A new AssetName instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> asset_name = AssetName.from_hex("4d79546f6b656e")  # "MyToken"
        """
        out = ffi.new("cardano_asset_name_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_asset_name_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetName from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_string(cls, name: str) -> AssetName:
        """
        Creates an asset name from a UTF-8 string.

        Args:
            name: The asset name as a human-readable string.

        Returns:
            A new AssetName instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> asset_name = AssetName.from_string("MyToken")
        """
        out = ffi.new("cardano_asset_name_t**")
        name_bytes = name.encode("utf-8")
        err = lib.cardano_asset_name_from_string(name_bytes, len(name_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetName from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> AssetName:
        """
        Deserializes an AssetName from CBOR data.

        Args:
            reader: A CborReader positioned at the asset name data.

        Returns:
            A new AssetName deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_asset_name_t**")
        err = lib.cardano_asset_name_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize AssetName from CBOR (error code: {err})")
        return cls(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the asset name as raw bytes.

        Returns:
            The asset name bytes.
        """
        size = lib.cardano_asset_name_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        data_ptr = lib.cardano_asset_name_get_bytes(self._ptr)
        return bytes(ffi.buffer(data_ptr, size))

    def to_hex(self) -> str:
        """
        Returns the asset name as a hexadecimal string.

        Returns:
            The asset name as a hex string.
        """
        hex_ptr = lib.cardano_asset_name_get_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    def to_string(self) -> str:
        """
        Returns the asset name as a UTF-8 string.

        Returns:
            The asset name as a human-readable string.

        Note:
            If the asset name contains non-UTF-8 bytes, this may
            return an incomplete or garbled string.
        """
        str_ptr = lib.cardano_asset_name_get_string(self._ptr)
        if str_ptr == ffi.NULL:
            return ""
        return ffi.string(str_ptr).decode("utf-8", errors="replace")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the asset name to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_asset_name_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize AssetName to CBOR (error code: {err})")

    def to_cip116_json(self, writer: JsonWriter) -> None:
        """
        Serializes this asset name to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_asset_name_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize AssetName to CIP-116 JSON (error code: {err})")

    def __len__(self) -> int:
        """Returns the length of the asset name in bytes."""
        return int(lib.cardano_asset_name_get_bytes_size(self._ptr))

    def __eq__(self, other: object) -> bool:
        """Checks equality with another AssetName."""
        if not isinstance(other, AssetName):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns the string representation of the asset name."""
        return self.to_string() or self.to_hex()
