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


class Ed25519Signature:
    """
    Represents an Ed25519 digital signature.

    Ed25519 signatures are 64 bytes and are used throughout Cardano for
    transaction signing, stake pool registration, and other cryptographic
    operations requiring authentication.

    Example:
        >>> sig = Ed25519Signature.from_hex("00" * 64)
        >>> len(sig.to_bytes())
        64
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Ed25519Signature: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ed25519_signature_t**", self._ptr)
            lib.cardano_ed25519_signature_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Ed25519Signature:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Ed25519Signature({self.to_hex()[:16]}...)"

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Ed25519Signature:
        """
        Creates an Ed25519 signature from raw bytes.

        Args:
            data: The signature as raw bytes (64 bytes).

        Returns:
            A new Ed25519Signature instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> sig = Ed25519Signature.from_bytes(bytes(64))
        """
        out = ffi.new("cardano_ed25519_signature_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_ed25519_signature_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519Signature from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Ed25519Signature:
        """
        Creates an Ed25519 signature from a hexadecimal string.

        Args:
            hex_string: The signature as a hexadecimal string (128 characters).

        Returns:
            A new Ed25519Signature instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> sig = Ed25519Signature.from_hex("00" * 64)
        """
        out = ffi.new("cardano_ed25519_signature_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_ed25519_signature_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519Signature from hex (error code: {err})")
        return cls(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the signature as raw bytes.

        Returns:
            The 64-byte signature.
        """
        size = lib.cardano_ed25519_signature_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_ed25519_signature_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert signature to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_hex(self) -> str:
        """
        Returns the signature as a hexadecimal string.

        Returns:
            The signature as a 128-character hex string.
        """
        size = lib.cardano_ed25519_signature_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_ed25519_signature_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert signature to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Ed25519Signature."""
        if not isinstance(other, Ed25519Signature):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns the hexadecimal representation."""
        return self.to_hex()
