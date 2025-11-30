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
from .ed25519_public_key import Ed25519PublicKey
from .ed25519_signature import Ed25519Signature


class Ed25519PrivateKey:
    """
    Represents an Ed25519 private key within the Cardano ecosystem.

    Ed25519 private keys are used for signing transactions and messages.
    This class supports both "normal" (32-byte seed) and "extended" (64-byte)
    private key formats.

    Warning:
        Private keys should be handled with extreme care. Never expose them
        in logs, error messages, or user interfaces.

    Example:
        >>> priv_key = Ed25519PrivateKey.from_normal_hex("00" * 32)
        >>> pub_key = priv_key.get_public_key()
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Ed25519PrivateKey: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ed25519_private_key_t**", self._ptr)
            lib.cardano_ed25519_private_key_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Ed25519PrivateKey:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "Ed25519PrivateKey(<hidden>)"

    @classmethod
    def from_normal_bytes(cls, data: Union[bytes, bytearray]) -> Ed25519PrivateKey:
        """
        Creates an Ed25519 private key from a 32-byte seed.

        Args:
            data: The private key seed as raw bytes (32 bytes).

        Returns:
            A new Ed25519PrivateKey instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> priv_key = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        """
        out = ffi.new("cardano_ed25519_private_key_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_ed25519_private_key_from_normal_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PrivateKey from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_extended_bytes(cls, data: Union[bytes, bytearray]) -> Ed25519PrivateKey:
        """
        Creates an extended Ed25519 private key from 64 bytes.

        The extended format includes both the 32-byte private scalar and
        a 32-byte chain code or initialization vector.

        Args:
            data: The extended private key as raw bytes (64 bytes).

        Returns:
            A new Ed25519PrivateKey instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> priv_key = Ed25519PrivateKey.from_extended_bytes(bytes(64))
        """
        out = ffi.new("cardano_ed25519_private_key_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_ed25519_private_key_from_extended_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PrivateKey from extended bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_normal_hex(cls, hex_string: str) -> Ed25519PrivateKey:
        """
        Creates an Ed25519 private key from a hexadecimal seed string.

        Args:
            hex_string: The private key seed as a hexadecimal string (64 characters).

        Returns:
            A new Ed25519PrivateKey instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> priv_key = Ed25519PrivateKey.from_normal_hex("00" * 32)
        """
        out = ffi.new("cardano_ed25519_private_key_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_ed25519_private_key_from_normal_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PrivateKey from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_extended_hex(cls, hex_string: str) -> Ed25519PrivateKey:
        """
        Creates an extended Ed25519 private key from a hexadecimal string.

        Args:
            hex_string: The extended private key as a hexadecimal string (128 characters).

        Returns:
            A new Ed25519PrivateKey instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> priv_key = Ed25519PrivateKey.from_extended_hex("00" * 64)
        """
        out = ffi.new("cardano_ed25519_private_key_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_ed25519_private_key_from_extended_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PrivateKey from extended hex (error code: {err})")
        return cls(out[0])

    def get_public_key(self) -> Ed25519PublicKey:
        """
        Derives the corresponding public key from this private key.

        Returns:
            The Ed25519 public key derived from this private key.

        Raises:
            CardanoError: If derivation fails.
        """
        out = ffi.new("cardano_ed25519_public_key_t**")
        err = lib.cardano_ed25519_private_key_get_public_key(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to derive public key (error code: {err})")
        return Ed25519PublicKey(out[0])

    def sign(self, message: Union[bytes, bytearray]) -> Ed25519Signature:
        """
        Signs a message using this private key.

        Args:
            message: The message to sign.

        Returns:
            The Ed25519 signature of the message.

        Raises:
            CardanoError: If signing fails.

        Example:
            >>> priv_key = Ed25519PrivateKey.from_normal_hex("...")
            >>> sig = priv_key.sign(b"Hello, world!")
        """
        out = ffi.new("cardano_ed25519_signature_t**")
        c_message = ffi.from_buffer("byte_t[]", message)
        err = lib.cardano_ed25519_private_key_sign(self._ptr, c_message, len(message), out)
        if err != 0:
            raise CardanoError(f"Failed to sign message (error code: {err})")
        return Ed25519Signature(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the private key as raw bytes.

        Warning:
            Handle the returned bytes with care as they contain sensitive key material.

        Returns:
            The private key bytes (32 or 64 bytes depending on format).
        """
        size = lib.cardano_ed25519_private_key_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_ed25519_private_key_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert private key to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_hex(self) -> str:
        """
        Returns the private key as a hexadecimal string.

        Warning:
            Handle the returned string with care as it contains sensitive key material.

        Returns:
            The private key as a hex string.
        """
        size = lib.cardano_ed25519_private_key_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_ed25519_private_key_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert private key to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Ed25519PrivateKey."""
        if not isinstance(other, Ed25519PrivateKey):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns a safe string representation (does not expose key material)."""
        return "Ed25519PrivateKey(<hidden>)"
