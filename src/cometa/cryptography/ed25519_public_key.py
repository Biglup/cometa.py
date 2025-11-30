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
from .blake2b_hash import Blake2bHash
from .ed25519_signature import Ed25519Signature


class Ed25519PublicKey:
    """
    Represents an Ed25519 public key within the Cardano ecosystem.

    Ed25519 public keys are 32 bytes and are used for signature verification,
    address generation, and identifying stake pool operators and DReps.

    Example:
        >>> pub_key = Ed25519PublicKey.from_hex("00" * 32)
        >>> key_hash = pub_key.to_hash()
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Ed25519PublicKey: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ed25519_public_key_t**", self._ptr)
            lib.cardano_ed25519_public_key_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Ed25519PublicKey:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Ed25519PublicKey({self.to_hex()[:16]}...)"

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Ed25519PublicKey:
        """
        Creates an Ed25519 public key from raw bytes.

        Args:
            data: The public key as raw bytes (32 bytes).

        Returns:
            A new Ed25519PublicKey instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> pub_key = Ed25519PublicKey.from_bytes(bytes(32))
        """
        out = ffi.new("cardano_ed25519_public_key_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_ed25519_public_key_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PublicKey from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Ed25519PublicKey:
        """
        Creates an Ed25519 public key from a hexadecimal string.

        Args:
            hex_string: The public key as a hexadecimal string (64 characters).

        Returns:
            A new Ed25519PublicKey instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> pub_key = Ed25519PublicKey.from_hex("00" * 32)
        """
        out = ffi.new("cardano_ed25519_public_key_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_ed25519_public_key_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Ed25519PublicKey from hex (error code: {err})")
        return cls(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the public key as raw bytes.

        Returns:
            The 32-byte public key.
        """
        size = lib.cardano_ed25519_public_key_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_ed25519_public_key_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert public key to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_hex(self) -> str:
        """
        Returns the public key as a hexadecimal string.

        Returns:
            The public key as a 64-character hex string.
        """
        size = lib.cardano_ed25519_public_key_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_ed25519_public_key_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert public key to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def to_hash(self) -> Blake2bHash:
        """
        Computes the Blake2b-224 hash of this public key.

        This hash is commonly used as a key hash for credentials in addresses
        and governance operations.

        Returns:
            The Blake2b-224 hash of the public key.

        Raises:
            CardanoError: If hashing fails.
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_ed25519_public_key_to_hash(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to compute public key hash (error code: {err})")
        return Blake2bHash(out[0])

    def verify(self, signature: Ed25519Signature, message: Union[bytes, bytearray]) -> bool:
        """
        Verifies a signature against a message using this public key.

        Args:
            signature: The Ed25519 signature to verify.
            message: The message that was signed.

        Returns:
            True if the signature is valid, False otherwise.

        Example:
            >>> pub_key = Ed25519PublicKey.from_hex("...")
            >>> sig = Ed25519Signature.from_hex("...")
            >>> pub_key.verify(sig, b"Hello, world!")
            True
        """
        c_message = ffi.from_buffer("byte_t[]", message)
        return lib.cardano_ed25519_public_verify(self._ptr, signature._ptr, c_message, len(message))

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Ed25519PublicKey."""
        if not isinstance(other, Ed25519PublicKey):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns the hexadecimal representation."""
        return self.to_hex()
