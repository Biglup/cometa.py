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
from typing import Union, List

from .._ffi import ffi, lib
from ..errors import CardanoError
from .blake2b_hash import Blake2bHash
from .ed25519_public_key import Ed25519PublicKey


class Bip32PublicKey:
    """
    Represents a BIP32 hierarchical deterministic (HD) public key.

    BIP32 public keys enable the derivation of child public keys following
    a hierarchical tree structure. This allows for generating wallet addresses
    without access to the private key, enabling watch-only wallets.

    Example:
        >>> # Derive public key from a BIP32 private key
        >>> pub_key = priv_key.get_public_key()
        >>> child = pub_key.derive([0, 1])
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Bip32PublicKey: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_bip32_public_key_t**", self._ptr)
            lib.cardano_bip32_public_key_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Bip32PublicKey:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Bip32PublicKey({self.to_hex()[:16]}...)"

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Bip32PublicKey:
        """
        Creates a BIP32 public key from raw bytes.

        Args:
            data: The public key as raw bytes (64 bytes).

        Returns:
            A new Bip32PublicKey instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> pub_key = Bip32PublicKey.from_bytes(key_bytes)
        """
        out = ffi.new("cardano_bip32_public_key_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_bip32_public_key_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Bip32PublicKey from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Bip32PublicKey:
        """
        Creates a BIP32 public key from a hexadecimal string.

        Args:
            hex_string: The public key as a hexadecimal string (128 characters).

        Returns:
            A new Bip32PublicKey instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> pub_key = Bip32PublicKey.from_hex(hex_string)
        """
        out = ffi.new("cardano_bip32_public_key_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_bip32_public_key_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Bip32PublicKey from hex (error code: {err})")
        return cls(out[0])

    def derive(self, indices: List[int]) -> Bip32PublicKey:
        """
        Derives a child public key using the specified derivation path.

        Note: Only non-hardened derivation is possible with public keys.
        Hardened indices (>= 2^31) will fail.

        Args:
            indices: List of derivation indices.

        Returns:
            The derived child Bip32PublicKey.

        Raises:
            CardanoError: If derivation fails.

        Example:
            >>> child = pub_key.derive([0, 1, 2])
        """
        out = ffi.new("cardano_bip32_public_key_t**")
        c_indices = ffi.new("uint32_t[]", indices)
        err = lib.cardano_bip32_public_key_derive(self._ptr, c_indices, len(indices), out)
        if err != 0:
            raise CardanoError(f"Failed to derive child public key (error code: {err})")
        return Bip32PublicKey(out[0])

    def to_ed25519_key(self) -> Ed25519PublicKey:
        """
        Converts this BIP32 public key to an Ed25519 public key.

        Returns:
            The Ed25519 public key extracted from this BIP32 key.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_ed25519_public_key_t**")
        err = lib.cardano_bip32_public_key_to_ed25519_key(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to Ed25519 key (error code: {err})")
        return Ed25519PublicKey(out[0])

    def to_hash(self) -> Blake2bHash:
        """
        Computes the Blake2b-224 hash of this public key.

        Returns:
            The Blake2b-224 hash of the public key.

        Raises:
            CardanoError: If hashing fails.
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_bip32_public_key_to_hash(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to compute public key hash (error code: {err})")
        return Blake2bHash(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the public key as raw bytes.

        Returns:
            The 64-byte public key.
        """
        size = lib.cardano_bip32_public_key_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_bip32_public_key_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert public key to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_hex(self) -> str:
        """
        Returns the public key as a hexadecimal string.

        Returns:
            The public key as a 128-character hex string.
        """
        size = lib.cardano_bip32_public_key_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_bip32_public_key_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert public key to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Bip32PublicKey."""
        if not isinstance(other, Bip32PublicKey):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns the hexadecimal representation."""
        return self.to_hex()
