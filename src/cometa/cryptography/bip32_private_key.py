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
from .bip32_public_key import Bip32PublicKey
from .ed25519_private_key import Ed25519PrivateKey


class Bip32PrivateKey:
    """
    Represents a BIP32 hierarchical deterministic (HD) private key.

    BIP32 private keys enable the derivation of child keys following
    a hierarchical tree structure, allowing a single seed to generate
    a practically unlimited number of keys.

    This is the foundation for HD wallets in Cardano, following CIP-1852
    for key derivation paths.

    Warning:
        Private keys should be handled with extreme care. Never expose them
        in logs, error messages, or user interfaces.

    Example:
        >>> priv_key = Bip32PrivateKey.from_bip39_entropy(b"password", entropy)
        >>> child = priv_key.derive([harden(1852), harden(1815), harden(0)])
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Bip32PrivateKey: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_bip32_private_key_t**", self._ptr)
            lib.cardano_bip32_private_key_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Bip32PrivateKey:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "Bip32PrivateKey(<hidden>)"

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Bip32PrivateKey:
        """
        Creates a BIP32 private key from raw bytes.

        Args:
            data: The private key as raw bytes (96 bytes).

        Returns:
            A new Bip32PrivateKey instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_bip32_private_key_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_bip32_private_key_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Bip32PrivateKey from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Bip32PrivateKey:
        """
        Creates a BIP32 private key from a hexadecimal string.

        Args:
            hex_string: The private key as a hexadecimal string (192 characters).

        Returns:
            A new Bip32PrivateKey instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.
        """
        out = ffi.new("cardano_bip32_private_key_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_bip32_private_key_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Bip32PrivateKey from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bip39_entropy(
        cls,
        password: Union[bytes, bytearray, str],
        entropy: Union[bytes, bytearray]
    ) -> Bip32PrivateKey:
        """
        Generates a BIP32 private key from BIP39 entropy.

        This creates an HD root key from mnemonic entropy, typically derived
        from a 12, 15, 18, 21, or 24-word seed phrase.

        Args:
            password: Optional passphrase for additional security.
                     Can be empty string or bytes for no passphrase.
            entropy: The entropy derived from a BIP39 mnemonic.

        Returns:
            A new Bip32PrivateKey instance as the root key.

        Raises:
            CardanoError: If key generation fails.

        Example:
            >>> from cometa import mnemonic_to_entropy
            >>> entropy = mnemonic_to_entropy("abandon " * 11 + "about")
            >>> root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        """
        out = ffi.new("cardano_bip32_private_key_t**")
        if isinstance(password, str):
            password = password.encode("utf-8")
        c_password = ffi.from_buffer("byte_t[]", password) if password else ffi.NULL
        c_entropy = ffi.from_buffer("byte_t[]", entropy)
        err = lib.cardano_bip32_private_key_from_bip39_entropy(
            c_password, len(password) if password else 0,
            c_entropy, len(entropy),
            out
        )
        if err != 0:
            raise CardanoError(f"Failed to create Bip32PrivateKey from BIP39 entropy (error code: {err})")
        return cls(out[0])

    def derive(self, indices: List[int]) -> Bip32PrivateKey:
        """
        Derives a child private key using the specified derivation path.

        Both hardened (>= 2^31) and non-hardened indices are supported.
        Use the harden() function to create hardened indices.

        Args:
            indices: List of derivation indices.

        Returns:
            The derived child Bip32PrivateKey.

        Raises:
            CardanoError: If derivation fails.

        Example:
            >>> # CIP-1852 account derivation path
            >>> account = root_key.derive([harden(1852), harden(1815), harden(0)])
        """
        out = ffi.new("cardano_bip32_private_key_t**")
        c_indices = ffi.new("uint32_t[]", indices)
        err = lib.cardano_bip32_private_key_derive(self._ptr, c_indices, len(indices), out)
        if err != 0:
            raise CardanoError(f"Failed to derive child private key (error code: {err})")
        return Bip32PrivateKey(out[0])

    def get_public_key(self) -> Bip32PublicKey:
        """
        Derives the corresponding public key from this private key.

        Returns:
            The Bip32 public key derived from this private key.

        Raises:
            CardanoError: If derivation fails.
        """
        out = ffi.new("cardano_bip32_public_key_t**")
        err = lib.cardano_bip32_private_key_get_public_key(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to derive public key (error code: {err})")
        return Bip32PublicKey(out[0])

    def to_ed25519_key(self) -> Ed25519PrivateKey:
        """
        Converts this BIP32 private key to an Ed25519 private key.

        Returns:
            The Ed25519 private key extracted from this BIP32 key.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_ed25519_private_key_t**")
        err = lib.cardano_bip32_private_key_to_ed25519_key(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to Ed25519 key (error code: {err})")
        return Ed25519PrivateKey(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the private key as raw bytes.

        Warning:
            Handle the returned bytes with care as they contain sensitive key material.

        Returns:
            The private key bytes (96 bytes).
        """
        size = lib.cardano_bip32_private_key_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_bip32_private_key_to_bytes(self._ptr, buf, size)
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
        size = lib.cardano_bip32_private_key_get_hex_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_bip32_private_key_to_hex(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert private key to hex (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Bip32PrivateKey."""
        if not isinstance(other, Bip32PrivateKey):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns a safe string representation (does not expose key material)."""
        return "Bip32PrivateKey(<hidden>)"


def harden(index: int) -> int:
    """
    Hardens a BIP32 derivation index.

    In BIP32, hardened keys prevent derivation of child private keys from
    parent public keys, providing additional security for account-level keys.

    Args:
        index: The index to harden (0 to 2^31-1).

    Returns:
        The hardened index (index + 2^31).

    Example:
        >>> harden(1852)  # Purpose for Cardano
        2147485500
        >>> harden(1815)  # Coin type for ADA
        2147485463
        >>> harden(0)     # Account 0
        2147483648
    """
    return lib.cardano_bip32_harden(index)
