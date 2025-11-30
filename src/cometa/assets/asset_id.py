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
from typing import Union, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cryptography.blake2b_hash import Blake2bHash
from .asset_name import AssetName


class AssetId:
    """
    Represents a unique asset identifier in the Cardano blockchain.

    An asset ID is composed of a policy ID (Blake2b-224 hash) and an asset name.
    The special asset ID for Lovelace (ADA) has no policy ID or asset name.

    Example:
        >>> policy_id = Blake2bHash.from_hex("00" * 28)
        >>> asset_name = AssetName.from_string("MyToken")
        >>> asset_id = AssetId.new(policy_id, asset_name)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("AssetId: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_asset_id_t**", self._ptr)
            lib.cardano_asset_id_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AssetId:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        if self.is_lovelace:
            return "AssetId(lovelace)"
        return f"AssetId({self.to_hex()[:32]}...)"

    @classmethod
    def new(cls, policy_id: Blake2bHash, asset_name: AssetName) -> AssetId:
        """
        Creates a new asset ID from a policy ID and asset name.

        Args:
            policy_id: The minting policy ID (Blake2b-224 hash).
            asset_name: The name of the asset.

        Returns:
            A new AssetId instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> policy_id = Blake2bHash.from_hex("00" * 28)
            >>> asset_name = AssetName.from_string("MyToken")
            >>> asset_id = AssetId.new(policy_id, asset_name)
        """
        out = ffi.new("cardano_asset_id_t**")
        err = lib.cardano_asset_id_new(policy_id._ptr, asset_name._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetId (error code: {err})")
        return cls(out[0])

    @classmethod
    def new_lovelace(cls) -> AssetId:
        """
        Creates an asset ID representing Lovelace (ADA).

        Lovelace is the native currency of Cardano and has no associated
        policy ID or asset name.

        Returns:
            A new AssetId representing Lovelace.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> lovelace = AssetId.new_lovelace()
            >>> lovelace.is_lovelace
            True
        """
        out = ffi.new("cardano_asset_id_t**")
        err = lib.cardano_asset_id_new_lovelace(out)
        if err != 0:
            raise CardanoError(f"Failed to create Lovelace AssetId (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> AssetId:
        """
        Creates an asset ID from raw bytes.

        The bytes consist of the policy ID (28 bytes) followed by the
        asset name (0-32 bytes).

        Args:
            data: The asset ID as raw bytes (minimum 28 bytes).

        Returns:
            A new AssetId instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_asset_id_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_asset_id_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetId from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> AssetId:
        """
        Creates an asset ID from a hexadecimal string.

        Args:
            hex_string: The asset ID as a hexadecimal string.

        Returns:
            A new AssetId instance.

        Raises:
            CardanoError: If creation fails or hex is invalid.

        Example:
            >>> asset_id = AssetId.from_hex(policy_hex + asset_name_hex)
        """
        out = ffi.new("cardano_asset_id_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_asset_id_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create AssetId from hex (error code: {err})")
        return cls(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the asset ID as raw bytes.

        Returns:
            The asset ID bytes (policy ID + asset name).
        """
        size = lib.cardano_asset_id_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        data_ptr = lib.cardano_asset_id_get_bytes(self._ptr)
        return bytes(ffi.buffer(data_ptr, size))

    def to_hex(self) -> str:
        """
        Returns the asset ID as a hexadecimal string.

        Returns:
            The asset ID as a hex string.
        """
        hex_ptr = lib.cardano_asset_id_get_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    @property
    def is_lovelace(self) -> bool:
        """
        Checks if this asset ID represents Lovelace (ADA).

        Returns:
            True if this is the Lovelace asset ID, False otherwise.
        """
        return bool(lib.cardano_asset_id_is_lovelace(self._ptr))

    @property
    def policy_id(self) -> Optional[Blake2bHash]:
        """
        Retrieves the policy ID from this asset ID.

        Returns:
            The policy ID, or None if this is the Lovelace asset.

        Note:
            Call is_lovelace first to check if policy_id will be available.
        """
        if self.is_lovelace:
            return None
        ptr = lib.cardano_asset_id_get_policy_id(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)

    @property
    def asset_name(self) -> Optional[AssetName]:
        """
        Retrieves the asset name from this asset ID.

        Returns:
            The asset name, or None if this is the Lovelace asset.

        Note:
            Call is_lovelace first to check if asset_name will be available.
        """
        if self.is_lovelace:
            return None
        ptr = lib.cardano_asset_id_get_asset_name(self._ptr)
        if ptr == ffi.NULL:
            return None
        return AssetName(ptr)

    def __eq__(self, other: object) -> bool:
        """Checks equality with another AssetId."""
        if not isinstance(other, AssetId):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __str__(self) -> str:
        """Returns the hexadecimal representation."""
        if self.is_lovelace:
            return "lovelace"
        return self.to_hex()
