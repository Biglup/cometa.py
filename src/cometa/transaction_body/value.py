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

from typing import Optional, Union, Dict, List

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..assets.multi_asset import MultiAsset
from ..assets.asset_id_map import AssetIdMap
from ..assets.asset_id import AssetId
from ..assets.asset_id_list import AssetIdList


class Value:
    """
    Represents a value in Cardano containing both ADA (in lovelace) and multi-assets.

    A Value can represent:
    - Pure ADA amounts (coin only)
    - Multi-asset bundles (native tokens)
    - Combined ADA and multi-assets
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Value: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_value_t**", self._ptr)
            lib.cardano_value_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Value:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Value(coin={self.coin})"

    @classmethod
    def new(cls, coin: int, multi_asset: Optional[MultiAsset] = None) -> Value:
        """
        Creates a new Value with the given coin amount and optional multi-assets.

        Args:
            coin: The amount in lovelace.
            multi_asset: Optional multi-asset bundle.

        Returns:
            A new Value instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_value_t**")
        assets_ptr = multi_asset._ptr if multi_asset is not None else ffi.NULL
        err = lib.cardano_value_new(coin, assets_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Value (error code: {err})")
        return cls(out[0])

    @classmethod
    def zero(cls) -> Value:
        """
        Creates a zero Value.

        Returns:
            A new Value with zero coin and no assets.

        Raises:
            CardanoError: If creation fails.
        """
        ptr = lib.cardano_value_new_zero()
        if ptr == ffi.NULL:
            raise CardanoError("Failed to create zero Value")
        return cls(ptr)

    @classmethod
    def from_coin(cls, lovelace: int) -> Value:
        """
        Creates a Value from only ADA amount.

        Args:
            lovelace: The amount in lovelace.

        Returns:
            A new Value instance.

        Raises:
            CardanoError: If creation fails.
        """
        ptr = lib.cardano_value_new_from_coin(lovelace)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to create Value from coin")
        return cls(ptr)

    @classmethod
    def from_asset_map(cls, asset_map: AssetIdMap) -> Value:
        """
        Creates a Value from an asset ID map.

        Args:
            asset_map: The asset ID map containing asset quantities.

        Returns:
            A new Value instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_value_t**")
        err = lib.cardano_value_from_asset_map(asset_map._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Value from asset map (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Value:
        """
        Deserializes a Value from CBOR data.

        Args:
            reader: A CborReader positioned at the value data.

        Returns:
            A new Value deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_value_t**")
        err = lib.cardano_value_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Value from CBOR (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_dict(
        cls, data: Union[int, List[Union[int, Dict[bytes, Dict[bytes, int]]]]]
    ) -> Value:
        """
        Creates a Value from a Python dict representation.

        Args:
            data: Either:
                - An integer representing lovelace amount (ADA only)
                - A list of [lovelace, {policy_id: {asset_name: amount}}]

        Returns:
            A new Value instance.

        Raises:
            CardanoError: If creation fails.
            ValueError: If the format is invalid.

        Example:
            >>> # ADA only
            >>> value = Value.from_dict(1500000)

            >>> # ADA with native tokens
            >>> value = Value.from_dict([
            ...     1500000,
            ...     {
            ...         bytes.fromhex("57fca08..."): {
            ...             b"CHOC": 2000
            ...         }
            ...     }
            ... ])
        """
        if isinstance(data, int):
            return cls.from_coin(data)

        if not isinstance(data, (list, tuple)) or len(data) != 2:
            raise ValueError(
                "Value must be an int or a list of [lovelace, multi_asset_dict]"
            )

        lovelace, multi_asset_dict = data

        if not isinstance(lovelace, int):
            raise ValueError("First element (lovelace) must be an integer")

        if not isinstance(multi_asset_dict, dict):
            raise ValueError(
                "Second element must be a dict of {policy_id: {asset_name: amount}}"
            )

        # Create the value with coin
        value = cls.from_coin(lovelace)

        # Add each policy and its assets
        for policy_id_bytes, assets in multi_asset_dict.items():
            if not isinstance(policy_id_bytes, bytes):
                raise ValueError("Policy ID must be bytes")
            if not isinstance(assets, dict):
                raise ValueError("Assets must be a dict of {asset_name: amount}")

            for asset_name_bytes, amount in assets.items():
                if not isinstance(asset_name_bytes, bytes):
                    raise ValueError("Asset name must be bytes")
                if not isinstance(amount, int):
                    raise ValueError("Asset amount must be an integer")

                value.add_asset(policy_id_bytes, asset_name_bytes, amount)

        return value

    def to_dict(self) -> Union[int, List[Union[int, Dict[bytes, Dict[bytes, int]]]]]:
        """
        Converts this Value to a Python dict representation.

        Returns:
            Either an integer (if ADA only) or a list of [lovelace, multi_asset_dict].

        Example:
            >>> value = Value.from_coin(1500000)
            >>> value.to_dict()
            1500000

            >>> value.add_asset(policy_id, b"TOKEN", 100)
            >>> value.to_dict()
            [1500000, {policy_id: {b"TOKEN": 100}}]
        """
        multi_asset = self.multi_asset

        if multi_asset is None or multi_asset.policy_count == 0:
            return self.coin

        result_dict: Dict[bytes, Dict[bytes, int]] = {}

        for policy_id in multi_asset:
            policy_bytes = policy_id.to_bytes()
            assets = multi_asset.get_assets(policy_id)
            asset_dict: Dict[bytes, int] = {}

            for asset_name, amount in assets.items():
                asset_dict[asset_name.to_bytes()] = amount

            result_dict[policy_bytes] = asset_dict

        return [self.coin, result_dict]

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the value to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_value_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Value to CBOR (error code: {err})"
            )

    def to_cip116_json(self, writer) -> None:
        """
        Serializes this value to CIP-116 JSON format.

        CIP-116 defines a standard JSON representation for Cardano values.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> from cometa.json import JsonWriter
            >>> value = Value.from_coin(1000000)
            >>> writer = JsonWriter()
            >>> value.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_value_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Value to CIP-116 JSON (error code: {err})")

    @property
    def coin(self) -> int:
        """
        The ADA amount in lovelace.

        Returns:
            The coin amount.
        """
        return int(lib.cardano_value_get_coin(self._ptr))

    @coin.setter
    def coin(self, value: int) -> None:
        """
        Sets the ADA amount in lovelace.

        Args:
            value: The coin amount.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_value_set_coin(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set coin (error code: {err})")

    @property
    def multi_asset(self) -> Optional[MultiAsset]:
        """
        The multi-asset bundle.

        Returns:
            The MultiAsset if present, None otherwise.
        """
        ptr = lib.cardano_value_get_multi_asset(self._ptr)
        if ptr == ffi.NULL:
            return None
        return MultiAsset(ptr)

    @multi_asset.setter
    def multi_asset(self, value: Optional[MultiAsset]) -> None:
        """
        Sets the multi-asset bundle.

        Args:
            value: The MultiAsset to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        assets_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_value_set_multi_asset(self._ptr, assets_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set multi_asset (error code: {err})")

    def add_coin(self, coin: int) -> None:
        """
        Adds coin to this value (with overflow check).

        Args:
            coin: The amount to add in lovelace.

        Raises:
            CardanoError: If addition fails or would overflow.
        """
        err = lib.cardano_value_add_coin(self._ptr, coin)
        if err != 0:
            raise CardanoError(f"Failed to add coin (error code: {err})")

    def subtract_coin(self, coin: int) -> None:
        """
        Subtracts coin from this value (with underflow check).

        Args:
            coin: The amount to subtract in lovelace.

        Raises:
            CardanoError: If subtraction fails or would underflow.
        """
        err = lib.cardano_value_subtract_coin(self._ptr, coin)
        if err != 0:
            raise CardanoError(f"Failed to subtract coin (error code: {err})")

    def add_multi_asset(self, assets: MultiAsset) -> None:
        """
        Adds multi-assets to this value.

        Args:
            assets: The multi-assets to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_value_add_multi_asset(self._ptr, assets._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add multi_asset (error code: {err})")

    def subtract_multi_asset(self, assets: MultiAsset) -> None:
        """
        Subtracts multi-assets from this value.

        Args:
            assets: The multi-assets to subtract.

        Raises:
            CardanoError: If subtraction fails.
        """
        err = lib.cardano_value_subtract_multi_asset(self._ptr, assets._ptr)
        if err != 0:
            raise CardanoError(f"Failed to subtract multi_asset (error code: {err})")

    def add_asset(
        self, policy_id: bytes, asset_name: bytes, quantity: int
    ) -> None:
        """
        Adds a specific asset to this value.

        Args:
            policy_id: The policy ID (28 bytes).
            asset_name: The asset name.
            quantity: The quantity to add.

        Raises:
            CardanoError: If addition fails.
        """
        # Create blake2b_hash from policy_id
        hash_ptr = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_from_bytes(policy_id, len(policy_id), hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to create policy ID hash (error code: {err})")

        # Create asset_name
        name_ptr = ffi.new("cardano_asset_name_t**")
        err = lib.cardano_asset_name_from_bytes(asset_name, len(asset_name), name_ptr)
        if err != 0:
            lib.cardano_blake2b_hash_unref(hash_ptr)
            raise CardanoError(f"Failed to create asset name (error code: {err})")

        err = lib.cardano_value_add_asset(self._ptr, hash_ptr[0], name_ptr[0], quantity)

        lib.cardano_blake2b_hash_unref(hash_ptr)
        lib.cardano_asset_name_unref(name_ptr)

        if err != 0:
            raise CardanoError(f"Failed to add asset (error code: {err})")

    def add_asset_with_id(self, asset_id: AssetId, quantity: int) -> None:
        """
        Adds a specific asset to this value using an AssetId.

        Args:
            asset_id: The asset ID identifying the asset.
            quantity: The quantity to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_value_add_asset_with_id(self._ptr, asset_id._ptr, quantity)
        if err != 0:
            raise CardanoError(f"Failed to add asset with ID (error code: {err})")

    def as_asset_map(self) -> AssetIdMap:
        """
        Returns this value as a flattened asset ID map.

        Returns:
            An AssetIdMap containing all assets including ADA.
        """
        ptr = lib.cardano_value_as_assets_map(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get asset map")
        return AssetIdMap(ptr)

    @property
    def asset_count(self) -> int:
        """
        The number of distinct assets in this value (including ADA if non-zero).

        Returns:
            The asset count.
        """
        return int(lib.cardano_value_get_asset_count(self._ptr))

    @property
    def is_zero(self) -> bool:
        """
        Whether this value is zero.

        Returns:
            True if both coin and all assets are zero.
        """
        return bool(lib.cardano_value_is_zero(self._ptr))

    def __add__(self, other: Value) -> Value:
        """Adds two values together, returning a new value."""
        out = ffi.new("cardano_value_t**")
        err = lib.cardano_value_add(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to add values (error code: {err})")
        return Value(out[0])

    def __sub__(self, other: Value) -> Value:
        """Subtracts another value from this one, returning a new value."""
        out = ffi.new("cardano_value_t**")
        err = lib.cardano_value_subtract(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to subtract values (error code: {err})")
        return Value(out[0])

    def get_intersection(self, other: Value) -> AssetIdList:
        """
        Returns a list of assets that are present in both Values.

        Args:
            other: The other Value to intersect with.

        Returns:
            An AssetIdList containing asset IDs present in both Values.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("cardano_asset_id_list_t**")
        err = lib.cardano_value_get_intersection(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get intersection (error code: {err})")
        return AssetIdList(out[0])

    def get_intersection_count(self, other: Value) -> int:
        """
        Returns the count of assets present in both Values.

        Args:
            other: The other Value to intersect with.

        Returns:
            The number of assets present in both Values.

        Raises:
            CardanoError: If the operation fails.
        """
        out = ffi.new("uint64_t*")
        err = lib.cardano_value_get_intersection_count(self._ptr, other._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get intersection count (error code: {err})")
        return int(out[0])

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Value."""
        if not isinstance(other, Value):
            return NotImplemented
        return bool(lib.cardano_value_equals(self._ptr, other._ptr))

    def __bool__(self) -> bool:
        """Returns True if this value is non-zero."""
        return not self.is_zero
