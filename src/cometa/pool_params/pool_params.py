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
from typing import Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..cryptography.blake2b_hash import Blake2bHash
from ..common.unit_interval import UnitInterval
from ..address.reward_address import RewardAddress
from .pool_owners import PoolOwners
from .relays import Relays
from .pool_metadata import PoolMetadata


class PoolParams:
    """
    Represents stake pool registration/update certificate parameters.

    Pool parameters include:
    - operator_key_hash: The pool operator's Ed25519 key hash
    - vrf_vk_hash: The VRF verification key hash (32 bytes)
    - pledge: The amount of ADA pledged by the operator (in lovelaces)
    - cost: The operational cost per epoch (in lovelaces)
    - margin: The pool operator's margin (fraction of rewards)
    - reward_account: The account where rewards are deposited
    - owners: The set of pool owner key hashes
    - relays: The pool's network relays
    - metadata: Optional URL and hash of pool metadata
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PoolParams: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_pool_params_t**", self._ptr)
            lib.cardano_pool_params_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PoolParams:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return (
            f"PoolParams(operator={self.operator_key_hash.to_hex()[:16]}..., "
            f"pledge={self.pledge}, cost={self.cost})"
        )

    @classmethod
    def new(
        cls,
        operator_key_hash: Blake2bHash,
        vrf_vk_hash: Blake2bHash,
        pledge: int,
        cost: int,
        margin: UnitInterval,
        reward_account: RewardAddress,
        owners: PoolOwners,
        relays: Relays,
        metadata: Optional[PoolMetadata] = None,
    ) -> PoolParams:
        """
        Creates new pool parameters.

        Args:
            operator_key_hash: The pool operator's key hash (28 bytes).
            vrf_vk_hash: The VRF verification key hash (32 bytes).
            pledge: The pledge amount in lovelaces.
            cost: The operational cost per epoch in lovelaces.
            margin: The pool margin as a unit interval (0 to 1).
            reward_account: The reward account address.
            owners: The set of pool owner key hashes.
            relays: The pool's network relays.
            metadata: Optional pool metadata (URL and hash).

        Returns:
            A new PoolParams instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> params = PoolParams.new(
            ...     operator_key_hash=operator_hash,
            ...     vrf_vk_hash=vrf_hash,
            ...     pledge=1000000000,  # 1000 ADA
            ...     cost=340000000,     # 340 ADA
            ...     margin=UnitInterval.new(1, 100),  # 1%
            ...     reward_account=reward_addr,
            ...     owners=owners,
            ...     relays=relays,
            ...     metadata=metadata
            ... )
        """
        out = ffi.new("cardano_pool_params_t**")
        metadata_ptr = metadata._ptr if metadata is not None else ffi.NULL
        err = lib.cardano_pool_params_new(
            operator_key_hash._ptr,
            vrf_vk_hash._ptr,
            pledge,
            cost,
            margin._ptr,
            reward_account._ptr,
            owners._ptr,
            relays._ptr,
            metadata_ptr,
            out,
        )
        if err != 0:
            raise CardanoError(f"Failed to create PoolParams (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PoolParams:
        """
        Deserializes PoolParams from CBOR data.

        Args:
            reader: A CborReader positioned at the pool params data.

        Returns:
            A new PoolParams deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_pool_params_t**")
        err = lib.cardano_pool_params_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PoolParams from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the pool params to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_pool_params_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PoolParams to CBOR (error code: {err})")

    @property
    def operator_key_hash(self) -> Blake2bHash:
        """Returns the pool operator's key hash."""
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_pool_params_get_operator_key_hash(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get operator key hash (error code: {err})")
        return Blake2bHash(out[0])

    @operator_key_hash.setter
    def operator_key_hash(self, value: Blake2bHash) -> None:
        """Sets the pool operator's key hash."""
        err = lib.cardano_pool_params_set_operator_key_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set operator key hash (error code: {err})")

    @property
    def vrf_vk_hash(self) -> Blake2bHash:
        """Returns the VRF verification key hash."""
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_pool_params_get_vrf_vk_hash(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get VRF vk hash (error code: {err})")
        return Blake2bHash(out[0])

    @vrf_vk_hash.setter
    def vrf_vk_hash(self, value: Blake2bHash) -> None:
        """Sets the VRF verification key hash."""
        err = lib.cardano_pool_params_set_vrf_vk_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set VRF vk hash (error code: {err})")

    @property
    def pledge(self) -> int:
        """Returns the pledge amount in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_pool_params_get_pledge(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get pledge (error code: {err})")
        return int(out[0])

    @pledge.setter
    def pledge(self, value: int) -> None:
        """Sets the pledge amount in lovelaces."""
        err = lib.cardano_pool_params_set_pledge(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set pledge (error code: {err})")

    @property
    def cost(self) -> int:
        """Returns the operational cost per epoch in lovelaces."""
        out = ffi.new("uint64_t*")
        err = lib.cardano_pool_params_get_cost(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get cost (error code: {err})")
        return int(out[0])

    @cost.setter
    def cost(self, value: int) -> None:
        """Sets the operational cost per epoch in lovelaces."""
        err = lib.cardano_pool_params_set_cost(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set cost (error code: {err})")

    @property
    def margin(self) -> UnitInterval:
        """Returns the pool margin."""
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_pool_params_get_margin(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get margin (error code: {err})")
        return UnitInterval(out[0])

    @margin.setter
    def margin(self, value: UnitInterval) -> None:
        """Sets the pool margin."""
        err = lib.cardano_pool_params_set_margin(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set margin (error code: {err})")

    @property
    def reward_account(self) -> RewardAddress:
        """Returns the reward account address."""
        out = ffi.new("cardano_reward_address_t**")
        err = lib.cardano_pool_params_get_reward_account(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get reward account (error code: {err})")
        return RewardAddress(out[0])

    @reward_account.setter
    def reward_account(self, value: RewardAddress) -> None:
        """Sets the reward account address."""
        err = lib.cardano_pool_params_set_reward_account(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set reward account (error code: {err})")

    @property
    def owners(self) -> PoolOwners:
        """Returns the pool owners."""
        out = ffi.new("cardano_pool_owners_t**")
        err = lib.cardano_pool_params_get_owners(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get owners (error code: {err})")
        return PoolOwners(out[0])

    @owners.setter
    def owners(self, value: PoolOwners) -> None:
        """Sets the pool owners."""
        err = lib.cardano_pool_params_set_owners(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set owners (error code: {err})")

    @property
    def relays(self) -> Relays:
        """Returns the pool relays."""
        out = ffi.new("cardano_relays_t**")
        err = lib.cardano_pool_params_get_relays(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get relays (error code: {err})")
        return Relays(out[0])

    @relays.setter
    def relays(self, value: Relays) -> None:
        """Sets the pool relays."""
        err = lib.cardano_pool_params_set_relays(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set relays (error code: {err})")

    @property
    def metadata(self) -> Optional[PoolMetadata]:
        """Returns the pool metadata, or None if not set."""
        out = ffi.new("cardano_pool_metadata_t**")
        err = lib.cardano_pool_params_get_metadata(self._ptr, out)
        if err != 0:
            return None
        if out[0] == ffi.NULL:
            return None
        return PoolMetadata(out[0])

    @metadata.setter
    def metadata(self, value: Optional[PoolMetadata]) -> None:
        """Sets the pool metadata."""
        metadata_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_pool_params_set_metadata(self._ptr, metadata_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set metadata (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this pool params to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_pool_params_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
