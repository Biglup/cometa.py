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
from typing import Iterator, List, Union, overload

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..cryptography.blake2b_hash import Blake2bHash


class PoolOwners:
    """
    Represents a set of stake pool owners.

    Pool owners are identified by their Ed25519 key hashes (28 bytes).
    This class provides a set-like interface for managing pool owner key hashes.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("PoolOwners: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_pool_owners_t**", self._ptr)
            lib.cardano_pool_owners_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PoolOwners:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        hashes = [str(h) for h in self]
        return f"PoolOwners({hashes!r})"

    def __len__(self) -> int:
        return int(lib.cardano_pool_owners_get_length(self._ptr))

    @overload
    def __getitem__(self, index: int) -> Blake2bHash: ...

    @overload
    def __getitem__(self, index: slice) -> List[Blake2bHash]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union[Blake2bHash, List[Blake2bHash]]:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError("PoolOwners index out of range")
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_pool_owners_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get owner at index {index} (error code: {err})")
        return Blake2bHash(out[0])

    def __iter__(self) -> Iterator[Blake2bHash]:
        for i in range(len(self)):
            yield self[i]

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, Blake2bHash):
            return False
        item_bytes = item.to_bytes()
        for owner in self:
            if owner.to_bytes() == item_bytes:
                return True
        return False

    @classmethod
    def new(cls) -> PoolOwners:
        """
        Creates a new empty PoolOwners set.

        Returns:
            A new empty PoolOwners instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_pool_owners_t**")
        err = lib.cardano_pool_owners_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create PoolOwners (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PoolOwners:
        """
        Deserializes a PoolOwners set from CBOR data.

        Args:
            reader: A CborReader positioned at the pool owners data.

        Returns:
            A new PoolOwners deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_pool_owners_t**")
        err = lib.cardano_pool_owners_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PoolOwners from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the pool owners set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_pool_owners_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PoolOwners to CBOR (error code: {err})")

    def add(self, owner: Blake2bHash) -> None:
        """
        Adds an owner key hash to the set.

        Args:
            owner: The owner's key hash (28-byte Blake2b hash).

        Raises:
            CardanoError: If adding fails.
        """
        err = lib.cardano_pool_owners_add(self._ptr, owner._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add owner (error code: {err})")

    def append(self, owner: Blake2bHash) -> None:
        """
        Appends an owner key hash to the set (alias for add).

        Args:
            owner: The owner's key hash (28-byte Blake2b hash).

        Raises:
            CardanoError: If appending fails.
        """
        self.add(owner)

    def extend(self, owners: Union[PoolOwners, List[Blake2bHash]]) -> None:
        """
        Extends the set with owners from another set or list.

        Args:
            owners: Another PoolOwners set or a list of Blake2bHash objects.

        Raises:
            CardanoError: If extending fails.
        """
        for owner in owners:
            self.add(owner)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this pool owners set to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_pool_owners_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
