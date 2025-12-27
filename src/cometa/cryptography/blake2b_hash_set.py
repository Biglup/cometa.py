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
from collections.abc import Set
from typing import Iterable, Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from .blake2b_hash import Blake2bHash
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter


class Blake2bHashSet(Set["Blake2bHash"]):
    """
    Represents a set of Blake2b hashes.

    This collection type is used throughout Cardano for storing sets of
    transaction IDs, key hashes, and other Blake2b hash values.

    Example:
        >>> hash_set = Blake2bHashSet()
        >>> hash_set.add(Blake2bHash.from_hex("00" * 32))
        >>> len(hash_set)
        1
    """

    def __init__(self, ptr=None) -> None:
        """
        Initializes a new Blake2bHashSet.

        Args:
            ptr: Optional FFI pointer to an existing hash set. If None, creates a new empty set.

        Raises:
            CardanoError: If creation fails or if ptr is an invalid handle.
        """
        if ptr is None:
            out = ffi.new("cardano_blake2b_hash_set_t**")
            err = lib.cardano_blake2b_hash_set_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create Blake2bHashSet (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("Blake2bHashSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the hash set when the object is destroyed."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_blake2b_hash_set_t**", self._ptr)
            lib.cardano_blake2b_hash_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Blake2bHashSet:
        """Enters the context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exits the context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the hash set."""
        return f"Blake2bHashSet(len={len(self)})"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Blake2bHashSet:
        """
        Deserializes a Blake2bHashSet from CBOR data.

        Args:
            reader: A CborReader positioned at the hash set data.

        Returns:
            A new Blake2bHashSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_blake2b_hash_set_t**")
        err = lib.cardano_blake2b_hash_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Blake2bHashSet from CBOR (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_list(cls, hashes: Iterable[Blake2bHash]) -> Blake2bHashSet:
        """
        Creates a Blake2bHashSet from an iterable of Blake2bHash objects.

        Args:
            hashes: An iterable of Blake2bHash objects.

        Returns:
            A new Blake2bHashSet containing all the hashes.

        Raises:
            CardanoError: If creation fails.
        """
        hash_set = cls()
        for hash_value in hashes:
            hash_set.add(hash_value)
        return hash_set

    def add(self, hash_value: Blake2bHash) -> None:
        """
        Adds a hash to the set.

        Args:
            hash_value: The Blake2bHash to add.

        Raises:
            CardanoError: If addition fails.
        """
        err = lib.cardano_blake2b_hash_set_add(self._ptr, hash_value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add hash to set (error code: {err})")

    def get(self, index: int) -> Blake2bHash:
        """
        Retrieves a hash at the specified index.

        Args:
            index: The index of the hash to retrieve.

        Returns:
            The Blake2bHash at the specified index.

        Raises:
            CardanoError: If retrieval fails.
            IndexError: If index is out of bounds.
        """
        if index < 0 or index >= len(self):
            raise IndexError(f"Index {index} out of range for hash set of length {len(self)}")
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_blake2b_hash_set_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get hash at index {index} (error code: {err})")
        return Blake2bHash(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the hash set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_blake2b_hash_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Blake2bHashSet to CBOR (error code: {err})")

    def __len__(self) -> int:
        """Returns the number of hashes in the set."""
        return int(lib.cardano_blake2b_hash_set_get_length(self._ptr))

    def __getitem__(self, index: int) -> Blake2bHash:
        """Retrieves a hash at the specified index."""
        return self.get(index)

    def __iter__(self) -> Iterator[Blake2bHash]:
        """Iterates over all hashes in the set."""
        for i in range(len(self)):
            yield self.get(i)

    def __contains__(self, item: Blake2bHash) -> bool:
        """Checks if a hash is in the set."""
        for hash_val in self:
            if hash_val == item:
                return True
        return False

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Blake2bHashSet."""
        if not isinstance(other, Blake2bHashSet):
            return False
        if len(self) != len(other):
            return False
        for i in range(len(self)):
            if self.get(i) != other.get(i):
                return False
        return True
    def isdisjoint(self, other: "Iterable[Blake2bHash]") -> bool:
        """
        Returns True if the set has no elements in common with other.

        Args:
            other: Another iterable to compare with.

        Returns:
            True if the sets are disjoint.
        """
        for item in other:
            if item in self:
                return False
        return True
