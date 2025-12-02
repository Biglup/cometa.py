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
from typing import Optional, Iterator, Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..cryptography.blake2b_hash import Blake2bHash
from .protocol_param_update import ProtocolParamUpdate


class ProposedParamUpdates:
    """
    A map of genesis delegate key hashes to proposed protocol parameter updates.

    This is used in the Shelley-era update mechanism where genesis keys propose
    parameter changes. Each genesis delegate can propose their own set of
    parameter updates.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ProposedParamUpdates: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_proposed_param_updates_t**", self._ptr)
            lib.cardano_proposed_param_updates_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProposedParamUpdates:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ProposedParamUpdates(size={len(self)})"

    def __len__(self) -> int:
        """Returns the number of proposed updates in the map."""
        return int(lib.cardano_proposed_param_updates_get_size(self._ptr))

    def __iter__(self) -> Iterator[Tuple[Blake2bHash, ProtocolParamUpdate]]:
        """Iterates over key-value pairs in the map."""
        for i in range(len(self)):
            key_out = ffi.new("cardano_blake2b_hash_t**")
            value_out = ffi.new("cardano_protocol_param_update_t**")
            err = lib.cardano_proposed_param_updates_get_key_value_at(
                self._ptr, i, key_out, value_out
            )
            if err == 0 and key_out[0] != ffi.NULL and value_out[0] != ffi.NULL:
                yield Blake2bHash(key_out[0]), ProtocolParamUpdate(value_out[0])

    def __getitem__(self, key: Blake2bHash) -> ProtocolParamUpdate:
        """
        Gets the proposed update for a genesis delegate key hash.

        Args:
            key: The genesis delegate key hash.

        Returns:
            The ProtocolParamUpdate for that key.

        Raises:
            KeyError: If no update exists for the key.
        """
        update = self.get(key)
        if update is None:
            raise KeyError(f"No update for key {key}")
        return update

    def __setitem__(self, key: Blake2bHash, value: ProtocolParamUpdate) -> None:
        """
        Sets the proposed update for a genesis delegate key hash.

        Args:
            key: The genesis delegate key hash.
            value: The ProtocolParamUpdate to set.
        """
        self.insert(key, value)

    def __contains__(self, key: Blake2bHash) -> bool:
        """Checks if an update exists for the given key."""
        return self.get(key) is not None

    @classmethod
    def new(cls) -> ProposedParamUpdates:
        """
        Creates a new empty ProposedParamUpdates map.

        Returns:
            A new empty ProposedParamUpdates instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposed_param_updates_t**")
        err = lib.cardano_proposed_param_updates_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create ProposedParamUpdates (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ProposedParamUpdates:
        """
        Deserializes ProposedParamUpdates from CBOR data.

        Args:
            reader: A CborReader positioned at the updates data.

        Returns:
            A new ProposedParamUpdates deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_proposed_param_updates_t**")
        err = lib.cardano_proposed_param_updates_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ProposedParamUpdates from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the proposed param updates to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_proposed_param_updates_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ProposedParamUpdates to CBOR (error code: {err})"
            )

    def insert(self, key: Blake2bHash, update: ProtocolParamUpdate) -> None:
        """
        Inserts a proposed update for a genesis delegate key hash.

        Args:
            key: The genesis delegate key hash.
            update: The ProtocolParamUpdate to insert.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_proposed_param_updates_insert(self._ptr, key._ptr, update._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert proposed update (error code: {err})")

    def get(self, key: Blake2bHash) -> Optional[ProtocolParamUpdate]:
        """
        Retrieves the proposed update for a genesis delegate key hash.

        Args:
            key: The genesis delegate key hash.

        Returns:
            The ProtocolParamUpdate if found, None otherwise.
        """
        out = ffi.new("cardano_protocol_param_update_t**")
        err = lib.cardano_proposed_param_updates_get(self._ptr, key._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ProtocolParamUpdate(out[0])

    def get_key_at(self, index: int) -> Optional[Blake2bHash]:
        """
        Gets the key at a specific index.

        Args:
            index: The index (0-based).

        Returns:
            The Blake2bHash key at that index, or None if out of range.
        """
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_proposed_param_updates_get_key_at(self._ptr, index, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return Blake2bHash(out[0])

    def get_value_at(self, index: int) -> Optional[ProtocolParamUpdate]:
        """
        Gets the value at a specific index.

        Args:
            index: The index (0-based).

        Returns:
            The ProtocolParamUpdate at that index, or None if out of range.
        """
        out = ffi.new("cardano_protocol_param_update_t**")
        err = lib.cardano_proposed_param_updates_get_value_at(self._ptr, index, out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return ProtocolParamUpdate(out[0])

    def keys(self) -> Iterator[Blake2bHash]:
        """Iterates over the genesis delegate key hashes."""
        for i in range(len(self)):
            key = self.get_key_at(i)
            if key is not None:
                yield key

    def values(self) -> Iterator[ProtocolParamUpdate]:
        """Iterates over the proposed updates."""
        for i in range(len(self)):
            value = self.get_value_at(i)
            if value is not None:
                yield value

    def items(self) -> Iterator[Tuple[Blake2bHash, ProtocolParamUpdate]]:
        """Iterates over key-value pairs."""
        return iter(self)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_proposed_param_updates_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
