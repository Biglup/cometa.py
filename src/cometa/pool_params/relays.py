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
from .relay import Relay, RelayLike, to_relay


class Relays:
    """
    Represents a collection of relays for a Cardano stake pool.

    This class provides a list-like interface for managing pool relays,
    supporting iteration, indexing, and standard list operations.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Relays: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_relays_t**", self._ptr)
            lib.cardano_relays_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Relays:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Relays({list(self)!r})"

    def __len__(self) -> int:
        return int(lib.cardano_relays_get_length(self._ptr))

    @overload
    def __getitem__(self, index: int) -> Relay: ...

    @overload
    def __getitem__(self, index: slice) -> List[Relay]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union[Relay, List[Relay]]:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError("Relays index out of range")
        out = ffi.new("cardano_relay_t**")
        err = lib.cardano_relays_get(self._ptr, index, out)
        if err != 0:
            raise CardanoError(f"Failed to get relay at index {index} (error code: {err})")
        return Relay(out[0])

    def __iter__(self) -> Iterator[Relay]:
        for i in range(len(self)):
            yield self[i]

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, Relay):
            return False
        # Containment check not fully supported - would require deep equality comparison
        # For now, just return False to be conservative
        return False

    @classmethod
    def new(cls) -> Relays:
        """
        Creates a new empty Relays collection.

        Returns:
            A new empty Relays instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_relays_t**")
        err = lib.cardano_relays_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create Relays (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Relays:
        """
        Deserializes a Relays collection from CBOR data.

        Args:
            reader: A CborReader positioned at the relays data.

        Returns:
            A new Relays deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_relays_t**")
        err = lib.cardano_relays_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Relays from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the relays collection to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_relays_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Relays to CBOR (error code: {err})")

    def add(self, relay: RelayLike) -> None:
        """
        Adds a relay to the collection.

        Args:
            relay: The relay to add. Can be a Relay or any specific relay type.

        Raises:
            CardanoError: If adding fails.
        """
        wrapped = to_relay(relay)
        err = lib.cardano_relays_add(self._ptr, wrapped._ptr)
        if err != 0:
            raise CardanoError(f"Failed to add relay (error code: {err})")

    def append(self, relay: RelayLike) -> None:
        """
        Appends a relay to the collection (alias for add).

        Args:
            relay: The relay to append. Can be a Relay or any specific relay type.

        Raises:
            CardanoError: If appending fails.
        """
        self.add(relay)

    def extend(self, relays: Union[Relays, List[RelayLike]]) -> None:
        """
        Extends the collection with relays from another collection or list.

        Args:
            relays: Another Relays collection or a list of relay-like objects.

        Raises:
            CardanoError: If extending fails.
        """
        for relay in relays:
            self.add(relay)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this relays collection to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_relays_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
