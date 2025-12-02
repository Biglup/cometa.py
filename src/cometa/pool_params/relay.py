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
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .relay_type import RelayType
from .single_host_addr_relay import SingleHostAddrRelay
from .single_host_name_relay import SingleHostNameRelay
from .multi_host_name_relay import MultiHostNameRelay


class Relay:
    """
    Represents a generic relay for Cardano stake pools.

    A relay is a type of node that acts as an intermediary between core nodes
    (which produce blocks) and the wider internet. They help in passing along
    transactions and blocks, ensuring that data is propagated throughout the network.

    This class wraps the three specific relay types:
    - SingleHostAddrRelay: Connects via IPv4/IPv6 address and port
    - SingleHostNameRelay: Connects via DNS name and port
    - MultiHostNameRelay: Connects via DNS SRV record
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Relay: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_relay_t**", self._ptr)
            lib.cardano_relay_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Relay:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        relay_type = self.relay_type
        if relay_type == RelayType.SINGLE_HOST_ADDRESS:
            inner = self.to_single_host_addr()
            return f"Relay({inner!r})"
        if relay_type == RelayType.SINGLE_HOST_NAME:
            inner = self.to_single_host_name()
            return f"Relay({inner!r})"
        if relay_type == RelayType.MULTI_HOST_NAME:
            inner = self.to_multi_host_name()
            return f"Relay({inner!r})"
        return "Relay(unknown)"

    @classmethod
    def from_single_host_addr(cls, relay: SingleHostAddrRelay) -> Relay:
        """
        Creates a Relay from a SingleHostAddrRelay.

        Args:
            relay: The single host address relay.

        Returns:
            A new Relay wrapping the single host address relay.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_relay_t**")
        err = lib.cardano_relay_new_single_host_addr(relay._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Relay from SingleHostAddrRelay (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_single_host_name(cls, relay: SingleHostNameRelay) -> Relay:
        """
        Creates a Relay from a SingleHostNameRelay.

        Args:
            relay: The single host name relay.

        Returns:
            A new Relay wrapping the single host name relay.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_relay_t**")
        err = lib.cardano_relay_new_single_host_name(relay._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Relay from SingleHostNameRelay (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_multi_host_name(cls, relay: MultiHostNameRelay) -> Relay:
        """
        Creates a Relay from a MultiHostNameRelay.

        Args:
            relay: The multi-host name relay.

        Returns:
            A new Relay wrapping the multi-host name relay.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_relay_t**")
        err = lib.cardano_relay_new_multi_host_name(relay._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Relay from MultiHostNameRelay (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Relay:
        """
        Deserializes a Relay from CBOR data.

        Args:
            reader: A CborReader positioned at the relay data.

        Returns:
            A new Relay deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_relay_t**")
        err = lib.cardano_relay_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Relay from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the relay to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_relay_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Relay to CBOR (error code: {err})")

    @property
    def relay_type(self) -> RelayType:
        """Returns the type of this relay."""
        out = ffi.new("cardano_relay_type_t*")
        err = lib.cardano_relay_get_type(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get relay type (error code: {err})")
        return RelayType(out[0])

    def to_single_host_addr(self) -> SingleHostAddrRelay:
        """
        Converts this relay to a SingleHostAddrRelay.

        Returns:
            The underlying SingleHostAddrRelay.

        Raises:
            CardanoError: If this relay is not a single host address relay.
        """
        out = ffi.new("cardano_single_host_addr_relay_t**")
        err = lib.cardano_relay_to_single_host_addr(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Relay to SingleHostAddrRelay (error code: {err})")
        return SingleHostAddrRelay(out[0])

    def to_single_host_name(self) -> SingleHostNameRelay:
        """
        Converts this relay to a SingleHostNameRelay.

        Returns:
            The underlying SingleHostNameRelay.

        Raises:
            CardanoError: If this relay is not a single host name relay.
        """
        out = ffi.new("cardano_single_host_name_relay_t**")
        err = lib.cardano_relay_to_single_host_name(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Relay to SingleHostNameRelay (error code: {err})")
        return SingleHostNameRelay(out[0])

    def to_multi_host_name(self) -> MultiHostNameRelay:
        """
        Converts this relay to a MultiHostNameRelay.

        Returns:
            The underlying MultiHostNameRelay.

        Raises:
            CardanoError: If this relay is not a multi-host name relay.
        """
        out = ffi.new("cardano_multi_host_name_relay_t**")
        err = lib.cardano_relay_to_multi_host_name(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Relay to MultiHostNameRelay (error code: {err})")
        return MultiHostNameRelay(out[0])

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this relay to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_relay_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")


# Type alias for relay types that can be wrapped
RelayLike = Union[Relay, SingleHostAddrRelay, SingleHostNameRelay, MultiHostNameRelay]


def to_relay(relay: RelayLike) -> Relay:
    """
    Converts a relay-like object to a Relay.

    Args:
        relay: A Relay or one of the specific relay types.

    Returns:
        A Relay wrapping the input.

    Raises:
        CardanoError: If conversion fails.
        TypeError: If the input is not a valid relay type.
    """
    if isinstance(relay, Relay):
        return relay
    if isinstance(relay, SingleHostAddrRelay):
        return Relay.from_single_host_addr(relay)
    if isinstance(relay, SingleHostNameRelay):
        return Relay.from_single_host_name(relay)
    if isinstance(relay, MultiHostNameRelay):
        return Relay.from_multi_host_name(relay)
    raise TypeError(f"Cannot convert {type(relay).__name__} to Relay")
