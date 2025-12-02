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
from .ipv4 import IPv4
from .ipv6 import IPv6


class SingleHostAddrRelay:
    """
    Represents a single host address relay for Cardano stake pools.

    This relay type points to a single host via its IPv4/IPv6 address and a given port.
    At least one of IPv4 or IPv6 address should be provided. The port is optional.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("SingleHostAddrRelay: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_single_host_addr_relay_t**", self._ptr)
            lib.cardano_single_host_addr_relay_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> SingleHostAddrRelay:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        parts = []
        port = self.port
        if port is not None:
            parts.append(f"port={port}")
        ipv4 = self.ipv4
        if ipv4 is not None:
            parts.append(f"ipv4={ipv4}")
        ipv6 = self.ipv6
        if ipv6 is not None:
            parts.append(f"ipv6={ipv6}")
        return f"SingleHostAddrRelay({', '.join(parts)})"

    @classmethod
    def new(
        cls,
        port: Optional[int] = None,
        ipv4: Optional[IPv4] = None,
        ipv6: Optional[IPv6] = None,
    ) -> SingleHostAddrRelay:
        """
        Creates a new single host address relay.

        Args:
            port: Optional port number (0-65535).
            ipv4: Optional IPv4 address.
            ipv6: Optional IPv6 address.

        Returns:
            A new SingleHostAddrRelay instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> ipv4 = IPv4.from_string("192.168.1.1")
            >>> relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        """
        out = ffi.new("cardano_single_host_addr_relay_t**")
        port_ptr = ffi.NULL
        if port is not None:
            port_ptr = ffi.new("uint16_t*", port)

        ipv4_ptr = ipv4._ptr if ipv4 is not None else ffi.NULL
        ipv6_ptr = ipv6._ptr if ipv6 is not None else ffi.NULL

        err = lib.cardano_single_host_addr_relay_new(port_ptr, ipv4_ptr, ipv6_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create SingleHostAddrRelay (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> SingleHostAddrRelay:
        """
        Deserializes a SingleHostAddrRelay from CBOR data.

        Args:
            reader: A CborReader positioned at the relay data.

        Returns:
            A new SingleHostAddrRelay deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_single_host_addr_relay_t**")
        err = lib.cardano_single_host_addr_relay_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize SingleHostAddrRelay from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the relay to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_single_host_addr_relay_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize SingleHostAddrRelay to CBOR (error code: {err})")

    @property
    def port(self) -> Optional[int]:
        """Returns the port number, or None if not set."""
        port_ptr = lib.cardano_single_host_addr_relay_get_port(self._ptr)
        if port_ptr == ffi.NULL:
            return None
        return int(port_ptr[0])

    @port.setter
    def port(self, value: Optional[int]) -> None:
        """Sets the port number."""
        if value is None:
            port_ptr = ffi.NULL
        else:
            port_ptr = ffi.new("uint16_t*", value)
        err = lib.cardano_single_host_addr_relay_set_port(self._ptr, port_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set port (error code: {err})")

    @property
    def ipv4(self) -> Optional[IPv4]:
        """Returns the IPv4 address, or None if not set."""
        out = ffi.new("cardano_ipv4_t**")
        err = lib.cardano_single_host_addr_relay_get_ipv4(self._ptr, out)
        if err != 0:
            return None
        if out[0] == ffi.NULL:
            return None
        return IPv4(out[0])

    @ipv4.setter
    def ipv4(self, value: Optional[IPv4]) -> None:
        """Sets the IPv4 address."""
        ipv4_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_single_host_addr_relay_set_ipv4(self._ptr, ipv4_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set IPv4 (error code: {err})")

    @property
    def ipv6(self) -> Optional[IPv6]:
        """Returns the IPv6 address, or None if not set."""
        out = ffi.new("cardano_ipv6_t**")
        err = lib.cardano_single_host_addr_relay_get_ipv6(self._ptr, out)
        if err != 0:
            return None
        if out[0] == ffi.NULL:
            return None
        return IPv6(out[0])

    @ipv6.setter
    def ipv6(self, value: Optional[IPv6]) -> None:
        """Sets the IPv6 address."""
        ipv6_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_single_host_addr_relay_set_ipv6(self._ptr, ipv6_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set IPv6 (error code: {err})")

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
        err = lib.cardano_single_host_addr_relay_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
