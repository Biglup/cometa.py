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


class SingleHostNameRelay:
    """
    Represents a single host name relay for Cardano stake pools.

    This relay type points to a single host via a DNS name (A or AAAA record) and
    an optional port number.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("SingleHostNameRelay: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_single_host_name_relay_t**", self._ptr)
            lib.cardano_single_host_name_relay_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> SingleHostNameRelay:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        parts = [f"dns={self.dns!r}"]
        port = self.port
        if port is not None:
            parts.append(f"port={port}")
        return f"SingleHostNameRelay({', '.join(parts)})"

    def __str__(self) -> str:
        port = self.port
        if port is not None:
            return f"{self.dns}:{port}"
        return self.dns

    @classmethod
    def new(cls, dns: str, port: Optional[int] = None) -> SingleHostNameRelay:
        """
        Creates a new single host name relay.

        Args:
            dns: The DNS hostname (e.g., "relay.example.com").
            port: Optional port number (0-65535).

        Returns:
            A new SingleHostNameRelay instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        """
        out = ffi.new("cardano_single_host_name_relay_t**")
        port_ptr = ffi.NULL
        if port is not None:
            port_ptr = ffi.new("uint16_t*", port)

        dns_bytes = dns.encode("utf-8")
        err = lib.cardano_single_host_name_relay_new(port_ptr, dns_bytes, len(dns_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create SingleHostNameRelay (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> SingleHostNameRelay:
        """
        Deserializes a SingleHostNameRelay from CBOR data.

        Args:
            reader: A CborReader positioned at the relay data.

        Returns:
            A new SingleHostNameRelay deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_single_host_name_relay_t**")
        err = lib.cardano_single_host_name_relay_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize SingleHostNameRelay from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the relay to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_single_host_name_relay_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize SingleHostNameRelay to CBOR (error code: {err})")

    @property
    def port(self) -> Optional[int]:
        """Returns the port number, or None if not set."""
        port_ptr = lib.cardano_single_host_name_relay_get_port(self._ptr)
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
        err = lib.cardano_single_host_name_relay_set_port(self._ptr, port_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set port (error code: {err})")

    @property
    def dns(self) -> str:
        """Returns the DNS hostname."""
        dns_ptr = lib.cardano_single_host_name_relay_get_dns(self._ptr)
        if dns_ptr == ffi.NULL:
            return ""
        return ffi.string(dns_ptr).decode("utf-8")

    @dns.setter
    def dns(self, value: str) -> None:
        """Sets the DNS hostname."""
        dns_bytes = value.encode("utf-8")
        err = lib.cardano_single_host_name_relay_set_dns(dns_bytes, len(dns_bytes), self._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set DNS (error code: {err})")

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
        err = lib.cardano_single_host_name_relay_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
