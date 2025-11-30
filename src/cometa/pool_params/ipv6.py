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


class IPv6:
    """
    Represents an IPv6 address used in Cardano stake pool relay configuration.

    IPv6 addresses are 16 bytes (128 bits) and are used to identify single-host
    address relays in stake pool registration certificates.
    """

    IP_SIZE = 16  # IPv6 addresses are 16 bytes

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("IPv6: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ipv6_t**", self._ptr)
            lib.cardano_ipv6_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> IPv6:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"IPv6({self.to_string()})"

    def __str__(self) -> str:
        return self.to_string()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IPv6):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> IPv6:
        """
        Creates an IPv6 address from raw bytes.

        Args:
            data: The raw IPv6 bytes (must be exactly 16 bytes).

        Returns:
            A new IPv6 address.

        Raises:
            CardanoError: If the bytes are invalid.

        Example:
            >>> ipv6 = IPv6.from_bytes(bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))
            >>> str(ipv6)
            '::1'
        """
        if len(data) != cls.IP_SIZE:
            raise CardanoError(f"IPv6 requires exactly {cls.IP_SIZE} bytes, got {len(data)}")
        out = ffi.new("cardano_ipv6_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_ipv6_new(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create IPv6 from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_string(cls, ip_string: str) -> IPv6:
        """
        Creates an IPv6 address from a string.

        Args:
            ip_string: The IPv6 address in standard notation (e.g., "::1" or "2001:db8::1").

        Returns:
            A new IPv6 address.

        Raises:
            CardanoError: If the string is not a valid IPv6 address.

        Example:
            >>> ipv6 = IPv6.from_string("::1")
            >>> ipv6.to_bytes()[-1]
            1
        """
        out = ffi.new("cardano_ipv6_t**")
        ip_bytes = ip_string.encode("utf-8")
        err = lib.cardano_ipv6_from_string(ip_bytes, len(ip_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create IPv6 from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> IPv6:
        """
        Deserializes an IPv6 address from CBOR data.

        Args:
            reader: A CborReader positioned at the IPv6 data.

        Returns:
            A new IPv6 address deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_ipv6_t**")
        err = lib.cardano_ipv6_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize IPv6 from CBOR (error code: {err})")
        return cls(out[0])

    def to_bytes(self) -> bytes:
        """
        Returns the raw IPv6 bytes.

        Returns:
            The IPv6 address as a 16-byte bytes object.

        Example:
            >>> ipv6 = IPv6.from_string("::1")
            >>> len(ipv6.to_bytes())
            16
        """
        size = lib.cardano_ipv6_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        data_ptr = lib.cardano_ipv6_get_bytes(self._ptr)
        if data_ptr == ffi.NULL:
            return b""
        return bytes(ffi.buffer(data_ptr, size))

    def to_string(self) -> str:
        """
        Returns the IPv6 address in standard notation.

        Returns:
            The IPv6 address as a string (e.g., "::1" or "2001:db8::1").

        Example:
            >>> ipv6 = IPv6.from_bytes(bytes([0]*15 + [1]))
            >>> ipv6.to_string()
            '::1'
        """
        str_ptr = lib.cardano_ipv6_get_string(self._ptr)
        if str_ptr == ffi.NULL:
            return ""
        return ffi.string(str_ptr).decode("utf-8")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the IPv6 address to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_ipv6_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize IPv6 to CBOR (error code: {err})")
