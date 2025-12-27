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
from typing import TYPE_CHECKING, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..common.network_id import NetworkId
from ..cryptography.blake2b_hash import Blake2bHash
from .byron_address_type import ByronAddressType
from .byron_address_attributes import ByronAddressAttributes

if TYPE_CHECKING:
    from .address import Address


class ByronAddress:
    """
    Represents a Byron-era Cardano address.

    Byron addresses are the original address format from the Byron era of Cardano.
    They use Base58 encoding and contain attributes such as an encrypted derivation
    path and optional network magic for testnet identification.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ByronAddress: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_byron_address_t**", self._ptr)
            lib.cardano_byron_address_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ByronAddress:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ByronAddress({str(self)})"

    @classmethod
    def from_credentials(
        cls,
        root: Blake2bHash,
        attributes: ByronAddressAttributes,
        address_type: ByronAddressType,
    ) -> ByronAddress:
        """
        Creates a Byron address from a root hash and attributes.

        Args:
            root: The root hash of the address (typically a hash of the public key).
            attributes: Address attributes including derivation path and network magic.
            address_type: The type of Byron address (PUBKEY, SCRIPT, or REDEEM).

        Returns:
            A new ByronAddress instance.

        Raises:
            CardanoError: If address creation fails.

        Example:
            >>> root = Blake2bHash.from_hex("00" * 28)
            >>> attrs = ByronAddressAttributes.mainnet()
            >>> addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)
        """
        out = ffi.new("cardano_byron_address_t**")
        c_attrs = ffi.new("cardano_byron_address_attributes_t*")
        if attributes.derivation_path:
            for i, byte in enumerate(attributes.derivation_path):
                c_attrs.derivation_path[i] = byte
            c_attrs.derivation_path_size = len(attributes.derivation_path)
        else:
            c_attrs.derivation_path_size = 0
        c_attrs.magic = attributes.magic
        err = lib.cardano_byron_address_from_credentials(
            root._ptr, c_attrs[0], int(address_type), out
        )
        if err != 0:
            raise CardanoError(f"Failed to create ByronAddress (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_address(cls, address: Address) -> ByronAddress:
        """
        Creates a ByronAddress from a generic Address.

        Args:
            address: A generic Address that must be a Byron address.

        Returns:
            A new ByronAddress instance.

        Raises:
            CardanoError: If the address is not a Byron address.
        """
        out = ffi.new("cardano_byron_address_t**")
        err = lib.cardano_byron_address_from_address(address._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to ByronAddress (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_base58(cls, base58_string: str) -> ByronAddress:
        """
        Creates a ByronAddress from a Base58-encoded string.

        Args:
            base58_string: The Base58-encoded address string (e.g., "Ae2td...").

        Returns:
            A new ByronAddress instance.

        Raises:
            CardanoError: If parsing fails.

        Example:
            >>> addr = ByronAddress.from_base58("Ae2tdPwUPEZ...")
        """
        out = ffi.new("cardano_byron_address_t**")
        data = base58_string.encode("utf-8")
        err = lib.cardano_byron_address_from_base58(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to parse ByronAddress from Base58 (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> ByronAddress:
        """
        Creates a ByronAddress from raw bytes.

        Args:
            data: The serialized address bytes.

        Returns:
            A new ByronAddress instance.

        Raises:
            CardanoError: If parsing fails.
        """
        out = ffi.new("cardano_byron_address_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_byron_address_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create ByronAddress from bytes (error code: {err})")
        return cls(out[0])

    @property
    def root(self) -> Blake2bHash:
        """Returns the root hash of the address."""
        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_byron_address_get_root(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get root hash (error code: {err})")
        return Blake2bHash(out[0])

    @property
    def attributes(self) -> ByronAddressAttributes:
        """Returns the address attributes."""
        attrs_out = ffi.new("cardano_byron_address_attributes_t*")
        err = lib.cardano_byron_address_get_attributes(self._ptr, attrs_out)
        if err != 0:
            raise CardanoError(f"Failed to get attributes (error code: {err})")
        derivation_path = b""
        if attrs_out.derivation_path != ffi.NULL and attrs_out.derivation_path_size > 0:
            derivation_path = bytes(ffi.buffer(attrs_out.derivation_path, attrs_out.derivation_path_size))
        return ByronAddressAttributes(
            derivation_path=derivation_path,
            magic=attrs_out.magic
        )

    @property
    def address_type(self) -> ByronAddressType:
        """Returns the Byron address type."""
        type_out = ffi.new("cardano_byron_address_type_t*")
        err = lib.cardano_byron_address_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get address type (error code: {err})")
        return ByronAddressType(type_out[0])

    @property
    def network_id(self) -> NetworkId:
        """Returns the network ID."""
        network_out = ffi.new("cardano_network_id_t*")
        err = lib.cardano_byron_address_get_network_id(self._ptr, network_out)
        if err != 0:
            raise CardanoError(f"Failed to get network ID (error code: {err})")
        return NetworkId(network_out[0])

    def to_address(self) -> Address:
        """
        Converts this ByronAddress to a generic Address.

        Returns:
            A generic Address instance.
        """
        from .address import Address
        ptr = lib.cardano_byron_address_to_address(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to convert to Address")
        return Address(ptr)

    def to_bytes(self) -> bytes:
        """Returns the serialized byte representation."""
        size = lib.cardano_byron_address_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_byron_address_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_base58(self) -> str:
        """Returns the Base58-encoded string representation."""
        size = lib.cardano_byron_address_get_base58_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_byron_address_to_base58(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert to Base58 (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __str__(self) -> str:
        """Returns the Base58 string representation."""
        str_ptr = lib.cardano_byron_address_get_string(self._ptr)
        if str_ptr == ffi.NULL:
            return ""
        return ffi.string(str_ptr).decode("utf-8")

    def __bytes__(self) -> bytes:
        """Returns the serialized bytes."""
        return self.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __eq__(self, other: object) -> bool:
        """Checks equality with another ByronAddress."""
        if not isinstance(other, ByronAddress):
            return False
        return self.to_bytes() == other.to_bytes()
