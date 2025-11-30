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
from typing import TYPE_CHECKING, Union, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..common.network_id import NetworkId
from .address_type import AddressType

if TYPE_CHECKING:
    from .base_address import BaseAddress
    from .byron_address import ByronAddress
    from .enterprise_address import EnterpriseAddress
    from .pointer_address import PointerAddress
    from .reward_address import RewardAddress


class Address:
    """
    Represents a Cardano address.

    This is the base class for all Cardano address types. It can represent any
    address format including base, enterprise, pointer, reward, and Byron addresses.

    Addresses can be created from:
        - A Bech32 or Base58 string representation
        - Raw bytes
        - Specific address type constructors (BaseAddress, EnterpriseAddress, etc.)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Address: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_address_t**", self._ptr)
            lib.cardano_address_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Address:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Address({str(self)})"

    @classmethod
    def from_string(cls, address_string: str) -> Address:
        """
        Creates an address from a string representation.

        Accepts both Bech32 (Shelley-era) and Base58 (Byron-era) encoded addresses.

        Args:
            address_string: The string representation of the address.

        Returns:
            A new Address instance.

        Raises:
            CardanoError: If the string is not a valid address format.

        Example:
            >>> addr = Address.from_string("addr1...")
        """
        out = ffi.new("cardano_address_t**")
        data = address_string.encode("utf-8")
        err = lib.cardano_address_from_string(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to parse address from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Address:
        """
        Creates an address from raw bytes.

        Args:
            data: The serialized address bytes.

        Returns:
            A new Address instance.

        Raises:
            CardanoError: If the bytes are not a valid address.

        Example:
            >>> addr = Address.from_bytes(address_bytes)
        """
        out = ffi.new("cardano_address_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_address_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create address from bytes (error code: {err})")
        return cls(out[0])

    @staticmethod
    def is_valid(address_string: str) -> bool:
        """
        Checks if a string is a valid Cardano address.

        Validates both Bech32 (Shelley) and Base58 (Byron) address formats.

        Args:
            address_string: The string to validate.

        Returns:
            True if the string is a valid Cardano address, False otherwise.

        Example:
            >>> Address.is_valid("addr1...")
            True
        """
        data = address_string.encode("utf-8")
        return bool(lib.cardano_address_is_valid(data, len(data)))

    @staticmethod
    def is_valid_bech32(address_string: str) -> bool:
        """
        Checks if a string is a valid Bech32-encoded Cardano address.

        Args:
            address_string: The string to validate.

        Returns:
            True if the string is a valid Bech32 Cardano address.

        Example:
            >>> Address.is_valid_bech32("addr1...")
            True
        """
        data = address_string.encode("utf-8")
        return bool(lib.cardano_address_is_valid_bech32(data, len(data)))

    @staticmethod
    def is_valid_byron(address_string: str) -> bool:
        """
        Checks if a string is a valid Byron-encoded Cardano address.

        Args:
            address_string: The string to validate.

        Returns:
            True if the string is a valid Byron address.

        Example:
            >>> Address.is_valid_byron("Ae2td...")
            True
        """
        data = address_string.encode("utf-8")
        return bool(lib.cardano_address_is_valid_byron(data, len(data)))

    @property
    def type(self) -> AddressType:
        """Returns the address type."""
        type_out = ffi.new("cardano_address_type_t*")
        err = lib.cardano_address_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get address type (error code: {err})")
        return AddressType(type_out[0])

    @property
    def network_id(self) -> NetworkId:
        """Returns the network ID (mainnet or testnet)."""
        network_out = ffi.new("cardano_network_id_t*")
        err = lib.cardano_address_get_network_id(self._ptr, network_out)
        if err != 0:
            raise CardanoError(f"Failed to get network ID (error code: {err})")
        return NetworkId(network_out[0])

    @property
    def is_mainnet(self) -> bool:
        """Returns True if this is a mainnet address."""
        return self.network_id == NetworkId.MAINNET

    @property
    def is_testnet(self) -> bool:
        """Returns True if this is a testnet address."""
        return self.network_id == NetworkId.TESTNET

    def to_bytes(self) -> bytes:
        """
        Returns the serialized byte representation of the address.

        Returns:
            The address as bytes.

        Example:
            >>> addr.to_bytes()
            b'\\x01...'
        """
        size = lib.cardano_address_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_address_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert address to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_base_address(self) -> Optional[BaseAddress]:
        """
        Converts this address to a BaseAddress if applicable.

        Returns:
            A BaseAddress instance, or None if the conversion is not possible.

        Example:
            >>> base = addr.to_base_address()
        """
        from .base_address import BaseAddress
        ptr = lib.cardano_address_to_base_address(self._ptr)
        if ptr == ffi.NULL:
            return None
        return BaseAddress(ptr)

    def to_byron_address(self) -> Optional[ByronAddress]:
        """
        Converts this address to a ByronAddress if applicable.

        Returns:
            A ByronAddress instance, or None if the conversion is not possible.

        Example:
            >>> byron = addr.to_byron_address()
        """
        from .byron_address import ByronAddress
        ptr = lib.cardano_address_to_byron_address(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ByronAddress(ptr)

    def to_enterprise_address(self) -> Optional[EnterpriseAddress]:
        """
        Converts this address to an EnterpriseAddress if applicable.

        Returns:
            An EnterpriseAddress instance, or None if the conversion is not possible.

        Example:
            >>> ent = addr.to_enterprise_address()
        """
        from .enterprise_address import EnterpriseAddress
        ptr = lib.cardano_address_to_enterprise_address(self._ptr)
        if ptr == ffi.NULL:
            return None
        return EnterpriseAddress(ptr)

    def to_pointer_address(self) -> Optional[PointerAddress]:
        """
        Converts this address to a PointerAddress if applicable.

        Returns:
            A PointerAddress instance, or None if the conversion is not possible.

        Example:
            >>> ptr_addr = addr.to_pointer_address()
        """
        from .pointer_address import PointerAddress
        ptr = lib.cardano_address_to_pointer_address(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PointerAddress(ptr)

    def to_reward_address(self) -> Optional[RewardAddress]:
        """
        Converts this address to a RewardAddress if applicable.

        Returns:
            A RewardAddress instance, or None if the conversion is not possible.

        Example:
            >>> reward = addr.to_reward_address()
        """
        from .reward_address import RewardAddress
        ptr = lib.cardano_address_to_reward_address(self._ptr)
        if ptr == ffi.NULL:
            return None
        return RewardAddress(ptr)

    def __str__(self) -> str:
        """Returns the string representation of the address (Bech32 or Base58)."""
        str_ptr = lib.cardano_address_get_string(self._ptr)
        if str_ptr == ffi.NULL:
            return ""
        return ffi.string(str_ptr).decode("utf-8")

    def __bytes__(self) -> bytes:
        """Returns the serialized bytes of the address."""
        return self.to_bytes()

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash(self.to_bytes())

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Address."""
        if not isinstance(other, Address):
            return False
        return bool(lib.cardano_address_equals(self._ptr, other._ptr))

    def __len__(self) -> int:
        """Returns the size of the serialized address in bytes."""
        return int(lib.cardano_address_get_bytes_size(self._ptr))
