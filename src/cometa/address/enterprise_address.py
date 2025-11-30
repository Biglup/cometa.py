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
from ..common.credential import Credential

if TYPE_CHECKING:
    from .address import Address


class EnterpriseAddress:
    """
    Represents a Cardano enterprise address.

    Enterprise addresses contain only a payment credential and no stake credential.
    Using these addresses means opting out of staking participation.

    Note: Using addresses with no stake rights decreases the total stake in the
    network, which could benefit potential adversaries of the proof-of-stake protocol.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("EnterpriseAddress: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_enterprise_address_t**", self._ptr)
            lib.cardano_enterprise_address_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> EnterpriseAddress:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"EnterpriseAddress({str(self)})"

    @classmethod
    def from_credentials(
        cls,
        network_id: NetworkId,
        payment: Credential,
    ) -> EnterpriseAddress:
        """
        Creates an enterprise address from a payment credential.

        Args:
            network_id: The network (mainnet or testnet).
            payment: The payment credential controlling spending.

        Returns:
            A new EnterpriseAddress instance.

        Raises:
            CardanoError: If address creation fails.

        Example:
            >>> payment = Credential.from_key_hash("00" * 28)
            >>> addr = EnterpriseAddress.from_credentials(NetworkId.MAINNET, payment)
        """
        out = ffi.new("cardano_enterprise_address_t**")
        err = lib.cardano_enterprise_address_from_credentials(
            int(network_id), payment._ptr, out
        )
        if err != 0:
            raise CardanoError(f"Failed to create EnterpriseAddress (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_address(cls, address: Address) -> EnterpriseAddress:
        """
        Creates an EnterpriseAddress from a generic Address.

        Args:
            address: A generic Address that must be an enterprise address.

        Returns:
            A new EnterpriseAddress instance.

        Raises:
            CardanoError: If the address is not an enterprise address.
        """
        out = ffi.new("cardano_enterprise_address_t**")
        err = lib.cardano_enterprise_address_from_address(address._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to EnterpriseAddress (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bech32(cls, bech32_string: str) -> EnterpriseAddress:
        """
        Creates an EnterpriseAddress from a Bech32-encoded string.

        Args:
            bech32_string: The Bech32-encoded address string.

        Returns:
            A new EnterpriseAddress instance.

        Raises:
            CardanoError: If parsing fails.
        """
        out = ffi.new("cardano_enterprise_address_t**")
        data = bech32_string.encode("utf-8")
        err = lib.cardano_enterprise_address_from_bech32(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to parse EnterpriseAddress from Bech32 (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> EnterpriseAddress:
        """
        Creates an EnterpriseAddress from raw bytes.

        Args:
            data: The serialized address bytes.

        Returns:
            A new EnterpriseAddress instance.

        Raises:
            CardanoError: If parsing fails.
        """
        out = ffi.new("cardano_enterprise_address_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_enterprise_address_from_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create EnterpriseAddress from bytes (error code: {err})")
        return cls(out[0])

    @property
    def payment_credential(self) -> Credential:
        """Returns the payment credential."""
        ptr = lib.cardano_enterprise_address_get_payment_credential(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get payment credential")
        return Credential(ptr)

    @property
    def network_id(self) -> NetworkId:
        """Returns the network ID."""
        network_out = ffi.new("cardano_network_id_t*")
        err = lib.cardano_enterprise_address_get_network_id(self._ptr, network_out)
        if err != 0:
            raise CardanoError(f"Failed to get network ID (error code: {err})")
        return NetworkId(network_out[0])

    def to_address(self) -> Address:
        """
        Converts this EnterpriseAddress to a generic Address.

        Returns:
            A generic Address instance.
        """
        from .address import Address
        ptr = lib.cardano_enterprise_address_to_address(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to convert to Address")
        return Address(ptr)

    def to_bytes(self) -> bytes:
        """Returns the serialized byte representation."""
        size = lib.cardano_enterprise_address_get_bytes_size(self._ptr)
        if size == 0:
            return b""
        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_enterprise_address_to_bytes(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert to bytes (error code: {err})")
        return bytes(ffi.buffer(buf, size))

    def to_bech32(self) -> str:
        """Returns the Bech32-encoded string representation."""
        size = lib.cardano_enterprise_address_get_bech32_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_enterprise_address_to_bech32(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert to Bech32 (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __str__(self) -> str:
        """Returns the Bech32 string representation."""
        str_ptr = lib.cardano_enterprise_address_get_string(self._ptr)
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
        """Checks equality with another EnterpriseAddress."""
        if not isinstance(other, EnterpriseAddress):
            return False
        return self.to_bytes() == other.to_bytes()
