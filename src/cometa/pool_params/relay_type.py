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

from enum import IntEnum

from .._ffi import lib, ffi


class RelayType(IntEnum):
    """
    Enumerates the types of relays used in the Cardano network.

    Each type represents a different method of connecting to the network.
    """

    SINGLE_HOST_ADDRESS = 0
    """Relay connects to a single host using an IP address and a port number."""

    SINGLE_HOST_NAME = 1
    """Relay connects using a DNS name and a port number."""

    MULTI_HOST_NAME = 2
    """Relay uses a multi-host name via a DNS SRV record."""

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this relay type.

        Returns:
            A string representation of the relay type.

        Example:
            >>> from cometa.pool_params import RelayType
            >>> relay_type = RelayType.SINGLE_HOST_ADDRESS
            >>> relay_type.to_string()
            'Single Host Address'
        """
        result = lib.cardano_relay_type_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
