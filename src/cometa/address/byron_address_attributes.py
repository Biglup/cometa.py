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
from dataclasses import dataclass


@dataclass(frozen=True)
class ByronAddressAttributes:
    """
    Attributes specific to Byron-era addresses.

    Byron addresses contain optional attributes used during the Byron era of Cardano.
    The derivation_path was used by legacy random wallets for key derivation, while
    the magic attribute serves as a network identifier for test networks.
    """

    derivation_path: bytes = b""
    """Encrypted derivation path used by legacy wallets (maybe empty)."""
    magic: int = -1
    """Network magic identifier (-1 if not associated with a specific network)."""

    @classmethod
    def mainnet(cls) -> ByronAddressAttributes:
        """Creates attributes for a mainnet Byron address."""
        return cls(derivation_path=b"", magic=-1)

    @classmethod
    def testnet(cls, magic: int) -> ByronAddressAttributes:
        """Creates attributes for a testnet Byron address with the given network magic."""
        return cls(derivation_path=b"", magic=magic)

    @property
    def has_network_magic(self) -> bool:
        """Returns True if this address has a network magic (testnet)."""
        return self.magic >= 0
