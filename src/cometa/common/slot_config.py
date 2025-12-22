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


@dataclass
class SlotConfig:
    """
    Configuration for slot/time calculations on a Cardano network.

    These values are derived from the Shelley genesis configuration and are
    used for converting between slots and POSIX time during script evaluation.

    Attributes:
        zero_time: Start time in milliseconds since Unix epoch, aligns with zero_slot.
        zero_slot: Initial slot number corresponding to zero_time.
        slot_length: Duration of each slot in milliseconds (typically 1000).

    Example:
        >>> # Mainnet configuration
        >>> config = SlotConfig.mainnet()
        >>> # Preview testnet configuration
        >>> config = SlotConfig.preview()
        >>> # Custom configuration
        >>> config = SlotConfig(
        ...     zero_time=1596059091000,
        ...     zero_slot=4492800,
        ...     slot_length=1000,
        ... )
    """

    zero_time: int
    zero_slot: int
    slot_length: int

    @classmethod
    def mainnet(cls) -> SlotConfig:
        """
        Returns the slot configuration for Cardano mainnet.

        Returns:
            SlotConfig configured for mainnet.
        """
        return cls(
            zero_time=1596059091000,
            zero_slot=4492800,
            slot_length=1000,
        )

    @classmethod
    def preview(cls) -> SlotConfig:
        """
        Returns the slot configuration for the Preview testnet.

        Returns:
            SlotConfig configured for Preview.
        """
        return cls(
            zero_time=1666656000000,
            zero_slot=0,
            slot_length=1000,
        )

    @classmethod
    def preprod(cls) -> SlotConfig:
        """
        Returns the slot configuration for the Preprod testnet.

        Returns:
            SlotConfig configured for Preprod.
        """
        return cls(
            zero_time=1654041600000 + 1728000000,
            zero_slot=86400,
            slot_length=1000,
        )
