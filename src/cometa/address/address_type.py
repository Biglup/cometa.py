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


class AddressType(IntEnum):
    """
    Types of addresses used within the Cardano blockchain.

    Shelley introduced several address types, each serving distinct purposes.
    Byron-era bootstrap addresses are also supported for backward compatibility.
    """

    BASE_PAYMENT_KEY_STAKE_KEY = 0b0000
    """Base address with both payment and stake credentials as key hashes."""

    BASE_PAYMENT_SCRIPT_STAKE_KEY = 0b0001
    """Base address with payment as script hash and stake as key hash."""

    BASE_PAYMENT_KEY_STAKE_SCRIPT = 0b0010
    """Base address with payment as key hash and stake as script hash."""

    BASE_PAYMENT_SCRIPT_STAKE_SCRIPT = 0b0011
    """Base address with both payment and stake credentials as script hashes."""

    POINTER_KEY = 0b0100
    """Pointer address with payment credential as key hash."""

    POINTER_SCRIPT = 0b0101
    """Pointer address with payment credential as script hash."""

    ENTERPRISE_KEY = 0b0110
    """Enterprise address with payment credential as key hash."""

    ENTERPRISE_SCRIPT = 0b0111
    """Enterprise address with payment credential as script hash."""

    BYRON = 0b1000
    """Byron-era bootstrap address (legacy format)."""

    REWARD_KEY = 0b1110
    """Reward account address with credential as key hash."""

    REWARD_SCRIPT = 0b1111
    """Reward account address with credential as script hash."""
