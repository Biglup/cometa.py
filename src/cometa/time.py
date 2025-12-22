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

from typing import Union

from ._ffi import lib
from .common.network_magic import NetworkMagic


def slot_from_unix_time(network: Union[NetworkMagic, int], unix_time: int) -> int:
    """
    Computes the Cardano network slot for a given Unix time.

    This function calculates the slot number on the Cardano network corresponding
    to a specified Unix timestamp. Since slot duration may vary across different
    networks and over time, this computation requires both the network magic and
    the Unix time.

    Args:
        network: The network magic identifying the specific Cardano network.
            Can be a NetworkMagic enum value or an integer.
        unix_time: The Unix timestamp in seconds for which to compute the slot.

    Returns:
        The computed slot number representing the slot at the specified Unix time.

    Example:
        >>> from cometa import NetworkMagic, slot_from_unix_time
        >>> slot = slot_from_unix_time(NetworkMagic.MAINNET, 1700000000)
        >>> print(f"Slot: {slot}")

    Note:
        Slot duration and epoch boundaries may vary across networks and can change
        over time. This function takes these network-specific configurations into
        account.
    """
    magic = network if isinstance(network, int) else network.value
    return int(lib.cardano_compute_slot_from_unix_time(magic, unix_time))


def unix_time_from_slot(network: Union[NetworkMagic, int], slot: int) -> int:
    """
    Computes the Unix time corresponding to a given Cardano network slot.

    This function calculates the Unix timestamp for a specified slot number on
    the Cardano network. Slot-to-time mapping depends on the network's specific
    slot duration and other time-related parameters that may vary across different
    Cardano networks and epochs.

    Args:
        network: The network magic identifying the specific Cardano network.
            Can be a NetworkMagic enum value or an integer.
        slot: The slot number for which to compute the Unix time.

    Returns:
        The computed Unix timestamp in seconds representing the time at the
        specified slot.

    Example:
        >>> from cometa import NetworkMagic, unix_time_from_slot
        >>> unix_time = unix_time_from_slot(NetworkMagic.MAINNET, 500000)
        >>> print(f"Unix time: {unix_time}")

    Note:
        The conversion relies on the network's configuration, as different networks
        and epochs may have varying slot durations, affecting the calculated Unix time.
    """
    magic = network if isinstance(network, int) else network.value
    return int(lib.cardano_compute_unix_time_from_slot(magic, slot))
