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


class NetworkMagic(IntEnum):
    """
    Enumerates the available Cardano network environments.

    This enumeration defines the different network environments that can be used
    with the Cardano blockchain. Each network has a unique magic number that
    identifies it.

    Example:
        >>> from cometa import NetworkMagic
        >>> magic = NetworkMagic.MAINNET
        >>> print(magic)
        NetworkMagic.MAINNET
        >>> print(magic.value)
        764824073
    """

    PREPROD = 1
    """
    The Pre-Production test network.

    The Pre-Production network is a Cardano testnet used for testing features
    before they are deployed to the Mainnet. It closely mirrors the Mainnet
    environment, providing a final testing ground for applications.
    """

    PREVIEW = 2
    """
    The Preview test network.

    The Preview network is a Cardano testnet used for testing upcoming features
    before they are released to the Pre-Production network. It allows developers
    to experiment with new functionalities in a controlled environment.
    """

    SANCHONET = 4
    """
    The SanchoNet test network.

    SanchoNet is the testnet for rolling out governance features for the Cardano
    blockchain, aligning with the comprehensive CIP-1694 specifications.
    """

    MAINNET = 764824073
    """
    The Mainnet network.

    The Mainnet is the live Cardano network where real transactions occur.
    Applications interacting with the Mainnet are dealing with actual ADA and
    other assets. Caution should be exercised to ensure correctness and security.
    """

    def __str__(self) -> str:
        """
        Returns the human-readable string representation of the network magic.

        Returns:
            The network name as a string.

        Example:
            >>> str(NetworkMagic.MAINNET)
            'Mainnet'
        """
        result = lib.cardano_network_magic_to_string(self.value)
        return ffi.string(result).decode("utf-8")

    def __repr__(self) -> str:
        """
        Returns the official string representation of the network magic.

        Returns:
            The enum representation as a string.

        Example:
            >>> repr(NetworkMagic.MAINNET)
            'NetworkMagic.MAINNET'
        """
        return f"NetworkMagic.{self.name}"
