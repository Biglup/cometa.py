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

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Callable, Union

if TYPE_CHECKING:
    from ..cryptography.bip32_public_key import Bip32PublicKey
    from ..cryptography.ed25519_private_key import Ed25519PrivateKey
    from ..cryptography.ed25519_public_key import Ed25519PublicKey
    from ..witness_set.vkey_witness_set import VkeyWitnessSet


def harden(num: int) -> int:
    """
    Harden a BIP-32 child number.

    Args:
        num: The child number to harden.

    Returns:
        The hardened child number (num + 2^31).

    Example:
        >>> harden(1852)  # Purpose for Cardano
        2147485500
        >>> harden(1815)  # Coin type for ADA
        2147485463
        >>> harden(0)     # Account 0
        2147483648
    """
    return 0x80_00_00_00 + num


class CoinType(IntEnum):
    """
    Defines the coin type for Cardano in BIP-44/BIP-1852 derivation paths.
    """
    CARDANO = 1815


class KeyDerivationPurpose(IntEnum):
    """
    Defines the purpose for a BIP-1852 derivation path.
    """
    STANDARD = 1852
    MULTISIG = 1854


class KeyDerivationRole(IntEnum):
    """
    Defines the role for a BIP-1852 derivation path, specifying the key's usage.
    """
    EXTERNAL = 0
    INTERNAL = 1
    STAKING = 2
    DREP = 3
    COMMITTEE_COLD = 4
    COMMITTEE_HOT = 5


@dataclass
class AccountDerivationPath:
    """
    Represents a BIP-1852 derivation path for an account.
    m / purpose' / 1815' / account'
    """
    purpose: int
    """The purpose index (should be hardened)."""
    coin_type: int
    """The coin type index (should be hardened, 1815 for Cardano)."""
    account: int
    """The account index (should be hardened)."""


@dataclass
class DerivationPath(AccountDerivationPath):
    """
    Represents a full BIP-1852 derivation path for a specific key.
    m / purpose' / 1815' / account' / role / index
    """
    role: KeyDerivationRole
    """The key role (External, Internal, Staking, etc.)."""
    index: int
    """The key index within the role."""


# Type alias for passphrase callback
PassphraseCallback = Callable[[], bytes]

class Bip32SecureKeyHandler(ABC):
    """
    Defines the contract for a secure key handler that manages a BIP32
    hierarchical deterministic (HD) root key.

    Implementations of this interface are responsible for keeping the root
    private key secure. The key should only be decrypted for the brief duration
    of a cryptographic operation in the case of in-memory implementations,
    after which it must be securely wiped from memory to minimize exposure.
    """

    @abstractmethod
    def sign_transaction(
        self,
        transaction: "Transaction",
        derivation_paths: list[DerivationPath]
    ) -> "VkeyWitnessSet":
        """
        Signs a transaction using BIP32-derived keys.

        Args:
            transaction: The transaction to be signed.
            derivation_paths: An array of derivation paths specifying which
                keys are required to sign the transaction.

        Returns:
            A VkeyWitnessSet containing the generated signatures.

        Note:
            During this operation, the root private key is temporarily decrypted
            in memory and securely wiped immediately after use.
        """

    @abstractmethod
    def sign_data(
        self,
        data: str,
        derivation_path: DerivationPath
    ) -> dict[str, str]:
        """
        Signs arbitrary data using a BIP32-derived key.

        Args:
            data: The hex-encoded data to be signed.
            derivation_path: The derivation path specifying which key to use.

        Returns:
            A dict with 'signature' and 'key' (public key) as hex strings.
        """

    @abstractmethod
    def get_private_key(
        self,
        derivation_path: DerivationPath
    ) -> "Ed25519PrivateKey":
        """
        Retrieves the securely stored private key.

        Args:
            derivation_path: The derivation path specifying which key to retrieve.

        Returns:
            The Ed25519PrivateKey.

        Warning:
            This operation exposes the private key in memory and should be used
            with extreme caution. The caller is responsible for securely handling
            and wiping the key from memory after use.
        """

    @abstractmethod
    def get_account_public_key(
        self,
        path: AccountDerivationPath
    ) -> "Bip32PublicKey":
        """
        Derives and returns an extended account public key from the root key.

        Args:
            path: The derivation path for the account (purpose, coin_type, account).

        Returns:
            The derived extended account public key.

        Note:
            This operation requires the root private key, which is temporarily
            decrypted in memory and securely wiped immediately after use.
        """

    @abstractmethod
    def serialize(self) -> bytes:
        """
        Serializes the encrypted root key and its configuration for secure storage.
        This allows the handler's state to be saved and later restored via deserialize.

        Returns:
            The encrypted and serialized key handler data.
        """


class Ed25519SecureKeyHandler(ABC):
    """
    Defines the contract for a secure key handler that manages a single,
    non-derivable Ed25519 private key.

    Implementations of this interface are responsible for keeping the private
    key secure. The key should only be decrypted for the brief duration of a
    cryptographic operation in the case of in-memory implementations, after
    which it must be securely wiped from memory to minimize exposure.
    """

    @abstractmethod
    def sign_transaction(self, transaction: str) -> "VkeyWitnessSet":
        """
        Signs a transaction using the securely stored Ed25519 private key.

        Args:
            transaction: The CBOR-encoded transaction hex string to be signed.

        Returns:
            A VkeyWitnessSet containing the signature.
        """

    @abstractmethod
    def sign_data(self, data: str) -> dict[str, str]:
        """
        Signs arbitrary data using the securely stored Ed25519 private key.

        Args:
            data: The hex-encoded data to be signed.

        Returns:
            A dict with 'signature' and 'key' (public key) as hex strings.
        """

    @abstractmethod
    def get_private_key(self) -> "Ed25519PrivateKey":
        """
        Retrieves the securely stored private key.

        Returns:
            The Ed25519PrivateKey.

        Warning:
            This operation exposes the private key in memory and should be used
            with extreme caution. The caller is responsible for securely handling
            and wiping the key from memory after use.
        """

    @abstractmethod
    def get_public_key(self) -> "Ed25519PublicKey":
        """
        Retrieves the public key corresponding to the securely stored private key.

        Returns:
            The corresponding Ed25519PublicKey.
        """

    @abstractmethod
    def serialize(self) -> bytes:
        """
        Serializes the encrypted key data for secure storage.
        This allows the handler's state to be saved and later restored.

        Returns:
            The encrypted and serialized key data.
        """


# Union type for any secure key handler
SecureKeyHandler = Union[Bip32SecureKeyHandler, Ed25519SecureKeyHandler]
