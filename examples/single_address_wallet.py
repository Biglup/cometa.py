"""
Simple single Address wallet implementation for programmatic use
on the examples.

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
from typing import Callable, Optional, List, Dict

import cometa
from cometa import (
    Address,
    AddressType,
    BaseAddress,
    Bip32PrivateKey,
    Bip32PublicKey,
    EnterpriseAddress,
    NetworkId,
    NetworkMagic,
    RewardAddress,
    Ed25519PublicKey,
    SoftwareBip32SecureKeyHandler,
    mnemonic_to_entropy,
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    DerivationPath,
    TxBuilder,
    VkeyWitnessSet,
    cip8_sign,
    cip8_sign_with_key_hash,
    Provider,
    Transaction, CborReader, SlotConfig
)
from cometa.cardano import memzero


@dataclass
class SingleAddressCredentialsConfig:
    """
    Defines part of the BIP-44 derivation path components for a single Cardano address.

    Attributes:
        account: The account index.
        payment_index: The address index for the payment key (role 0).
        staking_index: The address index for the staking key (role 2).
            If provided, a Base address (payment + staking) will be derived.
            If omitted, an Enterprise address (payment only) will be derived.
        drep_index: The address index for the DRep key (role 3).
            If not provided, 0 will be assumed.
    """
    account: int
    payment_index: int
    staking_index: Optional[int] = None
    drep_index: int = 0


def _coalesce_utxo_values(utxos: List[cometa.Utxo]) -> cometa.Value:
    """
    Coalesces the values from an array of UTxOs into a single, consolidated Value object.

    Args:
        utxos: An array of UTxOs to be coalesced.

    Returns:
        A single Value object representing the total sum of all coins and assets.
    """
    total_coins = 0
    total_assets: Dict[str, int] = {}

    for utxo in utxos:
        total_coins += utxo.output.value.coin
        if utxo.output.value.multi_asset:
            for policy_id in utxo.output.value.multi_asset.get_policies():
                assets = utxo.output.value.multi_asset.get_assets(policy_id)
                if assets:
                    for asset_name, amount in assets.items():
                        # Create unique key for aggregation
                        asset_id = policy_id.to_hex() + asset_name.to_hex()
                        total_assets[asset_id] = total_assets.get(asset_id, 0) + amount

    result = cometa.Value.new(total_coins)
    if total_assets:
        multi_asset = cometa.MultiAsset()
        for asset_id, amount in total_assets.items():
            policy_hex = asset_id[:56]
            name_hex = asset_id[56:]
            multi_asset.set(
                cometa.Blake2bHash.from_hex(policy_hex),
                cometa.AssetName.from_hex(name_hex),
                amount
            )

        result = cometa.Value.new(total_coins, multi_asset)
    return result


class SingleAddressWallet:
    """
    A simple, single-address wallet implementation for programmatic use, to be
    used with the examples.

    This class provides a straightforward wallet interface that manages a single
    payment and staking key pair derived from a specific path. It is not a
    full Hierarchical Deterministic (HD) wallet and does not perform address
    discovery. Its simplicity makes it ideal for testing or scripting
     where interaction with a single, known address is required.
    """

    def __init__(
        self,
        secure_key_handler: SoftwareBip32SecureKeyHandler,
        account_root_public_key: Bip32PublicKey,
        provider: Provider,
        credentials_config: SingleAddressCredentialsConfig
    ) -> None:
        """
        Constructs a new instance of the SingleAddressWallet.

        Args:
            secure_key_handler: The handler that manages encrypted private keys.
            account_root_public_key: The public key for the specified account from
                which addresses are derived.
            provider: The provider instance for interacting with the Cardano blockchain.
            credentials_config: Specifies the derivation path for the address this
                wallet will manage.

        Note:
            This constructor is typically not called directly. Use the static
            `create_from_mnemonics` method to create an instance.
        """
        self._secure_key_handler = secure_key_handler
        self._provider = provider
        self._credentials_config = credentials_config
        self._account_root_public_key = account_root_public_key
        self._payment_address: Optional[Address] = None
        self._reward_address: Optional[RewardAddress] = None
        self._drep_pub_key: Optional[Ed25519PublicKey] = None
        self._protocol_params: Optional[cometa.ProtocolParameters] = None

    @classmethod
    def create_from_mnemonics(
        cls,
        mnemonics: List[str],
        provider: Provider,
        credentials_config: SingleAddressCredentialsConfig,
        get_password: Callable[[], bytes]
    ) -> SingleAddressWallet:
        """
        Creates a new wallet instance from a mnemonic phrase.

        Args:
            mnemonics: The mnemonic (seed) phrase as a list of words.
            provider: The provider instance for interacting with the Cardano blockchain.
            credentials_config: Specifies the derivation path for the address this
                wallet will manage.
            get_password: An callback function that securely provides the password
                for encrypting the derived keys.

        Returns:
            A newly created wallet instance.
        """
        entropy = mnemonic_to_entropy(mnemonics)
        password = get_password()

        try:
            root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
            account_key = root_key.derive([
                harden(KeyDerivationPurpose.STANDARD),
                harden(CoinType.CARDANO),
                harden(credentials_config.account)
            ])
            account_root_public_key = account_key.get_public_key()

            secure_key_handler = SoftwareBip32SecureKeyHandler.from_entropy(
                entropy, password, get_password
            )

            return cls(
                secure_key_handler=secure_key_handler,
                account_root_public_key=account_root_public_key,
                provider=provider,
                credentials_config=credentials_config
            )
        finally:
            if isinstance(entropy, bytearray):
                memzero(entropy)
            if isinstance(password, bytearray):
                memzero(password)

    def get_network_id(self) -> NetworkId:
        """
        Returns the wallet's current network ID.

        Returns:
            The network ID (TESTNET for testnets, MAINNET for mainnet).
        """
        magic = self._provider.get_network_magic()
        return NetworkId.MAINNET if magic == NetworkMagic.MAINNET else NetworkId.TESTNET

    def get_unspent_outputs(self) -> List[cometa.Utxo]:
        """
        Fetches all Unspent Transaction Outputs (UTxOs) for the wallet's address.

        Returns:
            An array of the wallet's UTxOs.
        """
        address = self.get_address()
        return self._provider.get_unspent_outputs(str(address))

    def get_balance(self) -> cometa.Value:
        """
        Fetches and deserializes the total balance of all assets controlled by the wallet.

        Returns:
            A Value object representing the wallet's complete balance.
        """
        utxos = self.get_unspent_outputs()
        return _coalesce_utxo_values(utxos)

    def get_used_addresses(self) -> List[Address]:
        """
        Fetches and parses all used addresses controlled by the wallet.

        Returns:
            An array of parsed Address objects.
        """
        address = self.get_address()
        return [address]

    def get_unused_addresses(self) -> List[Address]:
        """
        Fetches and parses all unused addresses controlled by the wallet.

        Returns:
            An empty array (this wallet type does not track unused addresses).
        """
        return []

    def get_change_address(self) -> Address:
        """
        Fetches and parses a single change address from the wallet.

        Returns:
            The wallet's address to use for change outputs.
        """
        return self.get_address()

    def get_reward_addresses(self) -> List[RewardAddress]:
        """
        Fetches and parses all reward addresses controlled by the wallet.

        Returns:
            An array of parsed RewardAddress objects.
        """
        reward_address = self.get_reward_address()
        return [reward_address]

    def sign_transaction(self, transaction: Transaction, _partial_sign: bool = False) -> VkeyWitnessSet:
        """
        Requests a signature for a transaction using the wallet's keys.

        Args:
            transaction: The transaction to be signed.
            _partial_sign: A flag to control which credentials are used for signing.

        Returns:
            The VkeyWitnessSet containing the generated signatures.
        """
        if not self._drep_pub_key:
            self.get_pub_drep_key()

        required_signers = transaction.get_unique_signers()

        required_hashes = set()
        if required_signers:
            for key_hash in required_signers:
                required_hashes.add(key_hash.to_hex())

        reward_key_hash = None
        if self._credentials_config.staking_index is not None:
            reward_address = self.get_reward_address()
            reward_key_hash = reward_address.credential.hash.to_hex()

        drep_key_hash = self._drep_pub_key.to_hash().to_hex() if self._drep_pub_key else None

        derivation_paths = []

        derivation_paths.append(
            DerivationPath(
                purpose=harden(KeyDerivationPurpose.STANDARD),
                coin_type=harden(CoinType.CARDANO),
                account=harden(self._credentials_config.account),
                role=KeyDerivationRole.EXTERNAL,
                index=self._credentials_config.payment_index
            )
        )

        if (self._credentials_config.staking_index is not None and
            reward_key_hash and reward_key_hash in required_hashes):
            derivation_paths.append(
                DerivationPath(
                    purpose=harden(KeyDerivationPurpose.STANDARD),
                    coin_type=harden(CoinType.CARDANO),
                    account=harden(self._credentials_config.account),
                    role=KeyDerivationRole.STAKING,
                    index=self._credentials_config.staking_index
                )
            )

        if drep_key_hash and drep_key_hash in required_hashes:
            derivation_paths.append(
                DerivationPath(
                    purpose=harden(KeyDerivationPurpose.STANDARD),
                    coin_type=harden(CoinType.CARDANO),
                    account=harden(self._credentials_config.account),
                    role=KeyDerivationRole.DREP,
                    index=self._credentials_config.drep_index
                )
            )

        return self._secure_key_handler.sign_transaction(transaction, derivation_paths)

    def sign_data(self, address: Address, payload: str) -> Dict[str, str]:
        """
        Requests a CIP-8 compliant data signature from the wallet.

        Args:
            address: The address to sign with.
            payload: The hex-encoded data payload to be signed.

        Returns:
            A dict with 'signature' (COSE_Sign1) and 'key' (COSE_Key) as hex strings.
        """
        message = bytes.fromhex(payload)

        if address.type == AddressType.REWARD_KEY:
            return self._sign_with_reward_key(address, message)

        if address.type == AddressType.ENTERPRISE_KEY:
            result = self._sign_with_drep_key(address, message)
            if result:
                return result

        return self._sign_with_payment_key(address, message)

    def submit_transaction(self, tx_cbor: str) -> str:
        """
        Submits a fully signed transaction to the blockchain via the wallet's provider.

        Args:
            tx_cbor: The fully signed transaction as a CBOR hex string.

        Returns:
            The transaction ID (hash).
        """
        return self._provider.submit_transaction(tx_cbor)

    def get_collateral(self) -> List[cometa.Utxo]:
        """
        Fetches and deserializes the wallet's collateral UTxOs.

        Returns:
            An empty array (not currently supported).
        """
        return []

    def get_network_magic(self) -> NetworkMagic:
        """
        Returns the network magic number identifying the Cardano network.

        Returns:
            The network magic number.
        """
        return NetworkMagic(self._provider.get_network_magic())

    def get_pub_drep_key(self) -> str:
        """
        Returns the wallet's active public DRep (Delegated Representative) key.

        Returns:
            The hex-encoded public DRep key.
        """
        if self._drep_pub_key:
            return self._drep_pub_key.to_hex()

        bip32_public_key = self._account_root_public_key.derive([
            KeyDerivationRole.DREP,
            self._credentials_config.drep_index
        ])

        self._drep_pub_key = bip32_public_key.to_ed25519_key()
        return self._drep_pub_key.to_hex()

    def get_registered_pub_stake_keys(self) -> List[str]:
        """
        Returns public stake keys from the wallet that are currently registered.

        Returns:
            An empty array (not currently supported).
        """
        return []

    def get_unregistered_pub_stake_keys(self) -> List[str]:
        """
        Returns public stake keys from the wallet that are NOT yet registered.

        Returns:
            An empty array (not currently supported).
        """
        return []

    def create_transaction_builder(self) -> TxBuilder:
        """
        Creates and initializes a new transaction builder with the wallet's current state.

        Returns:
            A pre-configured TxBuilder instance.
        """
        own_address = self.get_address()
        own_utxos = self.get_unspent_outputs()

        if not self._protocol_params:
            self._protocol_params = self._provider.get_parameters()

        network_magic = self.get_network_magic()
        slot_config = SlotConfig.mainnet()
        match network_magic:
            case NetworkMagic.MAINNET:
                slot_config = SlotConfig.mainnet()
            case NetworkMagic.PREPROD:
                slot_config = SlotConfig.preprod()
            case NetworkMagic.PREVIEW:
                slot_config = SlotConfig.preview()
            case _: raise ValueError("SingleAddressWallet: Unsupported network magic.")

        builder = TxBuilder(self._protocol_params, slot_config)
        builder.set_change_address(own_address)
        builder.set_collateral_change_address(own_address)
        builder.set_collateral_utxos(own_utxos)
        builder.set_utxos(own_utxos)

        return builder

    def get_address(self) -> Address:
        """
        Derives the payment address based on the wallet's configuration.

        Returns:
            A BaseAddress (with staking) or an EnterpriseAddress (without staking).
        """
        if self._payment_address:
            return self._payment_address

        payment_key = self._account_root_public_key.derive([
            KeyDerivationRole.EXTERNAL,
            self._credentials_config.payment_index
        ])
        payment_credential = cometa.Credential.from_key_hash(
            payment_key.to_ed25519_key().to_hash()
        )

        network = self.get_network_id()

        if self._credentials_config.staking_index is not None:
            staking_key = self._account_root_public_key.derive([
                KeyDerivationRole.STAKING,
                self._credentials_config.staking_index
            ])
            staking_credential = cometa.Credential.from_key_hash(
                staking_key.to_ed25519_key().to_hash()
            )
            self._payment_address = BaseAddress.from_credentials(
                network, payment_credential, staking_credential
            ).to_address()
            return self._payment_address

        self._payment_address = EnterpriseAddress.from_credentials(
            network, payment_credential
        ).to_address()
        return self._payment_address

    def get_reward_address(self) -> RewardAddress:
        """
        Derives the rewards address based on the wallet's configuration.

        Returns:
            The RewardAddress for the wallet.

        Raises:
            TypeError: If staking_index was not provided in the configuration.
        """
        if self._reward_address:
            return self._reward_address

        if self._credentials_config.staking_index is None:
            raise TypeError("SingleAddressWallet: Staking index was not provided.")

        network = self.get_network_id()
        staking_key = self._account_root_public_key.derive([
            KeyDerivationRole.STAKING,
            self._credentials_config.staking_index
        ])

        staking_credential = cometa.Credential.from_key_hash(
            staking_key.to_ed25519_key().to_hash()
        )

        self._reward_address = RewardAddress.from_credentials(network, staking_credential)
        return self._reward_address

    def _sign_with_reward_key(self, sign_with: Address, message: bytes) -> Dict[str, str]:
        """Helper to sign data using the STAKING key associated with a Reward Address."""
        if self._credentials_config.staking_index is None:
            raise TypeError("SingleAddressWallet: Staking index was not provided.")

        wallet_reward_address = self.get_reward_address()

        if wallet_reward_address.to_bech32() != str(sign_with):
            raise ValueError(
                "SingleAddressWallet: The provided reward address does not belong to this wallet."
            )

        private_key = self._secure_key_handler.get_private_key(
            DerivationPath(
                purpose=harden(KeyDerivationPurpose.STANDARD),
                coin_type=harden(CoinType.CARDANO),
                account=harden(self._credentials_config.account),
                role=KeyDerivationRole.STAKING,
                index=self._credentials_config.staking_index
            )
        )

        result = cip8_sign(message, sign_with, private_key)
        return {
            "key": result.cose_key.hex(),
            "signature": result.cose_sign1.hex()
        }

    def _sign_with_drep_key(self, sign_with: Address, message: bytes) -> Optional[Dict[str, str]]:
        """
        Helper to sign data using the DREP key.
        Checks if the provided Enterprise address credential matches our DRep key.
        """
        enterprise = sign_with.to_enterprise_address()
        if not enterprise:
            return None

        cred = enterprise.payment_credential

        if not self._drep_pub_key:
            self.get_pub_drep_key()

        if self._drep_pub_key and cred.hash.to_hex() == self._drep_pub_key.to_hash().to_hex():
            private_key = self._secure_key_handler.get_private_key(
                DerivationPath(
                    purpose=harden(KeyDerivationPurpose.STANDARD),
                    coin_type=harden(CoinType.CARDANO),
                    account=harden(self._credentials_config.account),
                    role=KeyDerivationRole.DREP,
                    index=self._credentials_config.drep_index
                )
            )

            result = cip8_sign_with_key_hash(message, cred.hash, private_key)
            return {
                "key": result.cose_key.hex(),
                "signature": result.cose_sign1.hex()
            }

        return None

    def _sign_with_payment_key(
        self,
        sign_with: Address,
        message: bytes
    ) -> Dict[str, str]:
        """Helper to sign data using the PAYMENT key associated with Base or Enterprise Address."""
        payment_address = self.get_address()

        wallet_payment_cred = None
        if payment_address.type == AddressType.ENTERPRISE_KEY:
            enterprise = payment_address.to_enterprise_address()
            if enterprise:
                wallet_payment_cred = enterprise.payment_credential
        else:
            base = payment_address.to_base_address()
            if base:
                wallet_payment_cred = base.payment_credential

        sign_with_payment_cred = None
        if sign_with.type == AddressType.ENTERPRISE_KEY:
            enterprise = sign_with.to_enterprise_address()
            if enterprise:
                sign_with_payment_cred = enterprise.payment_credential
        else:
            base = sign_with.to_base_address()
            if base:
                sign_with_payment_cred = base.payment_credential

        if (wallet_payment_cred and sign_with_payment_cred and
                wallet_payment_cred.hash.to_hex() == sign_with_payment_cred.hash.to_hex()):
            private_key = self._secure_key_handler.get_private_key(
                DerivationPath(
                    purpose=harden(KeyDerivationPurpose.STANDARD),
                    coin_type=harden(CoinType.CARDANO),
                    account=harden(self._credentials_config.account),
                    role=KeyDerivationRole.EXTERNAL,
                    index=self._credentials_config.payment_index
                )
            )

            result = cip8_sign(message, sign_with, private_key)
            return {
                "key": result.cose_key.hex(),
                "signature": result.cose_sign1.hex()
            }

        raise ValueError("SingleAddressWallet: The provided address does not belong to this wallet.")
