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

from typing import Protocol, Union, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..protocol_params import ProtocolParameters
    from ..address import Address, RewardAddress
    from ..transaction_body import TransactionInput, TransactionInputSet
    from ..witness_set import Redeemer
    from ..assets import AssetId
    from ..cryptography import Blake2bHash
    from ..common.utxo import Utxo
    from ..common.utxo_list import UtxoList


class ProviderProtocol(Protocol):
    """
    Protocol defining the interface for Cardano blockchain data providers.

    Providers are responsible for interacting with the Cardano blockchain to:
    - Fetch protocol parameters
    - Query UTXOs for addresses
    - Resolve datums
    - Submit and confirm transactions
    - Evaluate Plutus script execution

    Implement this protocol to create custom providers (e.g., Blockfrost, Koios, etc.).
    """

    def get_name(self) -> str:
        """
        Get the human-readable name of this provider.

        Returns:
            The provider name (e.g., "Blockfrost", "Koios").
        """

    def get_network_magic(self) -> int:
        """
        Get the network magic number this provider is connected to.

        Returns:
            The network magic (e.g., 764824073 for mainnet).
        """

    def get_parameters(self) -> "ProtocolParameters":
        """
        Retrieve the current protocol parameters from the blockchain.

        Returns:
            The current ProtocolParameters.

        Raises:
            Exception: If the request fails.
        """

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """
        Get all unspent transaction outputs (UTXOs) for an address.

        Args:
            address: The payment address to query.

        Returns:
            A list of Utxo objects.

        Raises:
            Exception: If the request fails.
        """

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """
        Get the current staking rewards balance for a reward account.

        Args:
            reward_account: The reward address to query.

        Returns:
            The rewards balance in lovelace.

        Raises:
            Exception: If the request fails.
        """

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        """
        Get UTXOs for an address that contain a specific asset.

        Args:
            address: The payment address to query.
            asset_id: The asset identifier to filter by.

        Returns:
            A list of Utxo objects containing the asset.

        Raises:
            Exception: If the request fails.
        """

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """
        Get the UTXO containing a specific NFT.

        Args:
            asset_id: The NFT asset identifier.

        Returns:
            The Utxo containing the NFT.

        Raises:
            Exception: If the NFT is not found or held by multiple UTXOs.
        """

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        """
        Resolve transaction inputs to their corresponding UTXOs.

        Args:
            tx_ins: The transaction inputs to resolve.

        Returns:
            A list of resolved Utxo objects.

        Raises:
            Exception: If resolution fails.
        """

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        """
        Resolve a datum by its hash.

        Args:
            datum_hash: The hash of the datum to resolve.

        Returns:
            The CBOR-encoded datum as a hex string.

        Raises:
            Exception: If the datum is not found.
        """

    def confirm_transaction(self, tx_id: str, timeout_ms: int | None = None) -> bool:
        """
        Wait for a transaction to be confirmed on-chain.

        Args:
            tx_id: The transaction ID (hex string).
            timeout_ms: Optional timeout in milliseconds.

        Returns:
            True if confirmed, False if timeout reached.

        Raises:
            Exception: If confirmation check fails.
        """

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """
        Submit a signed transaction to the blockchain.

        Args:
            tx_cbor_hex: The CBOR-encoded transaction as a hex string.

        Returns:
            The transaction ID (hex string) of the submitted transaction.

        Raises:
            Exception: If submission fails.
        """

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union["UtxoList", List["Utxo"]] | None = None,
    ) -> List["Redeemer"]:
        """
        Evaluate a transaction to get execution units for Plutus scripts.

        Args:
            tx_cbor_hex: The CBOR-encoded transaction as a hex string.
            additional_utxos: Optional additional UTXOs for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.

        Raises:
            Exception: If evaluation fails.
        """

Provider = ProviderProtocol
