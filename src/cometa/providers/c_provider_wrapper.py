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

from typing import Union, List, Optional

from .._ffi import ffi, lib
from ..errors import CardanoError


class CProviderWrapper:
    """
    Wrapper around a C cardano_provider_t* to use it from Python.

    This class allows using providers created in C (e.g., via C library functions)
    from Python code, providing a Python-friendly interface.

    Example:
        >>> # Assuming you have a C provider pointer
        >>> wrapper = CProviderWrapper(c_provider_ptr)
        >>> params = wrapper.get_parameters()
        >>> utxos = wrapper.get_unspent_outputs(address)
    """

    def __init__(self, ptr, owns_ref: bool = True) -> None:
        """
        Create a wrapper around a C provider pointer.

        Args:
            ptr: A cardano_provider_t* pointer.
            owns_ref: If True, increment ref count on init and decrement on del.
                     If False, just borrow the pointer without managing lifetime.

        Raises:
            CardanoError: If the pointer is NULL.
        """
        if ptr == ffi.NULL:
            raise CardanoError("CProviderWrapper: invalid handle")
        self._ptr = ptr
        self._owns_ref = owns_ref
        if owns_ref:
            # Increment reference count since we're taking a shared reference
            lib.cardano_provider_ref(ptr)

    def __del__(self) -> None:
        owns_ref = getattr(self, "_owns_ref", False)
        ptr = getattr(self, "_ptr", ffi.NULL)
        if owns_ref and ptr not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_provider_t**", ptr)
            lib.cardano_provider_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CProviderWrapper:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CProviderWrapper(name={self.get_name()})"

    @property
    def ptr(self):
        """Return the underlying cardano_provider_t* pointer."""
        return self._ptr

    def get_name(self) -> str:
        """Get the provider name."""
        result = lib.cardano_provider_get_name(self._ptr)
        return ffi.string(result).decode("utf-8")

    def get_network_magic(self) -> int:
        """Get the network magic number."""
        return int(lib.cardano_provider_get_network_magic(self._ptr))

    def get_last_error(self) -> str:
        """Get the last error message from the provider."""
        result = lib.cardano_provider_get_last_error(self._ptr)
        return ffi.string(result).decode("utf-8")

    def get_parameters(self) -> "ProtocolParameters":
        """
        Retrieve the current protocol parameters.

        Returns:
            The current ProtocolParameters.

        Raises:
            CardanoError: If the request fails.
        """
        from ..protocol_params import ProtocolParameters

        out = ffi.new("cardano_protocol_parameters_t**")
        err = lib.cardano_provider_get_parameters(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get parameters (error code: {err}): {self.get_last_error()}"
            )
        return ProtocolParameters(out[0])

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """
        Get all unspent transaction outputs for an address.

        Args:
            address: The payment address to query.

        Returns:
            A list of Utxo objects.

        Raises:
            CardanoError: If the request fails.
        """
        from ..address import Address
        from ..common.utxo_list import UtxoList

        if isinstance(address, str):
            address = Address.from_string(address)

        out = ffi.new("cardano_utxo_list_t**")
        err = lib.cardano_provider_get_unspent_outputs(self._ptr, address._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to get unspent outputs (error code: {err}): {self.get_last_error()}"
            )

        utxo_list = UtxoList(out[0])
        return list(utxo_list)

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """
        Get the staking rewards balance for a reward account.

        Args:
            reward_account: The reward address to query.

        Returns:
            The rewards balance in lovelace.

        Raises:
            CardanoError: If the request fails.
        """
        from ..address import RewardAddress

        if isinstance(reward_account, str):
            reward_account = RewardAddress.from_bech32(reward_account)

        out = ffi.new("uint64_t*")
        err = lib.cardano_provider_get_rewards_available(
            self._ptr, reward_account._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get rewards balance (error code: {err}): {self.get_last_error()}"
            )
        return int(out[0])

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
            CardanoError: If the request fails.
        """
        from ..address import Address
        from ..assets import AssetId
        from ..common.utxo_list import UtxoList

        if isinstance(address, str):
            address = Address.from_string(address)
        if isinstance(asset_id, str):
            asset_id = AssetId.from_hex(asset_id)

        out = ffi.new("cardano_utxo_list_t**")
        err = lib.cardano_provider_get_unspent_outputs_with_asset(
            self._ptr, address._ptr, asset_id._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get unspent outputs with asset (error code: {err}): {self.get_last_error()}"
            )

        utxo_list = UtxoList(out[0])
        return list(utxo_list)

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """
        Get the UTXO containing a specific NFT.

        Args:
            asset_id: The NFT asset identifier.

        Returns:
            The Utxo containing the NFT.

        Raises:
            CardanoError: If the NFT is not found.
        """
        from ..assets import AssetId
        from ..common.utxo import Utxo

        if isinstance(asset_id, str):
            asset_id = AssetId.from_hex(asset_id)

        out = ffi.new("cardano_utxo_t**")
        err = lib.cardano_provider_get_unspent_output_by_nft(
            self._ptr, asset_id._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to get unspent output by NFT (error code: {err}): {self.get_last_error()}"
            )
        return Utxo(out[0])

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
            CardanoError: If resolution fails.
        """
        from ..transaction_body import TransactionInputSet
        from ..common.utxo_list import UtxoList

        if isinstance(tx_ins, list):
            tx_ins = TransactionInputSet.from_list(tx_ins)

        out = ffi.new("cardano_utxo_list_t**")
        err = lib.cardano_provider_resolve_unspent_outputs(
            self._ptr, tx_ins._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to resolve unspent outputs (error code: {err}): {self.get_last_error()}"
            )

        utxo_list = UtxoList(out[0])
        return list(utxo_list)

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> "PlutusData":
        """
        Resolve a datum by its hash.

        Args:
            datum_hash: The hash of the datum to resolve.

        Returns:
            The PlutusData object.

        Raises:
            CardanoError: If the datum is not found.
        """
        from ..cryptography import Blake2bHash
        from ..plutus_data import PlutusData

        if isinstance(datum_hash, str):
            datum_hash = Blake2bHash.from_hex(datum_hash)

        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_provider_resolve_datum(self._ptr, datum_hash._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to resolve datum (error code: {err}): {self.get_last_error()}"
            )
        return PlutusData(out[0])

    def confirm_transaction(
        self, tx_id: Union["Blake2bHash", str], timeout_ms: int = 0
    ) -> bool:
        """
        Wait for a transaction to be confirmed on-chain.

        Args:
            tx_id: The transaction ID.
            timeout_ms: Timeout in milliseconds (0 for no timeout).

        Returns:
            True if confirmed, False if timeout reached.

        Raises:
            CardanoError: If confirmation check fails.
        """
        from ..cryptography import Blake2bHash

        if isinstance(tx_id, str):
            tx_id = Blake2bHash.from_hex(tx_id)

        out = ffi.new("bool*")
        err = lib.cardano_provider_confirm_transaction(
            self._ptr, tx_id._ptr, timeout_ms, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to confirm transaction (error code: {err}): {self.get_last_error()}"
            )
        return bool(out[0])

    def submit_transaction(self, transaction: Union["Transaction", str]) -> "Blake2bHash":
        """
        Submit a signed transaction to the blockchain.

        Args:
            transaction: The transaction object or CBOR hex string.

        Returns:
            The transaction ID as a Blake2bHash.

        Raises:
            CardanoError: If submission fails.
        """
        from ..transaction import Transaction
        from ..cryptography import Blake2bHash
        from ..cbor.cbor_reader import CborReader

        if isinstance(transaction, str):
            reader = CborReader.from_hex(transaction)
            transaction = Transaction.from_cbor(reader)

        out = ffi.new("cardano_blake2b_hash_t**")
        err = lib.cardano_provider_submit_transaction(self._ptr, transaction._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to submit transaction (error code: {err}): {self.get_last_error()}"
            )
        return Blake2bHash(out[0])

    def evaluate_transaction(
        self,
        transaction: Union["Transaction", str],
        additional_utxos: Optional[Union["UtxoList", List["Utxo"]]] = None,
    ) -> "RedeemerList":
        """
        Evaluate a transaction to get execution units for Plutus scripts.

        Args:
            transaction: The transaction object or CBOR hex string.
            additional_utxos: Optional additional UTXOs for evaluation.

        Returns:
            A RedeemerList with computed execution units.

        Raises:
            CardanoError: If evaluation fails.
        """
        from ..transaction import Transaction
        from ..common.utxo_list import UtxoList
        from ..witness_set import RedeemerList
        from ..cbor.cbor_reader import CborReader

        if isinstance(transaction, str):
            reader = CborReader.from_hex(transaction)
            transaction = Transaction.from_cbor(reader)

        utxo_ptr = ffi.NULL
        if additional_utxos is not None:
            if isinstance(additional_utxos, list):
                additional_utxos = UtxoList.from_list(additional_utxos)
            utxo_ptr = additional_utxos._ptr

        out = ffi.new("cardano_redeemer_list_t**")
        err = lib.cardano_provider_evaluate_transaction(
            self._ptr, transaction._ptr, utxo_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to evaluate transaction (error code: {err}): {self.get_last_error()}"
            )
        return RedeemerList(out[0])
