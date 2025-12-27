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

from typing import TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from .provider import Provider


# pylint: disable=too-many-instance-attributes
class ProviderHandle:
    """
    Wraps a Python Provider and exposes a cardano_provider_t* for libcardano-c.

    This class bridges Python provider implementations with the C library by creating
    CFFI callbacks that delegate to the Python provider methods.

    Example:
        >>> class MyProvider:
        ...     def get_name(self) -> str:
        ...         return "MyProvider"
        ...     # ... implement other methods
        >>> provider = MyProvider()
        >>> handle = ProviderHandle(provider)
        >>> c_provider_ptr = handle.ptr  # Pass to C functions
    """

    def __init__(self, provider: Provider):
        """
        Initialize a ProviderHandle to bridge Python provider with C library.

        Args:
            provider: A Python object implementing the Provider protocol with methods
                     for blockchain operations (get_parameters, get_unspent_outputs, etc.)

        Raises:
            CardanoError: If provider creation fails in the C library.
        """
        self._provider = provider
        self._provider_ptr = ffi.new("cardano_provider_t**")
        self._impl = ffi.new("cardano_provider_impl_t*")

        # Keep callbacks alive on the instance to prevent garbage collection
        self._cb_get_parameters = None
        self._cb_get_unspent_outputs = None
        self._cb_get_rewards_balance = None
        self._cb_get_unspent_outputs_with_asset = None
        self._cb_get_unspent_output_by_nft = None
        self._cb_resolve_unspent_outputs = None
        self._cb_resolve_datum = None
        self._cb_confirm_transaction = None
        self._cb_submit_transaction = None
        self._cb_evaluate_transaction = None

        self._fill_impl_struct()
        self._create_provider()

    def _fill_impl_struct(self) -> None:
        """Fill the cardano_provider_impl_t struct with provider data and callbacks."""
        impl = self._impl[0]

        # Set provider name using ffi.memmove
        name_bytes = self._provider.get_name().encode("utf-8")
        max_len = len(impl.name) - 1
        name_bytes = name_bytes[:max_len]
        ffi.memmove(impl.name, name_bytes, len(name_bytes))
        impl.name[len(name_bytes)] = b"\x00"

        # Initialize error_message to empty
        impl.error_message[0] = b"\x00"

        # Set network magic
        impl.network_magic = self._provider.get_network_magic()

        # Context: not used in Python implementation
        impl.context = ffi.NULL

        # Install all callbacks
        self._install_callbacks(impl)

    # pylint: disable=too-many-statements,broad-except
    def _install_callbacks(self, impl) -> None:
        """Create and install all callback functions.

        Note: All callbacks use broad exception handling (Exception) intentionally.
        FFI callbacks must not raise Python exceptions as this would crash the C code.
        """
        provider = self._provider

        def set_error_message(msg: str) -> None:
            """Helper to set error message in impl struct."""
            msg_bytes = msg.encode("utf-8")[: len(impl.error_message) - 1]
            ffi.memmove(impl.error_message, msg_bytes, len(msg_bytes))
            impl.error_message[len(msg_bytes)] = b"\x00"

        # ----------------------------------------------------------------
        # get_parameters callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_protocol_parameters_t**)"
        )
        def cb_get_parameters(_impl, out_params):
            try:
                params = provider.get_parameters()
                # Increment ref count since C will take ownership
                lib.cardano_protocol_parameters_ref(params._ptr)
                out_params[0] = params._ptr
                return 0
            except Exception as exc:
                set_error_message(f"get_parameters: {exc}")
                return 1  # CARDANO_ERROR_GENERIC

        self._cb_get_parameters = cb_get_parameters
        impl.get_parameters = cb_get_parameters

        # ----------------------------------------------------------------
        # get_unspent_outputs callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_address_t*, cardano_utxo_list_t**)"
        )
        def cb_get_unspent_outputs(_impl, c_address, out_list):
            try:
                from ..address import Address
                from ..common.utxo_list import UtxoList

                # Wrap C address - increment ref since we're creating a new wrapper
                lib.cardano_address_ref(c_address)
                addr = Address(c_address)

                # Call Python provider
                utxos = provider.get_unspent_outputs(addr)

                # Build UtxoList from Python list
                utxo_list = UtxoList.from_list(utxos) if isinstance(utxos, list) else utxos

                # Increment ref count since C will take ownership
                lib.cardano_utxo_list_ref(utxo_list._ptr)
                out_list[0] = utxo_list._ptr
                return 0
            except Exception as exc:
                set_error_message(f"get_unspent_outputs: {exc}")
                return 1

        self._cb_get_unspent_outputs = cb_get_unspent_outputs
        impl.get_unspent_outputs = cb_get_unspent_outputs

        # ----------------------------------------------------------------
        # get_rewards_balance callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_reward_address_t*, uint64_t*)"
        )
        def cb_get_rewards_balance(_impl, c_reward_addr, out_rewards):
            try:
                from ..address import RewardAddress

                # Wrap C reward address
                lib.cardano_reward_address_ref(c_reward_addr)
                addr = RewardAddress(c_reward_addr)

                # Call Python provider
                rewards = provider.get_rewards_balance(addr)
                out_rewards[0] = int(rewards)
                return 0
            except Exception as exc:
                set_error_message(f"get_rewards_balance: {exc}")
                return 1

        self._cb_get_rewards_balance = cb_get_rewards_balance
        impl.get_rewards_balance = cb_get_rewards_balance

        # ----------------------------------------------------------------
        # get_unspent_outputs_with_asset callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_address_t*, cardano_asset_id_t*, cardano_utxo_list_t**)"
        )
        def cb_get_unspent_outputs_with_asset(_impl, c_address, c_asset_id, out_list):
            try:
                from ..address import Address
                from ..assets import AssetId
                from ..common.utxo_list import UtxoList

                # Wrap C types
                lib.cardano_address_ref(c_address)
                addr = Address(c_address)

                lib.cardano_asset_id_ref(c_asset_id)
                asset_id = AssetId(c_asset_id)

                # Call Python provider
                utxos = provider.get_unspent_outputs_with_asset(addr, asset_id)

                # Build UtxoList
                utxo_list = UtxoList.from_list(utxos) if isinstance(utxos, list) else utxos

                lib.cardano_utxo_list_ref(utxo_list._ptr)
                out_list[0] = utxo_list._ptr
                return 0
            except Exception as exc:
                set_error_message(f"get_unspent_outputs_with_asset: {exc}")
                return 1

        self._cb_get_unspent_outputs_with_asset = cb_get_unspent_outputs_with_asset
        impl.get_unspent_outputs_with_asset = cb_get_unspent_outputs_with_asset

        # ----------------------------------------------------------------
        # get_unspent_output_by_nft callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_asset_id_t*, cardano_utxo_t**)"
        )
        def cb_get_unspent_output_by_nft(_impl, c_asset_id, out_utxo):
            try:
                from ..assets import AssetId

                # Wrap C asset id
                lib.cardano_asset_id_ref(c_asset_id)
                asset_id = AssetId(c_asset_id)

                # Call Python provider
                utxo = provider.get_unspent_output_by_nft(asset_id)

                lib.cardano_utxo_ref(utxo._ptr)
                out_utxo[0] = utxo._ptr
                return 0
            except Exception as exc:
                set_error_message(f"get_unspent_output_by_nft: {exc}")
                return 1

        self._cb_get_unspent_output_by_nft = cb_get_unspent_output_by_nft
        impl.get_unspent_output_by_nft = cb_get_unspent_output_by_nft

        # ----------------------------------------------------------------
        # resolve_unspent_outputs callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_transaction_input_set_t*, cardano_utxo_list_t**)"
        )
        def cb_resolve_unspent_outputs(_impl, c_tx_ins, out_list):
            try:
                from ..transaction_body import TransactionInputSet
                from ..common.utxo_list import UtxoList

                # Wrap C transaction input set
                lib.cardano_transaction_input_set_ref(c_tx_ins)
                tx_ins = TransactionInputSet(c_tx_ins)

                # Call Python provider
                utxos = provider.resolve_unspent_outputs(tx_ins)

                # Build UtxoList
                utxo_list = UtxoList.from_list(utxos) if isinstance(utxos, list) else utxos

                lib.cardano_utxo_list_ref(utxo_list._ptr)
                out_list[0] = utxo_list._ptr
                return 0
            except Exception as exc:
                set_error_message(f"resolve_unspent_outputs: {exc}")
                return 1

        self._cb_resolve_unspent_outputs = cb_resolve_unspent_outputs
        impl.resolve_unspent_outputs = cb_resolve_unspent_outputs

        # ----------------------------------------------------------------
        # resolve_datum callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_blake2b_hash_t*, cardano_plutus_data_t**)"
        )
        def cb_resolve_datum(_impl, c_datum_hash, out_datum):
            try:
                from ..cryptography import Blake2bHash
                from ..plutus_data import PlutusData
                from ..cbor.cbor_reader import CborReader

                # Wrap C datum hash
                lib.cardano_blake2b_hash_ref(c_datum_hash)
                datum_hash = Blake2bHash(c_datum_hash)

                # Call Python provider - returns CBOR hex string
                datum_cbor_hex = provider.resolve_datum(datum_hash)

                # Parse CBOR to PlutusData
                reader = CborReader.from_hex(datum_cbor_hex)
                datum = PlutusData.from_cbor(reader)

                lib.cardano_plutus_data_ref(datum._ptr)
                out_datum[0] = datum._ptr
                return 0
            except Exception as exc:
                set_error_message(f"resolve_datum: {exc}")
                return 1

        self._cb_resolve_datum = cb_resolve_datum
        impl.resolve_datum = cb_resolve_datum

        # ----------------------------------------------------------------
        # await_transaction_confirmation callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_blake2b_hash_t*, uint64_t, bool*)"
        )
        def cb_confirm_transaction(_impl, c_tx_id, timeout_ms, out_confirmed):
            try:
                from ..cryptography import Blake2bHash

                # Wrap C tx id
                lib.cardano_blake2b_hash_ref(c_tx_id)
                tx_id = Blake2bHash(c_tx_id)

                # Call Python provider
                confirmed = provider.confirm_transaction(tx_id.to_hex(), int(timeout_ms))
                out_confirmed[0] = bool(confirmed)
                return 0
            except Exception as exc:
                set_error_message(f"confirm_transaction: {exc}")
                return 1

        self._cb_confirm_transaction = cb_confirm_transaction
        impl.await_transaction_confirmation = cb_confirm_transaction

        # ----------------------------------------------------------------
        # post_transaction_to_chain callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_transaction_t*, cardano_blake2b_hash_t**)"
        )
        def cb_submit_transaction(_impl, c_tx, out_tx_id):
            try:
                from ..transaction import Transaction
                from ..cryptography import Blake2bHash
                from ..cbor.cbor_writer import CborWriter

                # Wrap C transaction
                lib.cardano_transaction_ref(c_tx)
                transaction = Transaction(c_tx)

                # Serialize to CBOR hex
                writer = CborWriter()
                transaction.to_cbor(writer)
                tx_cbor_hex = writer.encode().hex()

                # Call Python provider
                tx_id_hex = provider.submit_transaction(tx_cbor_hex)

                # Create Blake2bHash from returned tx id
                tx_id_hash = Blake2bHash.from_hex(tx_id_hex)

                lib.cardano_blake2b_hash_ref(tx_id_hash._ptr)
                out_tx_id[0] = tx_id_hash._ptr
                return 0
            except Exception as exc:
                set_error_message(f"submit_transaction: {exc}")
                return 1

        self._cb_submit_transaction = cb_submit_transaction
        impl.post_transaction_to_chain = cb_submit_transaction

        # ----------------------------------------------------------------
        # evaluate_transaction callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_provider_impl_t*, cardano_transaction_t*, cardano_utxo_list_t*, cardano_redeemer_list_t**)"
        )
        def cb_evaluate_transaction(_impl, c_tx, c_additional_utxos, out_redeemers):
            try:
                from ..transaction import Transaction
                from ..common.utxo_list import UtxoList
                from ..witness_set import RedeemerList
                from ..cbor.cbor_writer import CborWriter

                # Wrap C transaction
                lib.cardano_transaction_ref(c_tx)
                transaction = Transaction(c_tx)

                # Serialize transaction to CBOR hex
                writer = CborWriter()
                transaction.to_cbor(writer)
                tx_cbor_hex = writer.encode().hex()

                # Wrap additional UTXOs if provided
                additional_utxos = None
                if c_additional_utxos != ffi.NULL:
                    lib.cardano_utxo_list_ref(c_additional_utxos)
                    additional_utxos = UtxoList(c_additional_utxos)

                # Call Python provider
                redeemers = provider.evaluate_transaction(tx_cbor_hex, additional_utxos)

                # Build RedeemerList from Python list
                redeemer_list = RedeemerList.from_list(redeemers) if isinstance(redeemers, list) else redeemers

                lib.cardano_redeemer_list_ref(redeemer_list._ptr)
                out_redeemers[0] = redeemer_list._ptr
                return 0
            except Exception as exc:
                set_error_message(f"evaluate_transaction: {exc}")
                return 1

        self._cb_evaluate_transaction = cb_evaluate_transaction
        impl.evaluate_transaction = cb_evaluate_transaction

    def _create_provider(self) -> None:
        """Create the cardano_provider_t* from the implementation struct."""
        result = lib.cardano_provider_new(self._impl[0], self._provider_ptr)
        if result != 0:
            msg = ffi.string(self._impl[0].error_message).decode("utf-8", "ignore")
            raise CardanoError(f"cardano_provider_new failed: {result} {msg!r}")

    @property
    def ptr(self):
        """
        Return the underlying cardano_provider_t* as a cdata pointer.

        Returns:
            A CFFI cdata pointer to cardano_provider_t that can be passed to C functions.
        """
        return self._provider_ptr[0]

    def __del__(self):
        """
        Destructor that releases the C provider reference.

        Decrements the reference count of the underlying cardano_provider_t*.
        This is called automatically when the ProviderHandle is garbage collected.
        """
        if self._provider_ptr is not None and self._provider_ptr[0] != ffi.NULL:
            lib.cardano_provider_unref(self._provider_ptr)
            self._provider_ptr = None

    def __enter__(self) -> ProviderHandle:
        """
        Enter context manager.

        Returns:
            Self for use in 'with' statements.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit context manager.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_val: Exception value if an exception occurred, None otherwise.
            exc_tb: Exception traceback if an exception occurred, None otherwise.
        """
