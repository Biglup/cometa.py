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

# pylint: disable=too-many-lines

from __future__ import annotations

from typing import Union, List, TYPE_CHECKING
from .._ffi import ffi, lib
from ..errors import CardanoError, cardano_error_to_string
from .coin_selection import CoinSelectorHandle, CoinSelector
from .evaluation import TxEvaluatorHandle, TxEvaluator
from .transaction_builder_base import TransactionBuilderBase, _to_reward_address

if TYPE_CHECKING:
    from ..address import Address, RewardAddress
    from ..common import UtxoList, Utxo
    from ..transaction import Transaction, SubTransaction
    from ..transaction_body import AccountBalanceInterval


class TxBuilder(TransactionBuilderBase):
    """
    High-level transaction builder for the Cardano blockchain.

    The ``TxBuilder`` provides a fluent, Pythonic interface for constructing
    Cardano transactions. It encapsulates the complexities of transaction
    assembly, balancing, fee calculation, and UTXO management.

    **Key Concepts:**

    - **UTXOs**: Cardano uses an Unspent Transaction Output model. Each output
      from a previous transaction becomes an input for future transactions.
    - **Coin Selection**: The builder automatically selects UTXOs to cover the
      transaction's outputs and fees using configurable strategies.
    - **Balancing**: The builder ensures inputs equal outputs + fees, sending
      any excess to the change address.
    - **Plutus Scripts**: Smart contracts that validate spending, minting, or
      staking operations. They require redeemers (arguments) and consume
      execution units (CPU/memory).

    **Basic Usage:**

    Example:
        >>> from cometa import TxBuilder, SlotConfig
        >>>
        >>> # Initialize with protocol parameters and slot configuration
        >>> slot_config = SlotConfig.mainnet()
        >>> builder = TxBuilder(protocol_params, slot_config)
        >>>
        >>> # Configure and build a simple transfer
        >>> tx = builder \\
        ...     .set_change_address(my_address) \\
        ...     .set_utxos(my_utxos) \\
        ...     .send_lovelace(recipient, 5_000_000) \\
        ...     .expires_in(3600) \\
        ...     .build()
        >>>
        >>> # Sign and submit
        >>> signed_tx = wallet.sign_transaction(tx)
        >>> tx_hash = provider.submit_transaction(signed_tx)

    Note:
        All configuration and validation errors are deferred until ``build()``
        is called. This allows for flexible, incremental transaction construction.

    See Also:
        - :class:`Transaction`: The resulting transaction object
        - :class:`ProtocolParameters`: Required protocol configuration
        - :class:`SlotConfig`: Network timing configuration
        - :class:`CoinSelector`: Customizable UTXO selection strategies
        - :class:`TxEvaluator`: Customizable Plutus script evaluation strategies
    """


    def set_coin_selector(
        self,
        coin_selector: CoinSelector,
    ) -> TxBuilder:
        """
        Set the coin selection strategy for UTXO selection.

        The coin selector determines how UTXOs are chosen to cover the transaction's
        required value. Different strategies optimize for different goals:

        - **Large First**: Minimizes number of inputs by using largest UTXOs first
        - **Random Improve**: Balances between reducing fragmentation and privacy

        If not set, defaults to the native Random Improve strategy.

        Args:
            coin_selector: The coin selection strategy to use.

        Returns:
            Self for method chaining.

        Example:
            >>> class MySelector:
            ...     def get_name(self) -> str:
            ...         return "MySelector"
            ...     def select(self, pre_selected, available, target):
            ...         return selected, remaining
            >>> builder.set_coin_selector(MySelector())
        """
        self._coin_selector_handle = CoinSelectorHandle(coin_selector)
        selector_ptr = self._coin_selector_handle.ptr
        lib.cardano_tx_builder_set_coin_selector(self._ptr, selector_ptr)
        return self


    def set_evaluator(
        self,
        evaluator: TxEvaluator,
    ) -> TxBuilder:
        """
        Set the transaction evaluator for Plutus script execution.

        The evaluator computes execution units (CPU and memory) required for
        Plutus scripts. This is essential for accurate fee calculation when
        transactions contain smart contracts.

        If not set, uses cardano-c's native Plutus evaluator.

        Args:
            evaluator: The transaction evaluator to use.`

        Returns:
            Self for method chaining.

        Example:
            >>> class MyEvaluator:
            ...     def get_name(self) -> str:
            ...         return "MyEvaluator"
            ...     def evaluate(self, transaction, additional_utxos):
            ...         return redeemers
            >>> builder.set_evaluator(MyEvaluator())
        """
        from .evaluation.c_tx_evaluator_wrapper import CTxEvaluatorWrapper
        handle = evaluator if isinstance(evaluator, CTxEvaluatorWrapper) else TxEvaluatorHandle(evaluator)
        lib.cardano_tx_builder_set_tx_evaluator(self._ptr, handle.ptr)
        self._evaluator_handle = handle
        return self


    def set_change_address(self, address: Union["Address", str]) -> TxBuilder:
        """
        Set the address for receiving change.

        After covering outputs and fees, any remaining value from inputs is
        sent to this address. This is typically your own wallet address.

        Args:
            address: The change address. Can be an ``Address`` object or a
                bech32-encoded address string (e.g., "addr_test1...").

        Returns:
            Self for method chaining.

        Example:
            >>> builder.set_change_address("addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k...")
            >>> # Or with Address object
            >>> builder.set_change_address(my_address)
        """
        if isinstance(address, str):
            addr_bytes = address.encode("utf-8")
            lib.cardano_tx_builder_set_change_address_ex(
                self._ptr, addr_bytes, len(addr_bytes)
            )
        else:
            lib.cardano_tx_builder_set_change_address(self._ptr, address._ptr)
        return self


    def set_collateral_change_address(self, address: Union["Address", str]) -> TxBuilder:
        """
        Set the address for receiving collateral change.

        When a transaction includes Plutus scripts, collateral is required as
        a guarantee. If the collateral inputs exceed the required amount,
        the excess is sent to this address.

        If not set, defaults to the regular change address.

        Args:
            address: The collateral change address. Can be an ``Address`` object
                or a bech32-encoded address string.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.set_collateral_change_address("addr_test1...")
        """
        if isinstance(address, str):
            addr_bytes = address.encode("utf-8")
            lib.cardano_tx_builder_set_collateral_change_address_ex(
                self._ptr, addr_bytes, len(addr_bytes)
            )
        else:
            lib.cardano_tx_builder_set_collateral_change_address(self._ptr, address._ptr)
        return self


    def set_minimum_fee(self, fee: int) -> TxBuilder:
        """
        Set a minimum fee for the transaction.

        This overrides the calculated fee if it's higher. Useful when you need
        to ensure a specific fee amount regardless of transaction size.

        Args:
            fee: The minimum fee in lovelace (1 ADA = 1,000,000 lovelace).

        Returns:
            Self for method chaining.

        Example:
            >>> builder.set_minimum_fee(200_000)  # At least 0.2 ADA
        """
        lib.cardano_tx_builder_set_minimum_fee(self._ptr, fee)
        return self


    def set_utxos(self, utxos: Union["UtxoList", List["Utxo"]]) -> TxBuilder:
        """
        Set the available UTXOs for coin selection.

        These UTXOs will be used by the coin selector to cover the transaction's
        required inputs. Typically, these are all spendable UTXOs from your wallet.

        Args:
            utxos: List of available UTXOs. Can be a ``UtxoList`` or a Python
                list of ``Utxo`` objects.

        Returns:
            Self for method chaining.

        Example:
            >>> # Get UTXOs from provider
            >>> my_utxos = provider.get_utxos_at_address(my_address)
            >>> builder.set_utxos(my_utxos)
        """
        from ..common.utxo_list import UtxoList

        if isinstance(utxos, list):
            utxos = UtxoList.from_list(utxos)
        lib.cardano_tx_builder_set_utxos(self._ptr, utxos._ptr)
        return self


    def set_collateral_utxos(self, utxos: Union["UtxoList", List["Utxo"]]) -> TxBuilder:
        """
        Set UTXOs to use for script collateral.

        Collateral is required when a transaction includes Plutus scripts.
        It serves as a guarantee that gets forfeited if script validation fails.

        Collateral UTXOs should:
        - Contain only ADA (no native tokens)
        - Be from a key-based address (not a script address)
        - Have sufficient value to cover the collateral requirement

        If not set, the builder will try to use UTXOs from ``set_utxos()``.

        Args:
            utxos: List of UTXOs designated for collateral.

        Returns:
            Self for method chaining.

        Example:
            >>> # Use specific UTXOs for collateral
            >>> builder.set_collateral_utxos(ada_only_utxos)
        """
        from ..common.utxo_list import UtxoList

        if isinstance(utxos, list):
            utxos = UtxoList.from_list(utxos)
        lib.cardano_tx_builder_set_collateral_utxos(self._ptr, utxos._ptr)
        return self


    def pad_signer_count(self, count: int) -> TxBuilder:
        """
        Reserve space for additional signers in fee calculation.

        Use this when the final number of signers isn't known during
        transaction building, but you need accurate fee estimation.

        Args:
            count: Number of additional signers to account for.

        Returns:
            Self for method chaining.

        Example:
            >>> # Expect 3 additional signers
            >>> builder.pad_signer_count(3)
        """
        lib.cardano_tx_builder_pad_signer_count(self._ptr, count)
        return self


    def build(self) -> "Transaction":
        """
        Build and finalize the transaction.

        This method:
        1. Validates all configuration
        2. Performs coin selection to balance inputs/outputs
        3. Calculates fees
        4. Adds change output
        5. Evaluates Plutus scripts (if any)
        6. Constructs the final transaction

        Returns:
            The built (unsigned) ``Transaction`` ready for signing.

        Raises:
            CardanoError: If the transaction cannot be built due to:
                - Insufficient funds
                - Invalid configuration
                - Script evaluation failure
                - Protocol parameter violations

        Example:
            >>> tx = builder.build()
            >>> print(f"Transaction fee: {tx.body.fee} lovelace")
            >>>
            >>> # Sign and submit
            >>> signed_tx = sign_transaction(tx, private_key)
            >>> tx_hash = provider.submit_transaction(signed_tx)

        Note:
            The returned transaction is unsigned. You must sign it with
            the appropriate private keys before submission.
        """
        from ..transaction import Transaction

        tx_out = ffi.new("cardano_transaction_t**")
        self._deferred_errors.clear()
        err = lib.cardano_tx_builder_build(self._ptr, tx_out)
        if self._deferred_errors:
            lib.cardano_transaction_unref(tx_out)
            cause = self._deferred_errors.pop()
            self._deferred_errors.clear()
            raise CardanoError(f"Deferred redeemer failed: {cause}") from cause

        if err != 0:
            error_msg = self.get_last_error()
            raise CardanoError(
                f"Failed to build transaction (error code: {err} - {cardano_error_to_string(err)}): {error_msg}"
            )

        return Transaction(tx_out[0])



    def add_starting_account_balance_interval(
        self, reward_address: Union["RewardAddress", str], interval: "AccountBalanceInterval"
    ) -> TxBuilder:
        """Constrain the account balance at the start of the block (Dijkstra)."""
        address = _to_reward_address(reward_address)
        lib.cardano_tx_builder_add_starting_account_balance_interval(
            self._ptr, address._ptr, interval._ptr)
        return self

    def add_sub_transaction(self, transaction: "SubTransaction",
                            resolved_utxos: Union["UtxoList", List["Utxo"]]) -> TxBuilder:
        """Include a signed intent, preserving its body and witnesses.

        Resolve all its spent inputs and any reference inputs used for scripts.
        The enclosing builder balances the batch and pays its fees/collateral.
        """
        from ..common.utxo_list import UtxoList
        inputs = UtxoList.from_list(resolved_utxos) if isinstance(resolved_utxos, list) else resolved_utxos
        lib.cardano_tx_builder_add_sub_transaction(self._ptr, transaction._ptr, inputs._ptr)
        return self
