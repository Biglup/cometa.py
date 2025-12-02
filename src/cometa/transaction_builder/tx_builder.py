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

import datetime
import time
from typing import Optional, Union, List, TYPE_CHECKING, Dict, Any

from ..scripts import Script, ScriptLike, PlutusV2Script, PlutusV3Script, NativeScriptLike, PlutusV1Script
from ..providers import Provider, ProviderHandle
from ..common.network_id import NetworkId
from .._ffi import ffi, lib
from ..errors import CardanoError, cardano_error_to_string
from ..cryptography import Blake2bHash
from ..assets import AssetId, AssetName

from .coin_selection import (
    CoinSelectorHandle,
    CoinSelector,
)
from .evaluation import (
    TxEvaluatorHandle,
    TxEvaluator,
)

if TYPE_CHECKING:
    from ..protocol_params import ProtocolParameters
    from ..address import Address, RewardAddress
    from ..common import UtxoList, Utxo
    from ..transaction import Transaction
    from ..transaction_body import TransactionOutput, Value
    from ..plutus_data import PlutusData, Datum, Script
    from ..common import (
        DRep,
        Voter,
        GovernanceActionId,
        VotingProcedure,
        Anchor,
        ProtocolParamUpdate,
        ProtocolVersion,
        Constitution,
        UnitInterval,
        WithdrawalMap,
    )
    from ..certificates import Certificate
    from ..common import CommitteeMembersMap, CredentialSet
    from ..auxiliary_data import Metadatum


def _to_reward_address(value: Union["RewardAddress", str]) -> "RewardAddress":
    """Convert string to RewardAddress if needed."""
    if isinstance(value, str):
        from ..address import RewardAddress
        return RewardAddress.from_bech32(value)
    return value


def _to_drep(value: Union["DRep", str]) -> "DRep":
    """Convert string to DRep if needed."""
    if isinstance(value, str):
        from ..common import DRep
        return DRep.from_string(value)
    return value


class TxBuilder:
    """
    High-level transaction builder for the Cardano blockchain.

    The ``TxBuilder`` provides a fluent, Pythonic interface for constructing
    Cardano transactions. It encapsulates the complexities of transaction
    assembly, balancing, fee calculation, and validation.

    Note:
        All configuration and validation errors are deferred until ``build()``
        is called. This allows for flexible, incremental transaction construction.

    See Also:
        - :class:`Transaction`: The resulting transaction object
        - :class:`ProtocolParameters`: Required protocol configuration
        - :class:`CoinSelector`: Customizable UTXO selection strategies
        - :class:`TxEvaluator`: Customizable Plutus script evaluation strategies
    """

    def __init__(
        self,
        protocol_params: ProtocolParameters,
        provider: Provider,
    ) -> None:
        """
        Create a new transaction builder.

        Args:
            protocol_params: Protocol parameters for fee calculation and validation.
                These define network-specific rules like minimum fees, max transaction
                size, and execution unit costs.
            provider: A provider instance for fetching chain data. The provider is
                used to resolve UTXOs, query protocol parameters, and evaluate
                Plutus scripts.

        Raises:
            CardanoError: If the builder cannot be initialized (e.g., invalid
                parameters or provider).

        Example:
            >>> from cometa import TxBuilder
            >>>
            >>> builder = TxBuilder(protocol_params, provider)
        """
        self._provider = ProviderHandle(provider)
        self._ptr = lib.cardano_tx_builder_new(protocol_params._ptr, self._provider.ptr)
        if self._ptr == ffi.NULL:
            raise CardanoError("Failed to create transaction builder")

        self._coin_selector_handle: Optional[CoinSelectorHandle] = None
        self._evaluator_handle: Optional[TxEvaluatorHandle] = None

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_tx_builder_t**", self._ptr)
            lib.cardano_tx_builder_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TxBuilder:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "TxBuilder()"

    # =========================================================================
    # Configuration Methods
    # =========================================================================

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

        If not set, defaults to the Large First strategy.

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

        If not set, defaults to using the provider's built-in evaluator.

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
        self._evaluator_handle = TxEvaluatorHandle(evaluator)
        evaluator_ptr = self._evaluator_handle.ptr
        lib.cardano_tx_builder_set_tx_evaluator(self._ptr, evaluator_ptr)
        return self

    def set_network_id(self, network_id: NetworkId) -> TxBuilder:
        """
        Set the target network for this transaction.

        The network ID is included in the transaction body and ensures the
        transaction can only be submitted to the intended network.

        Args:
            network_id: The network identifier.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.set_network_id(NetworkId.TESTNET)  # Testnet
            >>> builder.set_network_id(NetworkId.MAINNET)  # Mainnet
        """
        lib.cardano_tx_builder_set_network_id(self._ptr, network_id)
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

    def set_donation(self, amount: int) -> TxBuilder:
        """
        Set a treasury donation amount.

        This Conway-era feature allows contributing ADA directly to the
        Cardano treasury as part of a transaction.

        Args:
            amount: The donation amount in lovelace.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.set_donation(1_000_000)  # Donate 1 ADA to treasury
        """
        lib.cardano_tx_builder_set_donation(self._ptr, amount)
        return self

    # =========================================================================
    # UTXO Configuration
    # =========================================================================

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

    def set_valid_until(
        self,
        *,
        slot: Optional[int] = None,
        unix_time: Optional[int] = None,
    ) -> TxBuilder:
        """
        Set when the transaction expires (invalid_hereafter).

        The transaction will be rejected if not included in a block before
        this point. You must specify either ``slot`` or ``unix_time``, not both.

        Args:
            slot: The slot number after which the transaction becomes invalid.
            unix_time: Unix timestamp (seconds since epoch) after which the
                transaction becomes invalid.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If neither or both parameters are provided.

        Example:
            >>> # Expire after specific slot
            >>> builder.set_valid_until(slot=12345678)
            >>>
            >>> # Expire 2 hours from now
            >>> import time
            >>> builder.set_valid_until(unix_time=int(time.time()) + 7200)
        """
        if slot is not None and unix_time is not None:
            raise ValueError("Specify either 'slot' or 'unix_time', not both")
        if slot is None and unix_time is None:
            raise ValueError("Must specify either 'slot' or 'unix_time'")

        if slot is not None:
            lib.cardano_tx_builder_set_invalid_after(self._ptr, slot)
        else:
            lib.cardano_tx_builder_set_invalid_after_ex(self._ptr, unix_time)
        return self

    def set_valid_from(
        self,
        *,
        slot: Optional[int] = None,
        unix_time: Optional[int] = None,
    ) -> TxBuilder:
        """
        Set when the transaction becomes valid (invalid_before).

        The transaction will be rejected if included in a block before this
        point. Useful for time-locked contracts.

        You must specify either ``slot`` or ``unix_time``, not both.

        Args:
            slot: The slot number before which the transaction is invalid.
            unix_time: Unix timestamp (seconds since epoch) before which the
                transaction is invalid.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If neither or both parameters are provided.

        Example:
            >>> # Valid starting from specific slot
            >>> builder.set_valid_from(slot=12345000)
            >>>
            >>> # Valid starting 1 hour from now
            >>> import time
            >>> builder.set_valid_from(unix_time=int(time.time()) + 3600)
        """
        if slot is not None and unix_time is not None:
            raise ValueError("Specify either 'slot' or 'unix_time', not both")
        if slot is None and unix_time is None:
            raise ValueError("Must specify either 'slot' or 'unix_time'")

        if slot is not None:
            lib.cardano_tx_builder_set_invalid_before(self._ptr, slot)
        else:
            lib.cardano_tx_builder_set_invalid_before_ex(self._ptr, unix_time)
        return self

    def expires_in(self, seconds: int) -> "TxBuilder":
        """
        Sets the transaction to be valid for a specific duration from now.

        This is a convenience method that calculates a future expiration date and sets it.
        The transaction will be marked as invalid if it is not included in a block
        within the specified duration.

        Args:
            seconds: The number of seconds from now that the transaction should remain valid.

        Returns:
            Self for method chaining.

        Example:
            >>> # Set the transaction to expire in 3 minutes (180 seconds) from now.
            >>> builder.expires_in(180)
        """
        now = int(time.time())
        return self.set_valid_until(unix_time=now + seconds)

    def expires_after(self, date: datetime) -> "TxBuilder":
        """
        Sets the transaction's expiration to a specific, absolute date and time.

        This function marks the transaction as invalid if it is not included in a block
        before the specified date.

        Args:
            date: The absolute date and time after which the transaction will be invalid.

        Returns:
            Self for method chaining.

        Example:
            >>> # Set the transaction to expire on New Year's Day, 2026.
            >>> from datetime import datetime, timezone
            >>> expiry_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
            >>> builder.expires_after(expiry_date)
        """
        unix_time = int(date.timestamp())
        return self.set_valid_until(unix_time=unix_time)

    def set_invalid_before(self, slot: int) -> "TxBuilder":
        """
        Sets the transaction's validity start time using an absolute slot number.

        This function marks the transaction as invalid if it is included in a block
        created before the specified slot.

        Args:
            slot: The absolute slot number before which this transaction is invalid.

        Returns:
            Self for method chaining.
        """
        return self.set_valid_from(slot=slot)

    def valid_from_date(self, date: datetime) -> "TxBuilder":
        """
        Sets the transaction's validity start time to a specific, absolute date and time.
        The transaction will be invalid if processed before this date.

        Args:
            date: The absolute date and time from which the transaction will be valid.

        Returns:
            Self for method chaining.

        Example:
            >>> # Make the transaction valid starting on New Year's Day, 2026.
            >>> from datetime import datetime, timezone
            >>> start_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
            >>> builder.valid_from_date(start_date)
        """
        unix_time = int(date.timestamp())
        return self.set_valid_from(unix_time=unix_time)

    def valid_after(self, seconds: int) -> "TxBuilder":
        """
        Sets the transaction to become valid only after a specified duration from now.
        This is a convenience method that calculates a future start date.

        Args:
            seconds: The number of seconds from now to wait before the transaction becomes valid.

        Returns:
            Self for method chaining.

        Example:
            >>> # Make the transaction valid only after 1 hour (3600 seconds) has passed.
            >>> builder.valid_after(3600)
        """
        now = int(time.time())
        return self.set_valid_from(unix_time=now + seconds)

    def send_lovelace(
        self,
        address: Union["Address", str],
        amount: int,
    ) -> TxBuilder:
        """
        Send ADA to an address.

        Creates an output that sends the specified amount of lovelace to the
        given address. This is the simplest way to transfer ADA.

        Args:
            address: The recipient address. Can be an ``Address`` object or
                a bech32-encoded address string.
            amount: The amount to send in lovelace (1 ADA = 1,000,000 lovelace).

        Returns:
            Self for method chaining.

        Example:
            >>> # Send 5 ADA
            >>> builder.send_lovelace("addr_test1...", 5_000_000)
            >>>
            >>> # Send 1.5 ADA
            >>> builder.send_lovelace(recipient_address, 1_500_000)
        """
        if isinstance(address, str):
            addr_bytes = address.encode("utf-8")
            lib.cardano_tx_builder_send_lovelace_ex(
                self._ptr, addr_bytes, len(addr_bytes), amount
            )
        else:
            lib.cardano_tx_builder_send_lovelace(self._ptr, address._ptr, amount)
        return self

    def send_value(
        self,
        address: Union["Address", str],
        value: "Value",
    ) -> TxBuilder:
        """
        Send a multi-asset value to an address.

        Creates an output containing ADA and/or native tokens. Use this when
        transferring tokens or when you need precise control over the output value.

        Args:
            address: The recipient address. Can be an ``Address`` object or
                a bech32-encoded address string.
            value: The value to send, containing ADA and optional native tokens.

        Returns:
            Self for method chaining.

        Example:
            >>> from cometa.transaction_body import Value
            >>>
            >>> # Create value with ADA and tokens
            >>> value = Value.from_coin(2_000_000)
            >>> value.add_asset(policy_id, asset_name, 100)
            >>>
            >>> builder.send_value("addr_test1...", value)
        """
        if isinstance(address, str):
            addr_bytes = address.encode("utf-8")
            lib.cardano_tx_builder_send_value_ex(
                self._ptr, addr_bytes, len(addr_bytes), value._ptr
            )
        else:
            lib.cardano_tx_builder_send_value(self._ptr, address._ptr, value._ptr)
        return self

    def lock_lovelace(
        self,
        script_address: Union["Address", str],
        amount: int,
        datum: "Datum",
    ) -> TxBuilder:
        """
        Lock ADA at a script address with a datum.

        Creates an output that sends ADA to a Plutus script address with an
        attached datum. The datum is required for the script to later validate
        spending of this output.

        Args:
            script_address: The script address to lock funds at.
            amount: The amount to lock in lovelace.
            datum: The datum to attach to the output. This data is used by
                the script when validating spending.

        Returns:
            Self for method chaining.

        Example:
            >>> from cometa.plutus_data import PlutusData
            >>>
            >>> # Create datum (e.g., a simple integer)
            >>> datum = PlutusData.from_int(42)
            >>>
            >>> # Lock 10 ADA at script
            >>> builder.lock_lovelace(script_address, 10_000_000, datum)
        """
        if isinstance(script_address, str):
            addr_bytes = script_address.encode("utf-8")
            lib.cardano_tx_builder_lock_lovelace_ex(
                self._ptr, addr_bytes, len(addr_bytes), amount, datum._ptr
            )
        else:
            lib.cardano_tx_builder_lock_lovelace(
                self._ptr, script_address._ptr, amount, datum._ptr
            )
        return self

    def lock_value(
        self,
        script_address: Union["Address", str],
        value: "Value",
        datum: "Datum",
    ) -> TxBuilder:
        """
        Lock a multi-asset value at a script address with a datum.

        Creates an output that sends ADA and/or native tokens to a Plutus
        script address with an attached datum.

        Args:
            script_address: The script address to lock funds at.
            value: The value to lock, containing ADA and optional native tokens.
            datum: The datum to attach to the output.

        Returns:
            Self for method chaining.

        Example:
            >>> # Lock tokens at a script address
            >>> value = Value.from_coin(5_000_000)
            >>> value.add_asset(policy_id, asset_name, 50)
            >>> builder.lock_value(script_addr, value, datum)
        """
        if isinstance(script_address, str):
            addr_bytes = script_address.encode("utf-8")
            lib.cardano_tx_builder_lock_value_ex(
                self._ptr, addr_bytes, len(addr_bytes), value._ptr, datum._ptr
            )
        else:
            lib.cardano_tx_builder_lock_value(
                self._ptr, script_address._ptr, value._ptr, datum._ptr
            )
        return self

    def add_input(
        self,
        utxo: "Utxo",
        redeemer: Optional["PlutusData"] = None,
        datum: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Add a specific UTXO as a transaction input.

        Use this to explicitly include a UTXO in the transaction, bypassing
        automatic coin selection. This is typically used for:

        - Spending from script addresses (with redeemer)
        - Including specific UTXOs that must be consumed
        - Script interactions where input order matters

        Args:
            utxo: The UTXO to spend.
            redeemer: The redeemer data for script validation. Required when
                spending from a Plutus script address.
            datum: The datum for the UTXO. Required if the UTXO doesn't have
                an inline datum and you're spending from a script address.

        Returns:
            Self for method chaining.

        Example:
            >>> # Spend from a key address (no redeemer needed)
            >>> builder.add_input(my_utxo)
            >>>
            >>> # Spend from a script address
            >>> builder.add_input(script_utxo, redeemer=spend_redeemer)
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        datum_ptr = datum._ptr if datum else ffi.NULL
        lib.cardano_tx_builder_add_input(self._ptr, utxo._ptr, redeemer_ptr, datum_ptr)
        return self

    def add_reference_input(self, utxo: "Utxo") -> TxBuilder:
        """
        Add a reference input to the transaction.

        Reference inputs allow reading UTXO data without spending it. This is
        useful for:

        - Reading on-chain data (oracles, configuration)
        - Referencing scripts without including them in the transaction
        - Sharing datum across multiple transactions

        Args:
            utxo: The UTXO to reference (not spend).

        Returns:
            Self for method chaining.

        Example:
            >>> # Reference an oracle UTXO
            >>> builder.add_reference_input(oracle_utxo)
        """
        lib.cardano_tx_builder_add_reference_input(self._ptr, utxo._ptr)
        return self

    def add_output(self, output: "TransactionOutput") -> TxBuilder:
        """
        Add a pre-built transaction output.

        Use this when you need full control over output construction,
        including inline datums, reference scripts, or complex configurations.

        Args:
            output: A fully constructed ``TransactionOutput`` object.

        Returns:
            Self for method chaining.

        Example:
            >>> from cometa.transaction_body import TransactionOutput
            >>>
            >>> output = TransactionOutput.new(address, 5_000_000)
            >>> output.set_inline_datum(my_datum)
            >>> builder.add_output(output)
        """
        lib.cardano_tx_builder_add_output(self._ptr, output._ptr)
        return self

    def mint_token(
        self,
        policy_id: Union["Blake2bHash", str, bytes],
        asset_name: Union["AssetName", str, bytes],
        amount: int,
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Mint or burn native tokens.

        Creates new tokens (positive amount) or burns existing tokens
        (negative amount) under the specified policy.

        Args:
            policy_id: The minting policy hash. Can be a ``Blake2bHash`` object,
                the raw bytes, or a hex-encoded string.
            asset_name: The token name. Can be an ``AssetName`` object, hex string,
                or raw bytes. Empty string for ADA-like unnamed tokens.
            amount: Number of tokens to mint (positive) or burn (negative).
            redeemer: The redeemer for Plutus minting policies.

        Returns:
            Self for method chaining.

        Example:
            >>> # Mint 1000 tokens
            >>> builder.mint_token(
            ...     policy_id="abc123...",
            ...     asset_name="MyToken",
            ...     amount=1000,
            ...     redeemer=mint_redeemer,
            ... )
            >>>
            >>> # Burn 50 tokens
            >>> builder.mint_token(policy_id, asset_name, amount=-50, redeemer=burn_redeemer)
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(policy_id, Blake2bHash):
            policy_obj = policy_id
        elif isinstance(policy_id, str):
            policy_obj = Blake2bHash.from_hex(policy_id.strip())
        elif isinstance(policy_id, (bytes, bytearray, memoryview)):
            policy_obj = Blake2bHash.from_bytes(bytes(policy_id))
        else:
            raise TypeError("policy_id must be Blake2bHash, hex string, or bytes")

        if isinstance(asset_name, AssetName):
            name_obj = asset_name
        elif isinstance(asset_name, str):
            s = asset_name

            if s == "":
                name_bytes = b""
            else:
                name_bytes = bytes.fromhex(s.strip())

            name_obj = AssetName.from_bytes(name_bytes)
        elif isinstance(asset_name, (bytes, bytearray, memoryview)):
            name_obj = AssetName.from_bytes(bytes(asset_name))
        else:
            raise TypeError("asset_name must be AssetName, string, or bytes")

        lib.cardano_tx_builder_mint_token(
            self._ptr,
            policy_obj._ptr,
            name_obj._ptr,
            amount,
            redeemer_ptr,
        )

        return self

    def mint_token_with_id(
        self,
        asset_id: Union["AssetId", str, bytes],
        amount: int,
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Mint or burn tokens using an asset ID.

        Alternative to ``mint_token()`` that uses the combined policy_id + asset_name
        identifier format.

        Args:
            asset_id: The full asset identifier. Can be an ``AssetId`` object
                or a hex string in the format "policy_id.asset_name".
            amount: Number of tokens to mint (positive) or burn (negative).
            redeemer: The redeemer for Plutus minting policies.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.mint_token_with_id(
            ...     "abc123...def456",  # policy_id.asset_name_hex
            ...     amount=500,
            ...     redeemer=mint_redeemer,
            ... )
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(asset_id, AssetId):
            lib.cardano_tx_builder_mint_token_with_id(
                self._ptr,
                asset_id._ptr,
                amount,
                redeemer_ptr,
            )
            return self

        if isinstance(asset_id, str):
            id_bytes = asset_id.strip().lower().encode("ascii")
            lib.cardano_tx_builder_mint_token_with_id_ex(
                self._ptr,
                id_bytes,
                len(id_bytes),
                amount,
                redeemer_ptr,
            )
            return self

        if isinstance(asset_id, (bytes, bytearray, memoryview)):
            raw = bytes(asset_id)
            hex_str = raw.hex()
            id_bytes = hex_str.encode("ascii")
            lib.cardano_tx_builder_mint_token_with_id_ex(
                self._ptr,
                id_bytes,
                len(id_bytes),
                amount,
                redeemer_ptr,
            )
            return self

        raise TypeError("asset_id must be AssetId, hex string, or bytes")

    def add_script(self, script: "ScriptLike") -> TxBuilder:
        """
        Add a script to the transaction witness set.

        Scripts must be included when:
        - Minting tokens with the script's policy
        - Spending from the script's address
        - Withdrawing from script-based stake credentials

        For reference scripts (CIP-33), use ``add_reference_input()`` instead.

        Args:
            script: The script to include (Native or Plutus).

        Returns:
            Self for method chaining.

        Example:
            >>> builder.add_script(minting_policy)
            >>> builder.add_script(spending_validator)
        """
        if isinstance(script, NativeScriptLike):
            script = Script.from_native(script)
        elif isinstance(script, PlutusV1Script):
            script = Script.from_plutus_v1(script)
        elif isinstance(script, PlutusV2Script):
            script = Script.from_plutus_v2(script)
        elif isinstance(script, PlutusV3Script):
            script = Script.from_plutus_v3(script)
        else:
            if not isinstance(script, Script):
                raise TypeError(
                    f"Expected Script, NativeScript or PlutusScript type, got {type(script).__name__}"
                )

        lib.cardano_tx_builder_add_script(self._ptr, script._ptr)
        return self

    def add_datum(self, datum: "PlutusData") -> TxBuilder:
        """
        Add a datum to the transaction witness set.

        Datums are required when spending UTXOs that have datum hashes
        (not inline datums). The datum must hash to the UTXO's datum hash.

        Args:
            datum: The datum to include.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.add_datum(original_datum)
        """
        lib.cardano_tx_builder_add_datum(self._ptr, datum._ptr)
        return self

    def add_signer(self, pub_key_hash: Union["Blake2bHash", str]) -> TxBuilder:
        """
        Add a required signer to the transaction.

        Required signers (CIP-30) specify that a particular key must sign
        the transaction. This is used by scripts that need to verify
        signatures from specific keys.

        Args:
            pub_key_hash: The public key hash of the required signer.
                Can be a ``Blake2bHash`` or hex string.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.add_signer("abc123...")  # Hex key hash
            >>> builder.add_signer(my_pub_key_hash)
        """
        if isinstance(pub_key_hash, str):
            hash_bytes = pub_key_hash.encode("utf-8")
            lib.cardano_tx_builder_add_signer_ex(self._ptr, hash_bytes, len(hash_bytes))
        else:
            lib.cardano_tx_builder_add_signer(self._ptr, pub_key_hash._ptr)
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

    # =========================================================================
    # Metadata
    # =========================================================================

    def set_metadata(
            self,
            tag: int,
            metadata: Union["Metadatum", str, Dict[Any, Any], List[Any]],
    ) -> TxBuilder:
        """
        Add metadata to the transaction.

        Transaction metadata (auxiliary data) allows attaching arbitrary
        data to transactions. Common uses include:

        - NFT metadata (tag 721)
        - Token registry metadata (tag 20)
        - Application-specific data

        Args:
            tag: The metadata label (0 to 2^64-1).
            metadata: The metadata content. Can be:
                - A ``Metadatum`` object.
                - A Python ``dict`` or ``list`` (will be serialized to JSON).
                - A JSON ``str``.

        Returns:
            Self for method chaining.

        Example:
            >>> # Add NFT metadata using a dict
            >>> metadata = {
            ...    "eb7e6282971727598462d39d7627bfa6fbbbf56496cb91b76840affb": {
            ...        "BerryOnyx": {
            ...            "color": "#0F0F0F",
            ...            "image": "ipfs://ipfs/QmS7w3Q5oVL9NE1gJnsMVPp6fcxia1e38cRT5pE5mmxawL",
            ...            "name": "Berry Onyx"
            ...         },
            ...     }
            ... }
            >>> builder.set_metadata(721, metadata)
            >>>
            >>> # Add JSON string directly
            >>> builder.set_metadata(674, '{"msg": "Hello Cardano!"}')
        """
        if isinstance(metadata, (dict, list)):
            import json
            metadata = json.dumps(metadata)

        if isinstance(metadata, str):
            json_bytes = metadata.encode("utf-8")
            lib.cardano_tx_builder_set_metadata_ex(
                self._ptr, tag, json_bytes, len(json_bytes)
            )
        else:
            lib.cardano_tx_builder_set_metadata(self._ptr, tag, metadata._ptr)

        return self

    def withdraw_rewards(
        self,
        reward_address: Union["RewardAddress", str],
        amount: int,
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Withdraw staking rewards.

        Withdraws accumulated staking rewards from a reward address. The
        withdrawal amount should match the available rewards.

        Args:
            reward_address: The stake/reward address to withdraw from.
                Can be a ``RewardAddress`` object or bech32 string (stake_test1...).
            amount: The amount to withdraw in lovelace.
            redeemer: Redeemer for script-based stake credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> rewards = provider.get_rewards(stake_address)
            >>> builder.withdraw_rewards("stake_test1...", rewards)
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(reward_address, str):
            addr_bytes = reward_address.encode("utf-8")
            lib.cardano_tx_builder_withdraw_rewards_ex(
                self._ptr, addr_bytes, len(addr_bytes), amount, redeemer_ptr
            )
        else:
            lib.cardano_tx_builder_withdraw_rewards(
                self._ptr, reward_address._ptr, amount, redeemer_ptr
            )
        return self

    def register_reward_address(
        self,
        reward_address: Union["RewardAddress", str],
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Register a stake address.

        Registers a new stake credential on-chain. This is required before
        the address can delegate to a pool or receive rewards.

        Note: Registration requires a deposit (currently 2 ADA) that is
        refunded upon deregistration.

        Args:
            reward_address: The stake address to register.
            redeemer: Redeemer for script-based stake credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.register_reward_address("stake_test1...")
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(reward_address, str):
            addr_bytes = reward_address.encode("utf-8")
            lib.cardano_tx_builder_register_reward_address_ex(
                self._ptr, addr_bytes, len(addr_bytes), redeemer_ptr
            )
        else:
            lib.cardano_tx_builder_register_reward_address(
                self._ptr, reward_address._ptr, redeemer_ptr
            )
        return self

    def deregister_reward_address(
        self,
        reward_address: Union["RewardAddress", str],
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Deregister a stake address.

        Removes a stake credential from the chain. The deposit paid during
        registration is refunded.

        Args:
            reward_address: The stake address to deregister.
            redeemer: Redeemer for script-based stake credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.deregister_reward_address("stake_test1...")
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(reward_address, str):
            addr_bytes = reward_address.encode("utf-8")
            lib.cardano_tx_builder_deregister_reward_address_ex(
                self._ptr, addr_bytes, len(addr_bytes), redeemer_ptr
            )
        else:
            lib.cardano_tx_builder_deregister_reward_address(
                self._ptr, reward_address._ptr, redeemer_ptr
            )
        return self

    def delegate_stake(
        self,
        reward_address: Union["RewardAddress", str],
        pool_id: Union["Blake2bHash", str],
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Delegate stake to a pool.

        Delegates the stake associated with a stake credential to a
        stake pool. Takes effect at the next epoch boundary.

        Args:
            reward_address: The stake address to delegate.
            pool_id: The pool to delegate to. Can be a ``Blake2bHash`` or
                a bech32 pool ID (pool1...) or hex hash.
            redeemer: Redeemer for script-based stake credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.delegate_stake(
            ...     "stake_test1...",
            ...     "pool1abc123...",
            ... )
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(reward_address, str) and isinstance(pool_id, str):
            addr_bytes = reward_address.encode("utf-8")
            pool_bytes = pool_id.encode("utf-8")
            lib.cardano_tx_builder_delegate_stake_ex(
                self._ptr,
                addr_bytes,
                len(addr_bytes),
                pool_bytes,
                len(pool_bytes),
                redeemer_ptr,
            )
        else:
            pool_ptr = pool_id if not isinstance(pool_id, str) else pool_id._ptr
            addr_ptr = reward_address if not isinstance(reward_address, str) else reward_address._ptr
            lib.cardano_tx_builder_delegate_stake(
                self._ptr, addr_ptr, pool_ptr, redeemer_ptr
            )
        return self

    def delegate_voting_power(
        self,
        reward_address: Union["RewardAddress", str],
        drep: Union["DRep", str],
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Delegate voting power to a DRep.

        Conway-era governance feature that delegates voting power to a
        Delegated Representative (DRep).

        Args:
            reward_address: The stake address delegating voting power.
            drep: The DRep to delegate to. Can be a ``DRep`` object,
                a DRep ID string, or special values like "abstain" or "no_confidence".
            redeemer: Redeemer for script-based stake credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.delegate_voting_power(
            ...     "stake_test1...",
            ...     "drep1abc123...",
            ... )
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL

        if isinstance(reward_address, str) and isinstance(drep, str):
            addr_bytes = reward_address.encode("utf-8")
            drep_bytes = drep.encode("utf-8")
            lib.cardano_tx_builder_delegate_voting_power_ex(
                self._ptr,
                addr_bytes,
                len(addr_bytes),
                drep_bytes,
                len(drep_bytes),
                redeemer_ptr,
            )
        else:
            lib.cardano_tx_builder_delegate_voting_power(
                self._ptr, reward_address._ptr, drep._ptr, redeemer_ptr
            )
        return self

    def register_drep(
        self,
        drep: Union["DRep", str],
        anchor: Optional["Anchor"] = None,
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Register as a DRep.

        Registers a new Delegated Representative for Conway-era governance.

        Args:
            drep: The DRep credential to register. Can be a ``DRep`` object
                or a DRep ID string (e.g., "drep1...").
            anchor: Optional metadata anchor with URL and hash.
            redeemer: Redeemer for script-based DRep credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.register_drep(drep, anchor=my_anchor)
            >>> builder.register_drep("drep1...", anchor=my_anchor)
        """
        drep_obj = _to_drep(drep)
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        anchor_ptr = anchor._ptr if anchor else ffi.NULL
        lib.cardano_tx_builder_register_drep(
            self._ptr, drep_obj._ptr, anchor_ptr, redeemer_ptr
        )
        return self

    def update_drep(
        self,
        drep: Union["DRep", str],
        anchor: Optional["Anchor"] = None,
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Update DRep metadata.

        Updates the metadata anchor for an existing DRep registration.

        Args:
            drep: The DRep to update. Can be a ``DRep`` object or DRep ID string.
            anchor: New metadata anchor (URL and hash).
            redeemer: Redeemer for script-based DRep credentials.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.update_drep(drep, anchor=new_anchor)
            >>> builder.update_drep("drep1...", anchor=new_anchor)
        """
        drep_obj = _to_drep(drep)
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        anchor_ptr = anchor._ptr if anchor else ffi.NULL
        lib.cardano_tx_builder_update_drep(
            self._ptr, drep_obj._ptr, anchor_ptr, redeemer_ptr
        )
        return self

    def deregister_drep(
        self,
        drep: Union["DRep", str],
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Deregister as a DRep.

        Removes a DRep registration and refunds the deposit.

        Args:
            drep: The DRep to deregister. Can be a ``DRep`` object or DRep ID string.
            redeemer: Redeemer for script-based DRep credentials.

        Returns:
            Self for method chaining.
        """
        drep_obj = _to_drep(drep)
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        lib.cardano_tx_builder_deregister_drep(self._ptr, drep_obj._ptr, redeemer_ptr)
        return self

    def vote(
        self,
        voter: "Voter",
        action_id: "GovernanceActionId",
        voting_procedure: "VotingProcedure",
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Cast a governance vote.

        Submits a vote on a governance action.

        Args:
            voter: The voter (DRep, SPO, or Committee member).
            action_id: The governance action being voted on.
            voting_procedure: The vote (yes, no, abstain) with optional anchor.
            redeemer: Redeemer for script-based voters.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.vote(
            ...     voter=my_drep_voter,
            ...     action_id=proposal_id,
            ...     voting_procedure=yes_vote,
            ... )
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        lib.cardano_tx_builder_vote(
            self._ptr,
            voter._ptr,
            action_id._ptr,
            voting_procedure._ptr,
            redeemer_ptr,
        )
        return self

    def add_certificate(
        self,
        certificate: "Certificate",
        redeemer: Optional["PlutusData"] = None,
    ) -> TxBuilder:
        """
        Add a certificate to the transaction.

        Low-level method for adding any certificate type. For common operations,
        prefer the specific methods like ``delegate_stake()``, ``register_reward_address()``, etc.

        Args:
            certificate: The certificate to include.
            redeemer: Redeemer for script-based certificates.

        Returns:
            Self for method chaining.
        """
        redeemer_ptr = redeemer._ptr if redeemer else ffi.NULL
        lib.cardano_tx_builder_add_certificate(self._ptr, certificate._ptr, redeemer_ptr)
        return self

    def propose_info(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
    ) -> TxBuilder:
        """
        Submit an info governance action.

        Info actions are used for signaling or polling without on-chain effects.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string (e.g., "stake1...").
            anchor: Metadata anchor with proposal details.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_info(reward_address, anchor)
            >>> builder.propose_info("stake1...", anchor)
        """
        addr = _to_reward_address(reward_address)
        lib.cardano_tx_builder_propose_info(
            self._ptr, addr._ptr, anchor._ptr
        )
        return self

    def propose_new_constitution(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        constitution: "Constitution",
        governance_action_id: Optional["GovernanceActionId"] = None,
    ) -> TxBuilder:
        """
        Submit a new constitution governance action.

        Proposes a new constitution to replace the current one.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            constitution: The new constitution being proposed.
            governance_action_id: Optional ID of the previous governance action
                this proposal builds upon.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_new_constitution(
            ...     reward_address,
            ...     anchor,
            ...     new_constitution,
            ... )
        """
        addr = _to_reward_address(reward_address)
        gov_action_ptr = governance_action_id._ptr if governance_action_id else ffi.NULL
        lib.cardano_tx_builder_propose_new_constitution(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            gov_action_ptr,
            constitution._ptr,
        )
        return self

    def propose_update_committee(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        members_to_remove: "CredentialSet",
        members_to_add: "CommitteeMembersMap",
        new_quorum: "UnitInterval",
        governance_action_id: Optional["GovernanceActionId"] = None,
    ) -> TxBuilder:
        """
        Submit an update committee governance action.

        Proposes changes to the constitutional committee membership.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            members_to_remove: Set of committee member credentials to remove.
            members_to_add: Map of new committee members with their term limits.
            new_quorum: The new quorum threshold for committee decisions.
            governance_action_id: Optional ID of the previous governance action.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_update_committee(
            ...     reward_address,
            ...     anchor,
            ...     members_to_remove,
            ...     members_to_add,
            ...     new_quorum,
            ... )
        """
        addr = _to_reward_address(reward_address)
        gov_action_ptr = governance_action_id._ptr if governance_action_id else ffi.NULL
        lib.cardano_tx_builder_propose_update_committee(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            gov_action_ptr,
            members_to_remove._ptr,
            members_to_add._ptr,
            new_quorum._ptr,
        )
        return self

    def propose_no_confidence(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        governance_action_id: Optional["GovernanceActionId"] = None,
    ) -> TxBuilder:
        """
        Submit a no confidence governance action.

        Proposes a vote of no confidence in the current constitutional committee.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            governance_action_id: Optional ID of the previous governance action.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_no_confidence(reward_address, anchor)
            >>> builder.propose_no_confidence("stake1...", anchor)
        """
        addr = _to_reward_address(reward_address)
        gov_action_ptr = governance_action_id._ptr if governance_action_id else ffi.NULL
        lib.cardano_tx_builder_propose_no_confidence(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            gov_action_ptr,
        )
        return self

    def propose_treasury_withdrawals(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        withdrawals: "WithdrawalMap",
        policy_hash: Optional["Blake2bHash"] = None,
    ) -> TxBuilder:
        """
        Submit a treasury withdrawals governance action.

        Proposes withdrawals from the Cardano treasury.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            withdrawals: Map of reward addresses to withdrawal amounts.
            policy_hash: Optional policy hash for guardrails script.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_treasury_withdrawals(
            ...     reward_address,
            ...     anchor,
            ...     withdrawals,
            ... )
        """
        addr = _to_reward_address(reward_address)
        policy_ptr = policy_hash._ptr if policy_hash else ffi.NULL
        lib.cardano_tx_builder_propose_treasury_withdrawals(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            withdrawals._ptr,
            policy_ptr,
        )
        return self

    def propose_hardfork(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        protocol_version: "ProtocolVersion",
        governance_action_id: Optional["GovernanceActionId"] = None,
    ) -> TxBuilder:
        """
        Submit a hardfork initiation governance action.

        Proposes a protocol version upgrade (hardfork).

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            protocol_version: The target protocol version for the hardfork.
            governance_action_id: Optional ID of the previous governance action.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_hardfork(
            ...     reward_address,
            ...     anchor,
            ...     protocol_version,
            ... )
        """
        addr = _to_reward_address(reward_address)
        gov_action_ptr = governance_action_id._ptr if governance_action_id else ffi.NULL
        lib.cardano_tx_builder_propose_hardfork(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            protocol_version._ptr,
            gov_action_ptr,
        )
        return self

    def propose_parameter_change(
        self,
        reward_address: Union["RewardAddress", str],
        anchor: "Anchor",
        protocol_param_update: "ProtocolParamUpdate",
        governance_action_id: Optional["GovernanceActionId"] = None,
        policy_hash: Optional["Blake2bHash"] = None,
    ) -> TxBuilder:
        """
        Submit a parameter change governance action.

        Proposes changes to protocol parameters.

        Args:
            reward_address: Address to receive the deposit refund. Can be a
                ``RewardAddress`` object or bech32 string.
            anchor: Metadata anchor with proposal details.
            protocol_param_update: The proposed parameter changes.
            governance_action_id: Optional ID of the previous governance action.
            policy_hash: Optional policy hash for guardrails script.

        Returns:
            Self for method chaining.

        Example:
            >>> builder.propose_parameter_change(
            ...     reward_address,
            ...     anchor,
            ...     param_update,
            ... )
        """
        addr = _to_reward_address(reward_address)
        gov_action_ptr = governance_action_id._ptr if governance_action_id else ffi.NULL
        policy_ptr = policy_hash._ptr if policy_hash else ffi.NULL
        lib.cardano_tx_builder_propose_parameter_change(
            self._ptr,
            addr._ptr,
            anchor._ptr,
            protocol_param_update._ptr,
            gov_action_ptr,
            policy_ptr,
        )
        return self

    # =========================================================================
    # Build
    # =========================================================================

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
        err = lib.cardano_tx_builder_build(self._ptr, tx_out)

        if err != 0:
            error_msg = self.get_last_error()
            raise CardanoError(
                f"Failed to build transaction (error code: {err} - {cardano_error_to_string(err)}): {error_msg}"
            )

        return Transaction(tx_out[0])

    def get_last_error(self) -> str:
        """
        Get the last error message from the builder.

        Returns:
            The error message, or empty string if no error.
        """
        result = lib.cardano_tx_builder_get_last_error(self._ptr)
        if result == ffi.NULL:
            return ""
        return ffi.string(result).decode("utf-8")
