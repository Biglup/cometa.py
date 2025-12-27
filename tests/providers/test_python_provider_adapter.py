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

import pytest
from typing import List, Union, Optional

from cometa import (
    NetworkMagic,
    Address,
    TransactionInput,
    TransactionOutput,
    Utxo,
    UtxoList,
    RewardAddress,
    Blake2bHash,
    AssetId,
    TransactionInputSet,
)
from cometa.providers import (
    ProviderHandle,
    CProviderWrapper,
)
from cometa.errors import CardanoError
from cometa._ffi import ffi


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
REWARD_ADDRESS = "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"


def create_test_utxo(index: int = 0, lovelace: int = 1000000) -> Utxo:
    """Helper to create a test UTXO."""
    tx_input = TransactionInput.from_hex(TX_ID_HASH, index)
    address = Address.from_string(TEST_ADDRESS)
    tx_output = TransactionOutput.new(address, lovelace)
    return Utxo.new(tx_input, tx_output)


class MinimalProvider:
    """
    Minimal provider implementation for testing ProviderHandle.

    This provider implements the bare minimum required methods to test
    the ProviderHandle adapter functionality.
    """

    def __init__(self, name: str = "MinimalProvider", network: NetworkMagic = NetworkMagic.PREPROD):
        self._name = name
        self._network = network

    def get_name(self) -> str:
        """Return the provider name."""
        return self._name

    def get_network_magic(self) -> int:
        """Return the network magic number."""
        return int(self._network)

    def get_parameters(self) -> "ProtocolParameters":
        """Return protocol parameters."""
        from cometa import ProtocolParameters
        return ProtocolParameters.new()

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """Return unspent outputs for an address."""
        return []

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """Return rewards balance."""
        return 0

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        """Return unspent outputs with specific asset."""
        return []

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """Return unspent output by NFT."""
        raise Exception("NFT not found")

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        """Resolve unspent outputs from transaction inputs."""
        return []

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        """Resolve datum from hash."""
        raise Exception("Datum not found")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        """Confirm transaction."""
        return False

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit transaction."""
        return "a" * 64

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union["UtxoList", List["Utxo"], None] = None,
    ) -> List["Redeemer"]:
        """Evaluate transaction."""
        return []


class ConfigurableProvider(MinimalProvider):
    """
    Provider with configurable behavior for testing callbacks.

    This provider extends MinimalProvider with state management
    to test callback functionality.
    """

    def __init__(self, name: str = "ConfigurableProvider", network: NetworkMagic = NetworkMagic.PREPROD):
        super().__init__(name, network)
        self._utxos: List[Utxo] = []
        self._rewards_balance = 0
        self._datums = {}
        self._submitted_txs = []
        self._redeemers = []

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """Return configured unspent outputs."""
        return self._utxos

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """Return configured rewards balance."""
        return self._rewards_balance

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        """Return configured unspent outputs with asset."""
        return self._utxos

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """Return first UTXO as NFT output."""
        if not self._utxos:
            raise Exception("NFT not found")
        return self._utxos[0]

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        """Return configured unspent outputs."""
        return self._utxos

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        """Resolve datum from configured datums."""
        hash_str = datum_hash.to_hex() if hasattr(datum_hash, "to_hex") else str(datum_hash)
        if hash_str in self._datums:
            return self._datums[hash_str]
        raise Exception(f"Datum not found: {hash_str}")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        """Confirm if transaction is in submitted list."""
        return tx_id in self._submitted_txs

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit transaction and return tx id."""
        tx_id = "b" * 64
        self._submitted_txs.append(tx_id)
        return tx_id

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union["UtxoList", List["Utxo"], None] = None,
    ) -> List["Redeemer"]:
        """Return configured redeemers."""
        return self._redeemers

    def add_utxo(self, utxo: Utxo) -> None:
        """Add a UTXO for testing."""
        self._utxos.append(utxo)

    def set_rewards_balance(self, balance: int) -> None:
        """Set rewards balance for testing."""
        self._rewards_balance = balance

    def add_datum(self, hash_hex: str, cbor_hex: str) -> None:
        """Add a datum for testing."""
        self._datums[hash_hex] = cbor_hex

    def add_redeemer(self, redeemer: "Redeemer") -> None:
        """Add a redeemer for testing."""
        self._redeemers.append(redeemer)


class TestProviderHandleInit:
    """Tests for ProviderHandle.__init__ method."""

    def test_init_with_minimal_provider(self):
        """Test initializing ProviderHandle with minimal provider."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        assert handle is not None
        assert handle._provider is provider
        assert handle._provider_ptr is not None
        assert handle._impl is not None

    def test_init_with_custom_name(self):
        """Test initializing with custom provider name."""
        provider = MinimalProvider(name="CustomProviderName")
        handle = ProviderHandle(provider)

        assert handle._provider.get_name() == "CustomProviderName"

    def test_init_with_mainnet(self):
        """Test initializing with mainnet network."""
        provider = MinimalProvider(network=NetworkMagic.MAINNET)
        handle = ProviderHandle(provider)

        assert handle._provider.get_network_magic() == int(NetworkMagic.MAINNET)

    def test_init_with_preprod(self):
        """Test initializing with preprod network."""
        provider = MinimalProvider(network=NetworkMagic.PREPROD)
        handle = ProviderHandle(provider)

        assert handle._provider.get_network_magic() == int(NetworkMagic.PREPROD)

    def test_init_with_preview(self):
        """Test initializing with preview network."""
        provider = MinimalProvider(network=NetworkMagic.PREVIEW)
        handle = ProviderHandle(provider)

        assert handle._provider.get_network_magic() == int(NetworkMagic.PREVIEW)

    def test_init_with_sanchonet(self):
        """Test initializing with sanchonet network."""
        provider = MinimalProvider(network=NetworkMagic.SANCHONET)
        handle = ProviderHandle(provider)

        assert handle._provider.get_network_magic() == int(NetworkMagic.SANCHONET)

    def test_init_callbacks_stored(self):
        """Test that callbacks are stored on instance."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        assert handle._cb_get_parameters is not None
        assert handle._cb_get_unspent_outputs is not None
        assert handle._cb_get_rewards_balance is not None
        assert handle._cb_get_unspent_outputs_with_asset is not None
        assert handle._cb_get_unspent_output_by_nft is not None
        assert handle._cb_resolve_unspent_outputs is not None
        assert handle._cb_resolve_datum is not None
        assert handle._cb_confirm_transaction is not None
        assert handle._cb_submit_transaction is not None
        assert handle._cb_evaluate_transaction is not None

    def test_init_creates_provider_ptr(self):
        """Test that init creates a valid provider pointer."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        assert handle.ptr is not None
        assert handle.ptr != ffi.NULL


class TestProviderHandlePtr:
    """Tests for ProviderHandle.ptr property."""

    def test_ptr_returns_cdata(self):
        """Test that ptr returns a cdata pointer."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        ptr = handle.ptr
        assert ptr is not None
        assert isinstance(ptr, ffi.CData)

    def test_ptr_is_valid_provider(self):
        """Test that ptr can be used to create CProviderWrapper."""
        provider = MinimalProvider(name="PtrTestProvider")
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_name() == "PtrTestProvider"

    def test_ptr_consistency(self):
        """Test that ptr returns same pointer on multiple calls."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        ptr1 = handle.ptr
        ptr2 = handle.ptr
        assert ptr1 == ptr2


class TestProviderHandleContextManager:
    """Tests for ProviderHandle context manager support."""

    def test_enter_returns_self(self):
        """Test that __enter__ returns self."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        result = handle.__enter__()
        assert result is handle

    def test_exit_does_not_raise(self):
        """Test that __exit__ completes without error."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        handle.__enter__()
        result = handle.__exit__(None, None, None)
        assert result is None

    def test_context_manager_usage(self):
        """Test using ProviderHandle with 'with' statement."""
        provider = MinimalProvider(name="ContextTest")

        with ProviderHandle(provider) as handle:
            assert handle is not None
            wrapper = CProviderWrapper(handle.ptr)
            assert wrapper.get_name() == "ContextTest"

    def test_context_manager_with_exception(self):
        """Test context manager with exception in body."""
        provider = MinimalProvider()

        with pytest.raises(ValueError):
            with ProviderHandle(provider):
                raise ValueError("Test exception")


class TestProviderHandleDestructor:
    """Tests for ProviderHandle.__del__ method."""

    def test_destructor_cleans_up(self):
        """Test that destructor cleans up resources."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        ptr_before = handle._provider_ptr
        assert ptr_before is not None

        del handle

    def test_destructor_with_null_ptr(self):
        """Test destructor when ptr is already NULL."""
        provider = MinimalProvider()
        handle = ProviderHandle(provider)

        handle._provider_ptr[0] = ffi.NULL

        del handle


class TestProviderHandleGetParametersCallback:
    """Tests for get_parameters callback."""

    def test_get_parameters_callback_success(self):
        """Test successful get_parameters callback."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        params = wrapper.get_parameters()
        assert params is not None

    def test_get_parameters_callback_type(self):
        """Test that get_parameters returns ProtocolParameters."""
        from cometa import ProtocolParameters

        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        params = wrapper.get_parameters()
        assert isinstance(params, ProtocolParameters)


class TestProviderHandleGetUnspentOutputsCallback:
    """Tests for get_unspent_outputs callback."""

    def test_get_unspent_outputs_empty(self):
        """Test get_unspent_outputs with no UTXOs."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert utxos == []

    def test_get_unspent_outputs_single_utxo(self):
        """Test get_unspent_outputs with single UTXO."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 1000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 1000000

    def test_get_unspent_outputs_multiple_utxos(self):
        """Test get_unspent_outputs with multiple UTXOs."""
        provider = ConfigurableProvider()
        for i in range(5):
            utxo = create_test_utxo(i, 1000000 * (i + 1))
            provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 5

    def test_get_unspent_outputs_with_address_object(self):
        """Test get_unspent_outputs with Address object."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 2000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        address = Address.from_string(TEST_ADDRESS)
        utxos = wrapper.get_unspent_outputs(address)
        assert len(utxos) == 1

    def test_get_unspent_outputs_large_value(self):
        """Test get_unspent_outputs with large ADA value."""
        provider = ConfigurableProvider()
        large_value = 45_000_000_000_000_000
        utxo = create_test_utxo(0, large_value)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert utxos[0].output.value.coin == large_value


class TestProviderHandleGetRewardsBalanceCallback:
    """Tests for get_rewards_balance callback."""

    def test_get_rewards_balance_zero(self):
        """Test get_rewards_balance with zero balance."""
        provider = ConfigurableProvider()
        provider.set_rewards_balance(0)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(REWARD_ADDRESS)
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == 0

    def test_get_rewards_balance_positive(self):
        """Test get_rewards_balance with positive balance."""
        provider = ConfigurableProvider()
        provider.set_rewards_balance(5000000)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(REWARD_ADDRESS)
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == 5000000

    def test_get_rewards_balance_large(self):
        """Test get_rewards_balance with large balance."""
        provider = ConfigurableProvider()
        large_balance = 45_000_000_000_000_000
        provider.set_rewards_balance(large_balance)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(REWARD_ADDRESS)
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == large_balance


class TestProviderHandleGetUnspentOutputsWithAssetCallback:
    """Tests for get_unspent_outputs_with_asset callback."""

    def test_get_unspent_outputs_with_asset_empty(self):
        """Test get_unspent_outputs_with_asset with no UTXOs."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id = AssetId.from_hex("a" * 56 + "544f4b454e")
        utxos = wrapper.get_unspent_outputs_with_asset(TEST_ADDRESS, asset_id)
        assert utxos == []

    def test_get_unspent_outputs_with_asset_single(self):
        """Test get_unspent_outputs_with_asset with single UTXO."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 3000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id = AssetId.from_hex("a" * 56 + "544f4b454e")
        utxos = wrapper.get_unspent_outputs_with_asset(TEST_ADDRESS, asset_id)
        assert len(utxos) == 1


class TestProviderHandleGetUnspentOutputByNftCallback:
    """Tests for get_unspent_output_by_nft callback."""

    def test_get_unspent_output_by_nft_success(self):
        """Test successful get_unspent_output_by_nft."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 2000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id = AssetId.from_hex("b" * 56 + "4e4654")
        result = wrapper.get_unspent_output_by_nft(asset_id)
        assert result is not None
        assert result.output.value.coin == 2000000

    def test_get_unspent_output_by_nft_not_found(self):
        """Test get_unspent_output_by_nft when NFT not found."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id = AssetId.from_hex("c" * 56 + "4e4654")
        with pytest.raises(CardanoError):
            wrapper.get_unspent_output_by_nft(asset_id)


class TestProviderHandleResolveUnspentOutputsCallback:
    """Tests for resolve_unspent_outputs callback."""

    def test_resolve_unspent_outputs_empty(self):
        """Test resolve_unspent_outputs with no UTXOs."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)

        resolved = wrapper.resolve_unspent_outputs(tx_inputs)
        assert resolved == []

    def test_resolve_unspent_outputs_single(self):
        """Test resolve_unspent_outputs with single UTXO."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 4000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)

        resolved = wrapper.resolve_unspent_outputs(tx_inputs)
        assert len(resolved) == 1
        assert resolved[0].output.value.coin == 4000000

    def test_resolve_unspent_outputs_multiple(self):
        """Test resolve_unspent_outputs with multiple UTXOs."""
        provider = ConfigurableProvider()
        for i in range(3):
            utxo = create_test_utxo(i, 1000000 * (i + 1))
            provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_inputs = TransactionInputSet()
        for i in range(3):
            tx_input = TransactionInput.from_hex(TX_ID_HASH, i)
            tx_inputs.add(tx_input)

        resolved = wrapper.resolve_unspent_outputs(tx_inputs)
        assert len(resolved) == 3


class TestProviderHandleResolveDatumCallback:
    """Tests for resolve_datum callback."""

    def test_resolve_datum_success(self):
        """Test successful resolve_datum."""
        provider = ConfigurableProvider()
        datum_hash = "d" * 64
        datum_cbor = "d8799f182aff"
        provider.add_datum(datum_hash, datum_cbor)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        blake_hash = Blake2bHash.from_hex(datum_hash)
        result = wrapper.resolve_datum(blake_hash)
        assert result is not None

    def test_resolve_datum_not_found(self):
        """Test resolve_datum when datum not found."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        blake_hash = Blake2bHash.from_hex("e" * 64)
        with pytest.raises(CardanoError):
            wrapper.resolve_datum(blake_hash)


class TestProviderHandleConfirmTransactionCallback:
    """Tests for confirm_transaction callback."""

    def test_confirm_transaction_not_submitted(self):
        """Test confirm_transaction for unsubmitted tx."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_hash = Blake2bHash.from_hex("a" * 64)
        result = wrapper.confirm_transaction(tx_hash, 1000)
        assert result is False

    def test_confirm_transaction_submitted(self):
        """Test confirm_transaction for submitted tx."""
        provider = ConfigurableProvider()
        tx_id = "b" * 64
        provider._submitted_txs.append(tx_id)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_hash = Blake2bHash.from_hex(tx_id)
        result = wrapper.confirm_transaction(tx_hash, 1000)
        assert result is True

    def test_confirm_transaction_zero_timeout(self):
        """Test confirm_transaction with zero timeout."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_hash = Blake2bHash.from_hex("c" * 64)
        result = wrapper.confirm_transaction(tx_hash, 0)
        assert result is False

    def test_confirm_transaction_large_timeout(self):
        """Test confirm_transaction with large timeout."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_hash = Blake2bHash.from_hex("d" * 64)
        result = wrapper.confirm_transaction(tx_hash, 999999999)
        assert result is False


class TestProviderHandleSubmitTransactionCallback:
    """Tests for submit_transaction callback."""

    def test_submit_transaction_success(self):
        """Test successful submit_transaction."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import Transaction, TransactionBody, WitnessSet, TransactionInputSet, TransactionOutputList
        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)
        tx_outputs = TransactionOutputList()
        address = Address.from_string(TEST_ADDRESS)
        output = TransactionOutput.new(address, 1000000)
        tx_outputs.add(output)
        body = TransactionBody.new(tx_inputs, tx_outputs, 0)
        witness_set = WitnessSet()
        tx = Transaction.new(body, witness_set)

        tx_id = wrapper.submit_transaction(tx)
        assert tx_id is not None
        assert len(tx_id.to_hex()) == 64

    def test_submit_transaction_returns_valid_hash(self):
        """Test that submit_transaction returns valid Blake2bHash."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import Transaction, TransactionBody, WitnessSet, TransactionInputSet, TransactionOutputList
        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)
        tx_outputs = TransactionOutputList()
        address = Address.from_string(TEST_ADDRESS)
        output = TransactionOutput.new(address, 1000000)
        tx_outputs.add(output)
        body = TransactionBody.new(tx_inputs, tx_outputs, 0)
        witness_set = WitnessSet()
        tx = Transaction.new(body, witness_set)

        tx_id = wrapper.submit_transaction(tx)
        assert isinstance(tx_id, Blake2bHash)


class TestProviderHandleEvaluateTransactionCallback:
    """Tests for evaluate_transaction callback."""

    def test_evaluate_transaction_no_scripts(self):
        """Test evaluate_transaction with no scripts."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import Transaction, TransactionBody, WitnessSet, TransactionInputSet, TransactionOutputList
        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)
        tx_outputs = TransactionOutputList()
        address = Address.from_string(TEST_ADDRESS)
        output = TransactionOutput.new(address, 1000000)
        tx_outputs.add(output)
        body = TransactionBody.new(tx_inputs, tx_outputs, 0)
        witness_set = WitnessSet()
        tx = Transaction.new(body, witness_set)

        redeemers = wrapper.evaluate_transaction(tx, None)
        assert len(redeemers) == 0

    def test_evaluate_transaction_with_additional_utxos(self):
        """Test evaluate_transaction with additional UTXOs."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import Transaction, TransactionBody, WitnessSet, TransactionInputSet, TransactionOutputList
        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)
        tx_outputs = TransactionOutputList()
        address = Address.from_string(TEST_ADDRESS)
        output = TransactionOutput.new(address, 1000000)
        tx_outputs.add(output)
        body = TransactionBody.new(tx_inputs, tx_outputs, 0)
        witness_set = WitnessSet()
        tx = Transaction.new(body, witness_set)

        utxo_list = UtxoList()
        utxo = create_test_utxo(0, 5000000)
        utxo_list.add(utxo)

        redeemers = wrapper.evaluate_transaction(tx, utxo_list)
        assert len(redeemers) == 0


class TestProviderHandleNameHandling:
    """Tests for provider name handling."""

    def test_short_name(self):
        """Test provider with short name."""
        provider = MinimalProvider(name="ABC")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == "ABC"

    def test_long_name(self):
        """Test provider with long name (truncation)."""
        long_name = "A" * 300
        provider = MinimalProvider(name=long_name)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()
        assert len(name) < 256
        assert name.startswith("AAA")

    def test_empty_name(self):
        """Test provider with empty name."""
        provider = MinimalProvider(name="")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == ""

    def test_unicode_name(self):
        """Test provider with unicode name."""
        unicode_name = "Provider-Ünïçödé"
        provider = MinimalProvider(name=unicode_name)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == unicode_name

    def test_special_characters_name(self):
        """Test provider with special characters."""
        special_name = "Provider_123-test.com"
        provider = MinimalProvider(name=special_name)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == special_name


class TestProviderHandleNetworkMagic:
    """Tests for network magic handling."""

    def test_all_network_types(self):
        """Test all network types."""
        networks = [
            NetworkMagic.MAINNET,
            NetworkMagic.PREPROD,
            NetworkMagic.PREVIEW,
            NetworkMagic.SANCHONET,
        ]

        for network in networks:
            provider = MinimalProvider(network=network)
            handle = ProviderHandle(provider)
            wrapper = CProviderWrapper(handle.ptr)

            assert wrapper.get_network_magic() == int(network)

    def test_mainnet_value(self):
        """Test mainnet network magic value."""
        provider = MinimalProvider(network=NetworkMagic.MAINNET)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_network_magic() == 764824073

    def test_preprod_value(self):
        """Test preprod network magic value."""
        provider = MinimalProvider(network=NetworkMagic.PREPROD)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_network_magic() == 1

    def test_preview_value(self):
        """Test preview network magic value."""
        provider = MinimalProvider(network=NetworkMagic.PREVIEW)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_network_magic() == 2

    def test_sanchonet_value(self):
        """Test sanchonet network magic value."""
        provider = MinimalProvider(network=NetworkMagic.SANCHONET)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_network_magic() == 4


class TestProviderHandleErrorHandling:
    """Tests for error handling in callbacks."""

    def test_callback_exception_captured(self):
        """Test that callback exceptions are captured."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        with pytest.raises(CardanoError):
            asset_id = AssetId.from_hex("d" * 56 + "4e4654")
            wrapper.get_unspent_output_by_nft(asset_id)

    def test_multiple_error_callbacks(self):
        """Test multiple failing callbacks."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        with pytest.raises(CardanoError):
            asset_id = AssetId.from_hex("e" * 56 + "4e4654")
            wrapper.get_unspent_output_by_nft(asset_id)

        with pytest.raises(CardanoError):
            datum_hash = Blake2bHash.from_hex("f" * 64)
            wrapper.resolve_datum(datum_hash)


class TestProviderHandleMultipleInstances:
    """Tests for multiple ProviderHandle instances."""

    def test_multiple_handles_same_provider(self):
        """Test creating multiple handles for same provider."""
        provider = ConfigurableProvider(name="SharedProvider")

        handle1 = ProviderHandle(provider)
        handle2 = ProviderHandle(provider)

        wrapper1 = CProviderWrapper(handle1.ptr)
        wrapper2 = CProviderWrapper(handle2.ptr)

        assert wrapper1.get_name() == "SharedProvider"
        assert wrapper2.get_name() == "SharedProvider"

    def test_multiple_handles_different_providers(self):
        """Test multiple handles for different providers."""
        provider1 = ConfigurableProvider(name="Provider1", network=NetworkMagic.MAINNET)
        provider2 = ConfigurableProvider(name="Provider2", network=NetworkMagic.PREPROD)

        handle1 = ProviderHandle(provider1)
        handle2 = ProviderHandle(provider2)

        wrapper1 = CProviderWrapper(handle1.ptr)
        wrapper2 = CProviderWrapper(handle2.ptr)

        assert wrapper1.get_name() == "Provider1"
        assert wrapper2.get_name() == "Provider2"
        assert wrapper1.get_network_magic() == int(NetworkMagic.MAINNET)
        assert wrapper2.get_network_magic() == int(NetworkMagic.PREPROD)

    def test_multiple_handles_independent_state(self):
        """Test that multiple handles maintain independent state."""
        provider1 = ConfigurableProvider(name="Provider1")
        provider1.add_utxo(create_test_utxo(0, 1000000))

        provider2 = ConfigurableProvider(name="Provider2")
        provider2.add_utxo(create_test_utxo(0, 2000000))

        handle1 = ProviderHandle(provider1)
        handle2 = ProviderHandle(provider2)

        wrapper1 = CProviderWrapper(handle1.ptr)
        wrapper2 = CProviderWrapper(handle2.ptr)

        utxos1 = wrapper1.get_unspent_outputs(TEST_ADDRESS)
        utxos2 = wrapper2.get_unspent_outputs(TEST_ADDRESS)

        assert utxos1[0].output.value.coin == 1000000
        assert utxos2[0].output.value.coin == 2000000


class TestProviderHandleLifecycle:
    """Tests for ProviderHandle lifecycle."""

    def test_handle_survives_provider_reference(self):
        """Test that handle works after provider reference is gone."""
        def create_handle():
            provider = ConfigurableProvider(name="TempProvider")
            return ProviderHandle(provider)

        handle = create_handle()
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == "TempProvider"

    def test_wrapper_after_handle_deletion(self):
        """Test wrapper behavior after handle is deleted."""
        provider = ConfigurableProvider(name="DeleteTest")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.get_name() == "DeleteTest"

        del handle

    def test_multiple_wrappers_same_handle(self):
        """Test creating multiple wrappers from same handle."""
        provider = ConfigurableProvider(name="MultiWrapper")
        handle = ProviderHandle(provider)

        wrapper1 = CProviderWrapper(handle.ptr)
        wrapper2 = CProviderWrapper(handle.ptr)

        assert wrapper1.get_name() == "MultiWrapper"
        assert wrapper2.get_name() == "MultiWrapper"


class TestProviderHandleEdgeCases:
    """Tests for edge cases in ProviderHandle."""

    def test_utxo_list_vs_list_handling(self):
        """Test that both UtxoList and list are handled correctly."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 6000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 1

    def test_null_additional_utxos(self):
        """Test evaluate_transaction with NULL additional_utxos."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import Transaction, TransactionBody, WitnessSet, TransactionInputSet, TransactionOutputList
        tx_inputs = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs.add(tx_input)
        tx_outputs = TransactionOutputList()
        address = Address.from_string(TEST_ADDRESS)
        output = TransactionOutput.new(address, 1000000)
        tx_outputs.add(output)
        body = TransactionBody.new(tx_inputs, tx_outputs, 0)
        witness_set = WitnessSet()
        tx = Transaction.new(body, witness_set)

        redeemers = wrapper.evaluate_transaction(tx, None)
        assert redeemers is not None

    def test_empty_transaction_input_set(self):
        """Test resolve_unspent_outputs with empty input set."""
        provider = ConfigurableProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_inputs = TransactionInputSet()
        resolved = wrapper.resolve_unspent_outputs(tx_inputs)
        assert resolved == []

    def test_zero_value_utxo(self):
        """Test handling UTXO with zero value."""
        provider = ConfigurableProvider()
        utxo = create_test_utxo(0, 0)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 0
