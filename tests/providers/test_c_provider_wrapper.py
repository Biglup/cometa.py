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
    RewardAddress,
    TransactionInput,
    TransactionOutput,
    TransactionInputSet,
    Transaction,
    Utxo,
    UtxoList,
    Blake2bHash,
    AssetId,
    CborReader,
    CborWriter,
    ProtocolParameters,
)
from cometa.providers import CProviderWrapper, ProviderHandle
from cometa._ffi import ffi, lib
from cometa.errors import CardanoError


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
REWARD_ADDRESS = "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"

VALID_TX_CBOR = "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b000b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b582088e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a10481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c71213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799fd8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9fd8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980fffff5f6"


def create_test_utxo(index: int = 0, lovelace: int = 1000000) -> Utxo:
    """Helper to create a test UTXO."""
    tx_input = TransactionInput.from_hex(TX_ID_HASH, index)
    address = Address.from_string(TEST_ADDRESS)
    tx_output = TransactionOutput.new(address, lovelace)
    return Utxo.new(tx_input, tx_output)


class MockProvider:
    """Mock provider implementation for testing."""

    def __init__(self, name: str = "MockProvider", network: NetworkMagic = NetworkMagic.PREPROD):
        self._name = name
        self._network = network
        self._utxos: List[Utxo] = []
        self._rewards_balance = 0
        self._datums = {}
        self._submitted_txs = []

    def get_name(self) -> str:
        return self._name

    def get_network_magic(self) -> int:
        return int(self._network)

    def get_parameters(self) -> ProtocolParameters:
        return ProtocolParameters.new()

    def get_unspent_outputs(self, address: Union[Address, str]) -> List[Utxo]:
        return self._utxos

    def get_rewards_balance(self, reward_account: Union[RewardAddress, str]) -> int:
        return self._rewards_balance

    def get_unspent_outputs_with_asset(
        self, address: Union[Address, str], asset_id: Union[AssetId, str]
    ) -> List[Utxo]:
        return self._utxos

    def get_unspent_output_by_nft(self, asset_id: Union[AssetId, str]) -> Utxo:
        if not self._utxos:
            raise Exception("NFT not found")
        return self._utxos[0]

    def resolve_unspent_outputs(
        self, tx_ins: Union[TransactionInputSet, List[TransactionInput]]
    ) -> List[Utxo]:
        return self._utxos

    def resolve_datum(self, datum_hash: Union[Blake2bHash, str]) -> str:
        hash_str = datum_hash.to_hex() if hasattr(datum_hash, "to_hex") else str(datum_hash)
        if hash_str in self._datums:
            return self._datums[hash_str]
        raise Exception(f"Datum not found: {hash_str}")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        return tx_id in self._submitted_txs

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        tx_id = "abcd1234" + "0" * 56
        self._submitted_txs.append(tx_id)
        return tx_id

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union[UtxoList, List[Utxo], None] = None,
    ) -> List:
        return []

    def add_utxo(self, utxo: Utxo) -> None:
        """Add a UTXO to the mock provider."""
        self._utxos.append(utxo)

    def set_rewards_balance(self, balance: int) -> None:
        """Set the rewards balance for testing."""
        self._rewards_balance = balance

    def add_datum(self, hash_hex: str, cbor_hex: str) -> None:
        """Add a datum for testing resolve_datum."""
        self._datums[hash_hex] = cbor_hex


class TestCProviderWrapperInit:
    """Tests for CProviderWrapper initialization."""

    def test_init_with_valid_ptr(self):
        """Test initialization with a valid provider pointer."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper is not None
        assert wrapper.ptr is not None
        assert wrapper.ptr == handle.ptr

    def test_init_with_null_ptr_raises(self):
        """Test that NULL pointer raises CardanoError."""
        with pytest.raises(CardanoError, match="invalid handle"):
            CProviderWrapper(ffi.NULL)

    def test_init_owns_ref_true(self):
        """Test initialization with owns_ref=True increments reference count."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        initial_refcount = lib.cardano_provider_refcount(handle.ptr)
        wrapper = CProviderWrapper(handle.ptr, owns_ref=True)
        new_refcount = lib.cardano_provider_refcount(handle.ptr)

        assert new_refcount == initial_refcount + 1

    def test_init_owns_ref_false(self):
        """Test initialization with owns_ref=False does not increment reference count."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        initial_refcount = lib.cardano_provider_refcount(handle.ptr)
        wrapper = CProviderWrapper(handle.ptr, owns_ref=False)
        new_refcount = lib.cardano_provider_refcount(handle.ptr)

        assert new_refcount == initial_refcount


class TestCProviderWrapperLifecycle:
    """Tests for CProviderWrapper lifecycle management."""

    def test_del_with_owns_ref_true(self):
        """Test that __del__ decrements reference count when owns_ref=True."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        initial_refcount = lib.cardano_provider_refcount(handle.ptr)
        wrapper = CProviderWrapper(handle.ptr, owns_ref=True)
        wrapper_refcount = lib.cardano_provider_refcount(handle.ptr)

        del wrapper

        final_refcount = lib.cardano_provider_refcount(handle.ptr)
        assert wrapper_refcount == initial_refcount + 1
        assert final_refcount == initial_refcount

    def test_context_manager_enter(self):
        """Test CProviderWrapper as context manager __enter__."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        with wrapper as ctx_wrapper:
            assert ctx_wrapper is wrapper
            assert ctx_wrapper.ptr is not None

    def test_context_manager_exit(self):
        """Test CProviderWrapper as context manager __exit__."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        with CProviderWrapper(handle.ptr) as wrapper:
            ptr = wrapper.ptr
            assert ptr is not None

    def test_repr(self):
        """Test __repr__ method."""
        provider = MockProvider(name="TestProvider")
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        repr_str = repr(wrapper)

        assert "CProviderWrapper" in repr_str
        assert "TestProvider" in repr_str


class TestCProviderWrapperProperties:
    """Tests for CProviderWrapper properties."""

    def test_ptr_property(self):
        """Test ptr property returns the underlying pointer."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)

        assert wrapper.ptr == handle.ptr
        assert wrapper.ptr is not None


class TestCProviderWrapperGetName:
    """Tests for CProviderWrapper.get_name method."""

    def test_get_name_returns_string(self):
        """Test get_name returns a string."""
        provider = MockProvider(name="TestProvider")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()

        assert isinstance(name, str)
        assert name == "TestProvider"

    def test_get_name_with_special_characters(self):
        """Test get_name with special characters."""
        provider = MockProvider(name="Test-Provider_123")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()

        assert name == "Test-Provider_123"

    def test_get_name_with_unicode(self):
        """Test get_name with unicode characters."""
        provider = MockProvider(name="Prövidér")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()

        assert name == "Prövidér"


class TestCProviderWrapperGetNetworkMagic:
    """Tests for CProviderWrapper.get_network_magic method."""

    def test_get_network_magic_mainnet(self):
        """Test get_network_magic returns mainnet value."""
        provider = MockProvider(network=NetworkMagic.MAINNET)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        magic = wrapper.get_network_magic()

        assert magic == int(NetworkMagic.MAINNET)
        assert magic == 764824073

    def test_get_network_magic_preprod(self):
        """Test get_network_magic returns preprod value."""
        provider = MockProvider(network=NetworkMagic.PREPROD)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        magic = wrapper.get_network_magic()

        assert magic == int(NetworkMagic.PREPROD)
        assert magic == 1

    def test_get_network_magic_preview(self):
        """Test get_network_magic returns preview value."""
        provider = MockProvider(network=NetworkMagic.PREVIEW)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        magic = wrapper.get_network_magic()

        assert magic == int(NetworkMagic.PREVIEW)
        assert magic == 2

    def test_get_network_magic_sanchonet(self):
        """Test get_network_magic returns sanchonet value."""
        provider = MockProvider(network=NetworkMagic.SANCHONET)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        magic = wrapper.get_network_magic()

        assert magic == int(NetworkMagic.SANCHONET)
        assert magic == 4


class TestCProviderWrapperGetLastError:
    """Tests for CProviderWrapper.get_last_error method."""

    def test_get_last_error_returns_string(self):
        """Test get_last_error returns a string."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        error = wrapper.get_last_error()

        assert isinstance(error, str)

    def test_get_last_error_empty(self):
        """Test get_last_error returns empty string when no error."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        error = wrapper.get_last_error()

        assert error == ""


class TestCProviderWrapperGetParameters:
    """Tests for CProviderWrapper.get_parameters method."""

    def test_get_parameters_returns_protocol_parameters(self):
        """Test get_parameters returns ProtocolParameters object."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        params = wrapper.get_parameters()

        assert params is not None
        assert isinstance(params, ProtocolParameters)

    def test_get_parameters_has_valid_ptr(self):
        """Test get_parameters returns object with valid pointer."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        params = wrapper.get_parameters()

        assert params._ptr is not None
        assert params._ptr != ffi.NULL


class TestCProviderWrapperGetUnspentOutputs:
    """Tests for CProviderWrapper.get_unspent_outputs method."""

    def test_get_unspent_outputs_with_string_address(self):
        """Test get_unspent_outputs with string address."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 5000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)

        assert isinstance(utxos, list)
        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 5000000

    def test_get_unspent_outputs_with_address_object(self):
        """Test get_unspent_outputs with Address object."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 3000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        address = Address.from_string(TEST_ADDRESS)
        utxos = wrapper.get_unspent_outputs(address)

        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 3000000

    def test_get_unspent_outputs_empty_list(self):
        """Test get_unspent_outputs returns empty list when no UTXOs."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)

        assert utxos == []

    def test_get_unspent_outputs_multiple_utxos(self):
        """Test get_unspent_outputs with multiple UTXOs."""
        provider = MockProvider()

        for i in range(5):
            utxo = create_test_utxo(i, 1000000 * (i + 1))
            provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)

        assert len(utxos) == 5
        values = [u.output.value.coin for u in utxos]
        assert values == [1000000, 2000000, 3000000, 4000000, 5000000]


class TestCProviderWrapperGetRewardsBalance:
    """Tests for CProviderWrapper.get_rewards_balance method."""

    def test_get_rewards_balance_with_string_address(self):
        """Test get_rewards_balance with string address."""
        provider = MockProvider()
        provider.set_rewards_balance(10000000)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        balance = wrapper.get_rewards_balance(REWARD_ADDRESS)

        assert isinstance(balance, int)
        assert balance == 10000000

    def test_get_rewards_balance_with_reward_address_object(self):
        """Test get_rewards_balance with RewardAddress object."""
        provider = MockProvider()
        provider.set_rewards_balance(5000000)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(REWARD_ADDRESS)
        balance = wrapper.get_rewards_balance(reward_addr)

        assert balance == 5000000

    def test_get_rewards_balance_zero(self):
        """Test get_rewards_balance returns zero when no rewards."""
        provider = MockProvider()
        provider.set_rewards_balance(0)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        balance = wrapper.get_rewards_balance(REWARD_ADDRESS)

        assert balance == 0

    def test_get_rewards_balance_large_value(self):
        """Test get_rewards_balance with large value."""
        provider = MockProvider()
        large_balance = 45_000_000_000_000_000
        provider.set_rewards_balance(large_balance)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(REWARD_ADDRESS)
        balance = wrapper.get_rewards_balance(reward_addr)

        assert balance == large_balance


class TestCProviderWrapperGetUnspentOutputsWithAsset:
    """Tests for CProviderWrapper.get_unspent_outputs_with_asset method."""

    def test_get_unspent_outputs_with_asset_string_inputs(self):
        """Test get_unspent_outputs_with_asset with string inputs."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 8000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id_hex = "a" * 56 + "544f4b454e"
        utxos = wrapper.get_unspent_outputs_with_asset(TEST_ADDRESS, asset_id_hex)

        assert isinstance(utxos, list)
        assert len(utxos) == 1

    def test_get_unspent_outputs_with_asset_objects(self):
        """Test get_unspent_outputs_with_asset with object inputs."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 7000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        address = Address.from_string(TEST_ADDRESS)
        asset_id = AssetId.from_hex("a" * 56 + "544f4b454e")

        utxos = wrapper.get_unspent_outputs_with_asset(address, asset_id)

        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 7000000

    def test_get_unspent_outputs_with_asset_empty_list(self):
        """Test get_unspent_outputs_with_asset returns empty list when no UTXOs."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id_hex = "b" * 56 + "4e4654"
        utxos = wrapper.get_unspent_outputs_with_asset(TEST_ADDRESS, asset_id_hex)

        assert utxos == []


class TestCProviderWrapperGetUnspentOutputByNft:
    """Tests for CProviderWrapper.get_unspent_output_by_nft method."""

    def test_get_unspent_output_by_nft_with_string(self):
        """Test get_unspent_output_by_nft with string asset_id."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 10000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id_hex = "c" * 56 + "4e4654"
        result_utxo = wrapper.get_unspent_output_by_nft(asset_id_hex)

        assert result_utxo is not None
        assert isinstance(result_utxo, Utxo)
        assert result_utxo.output.value.coin == 10000000

    def test_get_unspent_output_by_nft_with_asset_id_object(self):
        """Test get_unspent_output_by_nft with AssetId object."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 15000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id = AssetId.from_hex("d" * 56 + "4e4654")
        result_utxo = wrapper.get_unspent_output_by_nft(asset_id)

        assert result_utxo is not None
        assert result_utxo.output.value.coin == 15000000

    def test_get_unspent_output_by_nft_not_found_raises(self):
        """Test get_unspent_output_by_nft raises when NFT not found."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        asset_id_hex = "e" * 56 + "4e4654"

        with pytest.raises(CardanoError):
            wrapper.get_unspent_output_by_nft(asset_id_hex)


class TestCProviderWrapperResolveUnspentOutputs:
    """Tests for CProviderWrapper.resolve_unspent_outputs method."""

    def test_resolve_unspent_outputs_with_input_set(self):
        """Test resolve_unspent_outputs with TransactionInputSet."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 7000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs = TransactionInputSet()
        tx_inputs.add(tx_input)

        resolved = wrapper.resolve_unspent_outputs(tx_inputs)

        assert isinstance(resolved, list)
        assert len(resolved) == 1
        assert resolved[0].output.value.coin == 7000000

    def test_resolve_unspent_outputs_with_list(self):
        """Test resolve_unspent_outputs with list of TransactionInput."""
        provider = MockProvider()
        utxo1 = create_test_utxo(0, 5000000)
        utxo2 = create_test_utxo(1, 3000000)
        provider.add_utxo(utxo1)
        provider.add_utxo(utxo2)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_input1 = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_input2 = TransactionInput.from_hex(TX_ID_HASH, 1)

        resolved = wrapper.resolve_unspent_outputs([tx_input1, tx_input2])

        assert len(resolved) == 2

    def test_resolve_unspent_outputs_empty_list(self):
        """Test resolve_unspent_outputs returns empty list when no UTXOs."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_inputs = TransactionInputSet()
        resolved = wrapper.resolve_unspent_outputs(tx_inputs)

        assert resolved == []


class TestCProviderWrapperResolveDatum:
    """Tests for CProviderWrapper.resolve_datum method."""

    def test_resolve_datum_with_string(self):
        """Test resolve_datum with string hash."""
        provider = MockProvider()
        datum_hash = "a" * 64
        provider.add_datum(datum_hash, "d8799f182aff")

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        datum = wrapper.resolve_datum(datum_hash)

        assert datum is not None

    def test_resolve_datum_with_blake2b_hash_object(self):
        """Test resolve_datum with Blake2bHash object."""
        provider = MockProvider()
        datum_hash = "b" * 64
        provider.add_datum(datum_hash, "d8799f182aff")

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        hash_obj = Blake2bHash.from_hex(datum_hash)
        datum = wrapper.resolve_datum(hash_obj)

        assert datum is not None


class TestCProviderWrapperConfirmTransaction:
    """Tests for CProviderWrapper.confirm_transaction method."""

    def test_confirm_transaction_with_string_tx_id(self):
        """Test confirm_transaction with string tx_id."""
        provider = MockProvider()
        tx_id = "abcd1234" + "0" * 56
        provider._submitted_txs.append(tx_id)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        confirmed = wrapper.confirm_transaction(tx_id)

        assert isinstance(confirmed, bool)
        assert confirmed is True

    def test_confirm_transaction_with_blake2b_hash_object(self):
        """Test confirm_transaction with Blake2bHash object."""
        provider = MockProvider()
        tx_id = "abcd1234" + "0" * 56
        provider._submitted_txs.append(tx_id)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        hash_obj = Blake2bHash.from_hex(tx_id)
        confirmed = wrapper.confirm_transaction(hash_obj)

        assert confirmed is True

    def test_confirm_transaction_not_found(self):
        """Test confirm_transaction returns False when tx not found."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_id = "f" * 64
        confirmed = wrapper.confirm_transaction(tx_id)

        assert confirmed is False

    def test_confirm_transaction_with_timeout(self):
        """Test confirm_transaction with timeout parameter."""
        provider = MockProvider()
        tx_id = "abcd1234" + "0" * 56
        provider._submitted_txs.append(tx_id)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        confirmed = wrapper.confirm_transaction(tx_id, timeout_ms=60000)

        assert confirmed is True

    def test_confirm_transaction_with_zero_timeout(self):
        """Test confirm_transaction with zero timeout (no timeout)."""
        provider = MockProvider()
        tx_id = "abcd1234" + "0" * 56
        provider._submitted_txs.append(tx_id)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        confirmed = wrapper.confirm_transaction(tx_id, timeout_ms=0)

        assert confirmed is True


class TestCProviderWrapperSubmitTransaction:
    """Tests for CProviderWrapper.submit_transaction method."""

    def test_submit_transaction_with_string(self):
        """Test submit_transaction with CBOR hex string."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_id = wrapper.submit_transaction(VALID_TX_CBOR)

        assert tx_id is not None
        assert isinstance(tx_id, Blake2bHash)

    def test_submit_transaction_returns_blake2b_hash(self):
        """Test submit_transaction returns Blake2bHash object."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        tx_id = wrapper.submit_transaction(VALID_TX_CBOR)

        assert hasattr(tx_id, "to_hex")
        assert len(tx_id.to_hex()) == 64


class TestCProviderWrapperEvaluateTransaction:
    """Tests for CProviderWrapper.evaluate_transaction method."""

    def test_evaluate_transaction_with_string_no_additional_utxos(self):
        """Test evaluate_transaction with CBOR hex string and no additional UTXOs."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        redeemers = wrapper.evaluate_transaction(VALID_TX_CBOR)

        assert redeemers is not None

    def test_evaluate_transaction_with_string_and_utxo_list(self):
        """Test evaluate_transaction with additional UTXOs as UtxoList."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxo = create_test_utxo(0, 1000000)
        utxo_list = UtxoList()
        utxo_list.add(utxo)

        redeemers = wrapper.evaluate_transaction(VALID_TX_CBOR, additional_utxos=utxo_list)

        assert redeemers is not None

    def test_evaluate_transaction_with_string_and_utxo_python_list(self):
        """Test evaluate_transaction with additional UTXOs as Python list."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxo1 = create_test_utxo(0, 1000000)
        utxo2 = create_test_utxo(1, 2000000)

        redeemers = wrapper.evaluate_transaction(VALID_TX_CBOR, additional_utxos=[utxo1, utxo2])

        assert redeemers is not None

    def test_evaluate_transaction_with_none_additional_utxos(self):
        """Test evaluate_transaction with None as additional_utxos."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        redeemers = wrapper.evaluate_transaction(VALID_TX_CBOR, additional_utxos=None)

        assert redeemers is not None


class TestCProviderWrapperEdgeCases:
    """Tests for CProviderWrapper edge cases and error conditions."""

    def test_multiple_wrappers_same_provider(self):
        """Test creating multiple wrappers around the same provider."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper1 = CProviderWrapper(handle.ptr, owns_ref=False)
        wrapper2 = CProviderWrapper(handle.ptr, owns_ref=False)

        assert wrapper1.get_name() == wrapper2.get_name()
        assert wrapper1.get_network_magic() == wrapper2.get_network_magic()

    def test_wrapper_after_provider_operations(self):
        """Test wrapper remains valid after provider operations."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        params1 = wrapper.get_parameters()
        utxos1 = wrapper.get_unspent_outputs(TEST_ADDRESS)
        params2 = wrapper.get_parameters()

        assert params1 is not None
        assert params2 is not None
        assert utxos1 == []

    def test_wrapper_with_different_networks(self):
        """Test wrapper with different network configurations."""
        networks = [
            NetworkMagic.MAINNET,
            NetworkMagic.PREPROD,
            NetworkMagic.PREVIEW,
            NetworkMagic.SANCHONET,
        ]

        for network in networks:
            provider = MockProvider(network=network)
            handle = ProviderHandle(provider)
            wrapper = CProviderWrapper(handle.ptr)

            assert wrapper.get_network_magic() == int(network)

    def test_wrapper_with_empty_provider_name(self):
        """Test wrapper with empty provider name."""
        provider = MockProvider(name="")
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()

        assert name == ""

    def test_wrapper_with_long_provider_name(self):
        """Test wrapper with very long provider name."""
        long_name = "A" * 300
        provider = MockProvider(name=long_name)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        name = wrapper.get_name()

        assert len(name) < 256
        assert name.startswith("AAAA")
