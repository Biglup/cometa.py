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
    CborWriter,
)
from cometa.providers import (
    Provider,
    ProviderProtocol,
    ProviderHandle,
    CProviderWrapper,
    BlockfrostProvider,
    ProviderTxEvaluator,
)


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"


def create_test_utxo(index: int = 0, lovelace: int = 1000000) -> Utxo:
    """Helper to create a test UTXO."""
    tx_input = TransactionInput.from_hex(TX_ID_HASH, index)
    address = Address.from_string(TEST_ADDRESS)
    tx_output = TransactionOutput.new(address, lovelace)
    return Utxo.new(tx_input, tx_output)


class MockProtocolParameters:
    """Mock protocol parameters for testing."""

    def __init__(self):
        from cometa import ProtocolParameters
        self._params = ProtocolParameters.new()

    @property
    def _ptr(self):
        return self._params._ptr


class MockProvider:
    """
    Mock provider implementation for testing the ProviderHandle adapter.

    This provider implements all required methods of the ProviderProtocol
    with simple mock behavior for testing the Python-to-C bridge.
    """

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

    def get_parameters(self) -> "ProtocolParameters":
        from cometa import ProtocolParameters
        return ProtocolParameters.new()

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        return self._utxos

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        return self._rewards_balance

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        return self._utxos

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        if not self._utxos:
            raise Exception("NFT not found")
        return self._utxos[0]

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        return self._utxos

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        hash_str = datum_hash.to_hex() if hasattr(datum_hash, "to_hex") else str(datum_hash)
        if hash_str in self._datums:
            return self._datums[hash_str]
        raise Exception(f"Datum not found: {hash_str}")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        return tx_id in self._submitted_txs

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        # Return a mock tx id
        tx_id = "abcd1234" + "0" * 56
        self._submitted_txs.append(tx_id)
        return tx_id

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union["UtxoList", List["Utxo"], None] = None,
    ) -> List["Redeemer"]:
        from cometa import Redeemer, RedeemerTag, ExUnits
        # Return empty list - no scripts to evaluate
        return []

    # Helper methods for testing
    def add_utxo(self, utxo: Utxo) -> None:
        """Add a UTXO to the mock provider."""
        self._utxos.append(utxo)

    def set_rewards_balance(self, balance: int) -> None:
        """Set the rewards balance for testing."""
        self._rewards_balance = balance

    def add_datum(self, hash_hex: str, cbor_hex: str) -> None:
        """Add a datum for testing resolve_datum."""
        self._datums[hash_hex] = cbor_hex


class TestProviderProtocol:
    """Tests for the ProviderProtocol interface."""

    def test_provider_protocol_is_protocol(self):
        """Test that ProviderProtocol is a Protocol class."""
        from typing import Protocol
        assert issubclass(ProviderProtocol, Protocol)

    def test_mock_provider_implements_protocol(self):
        """Test that MockProvider can be used as a ProviderProtocol."""
        provider = MockProvider()

        # Should have all required methods
        assert hasattr(provider, "get_name")
        assert hasattr(provider, "get_network_magic")
        assert hasattr(provider, "get_parameters")
        assert hasattr(provider, "get_unspent_outputs")
        assert hasattr(provider, "get_rewards_balance")
        assert hasattr(provider, "get_unspent_outputs_with_asset")
        assert hasattr(provider, "get_unspent_output_by_nft")
        assert hasattr(provider, "resolve_unspent_outputs")
        assert hasattr(provider, "resolve_datum")
        assert hasattr(provider, "confirm_transaction")
        assert hasattr(provider, "submit_transaction")
        assert hasattr(provider, "evaluate_transaction")

    def test_provider_alias(self):
        """Test that Provider is an alias for ProviderProtocol."""
        assert Provider is ProviderProtocol


class TestMockProvider:
    """Tests for the MockProvider implementation."""

    def test_get_name(self):
        """Test getting provider name."""
        provider = MockProvider(name="TestProvider")
        assert provider.get_name() == "TestProvider"

    def test_get_network_magic(self):
        """Test getting network magic."""
        provider = MockProvider(network=NetworkMagic.MAINNET)
        assert provider.get_network_magic() == int(NetworkMagic.MAINNET)

    def test_get_parameters(self):
        """Test getting protocol parameters."""
        provider = MockProvider()
        params = provider.get_parameters()
        assert params is not None

    def test_get_unspent_outputs_empty(self):
        """Test getting UTXOs when none exist."""
        provider = MockProvider()
        utxos = provider.get_unspent_outputs(TEST_ADDRESS)
        assert utxos == []

    def test_get_unspent_outputs_with_utxos(self):
        """Test getting UTXOs."""
        provider = MockProvider()
        utxo1 = create_test_utxo(0, 1000000)
        utxo2 = create_test_utxo(1, 2000000)
        provider.add_utxo(utxo1)
        provider.add_utxo(utxo2)

        utxos = provider.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 2

    def test_get_rewards_balance(self):
        """Test getting rewards balance."""
        provider = MockProvider()
        provider.set_rewards_balance(5000000)

        balance = provider.get_rewards_balance("stake_test1...")
        assert balance == 5000000

    def test_submit_transaction(self):
        """Test submitting a transaction."""
        provider = MockProvider()
        tx_id = provider.submit_transaction("abcd1234")
        assert len(tx_id) == 64  # Valid tx hash length

    def test_confirm_transaction(self):
        """Test confirming a transaction."""
        provider = MockProvider()

        # Submit a tx first
        tx_id = provider.submit_transaction("abcd1234")

        # Should be confirmed (in our mock list)
        assert provider.confirm_transaction(tx_id) is True

        # Unknown tx should not be confirmed
        assert provider.confirm_transaction("unknown") is False


class TestProviderHandle:
    """Tests for the ProviderHandle adapter."""

    def test_provider_handle_creation(self):
        """Test creating a ProviderHandle from a Python provider."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        assert handle is not None
        assert handle.ptr is not None

    def test_provider_handle_ptr(self):
        """Test that the ptr property returns a valid C pointer."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        ptr = handle.ptr
        assert ptr is not None

    def test_provider_handle_context_manager(self):
        """Test ProviderHandle as context manager."""
        provider = MockProvider()

        with ProviderHandle(provider) as handle:
            assert handle is not None
            assert handle.ptr is not None

    def test_provider_handle_name_callback(self):
        """Test that provider name is passed correctly to C."""
        provider = MockProvider(name="MyCustomProvider")
        handle = ProviderHandle(provider)

        # The name should be accessible through the C wrapper
        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_name() == "MyCustomProvider"

    def test_provider_handle_network_magic_callback(self):
        """Test that network magic is passed correctly to C."""
        provider = MockProvider(network=NetworkMagic.PREVIEW)
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_network_magic() == int(NetworkMagic.PREVIEW)

    def test_provider_handle_get_parameters_callback(self):
        """Test the get_parameters callback."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        params = wrapper.get_parameters()
        assert params is not None

    def test_provider_handle_get_unspent_outputs_callback(self):
        """Test the get_unspent_outputs callback."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 5000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 5000000

    def test_provider_handle_get_rewards_balance_callback(self):
        """Test the get_rewards_balance callback."""
        from cometa import RewardAddress

        provider = MockProvider()
        provider.set_rewards_balance(10000000)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(
            "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"
        )
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == 10000000

    def test_provider_handle_multiple_utxos(self):
        """Test handling multiple UTXOs through the callback."""
        provider = MockProvider()

        for i in range(5):
            utxo = create_test_utxo(i, 1000000 * (i + 1))
            provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 5


class TestCProviderWrapper:
    """Tests for the CProviderWrapper class."""

    def test_c_provider_wrapper_from_handle(self):
        """Test creating a CProviderWrapper from a ProviderHandle."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper is not None

    def test_c_provider_wrapper_get_name(self):
        """Test getting provider name through wrapper."""
        provider = MockProvider(name="TestWrapper")
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_name() == "TestWrapper"

    def test_c_provider_wrapper_get_network_magic(self):
        """Test getting network magic through wrapper."""
        provider = MockProvider(network=NetworkMagic.MAINNET)
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_network_magic() == int(NetworkMagic.MAINNET)

    def test_c_provider_wrapper_repr(self):
        """Test string representation of wrapper."""
        provider = MockProvider(name="ReprTest")
        handle = ProviderHandle(provider)

        wrapper = CProviderWrapper(handle.ptr)
        repr_str = repr(wrapper)

        assert "CProviderWrapper" in repr_str
        assert "ReprTest" in repr_str

    def test_c_provider_wrapper_context_manager(self):
        """Test CProviderWrapper as context manager."""
        provider = MockProvider()
        handle = ProviderHandle(provider)

        with CProviderWrapper(handle.ptr) as wrapper:
            assert wrapper is not None
            assert wrapper.get_name() == "MockProvider"

    def test_c_provider_wrapper_null_ptr_raises(self):
        """Test that NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        from cometa.errors import CardanoError

        with pytest.raises(CardanoError):
            CProviderWrapper(ffi.NULL)


class TestBlockfrostProvider:
    """Tests for the BlockfrostProvider class."""

    def test_blockfrost_provider_creation(self):
        """Test creating a BlockfrostProvider."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )

        assert provider is not None
        assert provider.get_name() == "Blockfrost"
        assert provider.get_network_magic() == int(NetworkMagic.PREPROD)

    def test_blockfrost_provider_mainnet(self):
        """Test BlockfrostProvider with mainnet."""
        provider = BlockfrostProvider(
            network=NetworkMagic.MAINNET,
            project_id="mainnet_project_id",
        )

        assert provider.get_network_magic() == int(NetworkMagic.MAINNET)

    def test_blockfrost_provider_preview(self):
        """Test BlockfrostProvider with preview network."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREVIEW,
            project_id="preview_project_id",
        )

        assert provider.get_network_magic() == int(NetworkMagic.PREVIEW)

    def test_blockfrost_provider_custom_base_url(self):
        """Test BlockfrostProvider with custom base URL."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
            base_url="https://custom.blockfrost.io/api/v0",
        )

        assert provider._base_url == "https://custom.blockfrost.io/api/v0/"

    def test_blockfrost_provider_with_handle(self):
        """Test wrapping BlockfrostProvider with ProviderHandle."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )

        handle = ProviderHandle(provider)
        assert handle is not None
        assert handle.ptr is not None

        wrapper = CProviderWrapper(handle.ptr)
        assert wrapper.get_name() == "Blockfrost"


class TestProviderIntegration:
    """Integration tests for the provider system."""

    def test_full_provider_lifecycle(self):
        """Test complete provider lifecycle: create, wrap, use."""
        # Create a Python provider
        provider = MockProvider(name="LifecycleTest")
        provider.add_utxo(create_test_utxo(0, 10000000))
        provider.add_utxo(create_test_utxo(1, 20000000))
        provider.set_rewards_balance(5000000)

        # Wrap for C interop
        handle = ProviderHandle(provider)

        # Use through C wrapper
        wrapper = CProviderWrapper(handle.ptr)

        # Verify all operations work
        assert wrapper.get_name() == "LifecycleTest"
        assert wrapper.get_network_magic() == int(NetworkMagic.PREPROD)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 2
        assert utxos[0].output.value.coin == 10000000
        assert utxos[1].output.value.coin == 20000000

        params = wrapper.get_parameters()
        assert params is not None

    def test_multiple_providers(self):
        """Test using multiple providers simultaneously."""
        provider1 = MockProvider(name="Provider1", network=NetworkMagic.MAINNET)
        provider1.add_utxo(create_test_utxo(0, 1000000))

        provider2 = MockProvider(name="Provider2", network=NetworkMagic.PREPROD)
        provider2.add_utxo(create_test_utxo(0, 2000000))

        handle1 = ProviderHandle(provider1)
        handle2 = ProviderHandle(provider2)

        wrapper1 = CProviderWrapper(handle1.ptr)
        wrapper2 = CProviderWrapper(handle2.ptr)

        assert wrapper1.get_name() == "Provider1"
        assert wrapper2.get_name() == "Provider2"

        utxos1 = wrapper1.get_unspent_outputs(TEST_ADDRESS)
        utxos2 = wrapper2.get_unspent_outputs(TEST_ADDRESS)

        assert utxos1[0].output.value.coin == 1000000
        assert utxos2[0].output.value.coin == 2000000

    def test_provider_error_handling(self):
        """Test error handling through the provider callbacks."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        # Try to get NFT when none exists - should raise
        from cometa.errors import CardanoError
        with pytest.raises(CardanoError):
            wrapper.get_unspent_output_by_nft("deadbeef" * 14)

    def test_provider_with_address_object(self):
        """Test provider with Address object instead of string."""
        provider = MockProvider()
        provider.add_utxo(create_test_utxo(0, 3000000))

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        address = Address.from_string(TEST_ADDRESS)
        utxos = wrapper.get_unspent_outputs(address)

        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 3000000


class TestBlockfrostUtxoParsing:
    """Tests for BlockfrostProvider UTXO parsing."""

    def test_parse_utxo_ada_only(self):
        """Test parsing UTXO with only ADA."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 0,
            "amount": [
                {"unit": "lovelace", "quantity": "5000000"}
            ]
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.input.index == 0
        assert utxo.output.value.coin == 5000000

    def test_parse_utxo_with_native_token(self):
        """Test parsing UTXO with native tokens."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        # Policy ID (28 bytes = 56 hex chars) + asset name
        policy_id = "a" * 56
        asset_name_hex = "544f4b454e"  # "TOKEN" in hex

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 1,
            "amount": [
                {"unit": "lovelace", "quantity": "2000000"},
                {"unit": f"{policy_id}{asset_name_hex}", "quantity": "100"}
            ]
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 2000000
        # Verify multi-asset was added
        multi_asset = utxo.output.value.multi_asset
        assert multi_asset is not None

    def test_parse_utxo_with_multiple_tokens(self):
        """Test parsing UTXO with multiple native tokens."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        policy_id_1 = "a" * 56
        policy_id_2 = "b" * 56
        asset_name_1 = "41424344"  # "ABCD" in hex
        asset_name_2 = "45464748"  # "EFGH" in hex

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 2,
            "amount": [
                {"unit": "lovelace", "quantity": "1500000"},
                {"unit": f"{policy_id_1}{asset_name_1}", "quantity": "50"},
                {"unit": f"{policy_id_2}{asset_name_2}", "quantity": "200"},
            ]
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 1500000
        multi_asset = utxo.output.value.multi_asset
        assert multi_asset is not None

    def test_parse_utxo_with_empty_asset_name(self):
        """Test parsing UTXO with empty asset name (like ADA handle)."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        policy_id = "c" * 56

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 3,
            "amount": [
                {"unit": "lovelace", "quantity": "1000000"},
                {"unit": policy_id, "quantity": "1"}  # No asset name
            ]
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 1000000

    def test_parse_utxo_with_datum_hash(self):
        """Test parsing UTXO with datum hash."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        datum_hash = "d" * 64

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 4,
            "amount": [
                {"unit": "lovelace", "quantity": "3000000"}
            ],
            "data_hash": datum_hash
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 3000000
        # Datum should be set
        datum = utxo.output.datum
        assert datum is not None

    def test_parse_utxo_with_inline_datum(self):
        """Test parsing UTXO with inline datum."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        datum_hash = "e" * 64
        # CBOR hex for PlutusData integer 42 (d8799f182aff = constructor 0 with fields [42])
        inline_datum_cbor = "d8799f182aff"

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 5,
            "amount": [
                {"unit": "lovelace", "quantity": "4000000"}
            ],
            "inline_datum": inline_datum_cbor,  # CBOR hex string
            "data_hash": datum_hash
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 4000000

    def test_parse_utxo_with_script_ref(self):
        """Test parsing UTXO with script reference."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        utxo_data = {
            "tx_hash": TX_ID_HASH,
            "output_index": 6,
            "amount": [
                {"unit": "lovelace", "quantity": "10000000"}
            ],
            "reference_script_hash": "f" * 56
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 10000000


class TestProviderCallbacks:
    """Tests for provider callback functions."""

    def test_resolve_unspent_outputs_callback(self):
        """Test resolve_unspent_outputs callback."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 7000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import TransactionInputSet

        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        tx_inputs = TransactionInputSet()
        tx_inputs.add(tx_input)

        resolved = wrapper.resolve_unspent_outputs(tx_inputs)
        assert len(resolved) == 1

    def test_get_unspent_outputs_with_asset_callback(self):
        """Test get_unspent_outputs_with_asset callback."""
        provider = MockProvider()
        utxo = create_test_utxo(0, 8000000)
        provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        from cometa import AssetId

        # Create a dummy asset ID
        asset_id = AssetId.from_hex("a" * 56 + "544f4b454e")

        utxos = wrapper.get_unspent_outputs_with_asset(TEST_ADDRESS, asset_id)
        assert len(utxos) == 1

    def test_long_provider_name(self):
        """Test provider with very long name (should truncate)."""
        long_name = "A" * 300  # Longer than 256 char limit
        provider = MockProvider(name=long_name)
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        # Name should be truncated but accessible
        name = wrapper.get_name()
        assert len(name) < 256
        assert name.startswith("AAAA")


class TestProviderEdgeCases:
    """Tests for provider edge cases."""

    def test_empty_utxo_list(self):
        """Test handling empty UTXO list."""
        provider = MockProvider()
        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert utxos == []

    def test_zero_rewards_balance(self):
        """Test zero rewards balance."""
        from cometa import RewardAddress

        provider = MockProvider()
        provider.set_rewards_balance(0)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(
            "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"
        )
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == 0

    def test_large_rewards_balance(self):
        """Test large rewards balance."""
        from cometa import RewardAddress

        provider = MockProvider()
        large_balance = 45_000_000_000_000_000  # 45 billion ADA in lovelace
        provider.set_rewards_balance(large_balance)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        reward_addr = RewardAddress.from_bech32(
            "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"
        )
        balance = wrapper.get_rewards_balance(reward_addr)
        assert balance == large_balance

    def test_provider_with_all_networks(self):
        """Test provider with all network types."""
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

    def test_provider_special_characters_in_name(self):
        """Test provider with special characters in name."""
        special_names = [
            "Provider-1",
            "Provider_2",
            "Provider.3",
            "Provider 4",
            "Prövidér",  # Unicode
        ]

        for name in special_names:
            provider = MockProvider(name=name)
            handle = ProviderHandle(provider)
            wrapper = CProviderWrapper(handle.ptr)

            retrieved_name = wrapper.get_name()
            assert retrieved_name == name

    def test_multiple_utxos_same_index(self):
        """Test multiple UTXOs from same transaction."""
        provider = MockProvider()

        # Different outputs from same transaction
        for i in range(3):
            utxo = create_test_utxo(i, 1000000 * (i + 1))
            provider.add_utxo(utxo)

        handle = ProviderHandle(provider)
        wrapper = CProviderWrapper(handle.ptr)

        utxos = wrapper.get_unspent_outputs(TEST_ADDRESS)
        assert len(utxos) == 3

        # Verify values are preserved
        values = sorted([u.output.value.coin for u in utxos])
        assert values == [1000000, 2000000, 3000000]


class TestBlockfrostProviderNetworks:
    """Tests for BlockfrostProvider network configuration."""

    def test_mainnet_url(self):
        """Test mainnet base URL."""
        provider = BlockfrostProvider(
            network=NetworkMagic.MAINNET,
            project_id="test",
        )
        assert "cardano-mainnet" in provider._base_url

    def test_preprod_url(self):
        """Test preprod base URL."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )
        assert "cardano-preprod" in provider._base_url

    def test_preview_url(self):
        """Test preview base URL."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREVIEW,
            project_id="test",
        )
        assert "cardano-preview" in provider._base_url

    def test_sanchonet_url(self):
        """Test sanchonet base URL."""
        provider = BlockfrostProvider(
            network=NetworkMagic.SANCHONET,
            project_id="test",
        )
        assert "cardano-sanchonet" in provider._base_url

    def test_custom_url_trailing_slash(self):
        """Test custom URL with trailing slash is normalized."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
            base_url="https://custom.blockfrost.io/api/v0/",
        )
        assert provider._base_url == "https://custom.blockfrost.io/api/v0/"

    def test_custom_url_without_trailing_slash(self):
        """Test custom URL without trailing slash gets one added."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
            base_url="https://custom.blockfrost.io/api/v0",
        )
        assert provider._base_url == "https://custom.blockfrost.io/api/v0/"


class TestProviderTxEvaluator:
    """Tests for ProviderTxEvaluator."""

    def test_create_from_blockfrost_provider(self):
        """Test creating ProviderTxEvaluator from a Blockfrost provider."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator is not None
        assert evaluator.provider is provider

    def test_get_name_returns_provider_name(self):
        """Test get_name returns the provider's name."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.get_name() == "Blockfrost"

    def test_provider_property(self):
        """Test provider property returns the provider."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.provider is provider

    def test_evaluator_with_mock_provider(self):
        """Test ProviderTxEvaluator can wrap any provider implementing ProviderProtocol."""
        provider = MockProvider(name="CustomProvider")
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.get_name() == "CustomProvider"
        assert evaluator.provider is provider

    def test_evaluator_implements_protocol(self):
        """Test that ProviderTxEvaluator has required protocol methods."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        assert hasattr(evaluator, "get_name")
        assert hasattr(evaluator, "evaluate")
        assert callable(evaluator.get_name)
        assert callable(evaluator.evaluate)

    def test_evaluator_name_changes_with_provider(self):
        """Test that evaluator name reflects the underlying provider name."""
        mock_provider = MockProvider(name="MyCustomProvider")
        blockfrost_provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        mock_evaluator = ProviderTxEvaluator(mock_provider)
        blockfrost_evaluator = ProviderTxEvaluator(blockfrost_provider)

        assert mock_evaluator.get_name() == "MyCustomProvider"
        assert blockfrost_evaluator.get_name() == "Blockfrost"
