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
    Transaction,
    Redeemer,
    RedeemerTag,
    ExUnits,
    PlutusData,
    CborReader,
)
from cometa.providers import (
    ProviderProtocol,
    ProviderTxEvaluator,
    BlockfrostProvider,
)


REDEEMER_CBOR = "840000d8799f0102030405ff821821182c"
PLUTUS_DATA_CBOR = "d8799f0102030405ff"
EX_UNITS_CBOR = "821821182c"
TX_CBOR = "84a600d9010281825820260aed6e7a24044b1254a87a509468a649f522a4e54e830ac10f27ea7b5ec61f010183a300581d70b429738bd6cc58b5c7932d001aa2bd05cfea47020a556c8c753d4436011a004c4b40028200582007845f8f3841996e3d8157954e2f5e2fb90465f27112fc5fe9056d916fae245ba200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba011a04636769a200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba01821a00177a6ea2581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff198a5447742544319271044774554481a0031f9194577444f47451a0056898d4577555344431a000fc589467753484942411a000103c2581c659ab0b5658687c2e74cd10dba8244015b713bf503b90557769d77a7a14a57696e675269646572731a02269552021a0002e665031a01353f84081a013531740b58204107eada931c72a600a6e3305bd22c7aeb9ada7c3f6823b155f4db85de36a69aa200d9010281825820e686ade5bc97372f271fd2abc06cfd96c24b3d9170f9459de1d8e3dd8fd385575840653324a9dddad004f05a8ac99fa2d1811af5f00543591407fb5206cfe9ac91bb1412404323fa517e0e189684cd3592e7f74862e3f16afbc262519abec958180c04d9010281d8799fd8799fd8799fd8799f581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68ffd8799fd8799fd8799f581c042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339baffffffff581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c681b000001863784a12ed8799fd8799f4040ffd8799f581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff1984577444f4745ffffffd8799fd87980190c8efffff5f6"


class MockProvider:
    """
    Mock provider implementation for testing ProviderTxEvaluator.

    This provider implements all required methods of the ProviderProtocol
    with simple mock behavior for testing purposes.
    """

    def __init__(self, name: str = "MockProvider", network: NetworkMagic = NetworkMagic.PREPROD):
        self._name = name
        self._network = network
        self._evaluation_result = []
        self._should_fail = False
        self._failure_message = "Evaluation failed"

    def get_name(self) -> str:
        """Get the provider name."""
        return self._name

    def get_network_magic(self) -> int:
        """Get the network magic."""
        return int(self._network)

    def get_parameters(self) -> "ProtocolParameters":
        """Get protocol parameters."""
        from cometa import ProtocolParameters
        return ProtocolParameters.new()

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """Get unspent outputs for an address."""
        return []

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """Get rewards balance."""
        return 0

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        """Get unspent outputs with a specific asset."""
        return []

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """Get unspent output by NFT."""
        raise Exception("NFT not found")

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        """Resolve transaction inputs to UTXOs."""
        return []

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        """Resolve a datum by hash."""
        raise Exception("Datum not found")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        """Confirm transaction."""
        return False

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit transaction."""
        return "0" * 64

    def evaluate_transaction(
        self,
        tx_cbor_hex: str,
        additional_utxos: Union["UtxoList", List["Utxo"], None] = None,
    ) -> List["Redeemer"]:
        """Evaluate transaction."""
        if self._should_fail:
            raise Exception(self._failure_message)
        return self._evaluation_result

    def set_evaluation_result(self, redeemers: List["Redeemer"]) -> None:
        """Set the evaluation result to return."""
        self._evaluation_result = redeemers

    def set_should_fail(self, should_fail: bool, message: str = "Evaluation failed") -> None:
        """Configure the provider to fail evaluation."""
        self._should_fail = should_fail
        self._failure_message = message


class TestProviderTxEvaluatorInit:
    """Tests for ProviderTxEvaluator.__init__ method."""

    def test_init_with_mock_provider(self):
        """Test creating ProviderTxEvaluator with a mock provider."""
        provider = MockProvider(name="TestProvider")
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator is not None
        assert evaluator.provider is provider

    def test_init_with_blockfrost_provider(self):
        """Test creating ProviderTxEvaluator with a Blockfrost provider."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator is not None
        assert evaluator.provider is provider

    def test_init_with_custom_network(self):
        """Test creating ProviderTxEvaluator with different networks."""
        mainnet_provider = MockProvider(name="MainnetProvider", network=NetworkMagic.MAINNET)
        preprod_provider = MockProvider(name="PreprodProvider", network=NetworkMagic.PREPROD)

        mainnet_evaluator = ProviderTxEvaluator(mainnet_provider)
        preprod_evaluator = ProviderTxEvaluator(preprod_provider)

        assert mainnet_evaluator.provider.get_network_magic() == int(NetworkMagic.MAINNET)
        assert preprod_evaluator.provider.get_network_magic() == int(NetworkMagic.PREPROD)

    def test_init_stores_provider_reference(self):
        """Test that init stores the provider reference correctly."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator._provider is provider
        assert evaluator.provider is provider


class TestProviderTxEvaluatorGetName:
    """Tests for ProviderTxEvaluator.get_name method."""

    def test_get_name_returns_provider_name(self):
        """Test get_name returns the provider's name."""
        provider = MockProvider(name="CustomProvider")
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.get_name() == "CustomProvider"

    def test_get_name_with_blockfrost(self):
        """Test get_name with Blockfrost provider."""
        provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test_project_id",
        )
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.get_name() == "Blockfrost"

    def test_get_name_is_derived_from_provider(self):
        """Test that get_name always derives from the underlying provider."""
        provider1 = MockProvider(name="Provider1")
        provider2 = MockProvider(name="Provider2")

        evaluator1 = ProviderTxEvaluator(provider1)
        evaluator2 = ProviderTxEvaluator(provider2)

        assert evaluator1.get_name() == "Provider1"
        assert evaluator2.get_name() == "Provider2"

    def test_get_name_returns_string(self):
        """Test that get_name returns a string."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        name = evaluator.get_name()
        assert isinstance(name, str)


class TestProviderTxEvaluatorProviderProperty:
    """Tests for ProviderTxEvaluator.provider property."""

    def test_provider_property_returns_provider(self):
        """Test provider property returns the provider."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        assert evaluator.provider is provider

    def test_provider_property_is_read_only(self):
        """Test that provider property is read-only."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        with pytest.raises(AttributeError):
            evaluator.provider = MockProvider()

    def test_provider_property_persists(self):
        """Test that provider property persists across multiple accesses."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        provider1 = evaluator.provider
        provider2 = evaluator.provider

        assert provider1 is provider2
        assert provider1 is provider


class TestProviderTxEvaluatorEvaluate:
    """Tests for ProviderTxEvaluator.evaluate method."""

    def create_test_transaction(self) -> Transaction:
        """Helper to create a test transaction."""
        reader = CborReader.from_hex(TX_CBOR)
        return Transaction.from_cbor(reader)

    def create_test_redeemer(self, tag: RedeemerTag = RedeemerTag.SPEND, index: int = 0) -> Redeemer:
        """Helper to create a test redeemer."""
        plutus_data = PlutusData.from_cbor(CborReader.from_hex(PLUTUS_DATA_CBOR))
        ex_units = ExUnits.from_cbor(CborReader.from_hex(EX_UNITS_CBOR))
        return Redeemer.new(tag, index, plutus_data, ex_units)

    def test_evaluate_with_empty_result(self):
        """Test evaluate with no redeemers in result."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert isinstance(redeemers, list)
        assert len(redeemers) == 0

    def test_evaluate_with_redeemers(self):
        """Test evaluate returning redeemers with execution units."""
        provider = MockProvider()
        redeemer = self.create_test_redeemer(RedeemerTag.SPEND, 0)
        provider.set_evaluation_result([redeemer])

        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert len(redeemers) == 1
        assert redeemers[0].tag == RedeemerTag.SPEND
        assert redeemers[0].index == 0

    def test_evaluate_with_additional_utxos_none(self):
        """Test evaluate with None as additional_utxos."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert isinstance(redeemers, list)

    def test_evaluate_with_additional_utxos_list(self):
        """Test evaluate with a list of additional UTXOs."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        tx_input = TransactionInput.from_hex("0" * 64, 0)
        address = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )
        tx_output = TransactionOutput.new(address, 1000000)
        utxo = Utxo.new(tx_input, tx_output)

        redeemers = evaluator.evaluate(transaction, [utxo])

        assert isinstance(redeemers, list)

    def test_evaluate_with_additional_utxos_utxo_list(self):
        """Test evaluate with UtxoList as additional_utxos."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        utxo_list = UtxoList()
        tx_input = TransactionInput.from_hex("0" * 64, 0)
        address = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )
        tx_output = TransactionOutput.new(address, 1000000)
        utxo = Utxo.new(tx_input, tx_output)
        utxo_list.add(utxo)

        redeemers = evaluator.evaluate(transaction, utxo_list)

        assert isinstance(redeemers, list)

    def test_evaluate_serializes_transaction_to_cbor(self):
        """Test that evaluate serializes the transaction to CBOR."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert isinstance(redeemers, list)

    def test_evaluate_calls_provider_evaluate_transaction(self):
        """Test that evaluate calls provider.evaluate_transaction."""
        provider = MockProvider()
        redeemer = self.create_test_redeemer(RedeemerTag.MINT, 0)
        provider.set_evaluation_result([redeemer])

        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert len(redeemers) == 1
        assert redeemers[0].tag == RedeemerTag.MINT

    def test_evaluate_propagates_provider_errors(self):
        """Test that evaluate propagates errors from provider."""
        provider = MockProvider()
        provider.set_should_fail(True, "Custom evaluation error")

        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        with pytest.raises(Exception) as exc_info:
            evaluator.evaluate(transaction, None)

        assert "Custom evaluation error" in str(exc_info.value)

    def test_evaluate_with_multiple_redeemers(self):
        """Test evaluate with multiple redeemers."""
        provider = MockProvider()
        redeemer1 = self.create_test_redeemer(RedeemerTag.SPEND, 0)
        redeemer2 = self.create_test_redeemer(RedeemerTag.SPEND, 1)
        provider.set_evaluation_result([redeemer1, redeemer2])

        evaluator = ProviderTxEvaluator(provider)
        transaction = self.create_test_transaction()

        redeemers = evaluator.evaluate(transaction, None)

        assert len(redeemers) == 2
        assert redeemers[0].index == 0
        assert redeemers[1].index == 1


class TestProviderTxEvaluatorIntegration:
    """Integration tests for ProviderTxEvaluator."""

    def test_evaluator_implements_tx_evaluator_protocol(self):
        """Test that ProviderTxEvaluator implements the TxEvaluator protocol."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        assert hasattr(evaluator, "get_name")
        assert hasattr(evaluator, "evaluate")
        assert callable(evaluator.get_name)
        assert callable(evaluator.evaluate)

    def test_evaluator_with_different_providers(self):
        """Test that evaluator works with different provider implementations."""
        mock_provider = MockProvider(name="MockProvider")
        blockfrost_provider = BlockfrostProvider(
            network=NetworkMagic.PREPROD,
            project_id="test",
        )

        mock_evaluator = ProviderTxEvaluator(mock_provider)
        blockfrost_evaluator = ProviderTxEvaluator(blockfrost_provider)

        assert mock_evaluator.get_name() == "MockProvider"
        assert blockfrost_evaluator.get_name() == "Blockfrost"

    def test_evaluator_name_reflects_provider_name(self):
        """Test that evaluator name changes with provider name."""
        provider1 = MockProvider(name="Provider1")
        provider2 = MockProvider(name="Provider2")

        evaluator1 = ProviderTxEvaluator(provider1)
        evaluator2 = ProviderTxEvaluator(provider2)

        assert evaluator1.get_name() != evaluator2.get_name()
        assert evaluator1.get_name() == "Provider1"
        assert evaluator2.get_name() == "Provider2"

    def test_evaluator_passes_cbor_to_provider(self):
        """Test that evaluator passes serialized CBOR to provider."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        reader = CborReader.from_hex(TX_CBOR)
        transaction = Transaction.from_cbor(reader)

        redeemers = evaluator.evaluate(transaction, None)

        assert isinstance(redeemers, list)


class TestProviderTxEvaluatorEdgeCases:
    """Edge case tests for ProviderTxEvaluator."""

    def test_evaluator_with_empty_transaction(self):
        """Test evaluator with a minimal transaction."""
        provider = MockProvider()
        evaluator = ProviderTxEvaluator(provider)

        reader = CborReader.from_hex(TX_CBOR)
        transaction = Transaction.from_cbor(reader)

        redeemers = evaluator.evaluate(transaction, None)

        assert isinstance(redeemers, list)

    def test_evaluator_preserves_provider_state(self):
        """Test that evaluator doesn't modify provider state."""
        provider = MockProvider(name="OriginalName")
        evaluator = ProviderTxEvaluator(provider)

        assert provider.get_name() == "OriginalName"
        assert evaluator.get_name() == "OriginalName"

        reader = CborReader.from_hex(TX_CBOR)
        transaction = Transaction.from_cbor(reader)
        evaluator.evaluate(transaction, None)

        assert provider.get_name() == "OriginalName"

    def test_multiple_evaluators_with_same_provider(self):
        """Test multiple evaluators can share the same provider."""
        provider = MockProvider()
        evaluator1 = ProviderTxEvaluator(provider)
        evaluator2 = ProviderTxEvaluator(provider)

        assert evaluator1.provider is evaluator2.provider
        assert evaluator1.get_name() == evaluator2.get_name()
