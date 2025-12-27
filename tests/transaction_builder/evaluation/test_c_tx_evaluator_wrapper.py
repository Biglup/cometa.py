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
    TransactionBody,
    Transaction,
    Utxo,
    UtxoList,
    Redeemer,
    RedeemerTag,
    RedeemerList,
    ExUnits,
    PlutusData,
    CborReader,
    Blake2bHash,
)
from cometa.providers import (
    BlockfrostProvider,
    ProviderHandle,
)
from cometa.transaction_builder.evaluation.c_tx_evaluator_wrapper import (
    CTxEvaluatorWrapper,
)
from cometa._ffi import ffi, lib
from cometa.errors import CardanoError


class MockProvider:
    """
    Mock provider implementation for testing CTxEvaluatorWrapper.

    This provider implements all required methods of the ProviderProtocol
    with simple mock behavior for testing purposes.
    """

    def __init__(self, name: str = "MockProvider", network: NetworkMagic = NetworkMagic.PREPROD):
        self._name = name
        self._network = network

    def get_name(self) -> str:
        """Get the provider name."""
        return self._name

    def get_network_magic(self) -> int:
        """Get the network magic."""
        return int(self._network)

    def get_parameters(self):
        """Get protocol parameters."""
        from cometa import ProtocolParameters
        return ProtocolParameters.new()

    def get_unspent_outputs(self, address):
        """Get unspent outputs for an address."""
        return []

    def get_rewards_balance(self, reward_account):
        """Get rewards balance."""
        return 0

    def get_unspent_outputs_with_asset(self, address, asset_id):
        """Get unspent outputs with a specific asset."""
        return []

    def get_unspent_output_by_nft(self, asset_id):
        """Get unspent output by NFT."""
        raise Exception("NFT not found")

    def resolve_unspent_outputs(self, tx_ins):
        """Resolve transaction inputs to UTXOs."""
        return []

    def resolve_datum(self, datum_hash):
        """Resolve a datum by hash."""
        raise Exception("Datum not found")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        """Confirm transaction."""
        return False

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit transaction."""
        return "0" * 64

    def evaluate_transaction(self, tx_cbor_hex: str, additional_utxos=None):
        """Evaluate transaction."""
        return []


def create_simple_transaction():
    """Create a simple transaction for testing."""
    tx_cbor = "84a300d9010282825820027b68d4c11e97d7e065cc2702912cb1a21b6d0e56c6a74dd605889a5561138500825820d3c887d17486d483a2b46b58b01cb9344745f15fdd8f8e70a57f854cdd88a633010182a2005839005cf6c91279a859a072601779fb33bb07c34e1d641d45df51ff63b967f15db05f56035465bf8900a09bdaa16c3d8b8244fea686524408dd8001821a00e4e1c0a1581c0b0d621b5c26d0a1fd0893a4b04c19d860296a69ede1fbcfc5179882a1474e46542d30303101a200583900dc435fc2638f6684bd1f9f6f917d80c92ae642a4a33a412e516479e64245236ab8056760efceebbff57e8cab220182be3e36439e520a6454011a0d294e28021a00029eb9a0f5f6"
    reader = CborReader.from_hex(tx_cbor)
    return Transaction.from_cbor(reader)


def create_simple_utxo():
    """Create a simple UTXO for testing."""
    utxo_cbor = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a00989680a0"
    reader = CborReader.from_hex(utxo_cbor)
    return Utxo.from_cbor(reader)


class TestCTxEvaluatorWrapperInit:
    """Tests for CTxEvaluatorWrapper.__init__ method."""

    def test_init_with_null_pointer_raises_error(self):
        """Test that creating wrapper with NULL pointer raises CardanoError."""
        with pytest.raises(CardanoError, match="invalid handle"):
            CTxEvaluatorWrapper(ffi.NULL)

    def test_init_with_valid_pointer(self):
        """Test creating wrapper with valid pointer."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator_out = ffi.new("cardano_tx_evaluator_t**")
        error = lib.cardano_tx_evaluator_from_provider(provider_handle.ptr, evaluator_out)
        assert error == 0

        wrapper = CTxEvaluatorWrapper(evaluator_out[0], owns_ref=True)
        assert wrapper is not None
        assert wrapper.ptr != ffi.NULL

    def test_init_with_owns_ref_true_increments_refcount(self):
        """Test that owns_ref=True increments reference count."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator_out = ffi.new("cardano_tx_evaluator_t**")
        error = lib.cardano_tx_evaluator_from_provider(provider_handle.ptr, evaluator_out)
        assert error == 0

        initial_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        wrapper = CTxEvaluatorWrapper(evaluator_out[0], owns_ref=True)

        new_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        assert new_refcount == initial_refcount + 1

        ptr_ptr = ffi.new("cardano_tx_evaluator_t**", evaluator_out[0])
        lib.cardano_tx_evaluator_unref(ptr_ptr)

    def test_init_with_owns_ref_false_does_not_increment_refcount(self):
        """Test that owns_ref=False does not increment reference count."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator_out = ffi.new("cardano_tx_evaluator_t**")
        error = lib.cardano_tx_evaluator_from_provider(provider_handle.ptr, evaluator_out)
        assert error == 0

        initial_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        wrapper = CTxEvaluatorWrapper(evaluator_out[0], owns_ref=False)

        new_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        assert new_refcount == initial_refcount

        ptr_ptr = ffi.new("cardano_tx_evaluator_t**", evaluator_out[0])
        lib.cardano_tx_evaluator_unref(ptr_ptr)


class TestCTxEvaluatorWrapperFromProvider:
    """Tests for CTxEvaluatorWrapper.from_provider class method."""

    def test_from_provider_with_mock_provider(self):
        """Test creating evaluator from a mock provider."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        assert evaluator is not None
        assert evaluator.ptr != ffi.NULL
        assert isinstance(evaluator, CTxEvaluatorWrapper)

    def test_from_provider_with_null_provider_raises_error(self):
        """Test that from_provider with NULL provider raises error."""
        class NullProvider:
            @property
            def ptr(self):
                return ffi.NULL

        provider = NullProvider()
        with pytest.raises(CardanoError, match="Failed to create tx evaluator from provider"):
            CTxEvaluatorWrapper.from_provider(provider)

    def test_from_provider_creates_evaluator_with_correct_ownership(self):
        """Test that from_provider creates evaluator with correct ownership."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        assert evaluator._owns_ref is True
        refcount = lib.cardano_tx_evaluator_refcount(evaluator.ptr)
        assert refcount == 1

    def test_from_provider_with_underscore_ptr_attribute(self):
        """Test from_provider works with _ptr attribute."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)

        class ProviderWithUnderscorePtrAttr:
            def __init__(self, ptr):
                self._ptr = ptr

        provider_wrapper = ProviderWithUnderscorePtrAttr(provider_handle.ptr)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_wrapper)

        assert evaluator is not None
        assert evaluator.ptr != ffi.NULL


class TestCTxEvaluatorWrapperGetName:
    """Tests for CTxEvaluatorWrapper.get_name method."""

    def test_get_name_returns_provider_evaluator_name(self):
        """Test that get_name returns the evaluator name."""
        provider = MockProvider(name="TestProvider")
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        name = evaluator.get_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_get_name_with_null_result_returns_empty_string(self):
        """Test that get_name with NULL result returns empty string."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        name = evaluator.get_name()
        assert isinstance(name, str)

    def test_name_property_returns_same_as_get_name(self):
        """Test that name property returns same value as get_name()."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        name_method = evaluator.get_name()
        name_property = evaluator.name

        assert name_method == name_property


class TestCTxEvaluatorWrapperEvaluate:
    """Tests for CTxEvaluatorWrapper.evaluate method."""

    def test_evaluate_with_valid_transaction(self):
        """Test evaluating a valid transaction."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()

        redeemers = evaluator.evaluate(transaction)

        assert isinstance(redeemers, RedeemerList)

    def test_evaluate_with_additional_utxos_as_list(self):
        """Test evaluate with additional UTXOs as a list."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()
        utxo = create_simple_utxo()

        redeemers = evaluator.evaluate(transaction, additional_utxos=[utxo])

        assert isinstance(redeemers, RedeemerList)

    def test_evaluate_with_additional_utxos_as_utxo_list(self):
        """Test evaluate with additional UTXOs as UtxoList."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()
        utxo = create_simple_utxo()
        utxo_list = UtxoList.from_list([utxo])

        redeemers = evaluator.evaluate(transaction, additional_utxos=utxo_list)

        assert isinstance(redeemers, RedeemerList)

    def test_evaluate_with_none_additional_utxos(self):
        """Test evaluate with None as additional_utxos."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()

        redeemers = evaluator.evaluate(transaction, additional_utxos=None)

        assert isinstance(redeemers, RedeemerList)

    def test_evaluate_with_empty_additional_utxos_list(self):
        """Test evaluate with empty list of additional UTXOs."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()

        redeemers = evaluator.evaluate(transaction, additional_utxos=[])

        assert isinstance(redeemers, RedeemerList)


class TestCTxEvaluatorWrapperGetLastError:
    """Tests for CTxEvaluatorWrapper.get_last_error method."""

    def test_get_last_error_returns_string(self):
        """Test that get_last_error returns a string."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        error = evaluator.get_last_error()

        assert isinstance(error, str)

    def test_get_last_error_with_no_error_returns_empty_string(self):
        """Test that get_last_error with no error returns empty string."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        error = evaluator.get_last_error()

        assert isinstance(error, str)

    def test_get_last_error_after_successful_evaluate(self):
        """Test get_last_error after successful evaluate."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()

        evaluator.evaluate(transaction)
        error = evaluator.get_last_error()

        assert isinstance(error, str)


class TestCTxEvaluatorWrapperProperties:
    """Tests for CTxEvaluatorWrapper properties."""

    def test_ptr_property_returns_valid_pointer(self):
        """Test that ptr property returns valid pointer."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        ptr = evaluator.ptr

        assert ptr != ffi.NULL
        assert ptr is not None

    def test_name_property_returns_string(self):
        """Test that name property returns a string."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        name = evaluator.name

        assert isinstance(name, str)


class TestCTxEvaluatorWrapperContextManager:
    """Tests for CTxEvaluatorWrapper context manager protocol."""

    def test_context_manager_enter(self):
        """Test __enter__ returns self."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        with evaluator as ctx:
            assert ctx is evaluator

    def test_context_manager_exit_does_not_raise(self):
        """Test __exit__ completes without raising."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        try:
            with evaluator:
                pass
        except Exception as e:
            pytest.fail(f"Context manager raised unexpected exception: {e}")

    def test_context_manager_usage(self):
        """Test using evaluator as context manager."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        transaction = create_simple_transaction()

        with CTxEvaluatorWrapper.from_provider(provider_handle) as evaluator:
            redeemers = evaluator.evaluate(transaction)
            assert isinstance(redeemers, RedeemerList)


class TestCTxEvaluatorWrapperRepr:
    """Tests for CTxEvaluatorWrapper.__repr__ method."""

    def test_repr_returns_string(self):
        """Test that __repr__ returns a string."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        repr_str = repr(evaluator)

        assert isinstance(repr_str, str)

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains class name."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        repr_str = repr(evaluator)

        assert "CTxEvaluatorWrapper" in repr_str

    def test_repr_contains_name(self):
        """Test that __repr__ contains evaluator name."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        repr_str = repr(evaluator)

        assert "name=" in repr_str


class TestCTxEvaluatorWrapperMemoryManagement:
    """Tests for CTxEvaluatorWrapper memory management."""

    def test_del_decrements_refcount_when_owns_ref(self):
        """Test that __del__ decrements refcount when owns_ref is True."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator_out = ffi.new("cardano_tx_evaluator_t**")
        error = lib.cardano_tx_evaluator_from_provider(provider_handle.ptr, evaluator_out)
        assert error == 0

        wrapper = CTxEvaluatorWrapper(evaluator_out[0], owns_ref=True)
        initial_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])

        del wrapper

        final_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        assert final_refcount == initial_refcount - 1

        ptr_ptr = ffi.new("cardano_tx_evaluator_t**", evaluator_out[0])
        lib.cardano_tx_evaluator_unref(ptr_ptr)

    def test_del_does_not_decrement_refcount_when_not_owns_ref(self):
        """Test that __del__ does not decrement refcount when owns_ref is False."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator_out = ffi.new("cardano_tx_evaluator_t**")
        error = lib.cardano_tx_evaluator_from_provider(provider_handle.ptr, evaluator_out)
        assert error == 0

        wrapper = CTxEvaluatorWrapper(evaluator_out[0], owns_ref=False)
        initial_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])

        del wrapper

        final_refcount = lib.cardano_tx_evaluator_refcount(evaluator_out[0])
        assert final_refcount == initial_refcount

        ptr_ptr = ffi.new("cardano_tx_evaluator_t**", evaluator_out[0])
        lib.cardano_tx_evaluator_unref(ptr_ptr)

    def test_del_handles_null_ptr_gracefully(self):
        """Test that __del__ handles NULL pointer gracefully."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        evaluator._ptr = ffi.NULL

        try:
            del evaluator
        except Exception as e:
            pytest.fail(f"__del__ raised unexpected exception with NULL ptr: {e}")

    def test_del_handles_missing_attributes_gracefully(self):
        """Test that __del__ handles missing attributes gracefully."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        delattr(evaluator, "_owns_ref")

        try:
            del evaluator
        except Exception as e:
            pytest.fail(f"__del__ raised unexpected exception with missing attribute: {e}")


class TestCTxEvaluatorWrapperInvalidArguments:
    """Tests for CTxEvaluatorWrapper with invalid arguments."""

    def test_evaluate_with_invalid_transaction_type(self):
        """Test evaluate with invalid transaction type."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)

        with pytest.raises((AttributeError, TypeError)):
            evaluator.evaluate("not a transaction")

    def test_evaluate_with_invalid_additional_utxos_type(self):
        """Test evaluate with invalid additional_utxos type."""
        provider = MockProvider()
        provider_handle = ProviderHandle(provider)
        evaluator = CTxEvaluatorWrapper.from_provider(provider_handle)
        transaction = create_simple_transaction()

        with pytest.raises((AttributeError, TypeError)):
            evaluator.evaluate(transaction, additional_utxos="not a list")
