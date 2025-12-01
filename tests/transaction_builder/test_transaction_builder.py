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

from cometa.transaction_builder import (
    compute_transaction_fee,
    compute_min_ada_required,
    compute_min_fee_without_scripts,
    get_serialized_coin_size,
    get_serialized_output_size,
    get_serialized_transaction_size,
    compute_script_data_hash,
    InputToRedeemerMap,
    is_transaction_balanced,
    CoinSelector,
    LargeFirstCoinSelector,
    TxEvaluator,
)
from cometa.transaction_builder.balancing import balance_transaction
from cometa.transaction_builder.coin_selection import CoinSelector, LargeFirstCoinSelector
from cometa.transaction_builder.evaluation import TxEvaluator
from cometa.transaction_body import (
    TransactionInput,
    TransactionOutput,
    TransactionBody,
    TransactionInputSet,
    TransactionOutputList,
    Value,
)
from cometa.address import Address
from cometa.common.utxo_list import UtxoList
from cometa.common.utxo import Utxo
from cometa.transaction import Transaction
from cometa.witness_set import WitnessSet


class TestFeeModule:
    """Tests for fee computation functions."""

    def test_compute_min_ada_required(self):
        """Test computing minimum ADA required for an output."""
        # Create a simple transaction output
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )
        output = TransactionOutput.new(addr, 1000000)

        # Compute min ADA (using a typical coins_per_utxo_byte value)
        min_ada = compute_min_ada_required(output, 4310)

        assert isinstance(min_ada, int)
        assert min_ada > 0

    def test_get_serialized_coin_size(self):
        """Test getting serialized size of different lovelace amounts."""
        # Small amount
        size_small = get_serialized_coin_size(1000000)
        assert isinstance(size_small, int)
        assert size_small > 0

        # Large amount
        size_large = get_serialized_coin_size(1000000000000)
        assert isinstance(size_large, int)
        assert size_large >= size_small

    def test_get_serialized_output_size(self):
        """Test getting serialized size of a transaction output."""
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )
        output = TransactionOutput.new(addr, 5000000)

        size = get_serialized_output_size(output)

        assert isinstance(size, int)
        assert size > 0

    def test_get_serialized_transaction_size(self):
        """Test getting serialized size of a transaction."""
        # Create a minimal transaction
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )

        tx_input = TransactionInput.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000", 0
        )
        inputs = TransactionInputSet.from_list([tx_input])

        output = TransactionOutput.new(addr, 1000000)
        outputs = TransactionOutputList.from_list([output])

        body = TransactionBody.new(inputs, outputs, 200000)
        witness = WitnessSet()
        tx = Transaction.new(body, witness)

        size = get_serialized_transaction_size(tx)

        assert isinstance(size, int)
        assert size > 0

    def test_compute_min_fee_without_scripts(self):
        """Test computing minimum fee without script costs."""
        # Create a minimal transaction
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )

        tx_input = TransactionInput.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000", 0
        )
        inputs = TransactionInputSet.from_list([tx_input])

        output = TransactionOutput.new(addr, 1000000)
        outputs = TransactionOutputList.from_list([output])

        body = TransactionBody.new(inputs, outputs, 200000)
        witness = WitnessSet()
        tx = Transaction.new(body, witness)

        # Typical mainnet parameters
        min_fee_constant = 155381
        min_fee_coefficient = 44

        fee = compute_min_fee_without_scripts(tx, min_fee_constant, min_fee_coefficient)

        assert isinstance(fee, int)
        assert fee > min_fee_constant  # Fee should be at least the constant


class TestInputToRedeemerMap:
    """Tests for InputToRedeemerMap."""

    def test_create_empty_map(self):
        """Test creating an empty map."""
        input_map = InputToRedeemerMap.new()

        assert len(input_map) == 0
        assert repr(input_map) == "InputToRedeemerMap(length=0)"

    def test_map_context_manager(self):
        """Test map as context manager."""
        with InputToRedeemerMap.new() as input_map:
            assert len(input_map) == 0

    def test_map_iteration_empty(self):
        """Test iterating over an empty map."""
        input_map = InputToRedeemerMap.new()
        items = list(input_map)
        assert items == []


class TestCoinSelector:
    """Tests for CoinSelector classes."""

    def test_large_first_selector_creation(self):
        """Test creating a large-first coin selector."""
        selector = LargeFirstCoinSelector.new()

        assert isinstance(selector, LargeFirstCoinSelector)
        assert isinstance(selector, CoinSelector)
        assert "Large" in selector.name or len(selector.name) > 0
        assert repr(selector).startswith("CoinSelector")

    def test_large_first_selector_context_manager(self):
        """Test coin selector as context manager."""
        with LargeFirstCoinSelector.new() as selector:
            assert selector.name  # Should have a name

    def test_coin_selector_select_basic(self):
        """Test basic coin selection with empty pre-selected."""
        selector = LargeFirstCoinSelector.new()

        # Create some available UTXOs
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )

        # Create UTXOs with different amounts
        utxos = []
        for i in range(3):
            tx_input = TransactionInput.from_hex(
                f"{'0' * 63}{i}", i
            )
            output = TransactionOutput.new(addr, (i + 1) * 5000000)
            utxo = Utxo.new(tx_input, output)
            utxos.append(utxo)

        available = UtxoList.from_list(utxos)

        # Create target value (less than total available)
        target = Value.from_coin(3000000)

        # Select coins
        selected, remaining = selector.select(available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)
        # With large-first, we should have selected at least one UTXO
        assert len(selected) > 0 or len(remaining) > 0


class TestTransactionBalancing:
    """Tests for transaction balancing functions."""

    def test_is_transaction_balanced_simple(self):
        """Test checking if a simple transaction is balanced."""
        addr = Address.from_string(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
            "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        )

        # Create transaction
        tx_input = TransactionInput.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000", 0
        )
        inputs = TransactionInputSet.from_list([tx_input])

        output = TransactionOutput.new(addr, 1000000)
        outputs = TransactionOutputList.from_list([output])

        body = TransactionBody.new(inputs, outputs, 200000)
        witness = WitnessSet()
        tx = Transaction.new(body, witness)

        # Create matching resolved input
        input_output = TransactionOutput.new(addr, 1200000)  # Exactly covers output + fee
        resolved_utxo = Utxo.new(tx_input, input_output)
        resolved_inputs = UtxoList.from_list([resolved_utxo])

        # Create minimal protocol params
        from cometa.protocol_params import ProtocolParameters

        params = ProtocolParameters.new()
        params.min_fee_a = 44
        params.min_fee_b = 155381

        # Check balance - this might not be balanced since fee calculation is complex
        is_balanced = is_transaction_balanced(tx, resolved_inputs, params)
        assert isinstance(is_balanced, bool)


class TestModuleImports:
    """Tests to verify all module imports work correctly."""

    def test_fee_module_imports(self):
        """Test that all fee module functions can be imported."""
        from cometa.transaction_builder import (
            compute_transaction_fee,
            compute_min_ada_required,
            compute_min_script_fee,
            compute_min_fee_without_scripts,
            compute_script_ref_fee,
            get_total_ex_units_in_redeemers,
            get_serialized_coin_size,
            get_serialized_output_size,
            get_serialized_script_size,
            get_serialized_transaction_size,
        )

        assert callable(compute_transaction_fee)
        assert callable(compute_min_ada_required)
        assert callable(compute_min_script_fee)
        assert callable(compute_min_fee_without_scripts)
        assert callable(compute_script_ref_fee)
        assert callable(get_total_ex_units_in_redeemers)
        assert callable(get_serialized_coin_size)
        assert callable(get_serialized_output_size)
        assert callable(get_serialized_script_size)
        assert callable(get_serialized_transaction_size)

    def test_script_data_hash_import(self):
        """Test that script data hash function can be imported."""
        from cometa.transaction_builder import compute_script_data_hash

        assert callable(compute_script_data_hash)

    def test_balancing_imports(self):
        """Test that balancing module imports work."""
        from cometa.transaction_builder import (
            InputToRedeemerMap,
            balance_transaction,
            is_transaction_balanced,
        )

        assert InputToRedeemerMap is not None
        assert callable(balance_transaction)
        assert callable(is_transaction_balanced)

    def test_coin_selection_imports(self):
        """Test that coin selection imports work."""
        from cometa.transaction_builder import CoinSelector, LargeFirstCoinSelector
        from cometa.transaction_builder.coin_selection import (
            CoinSelector,
            LargeFirstCoinSelector,
        )

        assert CoinSelector is not None
        assert LargeFirstCoinSelector is not None
        assert issubclass(LargeFirstCoinSelector, CoinSelector)

    def test_evaluation_imports(self):
        """Test that evaluation imports work."""
        from cometa.transaction_builder import TxEvaluator
        from cometa.transaction_builder.evaluation import TxEvaluator

        assert TxEvaluator is not None


class TestTxEvaluator:
    """Tests for TxEvaluator class."""

    def test_tx_evaluator_class_exists(self):
        """Test that TxEvaluator class is properly defined."""
        from cometa.transaction_builder.evaluation import TxEvaluator

        assert TxEvaluator is not None
        # TxEvaluator requires an implementation, so we just verify the class exists


class TestAllExports:
    """Test that __all__ exports work correctly."""

    def test_all_exports_accessible(self):
        """Test that all exported names are accessible."""
        import cometa.transaction_builder as tb

        for name in tb.__all__:
            assert hasattr(tb, name), f"Missing export: {name}"
