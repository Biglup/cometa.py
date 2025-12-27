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
from cometa.transaction_builder.coin_selection.large_first_coin_selector import (
    LargeFirstCoinSelector,
)
from cometa import (
    Utxo,
    UtxoList,
    TransactionInput,
    TransactionOutput,
    Address,
    Value,
)
from cometa.errors import CardanoError


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TX_ID_HASH_2 = "1111111111111111111111111111111111111111111111111111111111111111"
TX_ID_HASH_3 = "2222222222222222222222222222222222222222222222222222222222222222"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"


def create_test_utxo(
    index: int = 0, lovelace: int = 1000000, tx_hash: str = TX_ID_HASH
) -> Utxo:
    """
    Create a test UTXO for testing purposes.

    Args:
        index: The transaction input index.
        lovelace: The amount of lovelace in the output.
        tx_hash: The transaction hash.

    Returns:
        A new Utxo instance.
    """
    tx_input = TransactionInput.from_hex(tx_hash, index)
    address = Address.from_string(TEST_ADDRESS)
    tx_output = TransactionOutput.new(address, lovelace)
    return Utxo.new(tx_input, tx_output)


class TestLargeFirstCoinSelector:
    """Tests for LargeFirstCoinSelector."""

    def test_can_create_new_selector(self):
        """Test that a new LargeFirstCoinSelector can be created."""
        selector = LargeFirstCoinSelector.new()
        assert selector is not None
        assert isinstance(selector, LargeFirstCoinSelector)

    def test_selector_has_correct_name(self):
        """Test that the selector reports the correct name."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert name == "Large first coin selector"

    def test_selects_largest_first(self):
        """Test that the selector picks the largest UTXO first."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 3000000, TX_ID_HASH_3))

        target = Value.from_coin(2000000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert remaining is not None
        assert len(selected) >= 1

        first_utxo = selected[0]
        first_value = first_utxo.output.value.coin
        assert first_value == 5000000

    def test_selects_at_least_one_input_even_if_target_is_zero(self):
        """Test that at least one input is selected even with zero target."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))

        target = Value.from_coin(0)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert remaining is not None
        assert len(selected) >= 1

    def test_selects_largest_first_and_includes_preselected(self):
        """Test that the selector includes preselected UTXOs."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))

        preselected_utxos = UtxoList()
        preselected_utxos.add(create_test_utxo(2, 2000000, TX_ID_HASH_3))

        target = Value.from_coin(6000000)

        selected, remaining = selector.select(preselected_utxos, available_utxos, target)

        assert selected is not None
        assert remaining is not None
        assert len(selected) >= 2

        total_selected = sum(
            utxo.output.value.coin for utxo in selected
        )
        assert total_selected >= 6000000

    def test_selector_name_is_correct_string(self):
        """Test that get_name returns a valid string."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert isinstance(name, str)
        assert len(name) > 0
        assert "Large" in name or "large" in name
        assert "first" in name or "First" in name

    def test_can_use_selector_multiple_times(self):
        """Test that the same selector can be used for multiple selections."""
        selector = LargeFirstCoinSelector.new()

        for i in range(3):
            available_utxos = UtxoList()
            available_utxos.add(create_test_utxo(0, 1000000 * (i + 1), TX_ID_HASH))
            available_utxos.add(create_test_utxo(1, 5000000 * (i + 1), TX_ID_HASH_2))

            target = Value.from_coin(2000000)

            selected, remaining = selector.select(None, available_utxos, target)

            assert selected is not None
            assert len(selected) >= 1

    def test_empty_available_utxo_list(self):
        """Test selection with an empty available UTXO list."""
        selector = LargeFirstCoinSelector.new()
        available_utxos = UtxoList()
        target = Value.from_coin(1000000)

        with pytest.raises((CardanoError, Exception)):
            selector.select(None, available_utxos, target)

    def test_insufficient_balance(self):
        """Test that selector fails when balance is insufficient."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))

        target = Value.from_coin(99999999999)

        with pytest.raises((CardanoError, Exception)):
            selector.select(None, available_utxos, target)

    def test_preselected_utxo_satisfies_target(self):
        """Test when preselected UTXOs already satisfy the target."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))

        preselected_utxos = UtxoList()
        preselected_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))

        target = Value.from_coin(1000000)

        selected, remaining = selector.select(preselected_utxos, available_utxos, target)

        assert selected is not None
        assert len(selected) >= 1

    def test_single_utxo_exact_match(self):
        """Test selection when a single UTXO exactly matches the target."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 5000000, TX_ID_HASH))

        target = Value.from_coin(5000000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert len(selected) >= 1
        assert selected[0].output.value.coin == 5000000

    def test_selects_multiple_utxos_when_needed(self):
        """Test that multiple UTXOs are selected when a single one isn't enough."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 2000000, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 3000000, TX_ID_HASH_3))

        target = Value.from_coin(5000000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        total_selected = sum(
            utxo.output.value.coin for utxo in selected
        )
        assert total_selected >= 5000000
        assert len(selected) >= 2

    def test_selector_sorts_by_size(self):
        """Test that the selector properly sorts UTXOs by size."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 3000000, TX_ID_HASH_3))

        target = Value.from_coin(100000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert len(selected) >= 1
        first_value = selected[0].output.value.coin
        assert first_value == 5000000

    def test_remaining_utxos_are_correct(self):
        """Test that remaining UTXOs list is correctly populated."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 5000000, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 3000000, TX_ID_HASH_3))

        target = Value.from_coin(2000000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert remaining is not None
        total_count = len(selected) + len(remaining)
        assert total_count == 3

    def test_can_select_from_many_utxos(self):
        """Test selection from a large number of UTXOs."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        for i in range(10):
            available_utxos.add(
                create_test_utxo(i, (i + 1) * 1000000, TX_ID_HASH)
            )

        target = Value.from_coin(5000000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert remaining is not None
        total_selected = sum(
            utxo.output.value.coin for utxo in selected
        )
        assert total_selected >= 5000000


class TestLargeFirstCoinSelectorEdgeCases:
    """Tests for edge cases in LargeFirstCoinSelector."""

    def test_very_large_target_value(self):
        """Test with a very large target value."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000000, TX_ID_HASH))

        target = Value.from_coin(10000000000)

        with pytest.raises((CardanoError, Exception)):
            selector.select(None, available_utxos, target)

    def test_single_utxo_insufficient(self):
        """Test when a single UTXO is insufficient."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))

        target = Value.from_coin(2000000)

        with pytest.raises((CardanoError, Exception)):
            selector.select(None, available_utxos, target)

    def test_all_utxos_same_value(self):
        """Test when all UTXOs have the same value."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 1000000, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 1000000, TX_ID_HASH_3))

        target = Value.from_coin(2500000)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        total_selected = sum(
            utxo.output.value.coin for utxo in selected
        )
        assert total_selected >= 2500000

    def test_preselected_exceeds_target(self):
        """Test when preselected UTXOs exceed the target."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1000000, TX_ID_HASH))

        preselected_utxos = UtxoList()
        preselected_utxos.add(create_test_utxo(1, 10000000, TX_ID_HASH_2))

        target = Value.from_coin(5000000)

        selected, remaining = selector.select(preselected_utxos, available_utxos, target)

        assert selected is not None
        assert len(selected) >= 1

    def test_minimum_lovelace_value(self):
        """Test with minimum lovelace values."""
        selector = LargeFirstCoinSelector.new()

        available_utxos = UtxoList()
        available_utxos.add(create_test_utxo(0, 1, TX_ID_HASH))
        available_utxos.add(create_test_utxo(1, 2, TX_ID_HASH_2))
        available_utxos.add(create_test_utxo(2, 3, TX_ID_HASH_3))

        target = Value.from_coin(1)

        selected, remaining = selector.select(None, available_utxos, target)

        assert selected is not None
        assert len(selected) >= 1
