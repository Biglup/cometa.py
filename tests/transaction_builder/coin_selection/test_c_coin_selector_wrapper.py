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
from cometa import (
    Utxo,
    UtxoList,
    TransactionInput,
    TransactionOutput,
    Address,
    Value,
)
from cometa.transaction_builder.coin_selection import (
    LargeFirstCoinSelector,
    CCoinSelectorWrapper,
)
from cometa.errors import CardanoError
from cometa._ffi import ffi


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"


def create_test_utxo(index: int = 0, lovelace: int = 1000000) -> Utxo:
    """
    Create a test UTXO for testing purposes.

    Args:
        index: The transaction input index.
        lovelace: The amount of lovelace in the output.

    Returns:
        A new Utxo instance.
    """
    tx_input = TransactionInput.from_hex(TX_ID_HASH, index)
    address = Address.from_string(TEST_ADDRESS)
    tx_output = TransactionOutput.new(address, lovelace)
    return Utxo.new(tx_input, tx_output)


def create_test_utxo_list(count: int = 3, lovelace_per_utxo: int = 1000000) -> UtxoList:
    """
    Create a test UtxoList for testing purposes.

    Args:
        count: Number of UTXOs to create.
        lovelace_per_utxo: Amount of lovelace per UTXO.

    Returns:
        A new UtxoList instance.
    """
    utxos = [create_test_utxo(i, lovelace_per_utxo) for i in range(count)]
    return UtxoList.from_list(utxos)


class TestCCoinSelectorWrapperInit:
    """Tests for CCoinSelectorWrapper.__init__() method."""

    def test_init_with_null_pointer_raises_error(self):
        """Test that initialization with NULL pointer raises CardanoError."""
        with pytest.raises(CardanoError) as exc_info:
            CCoinSelectorWrapper(ffi.NULL)
        assert "invalid handle" in str(exc_info.value)

    def test_init_with_valid_pointer(self):
        """Test that initialization with valid pointer succeeds."""
        selector = LargeFirstCoinSelector.new()
        wrapper = CCoinSelectorWrapper(selector.ptr, owns_ref=False)
        assert wrapper is not None
        assert wrapper.ptr != ffi.NULL

    def test_init_with_owns_ref_true(self):
        """Test initialization with owns_ref=True increments reference."""
        selector = LargeFirstCoinSelector.new()
        wrapper = CCoinSelectorWrapper(selector.ptr, owns_ref=True)
        assert wrapper is not None
        assert wrapper._owns_ref is True

    def test_init_with_owns_ref_false(self):
        """Test initialization with owns_ref=False does not increment reference."""
        selector = LargeFirstCoinSelector.new()
        wrapper = CCoinSelectorWrapper(selector.ptr, owns_ref=False)
        assert wrapper is not None
        assert wrapper._owns_ref is False

    def test_init_default_owns_ref_is_true(self):
        """Test that default value for owns_ref is True."""
        selector = LargeFirstCoinSelector.new()
        wrapper = CCoinSelectorWrapper(selector.ptr)
        assert wrapper._owns_ref is True


class TestCCoinSelectorWrapperGetName:
    """Tests for CCoinSelectorWrapper.get_name() method."""

    def test_get_name_returns_string(self):
        """Test that get_name returns a string."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert isinstance(name, str)

    def test_get_name_returns_large_first(self):
        """Test that LargeFirstCoinSelector has expected name."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert "Large" in name or "large" in name

    def test_get_name_is_not_empty(self):
        """Test that get_name returns non-empty string."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert len(name) > 0

    def test_get_name_returns_consistent_value(self):
        """Test that get_name returns the same value on multiple calls."""
        selector = LargeFirstCoinSelector.new()
        name1 = selector.get_name()
        name2 = selector.get_name()
        assert name1 == name2


class TestCCoinSelectorWrapperNameProperty:
    """Tests for CCoinSelectorWrapper.name property."""

    def test_name_property_returns_string(self):
        """Test that name property returns a string."""
        selector = LargeFirstCoinSelector.new()
        name = selector.name
        assert isinstance(name, str)

    def test_name_property_matches_get_name(self):
        """Test that name property returns same value as get_name()."""
        selector = LargeFirstCoinSelector.new()
        assert selector.name == selector.get_name()

    def test_name_property_is_not_empty(self):
        """Test that name property returns non-empty string."""
        selector = LargeFirstCoinSelector.new()
        assert len(selector.name) > 0


class TestCCoinSelectorWrapperPtrProperty:
    """Tests for CCoinSelectorWrapper.ptr property."""

    def test_ptr_property_returns_pointer(self):
        """Test that ptr property returns a pointer."""
        selector = LargeFirstCoinSelector.new()
        ptr = selector.ptr
        assert ptr is not None
        assert ptr != ffi.NULL

    def test_ptr_property_is_consistent(self):
        """Test that ptr property returns the same pointer on multiple calls."""
        selector = LargeFirstCoinSelector.new()
        ptr1 = selector.ptr
        ptr2 = selector.ptr
        assert ptr1 == ptr2


class TestCCoinSelectorWrapperSelect:
    """Tests for CCoinSelectorWrapper.select() method."""

    def test_select_with_empty_available_utxos(self):
        """Test select with empty available UTXO list."""
        selector = LargeFirstCoinSelector.new()
        available = UtxoList()
        target = Value.new(1000000)

        with pytest.raises(CardanoError):
            selector.select(None, available, target)

    def test_select_with_sufficient_utxos(self):
        """Test select with sufficient UTXOs to meet target."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=5, lovelace_per_utxo=2000000)
        target = Value.new(3000000)

        selected, remaining = selector.select(None, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)
        assert len(selected) >= 2

    def test_select_with_pre_selected_utxos(self):
        """Test select with pre-selected UTXOs."""
        selector = LargeFirstCoinSelector.new()
        pre_selected = create_test_utxo_list(count=1, lovelace_per_utxo=1000000)
        available = create_test_utxo_list(count=3, lovelace_per_utxo=2000000)
        target = Value.new(4000000)

        selected, remaining = selector.select(pre_selected, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_with_list_of_utxos(self):
        """Test select with Python list of UTXOs instead of UtxoList."""
        selector = LargeFirstCoinSelector.new()
        utxos = [create_test_utxo(i, 2000000) for i in range(3)]
        target = Value.new(3000000)

        selected, remaining = selector.select(None, utxos, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_with_pre_selected_list(self):
        """Test select with pre-selected UTXOs as Python list."""
        selector = LargeFirstCoinSelector.new()
        pre_selected = [create_test_utxo(0, 1000000)]
        available = create_test_utxo_list(count=3, lovelace_per_utxo=2000000)
        target = Value.new(4000000)

        selected, remaining = selector.select(pre_selected, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_returns_tuple(self):
        """Test that select returns a tuple."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=2, lovelace_per_utxo=2000000)
        target = Value.new(1000000)

        result = selector.select(None, available, target)

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_select_with_exact_match(self):
        """Test select when available UTXOs exactly match target."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=2, lovelace_per_utxo=2000000)
        target = Value.new(4000000)

        selected, remaining = selector.select(None, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_with_single_large_utxo(self):
        """Test select with a single UTXO larger than target."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=1, lovelace_per_utxo=10000000)
        target = Value.new(1000000)

        selected, remaining = selector.select(None, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_with_multiple_small_utxos(self):
        """Test select with many small UTXOs."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=10, lovelace_per_utxo=100000)
        target = Value.new(500000)

        selected, remaining = selector.select(None, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_preserves_available_utxos(self):
        """Test that select does not modify input UTXO lists."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=3, lovelace_per_utxo=2000000)
        original_len = len(available)
        target = Value.new(1000000)

        selector.select(None, available, target)

        assert len(available) == original_len


class TestCCoinSelectorWrapperGetLastError:
    """Tests for CCoinSelectorWrapper.get_last_error() method."""

    def test_get_last_error_returns_string(self):
        """Test that get_last_error returns a string."""
        selector = LargeFirstCoinSelector.new()
        error = selector.get_last_error()
        assert isinstance(error, str)

    def test_get_last_error_initially_empty(self):
        """Test that get_last_error returns empty string initially."""
        selector = LargeFirstCoinSelector.new()
        error = selector.get_last_error()
        assert error == ""

    def test_get_last_error_after_failed_select(self):
        """Test that get_last_error returns error message after failure."""
        selector = LargeFirstCoinSelector.new()
        available = UtxoList()
        target = Value.new(1000000)

        try:
            selector.select(None, available, target)
        except CardanoError:
            error = selector.get_last_error()
            assert isinstance(error, str)


class TestCCoinSelectorWrapperRepr:
    """Tests for CCoinSelectorWrapper.__repr__() method."""

    def test_repr_returns_string(self):
        """Test that __repr__ returns a string."""
        selector = LargeFirstCoinSelector.new()
        repr_str = repr(selector)
        assert isinstance(repr_str, str)

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains the class name."""
        selector = LargeFirstCoinSelector.new()
        repr_str = repr(selector)
        assert "CCoinSelectorWrapper" in repr_str

    def test_repr_contains_name(self):
        """Test that __repr__ contains the selector name."""
        selector = LargeFirstCoinSelector.new()
        repr_str = repr(selector)
        assert "name=" in repr_str

    def test_repr_is_not_empty(self):
        """Test that __repr__ returns non-empty string."""
        selector = LargeFirstCoinSelector.new()
        repr_str = repr(selector)
        assert len(repr_str) > 0


class TestCCoinSelectorWrapperContextManager:
    """Tests for CCoinSelectorWrapper context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that CCoinSelectorWrapper can be used as context manager."""
        selector = LargeFirstCoinSelector.new()
        with selector as s:
            assert s is selector

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self."""
        selector = LargeFirstCoinSelector.new()
        with selector as s:
            assert s == selector

    def test_context_manager_exit_succeeds(self):
        """Test that __exit__ succeeds without error."""
        selector = LargeFirstCoinSelector.new()
        try:
            with selector:
                pass
        except Exception as e:
            pytest.fail(f"Context manager should not raise exception: {e}")

    def test_can_use_selector_inside_context(self):
        """Test that selector can be used inside context manager."""
        with LargeFirstCoinSelector.new() as selector:
            name = selector.get_name()
            assert isinstance(name, str)

    def test_selector_accessible_after_context(self):
        """Test that selector is still accessible after context exits."""
        selector = LargeFirstCoinSelector.new()
        with selector:
            pass
        name = selector.get_name()
        assert isinstance(name, str)


class TestCCoinSelectorWrapperLifecycle:
    """Tests for CCoinSelectorWrapper lifecycle management."""

    def test_del_does_not_crash(self):
        """Test that __del__ does not crash."""
        selector = LargeFirstCoinSelector.new()
        del selector

    def test_can_create_multiple_selectors(self):
        """Test that multiple selectors can coexist."""
        selector1 = LargeFirstCoinSelector.new()
        selector2 = LargeFirstCoinSelector.new()
        assert selector1 is not selector2
        assert selector1.ptr != selector2.ptr

    def test_selector_is_reusable(self):
        """Test that a selector can be used multiple times."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=3, lovelace_per_utxo=2000000)
        target = Value.new(1000000)

        result1 = selector.select(None, available, target)
        result2 = selector.select(None, available, target)

        assert isinstance(result1, tuple)
        assert isinstance(result2, tuple)

    def test_selector_cleanup_after_use(self):
        """Test that selector cleanup works properly."""
        selector = LargeFirstCoinSelector.new()
        name = selector.get_name()
        assert len(name) > 0
        del selector


class TestCCoinSelectorWrapperEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_select_with_zero_target(self):
        """Test select with zero target value."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=3, lovelace_per_utxo=1000000)
        target = Value.new(0)

        selected, remaining = selector.select(None, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)

    def test_select_with_very_large_target(self):
        """Test select with target larger than available UTXOs."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=2, lovelace_per_utxo=1000000)
        target = Value.new(10000000)

        with pytest.raises(CardanoError):
            selector.select(None, available, target)

    def test_multiple_selects_in_sequence(self):
        """Test multiple select operations in sequence."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=5, lovelace_per_utxo=2000000)
        target = Value.new(3000000)

        result1 = selector.select(None, available, target)
        result2 = selector.select(None, available, target)

        assert isinstance(result1, tuple)
        assert isinstance(result2, tuple)

    def test_get_name_multiple_times(self):
        """Test calling get_name multiple times."""
        selector = LargeFirstCoinSelector.new()
        names = [selector.get_name() for _ in range(10)]
        assert all(name == names[0] for name in names)

    def test_get_last_error_multiple_times(self):
        """Test calling get_last_error multiple times."""
        selector = LargeFirstCoinSelector.new()
        errors = [selector.get_last_error() for _ in range(5)]
        assert all(isinstance(error, str) for error in errors)


class TestCCoinSelectorWrapperDocumentation:
    """Tests to verify documentation is present and correct."""

    def test_class_has_docstring(self):
        """Test that CCoinSelectorWrapper has a docstring."""
        assert CCoinSelectorWrapper.__doc__ is not None
        assert len(CCoinSelectorWrapper.__doc__) > 0

    def test_init_has_docstring(self):
        """Test that __init__ has a docstring."""
        assert CCoinSelectorWrapper.__init__.__doc__ is not None

    def test_get_name_has_docstring(self):
        """Test that get_name has a docstring."""
        assert CCoinSelectorWrapper.get_name.__doc__ is not None

    def test_select_has_docstring(self):
        """Test that select has a docstring."""
        assert CCoinSelectorWrapper.select.__doc__ is not None

    def test_get_last_error_has_docstring(self):
        """Test that get_last_error has a docstring."""
        assert CCoinSelectorWrapper.get_last_error.__doc__ is not None

    def test_ptr_property_has_docstring(self):
        """Test that ptr property has a docstring."""
        assert CCoinSelectorWrapper.ptr.fget.__doc__ is not None

    def test_name_property_has_docstring(self):
        """Test that name property has a docstring."""
        assert CCoinSelectorWrapper.name.fget.__doc__ is not None

    def test_class_docstring_mentions_coin_selector(self):
        """Test that class docstring mentions coin selector."""
        assert "coin selector" in CCoinSelectorWrapper.__doc__.lower()

    def test_select_docstring_mentions_utxo(self):
        """Test that select docstring mentions UTXO."""
        assert "utxo" in CCoinSelectorWrapper.select.__doc__.lower()


class TestCCoinSelectorWrapperTypeAnnotations:
    """Tests for type annotations."""

    def test_get_name_returns_str(self):
        """Test that get_name returns str type."""
        selector = LargeFirstCoinSelector.new()
        result = selector.get_name()
        assert isinstance(result, str)

    def test_select_returns_tuple(self):
        """Test that select returns tuple type."""
        selector = LargeFirstCoinSelector.new()
        available = create_test_utxo_list(count=1, lovelace_per_utxo=2000000)
        target = Value.new(1000000)
        result = selector.select(None, available, target)
        assert isinstance(result, tuple)

    def test_get_last_error_returns_str(self):
        """Test that get_last_error returns str type."""
        selector = LargeFirstCoinSelector.new()
        result = selector.get_last_error()
        assert isinstance(result, str)


class TestCCoinSelectorWrapperIntegration:
    """Integration tests for CCoinSelectorWrapper."""

    def test_large_first_selector_integration(self):
        """Test integration with LargeFirstCoinSelector."""
        selector = LargeFirstCoinSelector.new()
        assert isinstance(selector, CCoinSelectorWrapper)
        assert "large" in selector.get_name().lower()

    def test_end_to_end_coin_selection(self):
        """Test end-to-end coin selection workflow."""
        selector = LargeFirstCoinSelector.new()

        utxo1 = create_test_utxo(0, 5000000)
        utxo2 = create_test_utxo(1, 3000000)
        utxo3 = create_test_utxo(2, 2000000)

        available = UtxoList.from_list([utxo1, utxo2, utxo3])
        target = Value.new(6000000)

        selected, remaining = selector.select(None, available, target)

        assert len(selected) >= 1
        assert len(selected) + len(remaining) == len(available)

    def test_coin_selection_with_pre_selected(self):
        """Test coin selection with pre-selected UTXOs."""
        selector = LargeFirstCoinSelector.new()

        pre_selected_utxo = create_test_utxo(0, 2000000)
        pre_selected = UtxoList.from_list([pre_selected_utxo])

        available_utxos = [
            create_test_utxo(1, 3000000),
            create_test_utxo(2, 4000000),
        ]
        available = UtxoList.from_list(available_utxos)

        target = Value.new(5000000)

        selected, remaining = selector.select(pre_selected, available, target)

        assert isinstance(selected, UtxoList)
        assert isinstance(remaining, UtxoList)
