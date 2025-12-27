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
from typing import List, Tuple, Union
from cometa.transaction_builder.coin_selection.coin_selector import (
    CoinSelectorProtocol,
    CoinSelector,
)


class MockCoinSelector:
    """Mock implementation of CoinSelectorProtocol for testing."""

    def __init__(self, name: str = "MockSelector"):
        """
        Initialize the mock coin selector.

        Args:
            name: The name of this coin selector.
        """
        self._name = name
        self._select_called = False
        self._get_name_called = False

    def get_name(self) -> str:
        """
        Get the human-readable name of this coin selector.

        Returns:
            The coin selector name.
        """
        self._get_name_called = True
        return self._name

    def select(
        self,
        pre_selected_utxo,
        available_utxo,
        target,
    ) -> Tuple[List, List]:
        """
        Select UTXOs to satisfy the target value.

        Args:
            pre_selected_utxo: UTXOs that must be included in the selection.
            available_utxo: Available UTXOs to choose from.
            target: The target value to satisfy.

        Returns:
            A tuple of (selected_utxos, remaining_utxos).
        """
        self._select_called = True
        if isinstance(available_utxo, list):
            return (list(available_utxo), [])
        return ([], [])


class EmptyCoinSelector:
    """Coin selector that returns empty lists."""

    def get_name(self) -> str:
        """Get the name of this coin selector."""
        return "Empty Coin Selector"

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Select no UTXOs."""
        return ([], list(available_utxo) if isinstance(available_utxo, list) else [])


class InsufficientFundsCoinSelector:
    """Coin selector that raises an exception for insufficient funds."""

    def get_name(self) -> str:
        """Get the name of this coin selector."""
        return "InsufficientFunds"

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Raise an exception to simulate insufficient funds."""
        raise Exception("Insufficient funds")


class TestCoinSelectorProtocol:
    """Tests for CoinSelectorProtocol."""

    def test_can_import_protocol(self):
        """Test that CoinSelectorProtocol can be imported."""
        assert CoinSelectorProtocol is not None

    def test_can_import_alias(self):
        """Test that CoinSelector alias can be imported."""
        assert CoinSelector is not None

    def test_alias_refers_to_protocol(self):
        """Test that CoinSelector is an alias for CoinSelectorProtocol."""
        assert CoinSelector is CoinSelectorProtocol

    def test_protocol_has_get_name_method(self):
        """Test that the protocol defines get_name method."""
        assert hasattr(CoinSelectorProtocol, "get_name")

    def test_protocol_has_select_method(self):
        """Test that the protocol defines select method."""
        assert hasattr(CoinSelectorProtocol, "select")

    def test_mock_implementation_conforms_to_protocol(self):
        """Test that MockCoinSelector conforms to the protocol."""
        selector = MockCoinSelector()
        assert hasattr(selector, "get_name")
        assert hasattr(selector, "select")
        assert callable(selector.get_name)
        assert callable(selector.select)


class TestMockCoinSelectorGetName:
    """Tests for MockCoinSelector.get_name() method."""

    def test_can_get_name(self):
        """Test that get_name returns the selector name."""
        selector = MockCoinSelector("TestSelector")
        name = selector.get_name()
        assert name == "TestSelector"

    def test_get_name_returns_string(self):
        """Test that get_name returns a string."""
        selector = MockCoinSelector()
        name = selector.get_name()
        assert isinstance(name, str)

    def test_get_name_with_default_name(self):
        """Test that get_name returns default name when not specified."""
        selector = MockCoinSelector()
        name = selector.get_name()
        assert name == "MockSelector"

    def test_get_name_with_empty_string(self):
        """Test that get_name can return empty string."""
        selector = MockCoinSelector("")
        name = selector.get_name()
        assert name == ""

    def test_get_name_sets_called_flag(self):
        """Test that get_name sets the called flag."""
        selector = MockCoinSelector()
        assert not selector._get_name_called
        selector.get_name()
        assert selector._get_name_called


class TestMockCoinSelectorSelect:
    """Tests for MockCoinSelector.select() method."""

    def test_can_select_with_empty_utxos(self):
        """Test that select works with empty UTXO lists."""
        selector = MockCoinSelector()
        selected, remaining = selector.select([], [], None)
        assert isinstance(selected, list)
        assert isinstance(remaining, list)

    def test_select_with_available_utxos(self):
        """Test that select returns available UTXOs as selected."""
        selector = MockCoinSelector()
        available = ["utxo1", "utxo2", "utxo3"]
        selected, remaining = selector.select([], available, None)
        assert selected == available
        assert remaining == []

    def test_select_with_none_pre_selected(self):
        """Test that select handles None pre_selected_utxo."""
        selector = MockCoinSelector()
        available = ["utxo1"]
        selected, remaining = selector.select(None, available, None)
        assert selected == available

    def test_select_with_none_available(self):
        """Test that select handles None available_utxo."""
        selector = MockCoinSelector()
        selected, remaining = selector.select([], None, None)
        assert selected == []
        assert remaining == []

    def test_select_with_none_target(self):
        """Test that select handles None target."""
        selector = MockCoinSelector()
        available = ["utxo1"]
        selected, remaining = selector.select([], available, None)
        assert len(selected) > 0

    def test_select_sets_called_flag(self):
        """Test that select sets the called flag."""
        selector = MockCoinSelector()
        assert not selector._select_called
        selector.select([], [], None)
        assert selector._select_called

    def test_select_returns_tuple(self):
        """Test that select returns a tuple."""
        selector = MockCoinSelector()
        result = selector.select([], [], None)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_select_returns_lists(self):
        """Test that select returns two lists."""
        selector = MockCoinSelector()
        selected, remaining = selector.select([], [], None)
        assert isinstance(selected, list)
        assert isinstance(remaining, list)


class TestEmptyCoinSelector:
    """Tests for EmptyCoinSelector implementation."""

    def test_get_name_returns_correct_name(self):
        """Test that get_name returns the correct name."""
        selector = EmptyCoinSelector()
        assert selector.get_name() == "Empty Coin Selector"

    def test_select_returns_empty_selected(self):
        """Test that select returns empty selected list."""
        selector = EmptyCoinSelector()
        selected, remaining = selector.select([], [], None)
        assert len(selected) == 0

    def test_select_preserves_available_utxos_in_remaining(self):
        """Test that select moves all available UTXOs to remaining."""
        selector = EmptyCoinSelector()
        available = ["utxo1", "utxo2"]
        selected, remaining = selector.select([], available, None)
        assert len(selected) == 0
        assert remaining == available

    def test_select_with_pre_selected_utxos(self):
        """Test that select ignores pre-selected UTXOs."""
        selector = EmptyCoinSelector()
        pre_selected = ["pre1", "pre2"]
        available = ["utxo1"]
        selected, remaining = selector.select(pre_selected, available, None)
        assert len(selected) == 0
        assert remaining == available


class TestInsufficientFundsCoinSelector:
    """Tests for InsufficientFundsCoinSelector implementation."""

    def test_get_name_returns_correct_name(self):
        """Test that get_name returns the correct name."""
        selector = InsufficientFundsCoinSelector()
        assert selector.get_name() == "InsufficientFunds"

    def test_select_raises_exception(self):
        """Test that select raises an exception."""
        selector = InsufficientFundsCoinSelector()
        with pytest.raises(Exception) as exc_info:
            selector.select([], [], None)
        assert "Insufficient funds" in str(exc_info.value)

    def test_select_raises_exception_with_utxos(self):
        """Test that select raises exception even with UTXOs available."""
        selector = InsufficientFundsCoinSelector()
        available = ["utxo1", "utxo2"]
        with pytest.raises(Exception) as exc_info:
            selector.select([], available, None)
        assert "Insufficient funds" in str(exc_info.value)


class TestCoinSelectorProtocolContract:
    """Tests to verify implementations conform to the protocol contract."""

    def test_implementations_have_required_methods(self):
        """Test that all implementations have required methods."""
        implementations = [
            MockCoinSelector(),
            EmptyCoinSelector(),
            InsufficientFundsCoinSelector(),
        ]
        for impl in implementations:
            assert hasattr(impl, "get_name")
            assert hasattr(impl, "select")
            assert callable(impl.get_name)
            assert callable(impl.select)

    def test_get_name_returns_string_for_all_implementations(self):
        """Test that get_name returns string for all implementations."""
        implementations = [
            MockCoinSelector(),
            EmptyCoinSelector(),
            InsufficientFundsCoinSelector(),
        ]
        for impl in implementations:
            name = impl.get_name()
            assert isinstance(name, str)

    def test_select_accepts_three_arguments(self):
        """Test that select accepts three arguments."""
        selector = MockCoinSelector()
        try:
            selector.select([], [], None)
        except TypeError as e:
            pytest.fail(f"select() should accept three arguments: {e}")

    def test_select_returns_tuple_with_two_elements(self):
        """Test that select returns tuple with two elements."""
        implementations = [MockCoinSelector(), EmptyCoinSelector()]
        for impl in implementations:
            result = impl.select([], [], None)
            assert isinstance(result, tuple)
            assert len(result) == 2


class TestCoinSelectorEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_selectors_can_coexist(self):
        """Test that multiple selector instances can coexist."""
        selector1 = MockCoinSelector("Selector1")
        selector2 = MockCoinSelector("Selector2")
        assert selector1.get_name() != selector2.get_name()

    def test_selector_is_reusable(self):
        """Test that a selector can be used multiple times."""
        selector = MockCoinSelector()
        result1 = selector.select([], ["utxo1"], None)
        result2 = selector.select([], ["utxo2"], None)
        assert result1 != result2

    def test_selector_with_unicode_name(self):
        """Test that selector can have unicode characters in name."""
        selector = MockCoinSelector("コインセレクター")
        assert selector.get_name() == "コインセレクター"

    def test_selector_with_very_long_name(self):
        """Test that selector can have a very long name."""
        long_name = "A" * 1000
        selector = MockCoinSelector(long_name)
        assert len(selector.get_name()) == 1000

    def test_empty_selector_with_empty_inputs(self):
        """Test empty selector with all empty inputs."""
        selector = EmptyCoinSelector()
        selected, remaining = selector.select([], [], None)
        assert selected == []
        assert remaining == []

    def test_selector_with_large_utxo_list(self):
        """Test selector with a large number of UTXOs."""
        selector = MockCoinSelector()
        large_list = [f"utxo{i}" for i in range(10000)]
        selected, remaining = selector.select([], large_list, None)
        assert len(selected) == 10000
        assert len(remaining) == 0


class TestCoinSelectorDocumentation:
    """Tests to verify documentation is present and correct."""

    def test_protocol_has_docstring(self):
        """Test that CoinSelectorProtocol has a docstring."""
        assert CoinSelectorProtocol.__doc__ is not None
        assert len(CoinSelectorProtocol.__doc__) > 0

    def test_protocol_docstring_mentions_coin_selection(self):
        """Test that protocol docstring mentions coin selection."""
        assert "coin selection" in CoinSelectorProtocol.__doc__.lower()

    def test_get_name_has_docstring(self):
        """Test that get_name method has a docstring."""
        selector = MockCoinSelector()
        assert selector.get_name.__doc__ is not None

    def test_select_has_docstring(self):
        """Test that select method has a docstring."""
        selector = MockCoinSelector()
        assert selector.select.__doc__ is not None

    def test_protocol_docstring_mentions_utxo(self):
        """Test that protocol docstring mentions UTXO."""
        assert "utxo" in CoinSelectorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_example(self):
        """Test that protocol docstring includes usage example."""
        assert "example" in CoinSelectorProtocol.__doc__.lower()


class TestCoinSelectorTypeAnnotations:
    """Tests for type annotations on the protocol."""

    def test_get_name_return_type(self):
        """Test that get_name has correct return type annotation."""
        import inspect
        sig = inspect.signature(CoinSelectorProtocol.get_name)
        assert sig.return_annotation in (str, "str")

    def test_select_return_type(self):
        """Test that select has correct return type annotation."""
        import inspect
        sig = inspect.signature(CoinSelectorProtocol.select)
        return_annotation = sig.return_annotation
        assert "Tuple" in str(return_annotation) or "tuple" in str(return_annotation)

    def test_protocol_methods_have_annotations(self):
        """Test that protocol methods have type annotations."""
        import inspect
        get_name_sig = inspect.signature(CoinSelectorProtocol.get_name)
        select_sig = inspect.signature(CoinSelectorProtocol.select)
        assert get_name_sig.return_annotation is not inspect.Signature.empty
        assert select_sig.return_annotation is not inspect.Signature.empty
