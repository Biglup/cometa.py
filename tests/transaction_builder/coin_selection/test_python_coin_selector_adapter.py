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
from typing import List, Tuple

from cometa import (
    Utxo,
    UtxoList,
    TransactionInput,
    TransactionOutput,
    Address,
    Value,
)
from cometa.transaction_builder.coin_selection.python_coin_selector_adapter import (
    CoinSelectorHandle,
)
from cometa.errors import CardanoError
from cometa._ffi import ffi, lib


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


class SimpleCoinSelector:
    """Simple coin selector that selects all available UTXOs."""

    def __init__(self, name: str = "SimpleCoinSelector"):
        """
        Initialize the simple coin selector.

        Args:
            name: The name of this coin selector.
        """
        self._name = name

    def get_name(self) -> str:
        """
        Get the human-readable name of this coin selector.

        Returns:
            The coin selector name.
        """
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
        all_utxos = []
        if pre_selected_utxo:
            all_utxos.extend(list(pre_selected_utxo))
        if available_utxo:
            all_utxos.extend(list(available_utxo))
        return (all_utxos, [])


class PartialCoinSelector:
    """Coin selector that selects only the first UTXO."""

    def get_name(self) -> str:
        """Get the name of this coin selector."""
        return "PartialCoinSelector"

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Select only the first UTXO."""
        if not available_utxo:
            return ([], [])
        available_list = list(available_utxo) if hasattr(available_utxo, '__iter__') else []
        if not available_list:
            return ([], [])
        return ([available_list[0]], available_list[1:])


class ErrorCoinSelector:
    """Coin selector that raises an exception."""

    def get_name(self) -> str:
        """Get the name of this coin selector."""
        return "ErrorCoinSelector"

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Raise an exception to simulate selection failure."""
        raise ValueError("Insufficient funds for transaction")


class LongNameCoinSelector:
    """Coin selector with a very long name for testing name truncation."""

    def get_name(self) -> str:
        """Get a very long name."""
        return "A" * 300

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Select all available UTXOs."""
        return (list(available_utxo) if available_utxo else [], [])


class UnicodeCoinSelector:
    """Coin selector with unicode characters in name."""

    def get_name(self) -> str:
        """Get name with unicode characters."""
        return "コインセレクター"

    def select(self, pre_selected_utxo, available_utxo, target) -> Tuple[List, List]:
        """Select all available UTXOs."""
        return (list(available_utxo) if available_utxo else [], [])


class TestCoinSelectorHandleInit:
    """Tests for CoinSelectorHandle.__init__() method."""

    def test_init_with_simple_selector(self):
        """Test initialization with a simple selector."""
        selector = SimpleCoinSelector("TestSelector")
        handle = CoinSelectorHandle(selector)
        assert handle is not None
        assert handle.ptr != ffi.NULL

    def test_init_creates_valid_pointer(self):
        """Test that initialization creates a valid C pointer."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._selector_ptr is not None
        assert handle._selector_ptr[0] != ffi.NULL

    def test_init_stores_selector_reference(self):
        """Test that initialization stores the Python selector reference."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._selector is selector

    def test_init_with_unicode_name(self):
        """Test initialization with unicode name."""
        selector = UnicodeCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle is not None
        assert handle.ptr != ffi.NULL

    def test_init_with_long_name(self):
        """Test initialization with very long name."""
        selector = LongNameCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle is not None
        assert handle.ptr != ffi.NULL

    def test_init_calls_fill_impl_struct(self):
        """Test that initialization fills the impl struct."""
        selector = SimpleCoinSelector("TestName")
        handle = CoinSelectorHandle(selector)
        name_from_c = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert "TestName" in name_from_c or name_from_c == "TestName"

    def test_init_creates_callback(self):
        """Test that initialization creates the callback."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._cb_select is not None


class TestCoinSelectorHandleFillImplStruct:
    """Tests for CoinSelectorHandle._fill_impl_struct() method."""

    def test_fill_impl_struct_sets_name(self):
        """Test that _fill_impl_struct sets the selector name."""
        selector = SimpleCoinSelector("MySelector")
        handle = CoinSelectorHandle(selector)
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert name == "MySelector"

    def test_fill_impl_struct_truncates_long_name(self):
        """Test that _fill_impl_struct truncates long names."""
        selector = LongNameCoinSelector()
        handle = CoinSelectorHandle(selector)
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert len(name) < 256

    def test_fill_impl_struct_handles_unicode(self):
        """Test that _fill_impl_struct handles unicode names."""
        selector = UnicodeCoinSelector()
        handle = CoinSelectorHandle(selector)
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert name == "コインセレクター"

    def test_fill_impl_struct_initializes_error_message(self):
        """Test that _fill_impl_struct initializes error message to empty."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        error = ffi.string(lib.cardano_coin_selector_get_last_error(handle.ptr)).decode("utf-8")
        assert error == ""

    def test_fill_impl_struct_sets_context_to_null(self):
        """Test that _fill_impl_struct sets context to NULL."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._impl[0].context == ffi.NULL


class TestCoinSelectorHandleInstallCallback:
    """Tests for CoinSelectorHandle._install_callback() method."""

    def test_callback_is_stored(self):
        """Test that the callback is stored on the instance."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._cb_select is not None

    def test_callback_is_assigned_to_impl(self):
        """Test that the callback is assigned to the impl struct."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._impl[0].select is not None


class TestCoinSelectorHandleCreateSelector:
    """Tests for CoinSelectorHandle._create_selector() method."""

    def test_create_selector_creates_valid_pointer(self):
        """Test that _create_selector creates a valid pointer."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._selector_ptr[0] != ffi.NULL

    def test_create_selector_sets_name(self):
        """Test that created selector has correct name."""
        selector = SimpleCoinSelector("TestName")
        handle = CoinSelectorHandle(selector)
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert name == "TestName"


class TestCoinSelectorHandlePtrProperty:
    """Tests for CoinSelectorHandle.ptr property."""

    def test_ptr_returns_pointer(self):
        """Test that ptr property returns a pointer."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        ptr = handle.ptr
        assert ptr is not None
        assert ptr != ffi.NULL

    def test_ptr_is_consistent(self):
        """Test that ptr property returns the same pointer on multiple calls."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        ptr1 = handle.ptr
        ptr2 = handle.ptr
        assert ptr1 == ptr2

    def test_ptr_property_matches_internal_pointer(self):
        """Test that ptr property matches internal _selector_ptr."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle.ptr == handle._selector_ptr[0]


class TestCoinSelectorHandleUnderscorePtrProperty:
    """Tests for CoinSelectorHandle._ptr property."""

    def test_underscore_ptr_returns_pointer(self):
        """Test that _ptr property returns a pointer."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        ptr = handle._ptr
        assert ptr is not None
        assert ptr != ffi.NULL

    def test_underscore_ptr_matches_ptr(self):
        """Test that _ptr property matches ptr property."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle._ptr == handle.ptr

    def test_underscore_ptr_is_consistent(self):
        """Test that _ptr property returns the same pointer on multiple calls."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        ptr1 = handle._ptr
        ptr2 = handle._ptr
        assert ptr1 == ptr2


class TestCoinSelectorHandleDel:
    """Tests for CoinSelectorHandle.__del__() method."""

    def test_del_does_not_crash(self):
        """Test that __del__ does not crash."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        del handle

    def test_del_cleans_up_pointer(self):
        """Test that __del__ cleans up the pointer."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        ptr = handle.ptr
        assert ptr != ffi.NULL
        del handle

    def test_multiple_handles_can_be_deleted(self):
        """Test that multiple handles can be deleted safely."""
        handles = [CoinSelectorHandle(SimpleCoinSelector()) for _ in range(5)]
        for handle in handles:
            del handle


class TestCoinSelectorHandleEnter:
    """Tests for CoinSelectorHandle.__enter__() method."""

    def test_enter_returns_self(self):
        """Test that __enter__ returns self."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        result = handle.__enter__()
        assert result is handle

    def test_enter_with_context_manager(self):
        """Test __enter__ with context manager."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        with handle as h:
            assert h is handle


class TestCoinSelectorHandleExit:
    """Tests for CoinSelectorHandle.__exit__() method."""

    def test_exit_does_not_crash(self):
        """Test that __exit__ does not crash."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        handle.__exit__(None, None, None)

    def test_exit_with_exception(self):
        """Test __exit__ with exception arguments."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        try:
            raise ValueError("test error")
        except ValueError as e:
            import sys
            exc_info = sys.exc_info()
            handle.__exit__(exc_info[0], exc_info[1], exc_info[2])

    def test_exit_with_context_manager(self):
        """Test __exit__ with context manager."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        try:
            with handle:
                pass
        except Exception as e:
            pytest.fail(f"Context manager should not raise exception: {e}")


class TestCoinSelectorHandleContextManager:
    """Tests for CoinSelectorHandle context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that CoinSelectorHandle can be used as context manager."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        with handle as h:
            assert h is handle

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        with handle as h:
            assert h == handle

    def test_can_use_handle_inside_context(self):
        """Test that handle can be used inside context manager."""
        selector = SimpleCoinSelector()
        with CoinSelectorHandle(selector) as handle:
            assert handle.ptr != ffi.NULL

    def test_handle_accessible_after_context(self):
        """Test that handle is still accessible after context exits."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        with handle:
            pass
        assert handle.ptr != ffi.NULL


class TestCoinSelectorHandleIntegrationWithSelect:
    """Integration tests for CoinSelectorHandle with select operations."""

    def test_simple_selector_select_with_utxos(self):
        """Test simple selector with actual UTXO selection."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo1 = create_test_utxo(0, 1000000)
        utxo2 = create_test_utxo(1, 2000000)
        available = UtxoList.from_list([utxo1, utxo2])
        target = Value.new(1500000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0
        assert selected_ptr[0] != ffi.NULL

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)

    def test_partial_selector_select(self):
        """Test partial selector that returns only some UTXOs."""
        selector = PartialCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo1 = create_test_utxo(0, 1000000)
        utxo2 = create_test_utxo(1, 2000000)
        utxo3 = create_test_utxo(2, 3000000)
        available = UtxoList.from_list([utxo1, utxo2, utxo3])
        target = Value.new(1000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0
        assert selected_ptr[0] != ffi.NULL
        assert remaining_ptr[0] != ffi.NULL

        from cometa import UtxoList as UL
        lib.cardano_utxo_list_ref(selected_ptr[0])
        selected_list = UL(selected_ptr[0])
        assert len(selected_list) == 1

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)

    def test_error_selector_returns_error(self):
        """Test error selector that raises exception."""
        selector = ErrorCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(1000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result != 0
        error_msg = ffi.string(lib.cardano_coin_selector_get_last_error(handle.ptr)).decode("utf-8")
        assert "Insufficient funds" in error_msg or "ValueError" in error_msg

    def test_select_with_pre_selected_utxos(self):
        """Test selection with pre-selected UTXOs."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        pre_selected_utxo = create_test_utxo(0, 1000000)
        pre_selected = UtxoList.from_list([pre_selected_utxo])

        available_utxo = create_test_utxo(1, 2000000)
        available = UtxoList.from_list([available_utxo])

        target = Value.new(2000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            pre_selected._ptr,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0
        assert selected_ptr[0] != ffi.NULL

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)

    def test_select_with_empty_available(self):
        """Test selection with empty available UTXOs."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        available = UtxoList()
        target = Value.new(1000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0
        assert selected_ptr[0] != ffi.NULL
        assert remaining_ptr[0] != ffi.NULL

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)


class TestCoinSelectorHandleEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_handles_can_coexist(self):
        """Test that multiple selector handles can coexist."""
        handle1 = CoinSelectorHandle(SimpleCoinSelector("Selector1"))
        handle2 = CoinSelectorHandle(SimpleCoinSelector("Selector2"))
        assert handle1 is not handle2
        assert handle1.ptr != handle2.ptr

    def test_handle_is_reusable(self):
        """Test that a handle can be used multiple times."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(500000)

        selected_ptr1 = ffi.new("cardano_utxo_list_t**")
        remaining_ptr1 = ffi.new("cardano_utxo_list_t**")

        result1 = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr1,
            remaining_ptr1
        )

        selected_ptr2 = ffi.new("cardano_utxo_list_t**")
        remaining_ptr2 = ffi.new("cardano_utxo_list_t**")

        result2 = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr2,
            remaining_ptr2
        )

        assert result1 == 0
        assert result2 == 0

        lib.cardano_utxo_list_unref(selected_ptr1)
        lib.cardano_utxo_list_unref(remaining_ptr1)
        lib.cardano_utxo_list_unref(selected_ptr2)
        lib.cardano_utxo_list_unref(remaining_ptr2)

    def test_empty_name_selector(self):
        """Test selector with empty name."""
        selector = SimpleCoinSelector("")
        handle = CoinSelectorHandle(selector)
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert name == ""

    def test_handle_with_large_utxo_list(self):
        """Test handle with a large number of UTXOs."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxos = [create_test_utxo(i, 1000000) for i in range(100)]
        available = UtxoList.from_list(utxos)
        target = Value.new(10000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)


class TestCoinSelectorHandleErrorHandling:
    """Tests for error handling in CoinSelectorHandle."""

    def test_error_selector_sets_error_message(self):
        """Test that error selector sets error message."""
        selector = ErrorCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(1000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result != 0
        error_msg = ffi.string(lib.cardano_coin_selector_get_last_error(handle.ptr)).decode("utf-8")
        assert len(error_msg) > 0

    def test_error_message_is_truncated(self):
        """Test that very long error messages are truncated."""

        class LongErrorSelector:
            """Selector that raises exception with very long message."""

            def get_name(self) -> str:
                """Get the name."""
                return "LongErrorSelector"

            def select(self, pre_selected_utxo, available_utxo, target):
                """Raise exception with long message."""
                raise Exception("A" * 2000)

        selector = LongErrorSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(1000000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result != 0
        error_msg = ffi.string(lib.cardano_coin_selector_get_last_error(handle.ptr)).decode("utf-8")
        assert len(error_msg) < 1024


class TestCoinSelectorHandleDocumentation:
    """Tests to verify documentation is present and correct."""

    def test_class_has_docstring(self):
        """Test that CoinSelectorHandle has a docstring."""
        assert CoinSelectorHandle.__doc__ is not None
        assert len(CoinSelectorHandle.__doc__) > 0

    def test_init_has_docstring(self):
        """Test that __init__ has a docstring."""
        assert CoinSelectorHandle.__init__.__doc__ is not None

    def test_fill_impl_struct_has_docstring(self):
        """Test that _fill_impl_struct has a docstring."""
        assert CoinSelectorHandle._fill_impl_struct.__doc__ is not None

    def test_install_callback_has_docstring(self):
        """Test that _install_callback has a docstring."""
        assert CoinSelectorHandle._install_callback.__doc__ is not None

    def test_create_selector_has_docstring(self):
        """Test that _create_selector has a docstring."""
        assert CoinSelectorHandle._create_selector.__doc__ is not None

    def test_ptr_property_has_docstring(self):
        """Test that ptr property has a docstring."""
        assert CoinSelectorHandle.ptr.fget.__doc__ is not None

    def test_underscore_ptr_property_has_docstring(self):
        """Test that _ptr property has a docstring."""
        assert CoinSelectorHandle._ptr.fget.__doc__ is not None

    def test_del_has_docstring(self):
        """Test that __del__ has a docstring."""
        assert CoinSelectorHandle.__del__.__doc__ is not None

    def test_enter_has_docstring(self):
        """Test that __enter__ has a docstring."""
        assert CoinSelectorHandle.__enter__.__doc__ is not None

    def test_exit_has_docstring(self):
        """Test that __exit__ has a docstring."""
        assert CoinSelectorHandle.__exit__.__doc__ is not None

    def test_class_docstring_mentions_coin_selector(self):
        """Test that class docstring mentions coin selector."""
        assert "coin selector" in CoinSelectorHandle.__doc__.lower()

    def test_class_docstring_has_example(self):
        """Test that class docstring has usage example."""
        assert "example" in CoinSelectorHandle.__doc__.lower()


class TestCoinSelectorHandleLifecycle:
    """Tests for CoinSelectorHandle lifecycle management."""

    def test_handle_creation_and_cleanup(self):
        """Test handle creation and cleanup."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)
        assert handle.ptr != ffi.NULL
        del handle

    def test_multiple_handles_independent(self):
        """Test that multiple handles are independent."""
        handle1 = CoinSelectorHandle(SimpleCoinSelector("Selector1"))
        handle2 = CoinSelectorHandle(SimpleCoinSelector("Selector2"))

        name1 = ffi.string(lib.cardano_coin_selector_get_name(handle1.ptr)).decode("utf-8")
        name2 = ffi.string(lib.cardano_coin_selector_get_name(handle2.ptr)).decode("utf-8")

        assert name1 == "Selector1"
        assert name2 == "Selector2"

    def test_handle_survives_selector_deletion(self):
        """Test that handle survives when original selector is deleted."""
        selector = SimpleCoinSelector("TestSelector")
        handle = CoinSelectorHandle(selector)
        del selector
        name = ffi.string(lib.cardano_coin_selector_get_name(handle.ptr)).decode("utf-8")
        assert name == "TestSelector"


class TestCoinSelectorHandleCallbackRefCounting:
    """Tests for proper reference counting in callbacks."""

    def test_callback_increments_refs(self):
        """Test that callback properly increments reference counts."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(500000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0
        assert selected_ptr[0] != ffi.NULL
        assert remaining_ptr[0] != ffi.NULL

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)

    def test_callback_returns_owned_references(self):
        """Test that callback returns owned references to C."""
        selector = SimpleCoinSelector()
        handle = CoinSelectorHandle(selector)

        utxo = create_test_utxo(0, 1000000)
        available = UtxoList.from_list([utxo])
        target = Value.new(500000)

        selected_ptr = ffi.new("cardano_utxo_list_t**")
        remaining_ptr = ffi.new("cardano_utxo_list_t**")

        result = lib.cardano_coin_selector_select(
            handle.ptr,
            ffi.NULL,
            available._ptr,
            target._ptr,
            selected_ptr,
            remaining_ptr
        )

        assert result == 0

        refcount_selected = lib.cardano_utxo_list_refcount(selected_ptr[0])
        refcount_remaining = lib.cardano_utxo_list_refcount(remaining_ptr[0])

        assert refcount_selected >= 1
        assert refcount_remaining >= 1

        lib.cardano_utxo_list_unref(selected_ptr)
        lib.cardano_utxo_list_unref(remaining_ptr)
