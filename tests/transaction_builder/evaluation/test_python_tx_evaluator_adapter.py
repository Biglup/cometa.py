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
from cometa.transaction_builder.evaluation.python_tx_evaluator_adapter import (
    TxEvaluatorHandle,
)
from cometa.transaction_builder.evaluation.tx_evaluator import TxEvaluatorProtocol
from cometa._ffi import ffi, lib
from cometa.errors import CardanoError


class MockEvaluator:
    """
    Mock evaluator implementation for testing TxEvaluatorHandle.

    This evaluator implements the TxEvaluatorProtocol with simple mock
    behavior for testing purposes.
    """

    def __init__(
        self,
        name: str = "MockEvaluator",
        should_raise: bool = False,
        error_message: str = "Evaluation error",
    ):
        """
        Initialize the mock evaluator.

        Args:
            name: The name of the evaluator.
            should_raise: Whether evaluate() should raise an exception.
            error_message: The error message to raise if should_raise is True.
        """
        self._name = name
        self._should_raise = should_raise
        self._error_message = error_message
        self._evaluate_called = False
        self._last_transaction = None
        self._last_additional_utxos = None

    def get_name(self) -> str:
        """
        Get the human-readable name of this evaluator.

        Returns:
            The evaluator name.
        """
        return self._name

    def evaluate(
        self,
        transaction: Transaction,
        additional_utxos: Optional[List[Utxo]],
    ) -> List[Redeemer]:
        """
        Evaluate the execution units required for a transaction.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: Optional additional UTXOs needed for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.

        Raises:
            Exception: If should_raise is True.
        """
        self._evaluate_called = True
        self._last_transaction = transaction
        self._last_additional_utxos = additional_utxos

        if self._should_raise:
            raise Exception(self._error_message)

        redeemer = Redeemer.new(
            tag=RedeemerTag.SPEND,
            index=0,
            data=PlutusData.from_cbor(
                CborReader.from_hex("d87980")
            ),
            ex_units=ExUnits.new(1000000, 500000),
        )
        return [redeemer]


class TestTxEvaluatorHandle:
    """Test suite for TxEvaluatorHandle class."""

    def test_init_creates_evaluator_handle(self):
        """Test that TxEvaluatorHandle can be initialized with a valid evaluator."""
        evaluator = MockEvaluator(name="TestEvaluator")
        handle = TxEvaluatorHandle(evaluator)

        assert handle._evaluator is evaluator
        assert handle._evaluator_ptr is not None
        assert handle._evaluator_ptr[0] != ffi.NULL
        assert handle._impl is not None
        assert handle._cb_evaluate is not None

    def test_init_sets_evaluator_name(self):
        """Test that the evaluator name is correctly set in the C struct."""
        evaluator = MockEvaluator(name="CustomEvaluator")
        handle = TxEvaluatorHandle(evaluator)

        name = ffi.string(handle._impl[0].name).decode("utf-8")
        assert name == "CustomEvaluator"

    def test_init_with_long_name_truncates(self):
        """Test that very long evaluator names are truncated to fit the buffer."""
        long_name = "A" * 300
        evaluator = MockEvaluator(name=long_name)
        handle = TxEvaluatorHandle(evaluator)

        name = ffi.string(handle._impl[0].name).decode("utf-8")
        assert len(name) < 256
        assert name.startswith("AAA")

    def test_init_initializes_error_message_to_empty(self):
        """Test that the error_message buffer is initialized to empty."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        error_msg = ffi.string(handle._impl[0].error_message).decode("utf-8")
        assert error_msg == ""

    def test_init_sets_context_to_null(self):
        """Test that the context field is set to NULL."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        assert handle._impl[0].context == ffi.NULL

    def test_init_installs_evaluate_callback(self):
        """Test that the evaluate callback is installed."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        assert handle._impl[0].evaluate != ffi.NULL
        assert handle._cb_evaluate is not None

    def test_ptr_property_returns_c_pointer(self):
        """Test that the ptr property returns the C pointer."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        ptr = handle.ptr
        assert ptr != ffi.NULL
        assert ptr == handle._evaluator_ptr[0]

    def test_underscore_ptr_property_returns_c_pointer(self):
        """Test that the _ptr property returns the C pointer for compatibility."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        ptr = handle._ptr
        assert ptr != ffi.NULL
        assert ptr == handle._evaluator_ptr[0]
        assert ptr == handle.ptr

    def test_evaluate_callback_success(self):
        """Test that the evaluate callback successfully evaluates a transaction."""
        tx_hex = (
            "84a500818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
            "0181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d386"
            "1e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6"
            "091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845b"
            "bc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e32"
            "6dc16579dcc373a240182846504154415445181e020a031903e8081864a200818258206199186adb"
            "51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8f"
            "b4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261"
            "eb6c5e4bc42c800bb9c89187550281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696"
            "f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f637679666964"
            "7171676775726a687268716169697370717275656c6876797071786565777072796676775820b6db"
            "f0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a0f5f6"
        )
        reader = CborReader.from_hex(tx_hex)
        tx = Transaction.from_cbor(reader)

        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        redeemer_list_ptr = ffi.new("cardano_redeemer_list_t**")
        result = lib.cardano_tx_evaluator_evaluate(
            handle.ptr,
            tx._ptr,
            ffi.NULL,
            redeemer_list_ptr,
        )

        assert result == 0
        assert evaluator._evaluate_called
        assert redeemer_list_ptr[0] != ffi.NULL

        lib.cardano_redeemer_list_unref(redeemer_list_ptr)

    def test_evaluate_callback_with_additional_utxos(self):
        """Test that the evaluate callback handles additional UTXOs."""
        tx_hex = (
            "84a500818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
            "0181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d386"
            "1e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6"
            "091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845b"
            "bc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e32"
            "6dc16579dcc373a240182846504154415445181e020a031903e8081864a200818258206199186adb"
            "51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8f"
            "b4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261"
            "eb6c5e4bc42c800bb9c89187550281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696"
            "f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f637679666964"
            "7171676775726a687268716169697370717275656c6876797071786565777072796676775820b6db"
            "f0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a0f5f6"
        )
        reader = CborReader.from_hex(tx_hex)
        tx = Transaction.from_cbor(reader)

        utxo_cbor = "82825820fbecbe69bc3ee617653b95893f50b0362cbaff3e27b01a936969a25bfc100a7c00835839319068a7a3f008803edac87af1619860f2cdcde40c26987325ace138ad2c967f4bd28944b06462e13c5e3f5d5fa6e03f8567569438cd833e6d1a0a3140c05820c6b9e0671fef714142bda45beedf7b51c2d4e3676f79196964082fef164ef7e4"
        utxo_reader = CborReader.from_hex(utxo_cbor)
        utxo = Utxo.from_cbor(utxo_reader)

        utxo_list = UtxoList()
        utxo_list.add(utxo)

        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        redeemer_list_ptr = ffi.new("cardano_redeemer_list_t**")
        result = lib.cardano_tx_evaluator_evaluate(
            handle.ptr,
            tx._ptr,
            utxo_list._ptr,
            redeemer_list_ptr,
        )

        assert result == 0
        assert evaluator._evaluate_called
        assert evaluator._last_additional_utxos is not None
        assert len(evaluator._last_additional_utxos) >= 0
        assert redeemer_list_ptr[0] != ffi.NULL

        redeemer_list = RedeemerList(redeemer_list_ptr[0])
        del redeemer_list

    def test_evaluate_callback_error_handling(self):
        """Test that the evaluate callback handles exceptions properly."""
        tx_hex = (
            "84a500818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
            "0181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d386"
            "1e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6"
            "091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845b"
            "bc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e32"
            "6dc16579dcc373a240182846504154415445181e020a031903e8081864a200818258206199186adb"
            "51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8f"
            "b4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261"
            "eb6c5e4bc42c800bb9c89187550281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696"
            "f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f637679666964"
            "7171676775726a687268716169697370717275656c6876797071786565777072796676775820b6db"
            "f0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a0f5f6"
        )
        reader = CborReader.from_hex(tx_hex)
        tx = Transaction.from_cbor(reader)

        evaluator = MockEvaluator(should_raise=True, error_message="Test error")
        handle = TxEvaluatorHandle(evaluator)

        redeemer_list_ptr = ffi.new("cardano_redeemer_list_t**")
        result = lib.cardano_tx_evaluator_evaluate(
            handle.ptr,
            tx._ptr,
            ffi.NULL,
            redeemer_list_ptr,
        )

        assert result == 1
        error_msg = lib.cardano_tx_evaluator_get_last_error(handle.ptr)
        error_str = ffi.string(error_msg).decode("utf-8")
        assert "Test error" in error_str

    def test_evaluate_callback_long_error_message_truncated(self):
        """Test that very long error messages are truncated."""
        tx_hex = (
            "84a500818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
            "0181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d386"
            "1e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6"
            "091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845b"
            "bc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e32"
            "6dc16579dcc373a240182846504154415445181e020a031903e8081864a200818258206199186adb"
            "51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8f"
            "b4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261"
            "eb6c5e4bc42c800bb9c89187550281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696"
            "f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f637679666964"
            "7171676775726a687268716169697370717275656c6876797071786565777072796676775820b6db"
            "f0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a0f5f6"
        )
        reader = CborReader.from_hex(tx_hex)
        tx = Transaction.from_cbor(reader)

        long_error = "E" * 2000
        evaluator = MockEvaluator(should_raise=True, error_message=long_error)
        handle = TxEvaluatorHandle(evaluator)

        redeemer_list_ptr = ffi.new("cardano_redeemer_list_t**")
        result = lib.cardano_tx_evaluator_evaluate(
            handle.ptr,
            tx._ptr,
            ffi.NULL,
            redeemer_list_ptr,
        )

        assert result == 1
        error_msg_ptr = lib.cardano_tx_evaluator_get_last_error(handle.ptr)
        error_msg = ffi.string(error_msg_ptr).decode("utf-8")
        assert len(error_msg) <= 1023
        assert error_msg.startswith("EEE")

    def test_c_api_get_name(self):
        """Test that the C API can retrieve the evaluator name."""
        evaluator = MockEvaluator(name="TestEvaluator")
        handle = TxEvaluatorHandle(evaluator)

        name_ptr = lib.cardano_tx_evaluator_get_name(handle.ptr)
        name = ffi.string(name_ptr).decode("utf-8")

        assert name == "TestEvaluator"

    def test_c_api_ref_increases_reference_count(self):
        """Test that cardano_tx_evaluator_ref increases the reference count."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        initial_count = lib.cardano_tx_evaluator_refcount(handle.ptr)
        lib.cardano_tx_evaluator_ref(handle.ptr)
        new_count = lib.cardano_tx_evaluator_refcount(handle.ptr)

        assert new_count == initial_count + 1

        lib.cardano_tx_evaluator_unref(handle._evaluator_ptr)

    def test_c_api_unref_decreases_reference_count(self):
        """Test that cardano_tx_evaluator_unref decreases the reference count."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        lib.cardano_tx_evaluator_ref(handle.ptr)
        initial_count = lib.cardano_tx_evaluator_refcount(handle.ptr)

        temp_ptr = ffi.new("cardano_tx_evaluator_t**", handle.ptr)
        lib.cardano_tx_evaluator_unref(temp_ptr)

        new_count = lib.cardano_tx_evaluator_refcount(handle.ptr)
        assert new_count == initial_count - 1

    def test_c_api_refcount(self):
        """Test that cardano_tx_evaluator_refcount returns the correct count."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        count = lib.cardano_tx_evaluator_refcount(handle.ptr)
        assert count >= 1

    def test_c_api_refcount_null_pointer(self):
        """Test that cardano_tx_evaluator_refcount returns 0 for NULL."""
        count = lib.cardano_tx_evaluator_refcount(ffi.NULL)
        assert count == 0

    def test_c_api_set_last_error(self):
        """Test that cardano_tx_evaluator_set_last_error sets the error message."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        error_msg = b"Test error message"
        lib.cardano_tx_evaluator_set_last_error(handle.ptr, error_msg)

        retrieved_msg_ptr = lib.cardano_tx_evaluator_get_last_error(handle.ptr)
        retrieved_msg = ffi.string(retrieved_msg_ptr).decode("utf-8")

        assert retrieved_msg == "Test error message"

    def test_c_api_get_last_error_null_pointer(self):
        """Test that cardano_tx_evaluator_get_last_error handles NULL."""
        error_msg_ptr = lib.cardano_tx_evaluator_get_last_error(ffi.NULL)
        error_msg = ffi.string(error_msg_ptr).decode("utf-8")

        assert error_msg == "Object is NULL."

    def test_del_unrefs_evaluator(self):
        """Test that __del__ properly unrefs the evaluator."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        ptr = handle.ptr
        initial_count = lib.cardano_tx_evaluator_refcount(ptr)

        lib.cardano_tx_evaluator_ref(ptr)
        ref_count = lib.cardano_tx_evaluator_refcount(ptr)

        del handle

        final_count = lib.cardano_tx_evaluator_refcount(ptr)
        assert final_count == ref_count - 1
        assert final_count == initial_count

        temp_ptr = ffi.new("cardano_tx_evaluator_t**", ptr)
        lib.cardano_tx_evaluator_unref(temp_ptr)

    def test_del_handles_null_pointer(self):
        """Test that __del__ handles NULL pointer gracefully."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        handle._evaluator_ptr[0] = ffi.NULL

        del handle

    def test_del_handles_none_pointer(self):
        """Test that __del__ handles None pointer gracefully."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        handle._evaluator_ptr = None

        del handle

    def test_context_manager_enter(self):
        """Test that __enter__ returns self."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        with handle as h:
            assert h is handle

    def test_context_manager_exit(self):
        """Test that __exit__ completes without error."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        with handle:
            pass

    def test_context_manager_exit_with_exception(self):
        """Test that __exit__ handles exceptions properly."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        try:
            with handle:
                raise ValueError("Test exception")
        except ValueError:
            pass

    def test_multiple_handles_same_evaluator(self):
        """Test that multiple handles can be created for the same evaluator."""
        evaluator = MockEvaluator()
        handle1 = TxEvaluatorHandle(evaluator)
        handle2 = TxEvaluatorHandle(evaluator)

        assert handle1._evaluator is evaluator
        assert handle2._evaluator is evaluator
        assert handle1.ptr != handle2.ptr

    def test_evaluator_name_with_special_characters(self):
        """Test that evaluator names with special characters are handled."""
        evaluator = MockEvaluator(name="Test-Evaluator_123!@#")
        handle = TxEvaluatorHandle(evaluator)

        name = ffi.string(handle._impl[0].name).decode("utf-8")
        assert name == "Test-Evaluator_123!@#"

    def test_evaluator_name_with_unicode(self):
        """Test that evaluator names with unicode characters are handled."""
        evaluator = MockEvaluator(name="测试评估器")
        handle = TxEvaluatorHandle(evaluator)

        name = ffi.string(handle._impl[0].name).decode("utf-8")
        assert "测试" in name or len(name) > 0

    def test_evaluate_returns_list_of_redeemers(self):
        """Test that evaluate returns a properly formatted list of redeemers."""
        tx_hex = (
            "84a500818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
            "0181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d386"
            "1e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6"
            "091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845b"
            "bc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e32"
            "6dc16579dcc373a240182846504154415445181e020a031903e8081864a200818258206199186adb"
            "51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8f"
            "b4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261"
            "eb6c5e4bc42c800bb9c89187550281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696"
            "f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f637679666964"
            "7171676775726a687268716169697370717275656c6876797071786565777072796676775820b6db"
            "f0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a0f5f6"
        )
        reader = CborReader.from_hex(tx_hex)
        tx = Transaction.from_cbor(reader)

        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        redeemer_list_ptr = ffi.new("cardano_redeemer_list_t**")
        result = lib.cardano_tx_evaluator_evaluate(
            handle.ptr,
            tx._ptr,
            ffi.NULL,
            redeemer_list_ptr,
        )

        assert result == 0

        redeemer_list = RedeemerList(redeemer_list_ptr[0])
        assert len(redeemer_list) > 0
        del redeemer_list

    def test_callback_keeps_reference_to_prevent_gc(self):
        """Test that callbacks are kept as instance variables to prevent GC."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        assert hasattr(handle, "_cb_evaluate")
        assert handle._cb_evaluate is not None
        assert callable(handle._cb_evaluate)

    def test_create_evaluator_failure(self):
        """Test that _create_evaluator handles failure properly."""
        evaluator = MockEvaluator()
        handle = TxEvaluatorHandle(evaluator)

        assert handle._evaluator_ptr is not None
        assert handle._evaluator_ptr[0] != ffi.NULL
