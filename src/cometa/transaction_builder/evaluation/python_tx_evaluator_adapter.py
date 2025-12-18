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

from __future__ import annotations

from typing import TYPE_CHECKING

from ..._ffi import ffi, lib
from ...errors import CardanoError

if TYPE_CHECKING:
    from .tx_evaluator import TxEvaluatorProtocol


class TxEvaluatorHandle:
    """
    Wraps a Python TxEvaluator and exposes a cardano_tx_evaluator_t* for libcardano-c.

    This class bridges Python transaction evaluator implementations with the C library
    by creating CFFI callbacks that delegate to the Python evaluator methods.

    Example:
        >>> class MyEvaluator:
        ...     def get_name(self) -> str:
        ...         return "MyEvaluator"
        ...     def evaluate(self, transaction, additional_utxos):
        ...         # Custom evaluation logic using external service
        ...         return redeemers
        >>> evaluator = MyEvaluator()
        >>> handle = TxEvaluatorHandle(evaluator)
        >>> c_evaluator_ptr = handle.ptr  # Pass to C functions
    """

    def __init__(self, evaluator: "TxEvaluatorProtocol"):
        self._evaluator = evaluator
        self._evaluator_ptr = ffi.new("cardano_tx_evaluator_t**")
        self._impl = ffi.new("cardano_tx_evaluator_impl_t*")

        # Keep callback alive on the instance to prevent garbage collection
        self._cb_evaluate = None

        self._fill_impl_struct()
        self._create_evaluator()

    def _fill_impl_struct(self) -> None:
        """Fill the cardano_tx_evaluator_impl_t struct with evaluator data and callbacks."""
        impl = self._impl[0]

        # Set evaluator name using ffi.memmove
        name_bytes = self._evaluator.get_name().encode("utf-8")
        max_len = len(impl.name) - 1
        name_bytes = name_bytes[:max_len]
        ffi.memmove(impl.name, name_bytes, len(name_bytes))
        impl.name[len(name_bytes)] = b"\x00"

        # Initialize error_message to empty
        impl.error_message[0] = b"\x00"

        # Context: not used in Python implementation
        impl.context = ffi.NULL

        # Install callback
        self._install_callback(impl)

    # pylint: disable=broad-except
    def _install_callback(self, impl) -> None:
        """Create and install the evaluate callback function.

        Note: The callback uses broad exception handling (Exception) intentionally.
        FFI callbacks must not raise Python exceptions as this would crash the C code.
        """
        evaluator = self._evaluator

        # ----------------------------------------------------------------
        # evaluate callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_tx_evaluator_impl_t*, cardano_transaction_t*, "
            "cardano_utxo_list_t*, cardano_redeemer_list_t**)"
        )
        def cb_evaluate(_impl, c_transaction, c_additional_utxos, out_redeemers):
            try:
                from ...transaction import Transaction
                from ...common.utxo_list import UtxoList
                from ...witness_set import RedeemerList

                # Wrap C transaction - increment ref since we're creating a wrapper
                lib.cardano_transaction_ref(c_transaction)
                transaction = Transaction(c_transaction)

                # Wrap additional UTXOs if provided
                additional_utxos = None
                if c_additional_utxos != ffi.NULL:
                    lib.cardano_utxo_list_ref(c_additional_utxos)
                    additional_utxos = UtxoList(c_additional_utxos)

                # Call Python evaluator
                redeemers = evaluator.evaluate(
                    transaction,
                    list(additional_utxos) if additional_utxos else None,
                )

                # Build output RedeemerList
                redeemer_list = RedeemerList.from_list(
                    redeemers if isinstance(redeemers, list) else list(redeemers)
                )

                # Increment ref count since C will take ownership
                lib.cardano_redeemer_list_ref(redeemer_list._ptr)
                out_redeemers[0] = redeemer_list._ptr
                return 0
            except Exception as exc:
                msg = f"{exc}"
                msg_bytes = msg.encode("utf-8")

                max_len = len(_impl.error_message) - 1
                msg_bytes = msg_bytes[:max_len]

                ffi.memmove(_impl.error_message, msg_bytes, len(msg_bytes))
                _impl.error_message[len(msg_bytes)] = b"\x00"

                return 1

        self._cb_evaluate = cb_evaluate
        impl.evaluate = cb_evaluate

    def _create_evaluator(self) -> None:
        """Create the cardano_tx_evaluator_t* from the implementation struct."""
        result = lib.cardano_tx_evaluator_new(self._impl[0], self._evaluator_ptr)
        if result != 0:
            msg = ffi.string(self._impl[0].error_message).decode("utf-8", "ignore")
            raise CardanoError(f"cardano_tx_evaluator_new failed: {result} {msg!r}")

    @property
    def ptr(self):
        """Return the underlying cardano_tx_evaluator_t* as a cdata pointer."""
        return self._evaluator_ptr[0]

    # Expose _ptr for compatibility with code that uses _ptr directly
    @property
    def _ptr(self):
        """Return the underlying cardano_tx_evaluator_t* as a cdata pointer."""
        return self._evaluator_ptr[0]

    def __del__(self):
        if self._evaluator_ptr is not None and self._evaluator_ptr[0] != ffi.NULL:
            lib.cardano_tx_evaluator_unref(self._evaluator_ptr)
            self._evaluator_ptr = None

    def __enter__(self) -> TxEvaluatorHandle:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass
