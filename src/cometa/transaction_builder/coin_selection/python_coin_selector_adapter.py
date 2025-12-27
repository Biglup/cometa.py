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
    from .coin_selector import CoinSelectorProtocol


class CoinSelectorHandle:
    """
    Wraps a Python CoinSelector and exposes a cardano_coin_selector_t* for libcardano-c.

    This class bridges Python coin selector implementations with the C library by creating
    CFFI callbacks that delegate to the Python selector methods.

    Example:
        >>> class MySelector:
        ...     def get_name(self) -> str:
        ...         return "MySelector"
        ...     def select(self, pre_selected, available, target):
        ...         # Custom selection logic
        ...         return selected, remaining
        >>> selector = MySelector()
        >>> handle = CoinSelectorHandle(selector)
        >>> c_selector_ptr = handle.ptr  # Pass to C functions
    """

    def __init__(self, selector: "CoinSelectorProtocol"):
        """
        Initialize a CoinSelectorHandle with a Python coin selector implementation.

        Args:
            selector: A Python object implementing the CoinSelectorProtocol
                      (must have get_name() and select() methods).

        Raises:
            CardanoError: If the C coin selector creation fails.
        """
        self._selector = selector
        self._selector_ptr = ffi.new("cardano_coin_selector_t**")
        self._impl = ffi.new("cardano_coin_selector_impl_t*")

        # Keep callback alive on the instance to prevent garbage collection
        self._cb_select = None

        self._fill_impl_struct()
        self._create_selector()

    def _fill_impl_struct(self) -> None:
        """Fill the cardano_coin_selector_impl_t struct with selector data and callbacks."""
        impl = self._impl[0]

        # Set selector name using ffi.memmove
        name_bytes = self._selector.get_name().encode("utf-8")
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
        """Create and install the select callback function.

        Note: The callback uses broad exception handling (Exception) intentionally.
        FFI callbacks must not raise Python exceptions as this would crash the C code.
        """
        selector = self._selector

        # ----------------------------------------------------------------
        # select callback
        # ----------------------------------------------------------------
        @ffi.callback(
            "cardano_error_t(cardano_coin_selector_impl_t*, cardano_utxo_list_t*, "
            "cardano_utxo_list_t*, cardano_value_t*, cardano_utxo_list_t**, "
            "cardano_utxo_list_t**)"
        )
        def cb_select( # pylint: disable=too-many-locals
            _impl, c_pre_selected, c_available, c_target, out_selection, out_remaining
        ):
            try:
                from ...common.utxo_list import UtxoList
                from ...transaction_body import Value

                # Wrap C types - increment refs since we're creating wrappers
                pre_selected = None
                if c_pre_selected != ffi.NULL:
                    lib.cardano_utxo_list_ref(c_pre_selected)
                    pre_selected = UtxoList(c_pre_selected)

                lib.cardano_utxo_list_ref(c_available)
                available = UtxoList(c_available)

                lib.cardano_value_ref(c_target)
                target = Value(c_target)

                # Call Python selector
                selected, remaining = selector.select(
                    list(pre_selected) if pre_selected else [],
                    list(available),
                    target,
                )

                # Build output UtxoLists
                selected_list = UtxoList.from_list(
                    selected if isinstance(selected, list) else list(selected)
                )
                remaining_list = UtxoList.from_list(
                    remaining if isinstance(remaining, list) else list(remaining)
                )

                # Increment ref count since C will take ownership
                lib.cardano_utxo_list_ref(selected_list._ptr)
                lib.cardano_utxo_list_ref(remaining_list._ptr)
                out_selection[0] = selected_list._ptr
                out_remaining[0] = remaining_list._ptr
                return 0
            except Exception as exc:
                msg = f"{exc}"
                msg_bytes = msg.encode("utf-8")

                max_len = len(_impl.error_message) - 1
                msg_bytes = msg_bytes[:max_len]

                ffi.memmove(_impl.error_message, msg_bytes, len(msg_bytes))
                _impl.error_message[len(msg_bytes)] = b"\x00"

                return 1

        self._cb_select = cb_select
        impl.select = cb_select

    def _create_selector(self) -> None:
        """Create the cardano_coin_selector_t* from the implementation struct."""
        result = lib.cardano_coin_selector_new(self._impl[0], self._selector_ptr)
        if result != 0:
            msg = ffi.string(self._impl[0].error_message).decode("utf-8", "ignore")
            raise CardanoError(f"cardano_coin_selector_new failed: {result} {msg!r}")

    @property
    def ptr(self):
        """Return the underlying cardano_coin_selector_t* as a cdata pointer."""
        return self._selector_ptr[0]

    # Expose _ptr for compatibility with code that uses _ptr directly
    @property
    def _ptr(self):
        """Return the underlying cardano_coin_selector_t* as a cdata pointer."""
        return self._selector_ptr[0]

    def __del__(self):
        """Clean up the underlying C coin selector when the handle is destroyed."""
        if self._selector_ptr is not None and self._selector_ptr[0] != ffi.NULL:
            lib.cardano_coin_selector_unref(self._selector_ptr)
            self._selector_ptr = None

    def __enter__(self) -> CoinSelectorHandle:
        """
        Enter the context manager.

        Returns:
            The CoinSelectorHandle instance.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit the context manager.

        Args:
            exc_type: The exception type if an exception was raised, None otherwise.
            exc_val: The exception value if an exception was raised, None otherwise.
            exc_tb: The exception traceback if an exception was raised, None otherwise.
        """
