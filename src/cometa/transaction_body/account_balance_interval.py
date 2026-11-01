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

from typing import Optional
from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor import CborReader, CborWriter


class AccountBalanceInterval:
    """An exact balance or inclusive-lower/exclusive-upper range in lovelace.

    Use new(lower, upper) for a range (None leaves a bound open), or
    new_exact(balance) for equality. Values are unsigned 64-bit integers.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("AccountBalanceInterval: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            lib.cardano_account_balance_interval_unref(
                ffi.new("cardano_account_balance_interval_t **", self._ptr))
            self._ptr = ffi.NULL

    @staticmethod
    def _amount(value):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
            raise ValueError("Balance must be an unsigned 64-bit integer")
        return value

    @classmethod
    def new(cls, inclusive_lower_bound: Optional[int] = None,
            exclusive_upper_bound: Optional[int] = None) -> AccountBalanceInterval:
        """Create a range; either bound may be omitted."""
        lower = ffi.NULL if inclusive_lower_bound is None else ffi.new(
            "uint64_t *", cls._amount(inclusive_lower_bound))
        upper = ffi.NULL if exclusive_upper_bound is None else ffi.new(
            "uint64_t *", cls._amount(exclusive_upper_bound))
        if lower != ffi.NULL and upper != ffi.NULL and lower[0] >= upper[0]:
            raise ValueError("The exclusive upper bound must exceed the inclusive lower bound")
        out = ffi.new("cardano_account_balance_interval_t **")
        err = lib.cardano_account_balance_interval_new(lower, upper, out)
        if err:
            raise CardanoError(f"Invalid account balance interval (error code: {err})")
        return cls(out[0])

    @classmethod
    def new_exact(cls, balance: int) -> AccountBalanceInterval:
        """Require an account balance equal to balance."""
        out = ffi.new("cardano_account_balance_interval_t **")
        err = lib.cardano_account_balance_interval_new_exact(cls._amount(balance), out)
        if err:
            raise CardanoError(f"Invalid exact balance (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> AccountBalanceInterval:
        """Decode an interval or exact balance from CBOR."""
        out = ffi.new("cardano_account_balance_interval_t **")
        err = lib.cardano_account_balance_interval_from_cbor(reader._ptr, out)
        if err:
            raise CardanoError(f"Invalid interval CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """Write the interval's ledger encoding."""
        err = lib.cardano_account_balance_interval_to_cbor(self._ptr, writer._ptr)
        if err:
            raise CardanoError(f"Failed to encode interval (error code: {err})")

    @property
    def is_exact(self) -> bool:
        """Whether this is an equality constraint."""
        return bool(lib.cardano_account_balance_interval_is_exact(self._ptr))

    @property
    def exact_balance(self) -> Optional[int]:
        """The exact balance, or None for a range."""
        ptr = lib.cardano_account_balance_interval_get_exact_balance(self._ptr)
        return None if ptr == ffi.NULL else int(ptr[0])

    @property
    def inclusive_lower_bound(self) -> Optional[int]:
        """The range's inclusive lower bound, if present."""
        ptr = lib.cardano_account_balance_interval_get_inclusive_lower_bound(self._ptr)
        return None if ptr == ffi.NULL else int(ptr[0])

    @property
    def exclusive_upper_bound(self) -> Optional[int]:
        """The range's exclusive upper bound, if present."""
        ptr = lib.cardano_account_balance_interval_get_exclusive_upper_bound(self._ptr)
        return None if ptr == ffi.NULL else int(ptr[0])
