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

from typing import Optional, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError, cardano_error_to_string
from .transaction_builder_base import TransactionBuilderBase, _to_plutus_data_ptr

if TYPE_CHECKING:
    from ..common import Credential
    from ..plutus_data import PlutusDataLike
    from ..transaction import SubTransaction


class SubTransactionBuilder(TransactionBuilderBase):
    """Build a Dijkstra intent with explicit inputs and no fee or collateral.

    Sign the returned SubTransaction before passing it and its resolved inputs
    to TxBuilder.add_sub_transaction. Balancing takes place over the whole batch.
    Deferred redeemers resolve once, using this sub-transaction's local indices.
    """

    _native_type = "cardano_sub_tx_builder"

    def require_top_level_guard(self, guard: Credential,
                                datum: Optional[PlutusDataLike] = None) -> SubTransactionBuilder:
        """Require the enclosing transaction to carry this guard and optional terms."""
        data = _to_plutus_data_ptr(datum)
        lib.cardano_sub_tx_builder_require_top_level_guard(
            self._ptr, guard._ptr, data._ptr if data is not None else ffi.NULL)
        return self

    def build(self) -> SubTransaction:
        """Build an unsigned intent; execution budgets and body are fixed before signing."""
        from ..transaction import SubTransaction
        out = ffi.new("cardano_sub_transaction_t **")
        self._deferred_errors.clear()
        err = lib.cardano_sub_tx_builder_build(self._ptr, out)
        if self._deferred_errors:
            lib.cardano_sub_transaction_unref(out)
            cause = self._deferred_errors.pop()
            self._deferred_errors.clear()
            raise CardanoError(f"Deferred redeemer failed: {cause}") from cause
        if err:
            lib.cardano_sub_transaction_unref(out)
            raise CardanoError(
                f"Failed to build sub-transaction ({cardano_error_to_string(err)}): {self.get_last_error()}")
        return SubTransaction(out[0])
