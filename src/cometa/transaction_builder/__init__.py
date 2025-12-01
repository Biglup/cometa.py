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

# Fee computation functions
from .fee import (
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

# Script data hash computation
from .script_data_hash import compute_script_data_hash

# Balancing
from .balancing import (
    InputToRedeemerMap,
    balance_transaction,
    is_transaction_balanced,
    ImplicitCoin,
    compute_implicit_coin,
)

# Coin selection
from .coin_selection import (
    CoinSelectorProtocol,
    CoinSelector,
    CoinSelectorHandle,
    CCoinSelectorWrapper,
    LargeFirstCoinSelector,
)

# Evaluation
from .evaluation import (
    TxEvaluatorProtocol,
    TxEvaluator,
    TxEvaluatorHandle,
    CTxEvaluatorWrapper,
)

# Transaction Builder
from .tx_builder import TxBuilder

__all__ = [
    # Fee functions
    "compute_transaction_fee",
    "compute_min_ada_required",
    "compute_min_script_fee",
    "compute_min_fee_without_scripts",
    "compute_script_ref_fee",
    "get_total_ex_units_in_redeemers",
    "get_serialized_coin_size",
    "get_serialized_output_size",
    "get_serialized_script_size",
    "get_serialized_transaction_size",
    # Script data hash
    "compute_script_data_hash",
    # Balancing
    "InputToRedeemerMap",
    "balance_transaction",
    "is_transaction_balanced",
    "ImplicitCoin",
    "compute_implicit_coin",
    # Coin selection
    "CoinSelectorProtocol",
    "CoinSelector",
    "CoinSelectorHandle",
    "CCoinSelectorWrapper",
    "LargeFirstCoinSelector",
    # Evaluation
    "TxEvaluatorProtocol",
    "TxEvaluator",
    "TxEvaluatorHandle",
    "CTxEvaluatorWrapper",
    # Transaction Builder
    "TxBuilder",
]
