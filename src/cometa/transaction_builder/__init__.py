# pylint: disable=undefined-all-variable
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

from typing import Any

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    # Fee computation functions
    "compute_transaction_fee": (".fee", "compute_transaction_fee"),
    "compute_min_ada_required": (".fee", "compute_min_ada_required"),
    "compute_min_script_fee": (".fee", "compute_min_script_fee"),
    "compute_min_fee_without_scripts": (".fee", "compute_min_fee_without_scripts"),
    "compute_script_ref_fee": (".fee", "compute_script_ref_fee"),
    "get_total_ex_units_in_redeemers": (".fee", "get_total_ex_units_in_redeemers"),
    "get_serialized_coin_size": (".fee", "get_serialized_coin_size"),
    "get_serialized_output_size": (".fee", "get_serialized_output_size"),
    "get_serialized_script_size": (".fee", "get_serialized_script_size"),
    "get_serialized_transaction_size": (".fee", "get_serialized_transaction_size"),
    # Script data hash computation
    "compute_script_data_hash": (".script_data_hash", "compute_script_data_hash"),
    # Balancing
    "InputToRedeemerMap": (".balancing", "InputToRedeemerMap"),
    "balance_transaction": (".balancing", "balance_transaction"),
    "is_transaction_balanced": (".balancing", "is_transaction_balanced"),
    "ImplicitCoin": (".balancing", "ImplicitCoin"),
    "compute_implicit_coin": (".balancing", "compute_implicit_coin"),
    # Coin selection
    "CoinSelectorProtocol": (".coin_selection", "CoinSelectorProtocol"),
    "CoinSelector": (".coin_selection", "CoinSelector"),
    "CoinSelectorHandle": (".coin_selection", "CoinSelectorHandle"),
    "CCoinSelectorWrapper": (".coin_selection", "CCoinSelectorWrapper"),
    "LargeFirstCoinSelector": (".coin_selection", "LargeFirstCoinSelector"),
    # Evaluation
    "TxEvaluatorProtocol": (".evaluation", "TxEvaluatorProtocol"),
    "TxEvaluator": (".evaluation", "TxEvaluator"),
    "TxEvaluatorHandle": (".evaluation", "TxEvaluatorHandle"),
    "CTxEvaluatorWrapper": (".evaluation", "CTxEvaluatorWrapper"),
    # Transaction Builder
    "TxBuilder": (".tx_builder", "TxBuilder"),
}

_cache: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    if name in _cache:
        return _cache[name]

    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        from importlib import import_module
        module = import_module(module_path, __name__)
        value = getattr(module, attr_name)
        _cache[name] = value
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(__all__)


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
