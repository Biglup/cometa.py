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

# Conversion of Dijkstra body collections to Python values.

from .._ffi import ffi, lib
from ..errors import CardanoError


def read_account_map(ptr, *, intervals=False):
    """Consume a deposit/interval map reference and return a Bech32-keyed dict."""
    from ..address import RewardAddress
    from .account_balance_interval import AccountBalanceInterval
    kind = "account_balance_intervals_map" if intervals else "direct_deposit_map"
    result = {}
    if ptr == ffi.NULL:
        return result
    try:
        for index in range(getattr(lib, f"cardano_{kind}_get_length")(ptr)):
            key = ffi.new("cardano_reward_address_t **")
            value = ffi.new("cardano_account_balance_interval_t **" if intervals else "uint64_t *")
            err = getattr(lib, f"cardano_{kind}_get_key_value_at")(ptr, index, key, value)
            if err:
                lib.cardano_reward_address_unref(key)
                if intervals:
                    lib.cardano_account_balance_interval_unref(value)
                raise CardanoError(f"Failed to read {kind} (error code: {err})")
            address = RewardAddress(key[0])
            item = AccountBalanceInterval(value[0]) if intervals else int(value[0])
            result[address.to_bech32()] = item
    finally:
        getattr(lib, f"cardano_{kind}_unref")(ffi.new(f"cardano_{kind}_t **", ptr))
    return result


def read_guards(ptr):
    """Consume a guard set reference and return credentials in ledger order."""
    from ..common import Credential
    result = []
    if ptr == ffi.NULL:
        return result
    try:
        for index in range(lib.cardano_guard_set_get_length(ptr)):
            out = ffi.new("cardano_credential_t **")
            err = lib.cardano_guard_set_get(ptr, index, out)
            if err:
                lib.cardano_credential_unref(out)
                raise CardanoError(f"Failed to read guard (error code: {err})")
            result.append(Credential(out[0]))
    finally:
        lib.cardano_guard_set_unref(ffi.new("cardano_guard_set_t **", ptr))
    return result


def read_required_guards(ptr):
    """Consume required guards and return (credential, optional datum) pairs."""
    from ..common import Credential
    from ..plutus_data import PlutusData
    result = []
    if ptr == ffi.NULL:
        return result
    try:
        for index in range(lib.cardano_required_guards_map_get_length(ptr)):
            key = ffi.new("cardano_credential_t **")
            value = ffi.new("cardano_plutus_data_t **")
            err = lib.cardano_required_guards_map_get_key_value_at(ptr, index, key, value)
            if err:
                lib.cardano_credential_unref(key)
                lib.cardano_plutus_data_unref(value)
                raise CardanoError(f"Failed to read required guard (error code: {err})")
            result.append((Credential(key[0]), None if value[0] == ffi.NULL else PlutusData(value[0])))
    finally:
        lib.cardano_required_guards_map_unref(ffi.new("cardano_required_guards_map_t **", ptr))
    return result


def read_sub_transactions(ptr):
    """Consume the set reference and return owned sub-transactions in ledger order."""
    from ..transaction import SubTransaction
    result = []
    if ptr == ffi.NULL:
        return result
    try:
        for index in range(lib.cardano_sub_transaction_set_get_length(ptr)):
            out = ffi.new("cardano_sub_transaction_t **")
            err = lib.cardano_sub_transaction_set_get(ptr, index, out)
            if err:
                lib.cardano_sub_transaction_unref(out)
                raise CardanoError(f"Failed to read sub-transaction (error code: {err})")
            result.append(SubTransaction(out[0]))
    finally:
        lib.cardano_sub_transaction_set_unref(ffi.new("cardano_sub_transaction_set_t **", ptr))
    return result
