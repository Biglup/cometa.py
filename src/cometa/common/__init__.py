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
    "ProtocolVersion": (".protocol_version", "ProtocolVersion"),
    "BigInt": (".bigint", "BigInt"),
    "ByteOrder": (".byte_order", "ByteOrder"),
    "NetworkId": (".network_id", "NetworkId"),
    "CredentialType": (".credential_type", "CredentialType"),
    "Credential": (".credential", "Credential"),
    "DatumType": (".datum_type", "DatumType"),
    "DRepType": (".drep_type", "DRepType"),
    "GovernanceKeyType": (".governance_key_type", "GovernanceKeyType"),
    "UnitInterval": (".unit_interval", "UnitInterval"),
    "ExUnits": (".ex_units", "ExUnits"),
    "Anchor": (".anchor", "Anchor"),
    "DRep": (".drep", "DRep"),
    "GovernanceActionId": (".governance_action_id", "GovernanceActionId"),
    "Datum": (".datum", "Datum"),
    "WithdrawalMap": (".withdrawal_map", "WithdrawalMap"),
    "RewardAddressList": (".reward_address_list", "RewardAddressList"),
    "SlotConfig": (".slot_config", "SlotConfig"),
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
    "Anchor",
    "BigInt",
    "ByteOrder",
    "Credential",
    "CredentialType",
    "Datum",
    "DatumType",
    "DRep",
    "DRepType",
    "ExUnits",
    "GovernanceActionId",
    "GovernanceKeyType",
    "NetworkId",
    "ProtocolVersion",
    "RewardAddressList",
    "UnitInterval",
    "WithdrawalMap",
    "SlotConfig",
]
