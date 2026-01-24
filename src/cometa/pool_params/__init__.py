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
    "RelayType": (".relay_type", "RelayType"),
    "IPv4": (".ipv4", "IPv4"),
    "IPv6": (".ipv6", "IPv6"),
    "SingleHostAddrRelay": (".single_host_addr_relay", "SingleHostAddrRelay"),
    "SingleHostNameRelay": (".single_host_name_relay", "SingleHostNameRelay"),
    "MultiHostNameRelay": (".multi_host_name_relay", "MultiHostNameRelay"),
    "Relay": (".relay", "Relay"),
    "RelayLike": (".relay", "RelayLike"),
    "to_relay": (".relay", "to_relay"),
    "Relays": (".relays", "Relays"),
    "PoolOwners": (".pool_owners", "PoolOwners"),
    "PoolMetadata": (".pool_metadata", "PoolMetadata"),
    "PoolParams": (".pool_params", "PoolParams"),
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
    "RelayType",
    "IPv4",
    "IPv6",
    "SingleHostAddrRelay",
    "SingleHostNameRelay",
    "MultiHostNameRelay",
    "Relay",
    "RelayLike",
    "to_relay",
    "Relays",
    "PoolOwners",
    "PoolMetadata",
    "PoolParams",
]
