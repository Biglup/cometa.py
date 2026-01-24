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
    "PlutusLanguageVersion": (".plutus_language_version", "PlutusLanguageVersion"),
    "PlutusV1Script": (".plutus_v1_script", "PlutusV1Script"),
    "PlutusV2Script": (".plutus_v2_script", "PlutusV2Script"),
    "PlutusV3Script": (".plutus_v3_script", "PlutusV3Script"),
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
    "PlutusLanguageVersion",
    "PlutusV1Script",
    "PlutusV2Script",
    "PlutusV3Script",
]
