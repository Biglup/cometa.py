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
    "ScriptLanguage": (".script_language", "ScriptLanguage"),
    "Script": (".script", "Script"),
    "ScriptLike": (".script", "ScriptLike"),
    "PlutusScriptLike": (".script", "PlutusScriptLike"),
    # Native scripts
    "NativeScriptType": (".native_scripts", "NativeScriptType"),
    "NativeScriptList": (".native_scripts", "NativeScriptList"),
    "NativeScript": (".native_scripts", "NativeScript"),
    "NativeScriptLike": (".native_scripts", "NativeScriptLike"),
    "ScriptPubkey": (".native_scripts", "ScriptPubkey"),
    "ScriptAll": (".native_scripts", "ScriptAll"),
    "ScriptAny": (".native_scripts", "ScriptAny"),
    "ScriptNOfK": (".native_scripts", "ScriptNOfK"),
    "ScriptInvalidBefore": (".native_scripts", "ScriptInvalidBefore"),
    "ScriptInvalidAfter": (".native_scripts", "ScriptInvalidAfter"),
    # Plutus scripts
    "PlutusLanguageVersion": (".plutus_scripts", "PlutusLanguageVersion"),
    "PlutusV1Script": (".plutus_scripts", "PlutusV1Script"),
    "PlutusV2Script": (".plutus_scripts", "PlutusV2Script"),
    "PlutusV3Script": (".plutus_scripts", "PlutusV3Script"),
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
    # Script types
    "ScriptLanguage",
    "Script",
    "ScriptLike",
    # Native scripts
    "NativeScriptType",
    "NativeScriptList",
    "NativeScript",
    "NativeScriptLike",
    "ScriptPubkey",
    "ScriptAll",
    "ScriptAny",
    "ScriptNOfK",
    "ScriptInvalidBefore",
    "ScriptInvalidAfter",
    # Plutus scripts
    "PlutusLanguageVersion",
    "PlutusV1Script",
    "PlutusV2Script",
    "PlutusV3Script",
    "PlutusScriptLike",
]
