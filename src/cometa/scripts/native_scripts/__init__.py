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

from typing import Any, Union, TYPE_CHECKING

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "NativeScriptType": (".native_script_type", "NativeScriptType"),
    "NativeScriptList": (".native_script_list", "NativeScriptList"),
    "NativeScript": (".native_script", "NativeScript"),
    "ScriptPubkey": (".script_pubkey", "ScriptPubkey"),
    "ScriptAll": (".script_all", "ScriptAll"),
    "ScriptAny": (".script_any", "ScriptAny"),
    "ScriptNOfK": (".script_n_of_k", "ScriptNOfK"),
    "ScriptInvalidBefore": (".script_invalid_before", "ScriptInvalidBefore"),
    "ScriptInvalidAfter": (".script_invalid_after", "ScriptInvalidAfter"),
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

    if name == "NativeScriptLike":
        from .native_script import NativeScript
        from .script_pubkey import ScriptPubkey
        from .script_all import ScriptAll
        from .script_any import ScriptAny
        from .script_n_of_k import ScriptNOfK
        from .script_invalid_before import ScriptInvalidBefore
        from .script_invalid_after import ScriptInvalidAfter
        value = Union[
            NativeScript,
            ScriptPubkey,
            ScriptAll,
            ScriptAny,
            ScriptNOfK,
            ScriptInvalidBefore,
            ScriptInvalidAfter,
        ]
        _cache[name] = value
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(__all__)


if TYPE_CHECKING:
    from .native_script import NativeScript
    from .script_pubkey import ScriptPubkey
    from .script_all import ScriptAll
    from .script_any import ScriptAny
    from .script_n_of_k import ScriptNOfK
    from .script_invalid_before import ScriptInvalidBefore
    from .script_invalid_after import ScriptInvalidAfter

    NativeScriptLike = Union[
        NativeScript,
        ScriptPubkey,
        ScriptAll,
        ScriptAny,
        ScriptNOfK,
        ScriptInvalidBefore,
        ScriptInvalidAfter,
    ]


__all__ = [
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
]
