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

from typing import Union

from .native_script_type import NativeScriptType
from .native_script_list import NativeScriptList
from .native_script import NativeScript
from .script_pubkey import ScriptPubkey
from .script_all import ScriptAll
from .script_any import ScriptAny
from .script_n_of_k import ScriptNOfK
from .script_invalid_before import ScriptInvalidBefore
from .script_invalid_after import ScriptInvalidAfter

# Type alias for any native script type
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
