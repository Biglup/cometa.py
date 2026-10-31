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

from typing import List, Union, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from ..plutus_data import PlutusList, PlutusDataLike


class ApplyParamsError(CardanoError):
    """The script could not be decoded or parameterized."""


def apply_params_to_script(params: Union["PlutusList", List["PlutusDataLike"]],
                           compiled_code: str) -> str:
    """Apply Plutus data parameters locally and return the resulting script hex.

    ``compiled_code`` is a single CBOR wrapper around the flat-encoded program.
    Parameter order and types must match the validator's arguments.
    The input script and parameter list are left unchanged.
    """
    from ..plutus_data import PlutusList
    param_list = PlutusList.from_list(params) if isinstance(params, list) else params
    try:
        script = bytes.fromhex(compiled_code)
    except ValueError as exc:
        raise ApplyParamsError("Invalid script hex") from exc
    out = ffi.new("cardano_buffer_t **")
    try:
        err = lib.cardano_uplc_apply_params_to_script(param_list._ptr, script, len(script), out)
        if err:
            raise ApplyParamsError(f"Failed to apply script parameters (error code: {err})")
        return bytes(ffi.buffer(lib.cardano_buffer_get_data(out[0]),
                                lib.cardano_buffer_get_size(out[0]))).hex()
    finally:
        lib.cardano_buffer_unref(out)
