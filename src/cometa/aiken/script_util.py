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

import json
from typing import TYPE_CHECKING, Union, List

from .._aiken_ffi import aiken_ffi, aiken_lib
from ..errors import CardanoError
from ..cbor import CborWriter

if TYPE_CHECKING:
    from ..plutus_data import PlutusList, PlutusData


class ApplyParamsError(CardanoError):
    """Exception raised when applying parameters to a script fails."""


def apply_params_to_script(
    params: Union["PlutusList", List["PlutusData"]],
    compiled_code: str,
) -> str:
    """
    Apply parameters to a parameterized Plutus script.

    This function takes a list of Plutus data parameters and a compiled
    script (in hex format), and returns the script with parameters applied.

    Args:
        params: A PlutusList or list of PlutusData representing the parameters
                to apply to the script.
        compiled_code: The compiled script code in hex format (from blueprint).

    Returns:
        The compiled code with parameters applied, in hex format.

    Raises:
        ApplyParamsError: If applying parameters fails.

    Example:
        >>> from cometa.aiken import apply_params_to_script
        >>> from cometa.plutus_data import PlutusList, PlutusData
        >>>
        >>> # Create parameters
        >>> params = PlutusList()
        >>> params.append(PlutusData.from_hex("d87980"))  # Owner pubkey hash
        >>> params.append(42)  # Some integer parameter
        >>>
        >>> # Apply to compiled script from Aiken blueprint
        >>> compiled = "..."  # hex from blueprint
        >>> result = apply_params_to_script(params, compiled)
    """
    from ..plutus_data import PlutusList

    if isinstance(params, list):
        param_list = PlutusList.from_list(params)
    else:
        param_list = params

    params_hex = _serialize_params(param_list)

    result_ptr = aiken_lib.apply_params_to_plutus_script(
        params_hex.encode("utf-8") + b'\0',
        compiled_code.encode("utf-8") + b'\0',
    )

    try:
        result_str = aiken_ffi.string(result_ptr)
        result = json.loads(result_str)
    finally:
        aiken_lib.drop_char_pointer(result_ptr)

    status = result.get("status", "").upper()
    if status != "SUCCESS":
        error_msg = result.get("error", "Unknown error applying parameters")
        raise ApplyParamsError(f"Failed to apply parameters to script: {error_msg}")

    return result.get("compiled_code", "")


def _serialize_params(params: "PlutusList") -> str:
    """Serializes parameters to CBOR hex."""
    writer = CborWriter()
    params.to_cbor(writer)
    return writer.to_hex()
