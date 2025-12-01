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

from typing import Optional, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from ..protocol_params import Costmdls
    from ..witness_set import RedeemerList, PlutusDataSet
    from ..cryptography import Blake2bHash


def compute_script_data_hash(
    costmdls: "Costmdls",
    redeemers: "RedeemerList",
    datums: Optional["PlutusDataSet"] = None,
) -> "Blake2bHash":
    """
    Compute the hash of script data in a transaction.

    This function processes redeemers, datums, and cost models to compute a 32-byte
    hash that represents the script data for a transaction. The data is encoded in
    CBOR format and hashed using the Blake2b hashing algorithm.

    The script data hash is required in the transaction body when the transaction
    includes Plutus scripts.

    Args:
        costmdls: The cost models for script execution.
        redeemers: The transaction's redeemers.
        datums: Optional set of datums included in the transaction.

    Returns:
        The computed 32-byte Blake2b hash for the script data.

    Raises:
        CardanoError: If hash computation fails.

    Example:
        >>> from cometa.transaction_builder import compute_script_data_hash
        >>> from cometa.protocol_params import Costmdls
        >>> from cometa.witness_set import RedeemerList
        >>>
        >>> costmdls = Costmdls.new()
        >>> redeemers = RedeemerList.new()
        >>> # ... populate costmdls and redeemers ...
        >>> script_hash = compute_script_data_hash(costmdls, redeemers)
        >>> print(script_hash.to_hex())
    """
    from ..cryptography import Blake2bHash

    datums_ptr = ffi.NULL
    if datums is not None:
        datums_ptr = datums._ptr

    data_hash_out = ffi.new("cardano_blake2b_hash_t**")
    err = lib.cardano_compute_script_data_hash(
        costmdls._ptr, redeemers._ptr, datums_ptr, data_hash_out
    )
    if err != 0:
        raise CardanoError(f"Failed to compute script data hash (error code: {err})")

    return Blake2bHash(data_hash_out[0])
