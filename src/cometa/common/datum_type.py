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

from enum import IntEnum


class DatumType(IntEnum):
    """
    Represents different ways of associating a Datum with a UTxO in a transaction.

    Datums provide a way to attach data to transaction outputs, which is essential
    for Plutus smart contract execution.
    """

    DATA_HASH = 0
    """
    A hash of the datum is included in the transaction output.

    Instead of including the full Datum directly within the transaction, only
    a hash of the Datum is stored. This makes the transaction more compact,
    especially for large datums. When spending, the actual Datum value must
    be provided in the transaction witness set.
    """

    INLINE_DATA = 1
    """
    The actual datum value is included directly in the transaction output.

    The full datum is "inlined" in the transaction data itself, making it
    immediately available without needing to provide it separately when spending.
    """
