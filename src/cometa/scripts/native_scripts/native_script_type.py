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


class NativeScriptType(IntEnum):
    """
    Enumerates the different types of native scripts in Cardano.

    Native scripts form an expression tree where each node evaluates to
    either true or false. The script type determines how the evaluation
    is performed.
    """

    REQUIRE_PUBKEY = 0
    """
    Requires a signature from a specific public key.

    This script evaluates to true if the transaction includes a valid key
    witness where the witness verification key hashes to the given hash.
    """

    REQUIRE_ALL_OF = 1
    """
    Requires all sub-scripts to evaluate to true.

    This script evaluates to true if all the sub-scripts evaluate to true.
    If the list of sub-scripts is empty, this script evaluates to true.
    """

    REQUIRE_ANY_OF = 2
    """
    Requires at least one sub-script to evaluate to true.

    This script evaluates to true if any of the sub-scripts evaluate to true.
    If the list of sub-scripts is empty, this script evaluates to false.
    """

    REQUIRE_N_OF_K = 3
    """
    Requires at least N of K sub-scripts to evaluate to true.

    This script evaluates to true if at least N (required field) of the
    sub-scripts evaluate to true.
    """

    INVALID_BEFORE = 4
    """
    Time-lock that activates at a specific slot.

    This script evaluates to true if the lower bound of the transaction
    validity interval is greater than or equal to the specified slot.
    """

    INVALID_AFTER = 5
    """
    Time-lock that expires at a specific slot.

    This script evaluates to true if the upper bound of the transaction
    validity interval is less than or equal to the specified slot.
    """
