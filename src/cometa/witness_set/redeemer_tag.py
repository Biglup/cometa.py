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


class RedeemerTag(IntEnum):
    """
    The redeemer tags act as an enumeration to signify the purpose or context of the
    redeemer in a transaction.

    When a Plutus script is executed, the specific action type related to the redeemer
    can be identified using these tags, allowing the script to respond appropriately.
    """

    SPEND = 0
    """
    Indicates the redeemer is associated with a spending script.

    A spending script validates the spending of a UTXO. A UTXO can have either a
    public key address or a script address. To spend a UTXO with a script address,
    the script whose hash matches the script address must be included in the
    transaction (either directly, or as a reference script), and is executed to
    validate it.
    """

    MINT = 1
    """
    Indicates the redeemer is associated with a minting script.

    Minting scripts, sometimes also referred to as minting policies, are used to
    approve or reject minting of new assets. In Cardano, we can uniquely identify
    an asset by its CurrencySymbol and TokenName.
    """

    CERTIFYING = 2
    """
    Indicates the redeemer is associated with a certifying script.

    A certifying script can validate a number of certificate-related transactions,
    such as: registering a staking credential, de-registering a staking credential,
    and delegating a staking credential to a particular delegatee.
    """

    REWARD = 3
    """
    Indicates the redeemer is associated with a rewarding script.

    A staking credential can contain either a public key hash or a script hash.
    To withdraw rewards from a reward account corresponding to a staking credential
    that contains a script hash, the script with that particular hash must be
    included in the transaction.
    """

    VOTING = 4
    """
    Indicates the redeemer is associated with a voting script.

    A voting script validates votes cast by a Delegated Representative (DRep) or
    a constitutional committee member (CCM) in a transaction.
    """

    PROPOSING = 5
    """
    Indicates the redeemer is associated with a proposing script.

    A proposing script, also known as constitution script or guardrail script,
    validates two kinds of governance actions: parameter change actions and
    treasury withdrawals actions.
    """
