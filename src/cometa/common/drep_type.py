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


class DRepType(IntEnum):
    """
    Represents the type of Delegated Representative (DRep) for governance participation.

    In order to participate in governance, a stake credential must be delegated to a DRep.
    Ada holders will generally delegate their voting rights to a registered DRep that will
    vote on their behalf. In addition, two pre-defined options are available: Abstain and
    No Confidence.
    """

    KEY_HASH = 0
    """A DRep identified by a stake key hash."""

    SCRIPT_HASH = 1
    """A DRep identified by a script hash."""

    ABSTAIN = 2
    """
    Indicates active non-participation in governance.

    If an Ada holder delegates to Abstain, their stake is actively marked as not
    participating in governance. The delegated stake will not be considered part
    of the active voting stake, but will still be considered registered for
    staking incentive purposes.
    """

    NO_CONFIDENCE = 3
    """
    Indicates a vote of no confidence in the constitutional committee.

    If an Ada holder delegates to No Confidence, their stake is counted as a Yes
    vote on every No Confidence action and a No vote on every other action. The
    delegated stake will be considered part of the active voting stake.
    """
