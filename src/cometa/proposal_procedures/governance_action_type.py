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


class GovernanceActionType(IntEnum):
    """
    Represents the different types of governance actions within the Cardano blockchain.

    These actions are part of Cardano's on-chain governance system (CIP-1694).
    """

    PARAMETER_CHANGE = 0
    """Updates one or more updatable protocol parameters, excluding hard forks."""

    HARD_FORK_INITIATION = 1
    """Initiates a non-backwards compatible upgrade of the network."""

    TREASURY_WITHDRAWALS = 2
    """Withdraws funds from the treasury."""

    NO_CONFIDENCE = 3
    """Proposes a state of no-confidence in the current constitutional committee."""

    UPDATE_COMMITTEE = 4
    """Modifies the composition of the constitutional committee."""

    NEW_CONSTITUTION = 5
    """Changes or amends the Constitution."""

    INFO = 6
    """An informational action with no direct effect on the blockchain."""
