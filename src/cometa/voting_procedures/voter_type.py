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

from .._ffi import lib, ffi


class VoterType(IntEnum):
    """
    Represents different kinds of voters within the Cardano governance system.

    Various roles in the Cardano ecosystem can participate in voting, including:
    - Constitutional Committee members (identified by key hash or script hash)
    - DReps (Delegation Representatives, identified by key hash or script hash)
    - SPOs (Stake Pool Operators, identified by key hash)
    """

    CONSTITUTIONAL_COMMITTEE_KEY_HASH = 0
    """Represents a constitutional committee member identified by a key hash."""

    CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH = 1
    """Represents a constitutional committee member identified by a script hash."""

    DREP_KEY_HASH = 2
    """Represents a DRep (Delegation Representative) identified by a key hash."""

    DREP_SCRIPT_HASH = 3
    """Represents a DRep (Delegation Representative) identified by a script hash."""

    STAKE_POOL_KEY_HASH = 4
    """Represents a Stake Pool Operator (SPO) identified by a key hash."""

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this voter type.

        Returns:
            A string representation of the voter type.

        Example:
            >>> from cometa.voting_procedures import VoterType
            >>> voter_type = VoterType.DREP_KEY_HASH
            >>> voter_type.to_string()
            'DRep Key Hash'
        """
        result = lib.cardano_voter_type_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
