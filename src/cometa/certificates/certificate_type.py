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


class CertificateType(IntEnum):
    """
    Enumerates the types of certificates available in the Cardano blockchain.

    Certificates are used to register and manage stake, delegation, and
    governance-related operations on the Cardano blockchain.
    """

    STAKE_REGISTRATION = 0
    """Registers a new staking key."""

    STAKE_DEREGISTRATION = 1
    """Deregisters an existing staking key."""

    STAKE_DELEGATION = 2
    """Delegates stake to a pool."""

    POOL_REGISTRATION = 3
    """Registers a new stake pool."""

    POOL_RETIREMENT = 4
    """Retires an existing stake pool."""

    GENESIS_KEY_DELEGATION = 5
    """Delegates genesis keys (used in Shelley era)."""

    MOVE_INSTANTANEOUS_REWARDS = 6
    """Moves instantaneous rewards between reserves and treasury."""

    REGISTRATION = 7
    """Conway era registration with optional deposit."""

    UNREGISTRATION = 8
    """Conway era unregistration with deposit refund."""

    VOTE_DELEGATION = 9
    """Delegates voting power to a DRep."""

    STAKE_VOTE_DELEGATION = 10
    """Delegates both stake and voting power."""

    STAKE_REGISTRATION_DELEGATION = 11
    """Registers stake key and delegates in one certificate."""

    VOTE_REGISTRATION_DELEGATION = 12
    """Registers voting and delegates to DRep in one certificate."""

    STAKE_VOTE_REGISTRATION_DELEGATION = 13
    """Registers stake, voting and delegates both in one certificate."""

    AUTH_COMMITTEE_HOT = 14
    """Authorizes a committee hot key."""

    RESIGN_COMMITTEE_COLD = 15
    """Resigns from the constitutional committee."""

    DREP_REGISTRATION = 16
    """Registers as a DRep (Delegated Representative)."""

    DREP_UNREGISTRATION = 17
    """Unregisters from being a DRep."""

    UPDATE_DREP = 18
    """Updates DRep information."""

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this certificate type.

        Returns:
            A string representation of the certificate type.

        Example:
            >>> from cometa.certificates import CertificateType
            >>> cert_type = CertificateType.STAKE_REGISTRATION
            >>> cert_type.to_string()
            'Stake Registration'
        """
        result = lib.cardano_cert_type_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
