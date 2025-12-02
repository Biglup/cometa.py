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

from typing import TYPE_CHECKING, Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .certificate_type import CertificateType

if TYPE_CHECKING:
    from .auth_committee_hot_cert import AuthCommitteeHotCert
    from .genesis_key_delegation_cert import GenesisKeyDelegationCert
    from .mir_cert import MirCert
    from .pool_registration_cert import PoolRegistrationCert
    from .pool_retirement_cert import PoolRetirementCert
    from .register_drep_cert import RegisterDRepCert
    from .registration_cert import RegistrationCert
    from .resign_committee_cold_cert import ResignCommitteeColdCert
    from .stake_delegation_cert import StakeDelegationCert
    from .stake_deregistration_cert import StakeDeregistrationCert
    from .stake_registration_cert import StakeRegistrationCert
    from .stake_registration_delegation_cert import StakeRegistrationDelegationCert
    from .stake_vote_delegation_cert import StakeVoteDelegationCert
    from .stake_vote_registration_delegation_cert import (
        StakeVoteRegistrationDelegationCert,
    )
    from .unregister_drep_cert import UnregisterDRepCert
    from .unregistration_cert import UnregistrationCert
    from .update_drep_cert import UpdateDRepCert
    from .vote_delegation_cert import VoteDelegationCert
    from .vote_registration_delegation_cert import VoteRegistrationDelegationCert


CertificateUnion = Union[
    "AuthCommitteeHotCert",
    "GenesisKeyDelegationCert",
    "MirCert",
    "PoolRegistrationCert",
    "PoolRetirementCert",
    "RegisterDRepCert",
    "RegistrationCert",
    "ResignCommitteeColdCert",
    "StakeDelegationCert",
    "StakeDeregistrationCert",
    "StakeRegistrationCert",
    "StakeRegistrationDelegationCert",
    "StakeVoteDelegationCert",
    "StakeVoteRegistrationDelegationCert",
    "UnregisterDRepCert",
    "UnregistrationCert",
    "UpdateDRepCert",
    "VoteDelegationCert",
    "VoteRegistrationDelegationCert",
]


class Certificate:
    """
    Represents a Cardano certificate.

    Certificates are a means to encode various essential operations related to stake
    delegation and stake pool management. Certificates are embedded in transactions and
    included in blocks. They're a vital aspect of Cardano's proof-of-stake mechanism,
    ensuring that stakeholders can participate in the protocol and its governance.

    The Certificate class can be constructed from any specific certificate type:

    Example:
        >>> stake_reg = StakeRegistrationCert.new(credential)
        >>> cert = Certificate(stake_reg)  # Automatic conversion
        >>> # Or explicitly:
        >>> cert = Certificate.from_cert(stake_reg)
    """

    # Map of certificate class names to their factory methods
    _CERT_FACTORIES = {
        "AuthCommitteeHotCert": "new_auth_committee_hot",
        "GenesisKeyDelegationCert": "new_genesis_key_delegation",
        "MirCert": "new_mir",
        "PoolRegistrationCert": "new_pool_registration",
        "PoolRetirementCert": "new_pool_retirement",
        "RegisterDRepCert": "new_register_drep",
        "RegistrationCert": "new_registration",
        "ResignCommitteeColdCert": "new_resign_committee_cold",
        "StakeDelegationCert": "new_stake_delegation",
        "StakeDeregistrationCert": "new_stake_deregistration",
        "StakeRegistrationCert": "new_stake_registration",
        "StakeRegistrationDelegationCert": "new_stake_registration_delegation",
        "StakeVoteDelegationCert": "new_stake_vote_delegation",
        "StakeVoteRegistrationDelegationCert": "new_stake_vote_registration_delegation",
        "UnregisterDRepCert": "new_unregister_drep",
        "UnregistrationCert": "new_unregistration",
        "UpdateDRepCert": "new_update_drep",
        "VoteDelegationCert": "new_vote_delegation",
        "VoteRegistrationDelegationCert": "new_vote_registration_delegation",
    }

    def __init__(self, cert_or_ptr) -> None:
        """
        Creates a Certificate from a raw pointer or a specific certificate type.

        Args:
            cert_or_ptr: Either a raw FFI pointer or a specific certificate instance
                        (e.g., StakeRegistrationCert, PoolRegistrationCert, etc.)

        Raises:
            CardanoError: If creation fails.
            TypeError: If the argument is not a valid certificate type.
        """
        # Check if it's a raw pointer (CData type from cffi)
        if isinstance(cert_or_ptr, ffi.CData):
            if cert_or_ptr == ffi.NULL:
                raise CardanoError("Certificate: invalid handle")
            self._ptr = cert_or_ptr
        else:
            # Try to convert from a specific certificate type
            class_name = type(cert_or_ptr).__name__
            if class_name in self._CERT_FACTORIES:
                factory_method = getattr(self, self._CERT_FACTORIES[class_name])
                converted = factory_method(cert_or_ptr)
                self._ptr = converted._ptr
                # Prevent the temporary from releasing the pointer
                converted._ptr = ffi.NULL
            elif class_name == "Certificate":
                # If it's already a Certificate, just ref the pointer
                lib.cardano_certificate_ref(cert_or_ptr._ptr)
                self._ptr = cert_or_ptr._ptr
            else:
                raise TypeError(
                    f"Cannot create Certificate from {class_name}. "
                    f"Expected a specific certificate type or raw pointer."
                )

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_certificate_t**", self._ptr)
            lib.cardano_certificate_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Certificate:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Certificate(type={self.cert_type.name})"

    @classmethod
    def from_cert(cls, cert: CertificateUnion) -> Certificate:
        """
        Creates a Certificate from any specific certificate type.

        This is an explicit conversion method. You can also use the constructor
        directly: Certificate(specific_cert).

        Args:
            cert: A specific certificate instance (e.g., StakeRegistrationCert,
                  PoolRegistrationCert, etc.)

        Returns:
            A new Certificate wrapping the specific certificate.

        Raises:
            TypeError: If the argument is not a valid certificate type.

        Example:
            >>> stake_reg = StakeRegistrationCert.new(credential)
            >>> cert = Certificate.from_cert(stake_reg)
        """
        return cls(cert)

    # Factory methods for creating certificates from specific types

    @classmethod
    def new_auth_committee_hot(cls, cert: AuthCommitteeHotCert) -> Certificate:
        """Creates a Certificate from an AuthCommitteeHotCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_auth_committee_hot(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from AuthCommitteeHotCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_genesis_key_delegation(
        cls, cert: GenesisKeyDelegationCert
    ) -> Certificate:
        """Creates a Certificate from a GenesisKeyDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_genesis_key_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from GenesisKeyDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_mir(cls, cert: MirCert) -> Certificate:
        """Creates a Certificate from a MirCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_mir(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from MirCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_pool_registration(cls, cert: PoolRegistrationCert) -> Certificate:
        """Creates a Certificate from a PoolRegistrationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_pool_registration(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from PoolRegistrationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_pool_retirement(cls, cert: PoolRetirementCert) -> Certificate:
        """Creates a Certificate from a PoolRetirementCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_pool_retirement(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from PoolRetirementCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_register_drep(cls, cert: RegisterDRepCert) -> Certificate:
        """Creates a Certificate from a RegisterDRepCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_register_drep(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from RegisterDRepCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_registration(cls, cert: RegistrationCert) -> Certificate:
        """Creates a Certificate from a RegistrationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_registration(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from RegistrationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_resign_committee_cold(cls, cert: ResignCommitteeColdCert) -> Certificate:
        """Creates a Certificate from a ResignCommitteeColdCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_resign_committee_cold(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from ResignCommitteeColdCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_delegation(cls, cert: StakeDelegationCert) -> Certificate:
        """Creates a Certificate from a StakeDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_deregistration(cls, cert: StakeDeregistrationCert) -> Certificate:
        """Creates a Certificate from a StakeDeregistrationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_deregistration(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeDeregistrationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_registration(cls, cert: StakeRegistrationCert) -> Certificate:
        """Creates a Certificate from a StakeRegistrationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_registration(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeRegistrationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_registration_delegation(
        cls, cert: StakeRegistrationDelegationCert
    ) -> Certificate:
        """Creates a Certificate from a StakeRegistrationDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_registration_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeRegistrationDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_vote_delegation(cls, cert: StakeVoteDelegationCert) -> Certificate:
        """Creates a Certificate from a StakeVoteDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_vote_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeVoteDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_stake_vote_registration_delegation(
        cls, cert: StakeVoteRegistrationDelegationCert
    ) -> Certificate:
        """Creates a Certificate from a StakeVoteRegistrationDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_stake_vote_registration_delegation(
            cert._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from StakeVoteRegistrationDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_unregister_drep(cls, cert: UnregisterDRepCert) -> Certificate:
        """Creates a Certificate from an UnregisterDRepCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_unregister_drep(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from UnregisterDRepCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_unregistration(cls, cert: UnregistrationCert) -> Certificate:
        """Creates a Certificate from an UnregistrationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_unregistration(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from UnregistrationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_update_drep(cls, cert: UpdateDRepCert) -> Certificate:
        """Creates a Certificate from an UpdateDRepCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_update_drep(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from UpdateDRepCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_vote_delegation(cls, cert: VoteDelegationCert) -> Certificate:
        """Creates a Certificate from a VoteDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_vote_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from VoteDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_vote_registration_delegation(
        cls, cert: VoteRegistrationDelegationCert
    ) -> Certificate:
        """Creates a Certificate from a VoteRegistrationDelegationCert."""
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_new_vote_registration_delegation(cert._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to create Certificate from VoteRegistrationDelegationCert (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Certificate:
        """
        Deserializes a Certificate from CBOR data.

        Args:
            reader: A CborReader positioned at the certificate data.

        Returns:
            A new Certificate deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_certificate_t**")
        err = lib.cardano_certificate_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Certificate from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the certificate to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_certificate_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Certificate to CBOR (error code: {err})"
            )

    @property
    def cert_type(self) -> CertificateType:
        """
        The type of this certificate.

        Returns:
            The CertificateType indicating the specific certificate type.
        """
        out = ffi.new("cardano_cert_type_t*")
        err = lib.cardano_cert_get_type(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get certificate type (error code: {err})")
        return CertificateType(out[0])

    # Conversion methods to extract specific certificate types

    def to_auth_committee_hot(self) -> AuthCommitteeHotCert:
        """Extracts the underlying AuthCommitteeHotCert."""
        from .auth_committee_hot_cert import AuthCommitteeHotCert

        out = ffi.new("cardano_auth_committee_hot_cert_t**")
        err = lib.cardano_certificate_to_auth_committee_hot(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to AuthCommitteeHotCert (error code: {err})"
            )
        return AuthCommitteeHotCert(out[0])

    def to_genesis_key_delegation(self) -> GenesisKeyDelegationCert:
        """Extracts the underlying GenesisKeyDelegationCert."""
        from .genesis_key_delegation_cert import GenesisKeyDelegationCert

        out = ffi.new("cardano_genesis_key_delegation_cert_t**")
        err = lib.cardano_certificate_to_genesis_key_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to GenesisKeyDelegationCert (error code: {err})"
            )
        return GenesisKeyDelegationCert(out[0])

    def to_mir(self) -> MirCert:
        """Extracts the underlying MirCert."""
        from .mir_cert import MirCert

        out = ffi.new("cardano_mir_cert_t**")
        err = lib.cardano_certificate_to_mir(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to MirCert (error code: {err})"
            )
        return MirCert(out[0])

    def to_pool_registration(self) -> PoolRegistrationCert:
        """Extracts the underlying PoolRegistrationCert."""
        from .pool_registration_cert import PoolRegistrationCert

        out = ffi.new("cardano_pool_registration_cert_t**")
        err = lib.cardano_certificate_to_pool_registration(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to PoolRegistrationCert (error code: {err})"
            )
        return PoolRegistrationCert(out[0])

    def to_pool_retirement(self) -> PoolRetirementCert:
        """Extracts the underlying PoolRetirementCert."""
        from .pool_retirement_cert import PoolRetirementCert

        out = ffi.new("cardano_pool_retirement_cert_t**")
        err = lib.cardano_certificate_to_pool_retirement(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to PoolRetirementCert (error code: {err})"
            )
        return PoolRetirementCert(out[0])

    def to_register_drep(self) -> RegisterDRepCert:
        """Extracts the underlying RegisterDRepCert."""
        from .register_drep_cert import RegisterDRepCert

        out = ffi.new("cardano_register_drep_cert_t**")
        err = lib.cardano_certificate_to_register_drep(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to RegisterDRepCert (error code: {err})"
            )
        return RegisterDRepCert(out[0])

    def to_registration(self) -> RegistrationCert:
        """Extracts the underlying RegistrationCert."""
        from .registration_cert import RegistrationCert

        out = ffi.new("cardano_registration_cert_t**")
        err = lib.cardano_certificate_to_registration(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to RegistrationCert (error code: {err})"
            )
        return RegistrationCert(out[0])

    def to_resign_committee_cold(self) -> ResignCommitteeColdCert:
        """Extracts the underlying ResignCommitteeColdCert."""
        from .resign_committee_cold_cert import ResignCommitteeColdCert

        out = ffi.new("cardano_resign_committee_cold_cert_t**")
        err = lib.cardano_certificate_to_resign_committee_cold(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to ResignCommitteeColdCert (error code: {err})"
            )
        return ResignCommitteeColdCert(out[0])

    def to_stake_delegation(self) -> StakeDelegationCert:
        """Extracts the underlying StakeDelegationCert."""
        from .stake_delegation_cert import StakeDelegationCert

        out = ffi.new("cardano_stake_delegation_cert_t**")
        err = lib.cardano_certificate_to_stake_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeDelegationCert (error code: {err})"
            )
        return StakeDelegationCert(out[0])

    def to_stake_deregistration(self) -> StakeDeregistrationCert:
        """Extracts the underlying StakeDeregistrationCert."""
        from .stake_deregistration_cert import StakeDeregistrationCert

        out = ffi.new("cardano_stake_deregistration_cert_t**")
        err = lib.cardano_certificate_to_stake_deregistration(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeDeregistrationCert (error code: {err})"
            )
        return StakeDeregistrationCert(out[0])

    def to_stake_registration(self) -> StakeRegistrationCert:
        """Extracts the underlying StakeRegistrationCert."""
        from .stake_registration_cert import StakeRegistrationCert

        out = ffi.new("cardano_stake_registration_cert_t**")
        err = lib.cardano_certificate_to_stake_registration(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeRegistrationCert (error code: {err})"
            )
        return StakeRegistrationCert(out[0])

    def to_stake_registration_delegation(self) -> StakeRegistrationDelegationCert:
        """Extracts the underlying StakeRegistrationDelegationCert."""
        from .stake_registration_delegation_cert import StakeRegistrationDelegationCert

        out = ffi.new("cardano_stake_registration_delegation_cert_t**")
        err = lib.cardano_certificate_to_stake_registration_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeRegistrationDelegationCert (error code: {err})"
            )
        return StakeRegistrationDelegationCert(out[0])

    def to_stake_vote_delegation(self) -> StakeVoteDelegationCert:
        """Extracts the underlying StakeVoteDelegationCert."""
        from .stake_vote_delegation_cert import StakeVoteDelegationCert

        out = ffi.new("cardano_stake_vote_delegation_cert_t**")
        err = lib.cardano_certificate_to_stake_vote_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeVoteDelegationCert (error code: {err})"
            )
        return StakeVoteDelegationCert(out[0])

    def to_stake_vote_registration_delegation(
        self,
    ) -> StakeVoteRegistrationDelegationCert:
        """Extracts the underlying StakeVoteRegistrationDelegationCert."""
        from .stake_vote_registration_delegation_cert import (
            StakeVoteRegistrationDelegationCert,
        )

        out = ffi.new("cardano_stake_vote_registration_delegation_cert_t**")
        err = lib.cardano_certificate_to_stake_vote_registration_delegation(
            self._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to StakeVoteRegistrationDelegationCert (error code: {err})"
            )
        return StakeVoteRegistrationDelegationCert(out[0])

    def to_unregister_drep(self) -> UnregisterDRepCert:
        """Extracts the underlying UnregisterDRepCert."""
        from .unregister_drep_cert import UnregisterDRepCert

        out = ffi.new("cardano_unregister_drep_cert_t**")
        err = lib.cardano_certificate_to_unregister_drep(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to UnregisterDRepCert (error code: {err})"
            )
        return UnregisterDRepCert(out[0])

    def to_unregistration(self) -> UnregistrationCert:
        """Extracts the underlying UnregistrationCert."""
        from .unregistration_cert import UnregistrationCert

        out = ffi.new("cardano_unregistration_cert_t**")
        err = lib.cardano_certificate_to_unregistration(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to UnregistrationCert (error code: {err})"
            )
        return UnregistrationCert(out[0])

    def to_update_drep(self) -> UpdateDRepCert:
        """Extracts the underlying UpdateDRepCert."""
        from .update_drep_cert import UpdateDRepCert

        out = ffi.new("cardano_update_drep_cert_t**")
        err = lib.cardano_certificate_to_update_drep(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to UpdateDRepCert (error code: {err})"
            )
        return UpdateDRepCert(out[0])

    def to_vote_delegation(self) -> VoteDelegationCert:
        """Extracts the underlying VoteDelegationCert."""
        from .vote_delegation_cert import VoteDelegationCert

        out = ffi.new("cardano_vote_delegation_cert_t**")
        err = lib.cardano_certificate_to_vote_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to VoteDelegationCert (error code: {err})"
            )
        return VoteDelegationCert(out[0])

    def to_vote_registration_delegation(self) -> VoteRegistrationDelegationCert:
        """Extracts the underlying VoteRegistrationDelegationCert."""
        from .vote_registration_delegation_cert import VoteRegistrationDelegationCert

        out = ffi.new("cardano_vote_registration_delegation_cert_t**")
        err = lib.cardano_certificate_to_vote_registration_delegation(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert Certificate to VoteRegistrationDelegationCert (error code: {err})"
            )
        return VoteRegistrationDelegationCert(out[0])

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this certificate to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_certificate_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
