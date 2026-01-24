# pylint: disable=undefined-all-variable
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

from typing import Any

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CertificateType": (".certificate_type", "CertificateType"),
    "MirCertPotType": (".mir_cert_pot_type", "MirCertPotType"),
    "MirCertType": (".mir_cert_type", "MirCertType"),
    "StakeRegistrationCert": (".stake_registration_cert", "StakeRegistrationCert"),
    "StakeDeregistrationCert": (".stake_deregistration_cert", "StakeDeregistrationCert"),
    "StakeDelegationCert": (".stake_delegation_cert", "StakeDelegationCert"),
    "PoolRegistrationCert": (".pool_registration_cert", "PoolRegistrationCert"),
    "PoolRetirementCert": (".pool_retirement_cert", "PoolRetirementCert"),
    "GenesisKeyDelegationCert": (".genesis_key_delegation_cert", "GenesisKeyDelegationCert"),
    "MirToPotCert": (".mir_to_pot_cert", "MirToPotCert"),
    "MirToStakeCredsCert": (".mir_to_stake_creds_cert", "MirToStakeCredsCert"),
    "MirCert": (".mir_cert", "MirCert"),
    "RegistrationCert": (".registration_cert", "RegistrationCert"),
    "UnregistrationCert": (".unregistration_cert", "UnregistrationCert"),
    "VoteDelegationCert": (".vote_delegation_cert", "VoteDelegationCert"),
    "StakeVoteDelegationCert": (".stake_vote_delegation_cert", "StakeVoteDelegationCert"),
    "StakeRegistrationDelegationCert": (".stake_registration_delegation_cert", "StakeRegistrationDelegationCert"),
    "VoteRegistrationDelegationCert": (".vote_registration_delegation_cert", "VoteRegistrationDelegationCert"),
    "StakeVoteRegistrationDelegationCert": (".stake_vote_registration_delegation_cert", "StakeVoteRegistrationDelegationCert"),
    "AuthCommitteeHotCert": (".auth_committee_hot_cert", "AuthCommitteeHotCert"),
    "ResignCommitteeColdCert": (".resign_committee_cold_cert", "ResignCommitteeColdCert"),
    "RegisterDRepCert": (".register_drep_cert", "RegisterDRepCert"),
    "UnregisterDRepCert": (".unregister_drep_cert", "UnregisterDRepCert"),
    "UpdateDRepCert": (".update_drep_cert", "UpdateDRepCert"),
    "Certificate": (".certificate", "Certificate"),
    "CertificateSet": (".certificate_set", "CertificateSet"),
}

_cache: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    if name in _cache:
        return _cache[name]

    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        from importlib import import_module
        module = import_module(module_path, __name__)
        value = getattr(module, attr_name)
        _cache[name] = value
        globals()[name] = value
        return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(__all__)


__all__ = [
    "AuthCommitteeHotCert",
    "Certificate",
    "CertificateSet",
    "CertificateType",
    "GenesisKeyDelegationCert",
    "MirCert",
    "MirCertPotType",
    "MirCertType",
    "MirToPotCert",
    "MirToStakeCredsCert",
    "PoolRegistrationCert",
    "PoolRetirementCert",
    "RegisterDRepCert",
    "RegistrationCert",
    "ResignCommitteeColdCert",
    "StakeDeregistrationCert",
    "StakeDelegationCert",
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
