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
    "Committee": (".committee", "Committee"),
    "CommitteeMembersMap": (".committee_members_map", "CommitteeMembersMap"),
    "Constitution": (".constitution", "Constitution"),
    "CredentialSet": (".credential_set", "CredentialSet"),
    "GovernanceActionType": (".governance_action_type", "GovernanceActionType"),
    "HardForkInitiationAction": (".hard_fork_initiation_action", "HardForkInitiationAction"),
    "InfoAction": (".info_action", "InfoAction"),
    "NewConstitutionAction": (".new_constitution_action", "NewConstitutionAction"),
    "NoConfidenceAction": (".no_confidence_action", "NoConfidenceAction"),
    "ParameterChangeAction": (".parameter_change_action", "ParameterChangeAction"),
    "ProposalProcedure": (".proposal_procedure", "ProposalProcedure"),
    "GovernanceAction": (".proposal_procedure", "GovernanceAction"),
    "ProposalProcedureSet": (".proposal_procedure_set", "ProposalProcedureSet"),
    "TreasuryWithdrawalsAction": (".treasury_withdrawals_action", "TreasuryWithdrawalsAction"),
    "UpdateCommitteeAction": (".update_committee_action", "UpdateCommitteeAction"),
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
    "Committee",
    "CommitteeMembersMap",
    "Constitution",
    "CredentialSet",
    "GovernanceAction",
    "GovernanceActionType",
    "HardForkInitiationAction",
    "InfoAction",
    "NewConstitutionAction",
    "NoConfidenceAction",
    "ParameterChangeAction",
    "ProposalProcedure",
    "ProposalProcedureSet",
    "TreasuryWithdrawalsAction",
    "UpdateCommitteeAction",
]
