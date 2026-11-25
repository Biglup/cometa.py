"""Hydra Cardano CLI JSON codecs for Conway Heads."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from ..cbor import CborReader
from ..common import Datum
from ..scripts import Script
from ._protocol import field_at, parameters
from ._outputs import output, inline_datum
from ._values import obj, hex_text, integer, invalid, unique

_FIELDS = {'collateralPercentage': 'collateralPercentage',
 'constitutionalCommitteeMaxTermLength': 'committeeMaxTermLength',
 'constitutionalCommitteeMinSize': 'committeeMinSize',
 'delegateRepresentativeDeposit.ada.lovelace': 'dRepDeposit',
 'delegateRepresentativeMaxIdleTime': 'dRepActivity',
 'delegateRepresentativeVotingThresholds.constitution': 'dRepVotingThresholds.updateToConstitution',
 'delegateRepresentativeVotingThresholds.constitutionalCommittee.default': 'dRepVotingThresholds.committeeNormal',
 'delegateRepresentativeVotingThresholds.constitutionalCommittee.stateOfNoConfidence': 'dRepVotingThresholds.committeeNoConfidence',
 'delegateRepresentativeVotingThresholds.hardForkInitiation': 'dRepVotingThresholds.hardForkInitiation',
 'delegateRepresentativeVotingThresholds.noConfidence': 'dRepVotingThresholds.motionNoConfidence',
 'delegateRepresentativeVotingThresholds.protocolParametersUpdate.economic': 'dRepVotingThresholds.ppEconomicGroup',
 'delegateRepresentativeVotingThresholds.protocolParametersUpdate.governance': 'dRepVotingThresholds.ppGovGroup',
 'delegateRepresentativeVotingThresholds.protocolParametersUpdate.network': 'dRepVotingThresholds.ppNetworkGroup',
 'delegateRepresentativeVotingThresholds.protocolParametersUpdate.technical': 'dRepVotingThresholds.ppTechnicalGroup',
 'delegateRepresentativeVotingThresholds.treasuryWithdrawals': 'dRepVotingThresholds.treasuryWithdrawal',
 'desiredNumberOfStakePools': 'stakePoolTargetNum',
 'governanceActionDeposit.ada.lovelace': 'govActionDeposit',
 'governanceActionLifetime': 'govActionLifetime',
 'maxBlockBodySize.bytes': 'maxBlockBodySize',
 'maxBlockHeaderSize.bytes': 'maxBlockHeaderSize',
 'maxCollateralInputs': 'maxCollateralInputs',
 'maxExecutionUnitsPerBlock.cpu': 'maxBlockExecutionUnits.steps',
 'maxExecutionUnitsPerBlock.memory': 'maxBlockExecutionUnits.memory',
 'maxExecutionUnitsPerTransaction.cpu': 'maxTxExecutionUnits.steps',
 'maxExecutionUnitsPerTransaction.memory': 'maxTxExecutionUnits.memory',
 'maxTransactionSize.bytes': 'maxTxSize',
 'maxValueSize.bytes': 'maxValueSize',
 'minFeeCoefficient': 'txFeePerByte',
 'minFeeConstant.ada.lovelace': 'txFeeFixed',
 'minFeeReferenceScripts.base': 'minFeeRefScriptCostPerByte',
 'minStakePoolCost.ada.lovelace': 'minPoolCost',
 'minUtxoDepositCoefficient': 'utxoCostPerByte',
 'monetaryExpansion': 'monetaryExpansion',
 'scriptExecutionPrices.cpu': 'executionUnitPrices.priceSteps',
 'scriptExecutionPrices.memory': 'executionUnitPrices.priceMemory',
 'stakeCredentialDeposit.ada.lovelace': 'stakeAddressDeposit',
 'stakePoolDeposit.ada.lovelace': 'stakePoolDeposit',
 'stakePoolPledgeInfluence': 'poolPledgeInfluence',
 'stakePoolRetirementEpochBound': 'poolRetireMaxEpoch',
 'stakePoolVotingThresholds.constitutionalCommittee.default': 'poolVotingThresholds.committeeNormal',
 'stakePoolVotingThresholds.constitutionalCommittee.stateOfNoConfidence': 'poolVotingThresholds.committeeNoConfidence',
 'stakePoolVotingThresholds.hardForkInitiation': 'poolVotingThresholds.hardForkInitiation',
 'stakePoolVotingThresholds.noConfidence': 'poolVotingThresholds.motionNoConfidence',
 'stakePoolVotingThresholds.protocolParametersUpdate.security': 'poolVotingThresholds.ppSecurityGroup',
 'treasuryExpansion': 'treasuryCut',
 'version.major': 'protocolVersion.major',
 'version.minor': 'protocolVersion.minor'}


def hydra_parameters(source):
    """Normalize Cardano CLI parameters, preserving exact decimal fractions."""
    normalized = {}
    for target, origin in _FIELDS.items():
        keys = target.split(".")
        parent = normalized
        for key in keys[:-1]:
            parent = parent.setdefault(key, {})
        parent[keys[-1]] = field_at(source, origin)
    major = integer(field_at(normalized, "version.major"))
    if not 9 <= major <= 11:
        raise ValueError("Unsupported Hydra ledger version")
    normalized["minFeeReferenceScripts"].update({"range": 25600, "multiplier": "6/5"})
    languages = {"PlutusV1": "plutus:v1", "PlutusV2": "plutus:v2", "PlutusV3": "plutus:v3"}
    models = obj(field_at(source, "costModels"))
    if models.keys() - languages.keys():
        invalid()
    normalized["plutusCostModels"] = {languages[key]: value for key, value in models.items()}
    return parameters(normalized)


def _script(raw):
    outer = obj(raw)
    envelope = obj(outer.get("script"))
    tags = {"SimpleScript": 0, "PlutusScriptV1": 1, "PlutusScriptV2": 2, "PlutusScriptV3": 3}
    kind = envelope.get("type")
    if kind not in tags:
        invalid()
    expected = "SimpleScriptLanguage" if tags[kind] == 0 else f"PlutusScriptLanguage {kind}"
    if outer.get("scriptLanguage") != expected:
        invalid()
    return Script.from_cbor(CborReader.from_hex(f"820{tags[kind]}" + hex_text(envelope.get("cborHex"))))


def _assets(value):
    result = {}
    for policy, tokens in value.items():
        if policy == "lovelace":
            continue
        normalized = hex_text(policy, 28)
        for name, quantity in obj(tokens).items():
            name = hex_text(name, empty=True)
            if len(name) > 64 or normalized + name in result:
                invalid()
            result[normalized + name] = integer(quantity, 1)
    return result


def hydra_outputs(source):
    """Decode snapshot UTxOs, including inline hashes and script envelopes."""
    outputs = []
    for reference, raw in obj(source).items():
        parts = reference.split("#")
        if len(parts) != 2:
            invalid()
        row = obj(raw)
        value = obj(row.get("value"))
        result = output(parts[0], parts[1], row.get("address"), value.get("lovelace", 0), _assets(value))
        tx_out = result.output
        if row.get("inlineDatumRaw") is not None:
            if row.get("datumhash") is not None:
                invalid()
            tx_out.datum = inline_datum(row["inlineDatumRaw"], row.get("inlineDatumhash"))
        else:
            if row.get("inlineDatum") is not None or row.get("inlineDatumhash") is not None:
                invalid()
            if row.get("datumhash") is not None:
                tx_out.datum = Datum.from_data_hash_hex(hex_text(row["datumhash"], 32))
        if row.get("referenceScript") is not None:
            tx_out.script_ref = _script(row["referenceScript"])
        outputs.append(result)
    return unique(outputs)
