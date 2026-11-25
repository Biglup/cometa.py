"""Complete Conway protocol parameters with exact rational prices."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from ..common import ExUnits, ProtocolVersion, UnitInterval
from ..protocol_params import ProtocolParameters, ExUnitPrices, Costmdls, CostModel, PoolVotingThresholds, DRepVotingThresholds
from ..scripts.plutus_scripts import PlutusLanguageVersion
from ._values import obj, array, integer, ratio, invalid

_NUMBERS = {
    "min_fee_a": "minFeeCoefficient", "min_fee_b": "minFeeConstant.ada.lovelace",
    "max_block_body_size": "maxBlockBodySize.bytes", "max_block_header_size": "maxBlockHeaderSize.bytes",
    "max_tx_size": "maxTransactionSize.bytes", "max_value_size": "maxValueSize.bytes",
    "key_deposit": "stakeCredentialDeposit.ada.lovelace", "pool_deposit": "stakePoolDeposit.ada.lovelace",
    "max_epoch": "stakePoolRetirementEpochBound", "n_opt": "desiredNumberOfStakePools",
    "min_pool_cost": "minStakePoolCost.ada.lovelace", "ada_per_utxo_byte": "minUtxoDepositCoefficient",
    "collateral_percentage": "collateralPercentage", "max_collateral_inputs": "maxCollateralInputs",
    "min_committee_size": "constitutionalCommitteeMinSize", "committee_term_limit": "constitutionalCommitteeMaxTermLength",
    "drep_deposit": "delegateRepresentativeDeposit.ada.lovelace", "drep_inactivity_period": "delegateRepresentativeMaxIdleTime",
    "governance_action_deposit": "governanceActionDeposit.ada.lovelace", "governance_action_validity_period": "governanceActionLifetime",
    "ref_script_cost_stride": "minFeeReferenceScripts.range",
}


def field_at(source, path):
    """Read a required dotted path without accepting missing fields."""
    for key in path.split("."):
        source = obj(source)
        if key not in source:
            invalid()
        source = source[key]
    return source


def parameters(source):
    """Decode the complete Ogmios v6/v7 Conway parameter object."""
    result = ProtocolParameters.new()
    for target, origin in _NUMBERS.items():
        setattr(result, target, integer(field_at(source, origin), 0, 2**64 - 1))
    result.protocol_version = ProtocolVersion.new(integer(field_at(source, "version.major")), integer(field_at(source, "version.minor")))
    for target, origin in [("pool_pledge_influence", "stakePoolPledgeInfluence"),
                           ("ref_script_cost_per_byte", "minFeeReferenceScripts.base"),
                           ("ref_script_cost_multiplier", "minFeeReferenceScripts.multiplier")]:
        setattr(result, target, ratio(field_at(source, origin)))
    result.expansion_rate = ratio(field_at(source, "monetaryExpansion"), unit=True)
    result.treasury_growth_rate = ratio(field_at(source, "treasuryExpansion"), unit=True)
    result.decentralisation_param = UnitInterval.new(0, 1)
    result.execution_costs = ExUnitPrices.new(ratio(field_at(source, "scriptExecutionPrices.memory")), ratio(field_at(source, "scriptExecutionPrices.cpu")))
    for target, origin in [("max_tx_ex_units", "maxExecutionUnitsPerTransaction"), ("max_block_ex_units", "maxExecutionUnitsPerBlock")]:
        setattr(result, target, ExUnits.new(integer(field_at(source, origin + ".memory")), integer(field_at(source, origin + ".cpu"))))
    for target, origin in [("max_ref_script_size_per_tx", "maxReferenceScriptsSizePerTransaction"),
                           ("max_ref_script_size_per_block", "maxReferenceScriptsSizePerBlock")]:
        if origin in source:
            setattr(result, target, integer(field_at(source, origin + ".bytes")))
    models = Costmdls.new()
    languages = {f"plutus:v{index}": PlutusLanguageVersion(index - 1) for index in range(1, 5)}
    for language, costs in obj(field_at(source, "plutusCostModels")).items():
        if language not in languages:
            invalid()
        models.insert(CostModel.new(languages[language], [integer(cost, -(2**63), 2**63 - 1) for cost in array(costs)]))
    result.cost_models = models
    result.pool_voting_thresholds = _pool_thresholds(field_at(source, "stakePoolVotingThresholds"))
    result.drep_voting_thresholds = _drep_thresholds(field_at(source, "delegateRepresentativeVotingThresholds"))
    return result


def _pool_thresholds(source):
    fields = ["noConfidence", "constitutionalCommittee.default", "constitutionalCommittee.stateOfNoConfidence",
              "hardForkInitiation", "protocolParametersUpdate.security"]
    return PoolVotingThresholds.new(*(ratio(field_at(source, field), unit=True) for field in fields))


def _drep_thresholds(source):
    fields = ["noConfidence", "constitutionalCommittee.default", "constitutionalCommittee.stateOfNoConfidence", "constitution",
              "hardForkInitiation", "protocolParametersUpdate.network", "protocolParametersUpdate.economic",
              "protocolParametersUpdate.technical", "protocolParametersUpdate.governance", "treasuryWithdrawals"]
    return DRepVotingThresholds.new(*(ratio(field_at(source, field), unit=True) for field in fields))
