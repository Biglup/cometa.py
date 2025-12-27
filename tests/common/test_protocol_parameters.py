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

import pytest
from cometa import (
    ProtocolParameters,
    UnitInterval,
    ProtocolVersion,
    ExUnits,
    Buffer,
    CardanoError,
)
from cometa.protocol_params import (
    Costmdls,
    ExUnitPrices,
    PoolVotingThresholds,
    DRepVotingThresholds,
)


class TestProtocolParametersNew:
    """Tests for ProtocolParameters.new() factory method."""

    def test_can_create_protocol_parameters(self):
        """Test that ProtocolParameters can be created."""
        params = ProtocolParameters.new()
        assert params is not None

    def test_protocol_parameters_repr(self):
        """Test that ProtocolParameters has a string representation."""
        params = ProtocolParameters.new()
        assert repr(params) == "ProtocolParameters(...)"

    def test_protocol_parameters_context_manager(self):
        """Test that ProtocolParameters can be used as a context manager."""
        with ProtocolParameters.new() as params:
            assert params is not None


class TestProtocolParametersFeeParameters:
    """Tests for fee-related parameters."""

    def test_get_min_fee_a_default_is_zero(self):
        """Test that min_fee_a defaults to zero."""
        params = ProtocolParameters.new()
        assert params.min_fee_a == 0

    def test_set_min_fee_a(self):
        """Test that min_fee_a can be set and retrieved."""
        params = ProtocolParameters.new()
        params.min_fee_a = 1000
        assert params.min_fee_a == 1000

    def test_set_min_fee_a_with_large_value(self):
        """Test that min_fee_a can handle large values."""
        params = ProtocolParameters.new()
        large_value = 18446744073709551615
        params.min_fee_a = large_value
        assert params.min_fee_a == large_value

    def test_get_min_fee_b_default_is_zero(self):
        """Test that min_fee_b defaults to zero."""
        params = ProtocolParameters.new()
        assert params.min_fee_b == 0

    def test_set_min_fee_b(self):
        """Test that min_fee_b can be set and retrieved."""
        params = ProtocolParameters.new()
        params.min_fee_b = 2000
        assert params.min_fee_b == 2000

    def test_set_min_fee_b_with_large_value(self):
        """Test that min_fee_b can handle large values."""
        params = ProtocolParameters.new()
        large_value = 18446744073709551615
        params.min_fee_b = large_value
        assert params.min_fee_b == large_value


class TestProtocolParametersSizeLimits:
    """Tests for size limit parameters."""

    def test_get_max_block_body_size_default_is_zero(self):
        """Test that max_block_body_size defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_block_body_size == 0

    def test_set_max_block_body_size(self):
        """Test that max_block_body_size can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_block_body_size = 65536
        assert params.max_block_body_size == 65536

    def test_get_max_tx_size_default_is_zero(self):
        """Test that max_tx_size defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_tx_size == 0

    def test_set_max_tx_size(self):
        """Test that max_tx_size can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_tx_size = 16384
        assert params.max_tx_size == 16384

    def test_get_max_block_header_size_default_is_zero(self):
        """Test that max_block_header_size defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_block_header_size == 0

    def test_set_max_block_header_size(self):
        """Test that max_block_header_size can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_block_header_size = 1100
        assert params.max_block_header_size == 1100


class TestProtocolParametersDepositParameters:
    """Tests for deposit-related parameters."""

    def test_get_key_deposit_default_is_zero(self):
        """Test that key_deposit defaults to zero."""
        params = ProtocolParameters.new()
        assert params.key_deposit == 0

    def test_set_key_deposit(self):
        """Test that key_deposit can be set and retrieved."""
        params = ProtocolParameters.new()
        params.key_deposit = 2000000
        assert params.key_deposit == 2000000

    def test_get_pool_deposit_default_is_zero(self):
        """Test that pool_deposit defaults to zero."""
        params = ProtocolParameters.new()
        assert params.pool_deposit == 0

    def test_set_pool_deposit(self):
        """Test that pool_deposit can be set and retrieved."""
        params = ProtocolParameters.new()
        params.pool_deposit = 500000000
        assert params.pool_deposit == 500000000


class TestProtocolParametersPoolParameters:
    """Tests for pool-related parameters."""

    def test_get_max_epoch_default_is_zero(self):
        """Test that max_epoch defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_epoch == 0

    def test_set_max_epoch(self):
        """Test that max_epoch can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_epoch = 18
        assert params.max_epoch == 18

    def test_get_n_opt_default_is_zero(self):
        """Test that n_opt defaults to zero."""
        params = ProtocolParameters.new()
        assert params.n_opt == 0

    def test_set_n_opt(self):
        """Test that n_opt can be set and retrieved."""
        params = ProtocolParameters.new()
        params.n_opt = 500
        assert params.n_opt == 500

    def test_get_pool_pledge_influence_default(self):
        """Test that pool_pledge_influence has a default value."""
        params = ProtocolParameters.new()
        result = params.pool_pledge_influence
        assert result is not None
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_pool_pledge_influence(self):
        """Test that pool_pledge_influence can be set and retrieved."""
        params = ProtocolParameters.new()
        unit_interval = UnitInterval.new(3, 10)
        params.pool_pledge_influence = unit_interval
        result = params.pool_pledge_influence
        assert result is not None
        assert result.numerator == 3
        assert result.denominator == 10

    def test_get_expansion_rate_default(self):
        """Test that expansion_rate has a default value."""
        params = ProtocolParameters.new()
        result = params.expansion_rate
        assert result is not None
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_expansion_rate(self):
        """Test that expansion_rate can be set and retrieved."""
        params = ProtocolParameters.new()
        unit_interval = UnitInterval.new(3, 1000)
        params.expansion_rate = unit_interval
        result = params.expansion_rate
        assert result is not None
        assert result.numerator == 3
        assert result.denominator == 1000

    def test_get_treasury_growth_rate_default(self):
        """Test that treasury_growth_rate has a default value."""
        params = ProtocolParameters.new()
        result = params.treasury_growth_rate
        assert result is not None
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_treasury_growth_rate(self):
        """Test that treasury_growth_rate can be set and retrieved."""
        params = ProtocolParameters.new()
        unit_interval = UnitInterval.new(2, 10)
        params.treasury_growth_rate = unit_interval
        result = params.treasury_growth_rate
        assert result is not None
        assert result.numerator == 2
        assert result.denominator == 10

    def test_get_d_default(self):
        """Test that d parameter has a default value."""
        params = ProtocolParameters.new()
        result = params.d
        assert result is not None
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_d(self):
        """Test that d parameter can be set and retrieved."""
        params = ProtocolParameters.new()
        unit_interval = UnitInterval.new(0, 1)
        params.d = unit_interval
        result = params.d
        assert result is not None
        assert result.numerator == 0
        assert result.denominator == 1

    def test_get_extra_entropy_default(self):
        """Test that extra_entropy has a default value."""
        params = ProtocolParameters.new()
        result = params.extra_entropy
        assert result is not None
        assert result.size == 0

    def test_set_extra_entropy(self):
        """Test that extra_entropy can be set and retrieved."""
        params = ProtocolParameters.new()
        buffer = Buffer.new(10)
        params.extra_entropy = buffer
        result = params.extra_entropy
        assert result is not None

    def test_get_protocol_version_default(self):
        """Test that protocol_version has a default value."""
        params = ProtocolParameters.new()
        result = params.protocol_version
        assert result is not None
        assert result.major == 0
        assert result.minor == 0

    def test_set_protocol_version(self):
        """Test that protocol_version can be set and retrieved."""
        params = ProtocolParameters.new()
        version = ProtocolVersion.new(8, 0)
        params.protocol_version = version
        result = params.protocol_version
        assert result is not None
        assert result.major == 8
        assert result.minor == 0

    def test_get_min_pool_cost_default_is_zero(self):
        """Test that min_pool_cost defaults to zero."""
        params = ProtocolParameters.new()
        assert params.min_pool_cost == 0

    def test_set_min_pool_cost(self):
        """Test that min_pool_cost can be set and retrieved."""
        params = ProtocolParameters.new()
        params.min_pool_cost = 340000000
        assert params.min_pool_cost == 340000000


class TestProtocolParametersUtxoParameters:
    """Tests for UTXO-related parameters."""

    def test_get_ada_per_utxo_byte_default_is_zero(self):
        """Test that ada_per_utxo_byte defaults to zero."""
        params = ProtocolParameters.new()
        assert params.ada_per_utxo_byte == 0

    def test_set_ada_per_utxo_byte(self):
        """Test that ada_per_utxo_byte can be set and retrieved."""
        params = ProtocolParameters.new()
        params.ada_per_utxo_byte = 4310
        assert params.ada_per_utxo_byte == 4310


class TestProtocolParametersPlutusParameters:
    """Tests for Plutus-related parameters."""

    def test_get_cost_models_default(self):
        """Test that cost_models has a default value."""
        params = ProtocolParameters.new()
        result = params.cost_models
        assert result is not None

    def test_set_cost_models(self):
        """Test that cost_models can be set and retrieved."""
        params = ProtocolParameters.new()
        costmdls = Costmdls.new()
        params.cost_models = costmdls
        result = params.cost_models
        assert result is not None

    def test_get_execution_costs_default(self):
        """Test that execution_costs has a default value."""
        params = ProtocolParameters.new()
        result = params.execution_costs
        assert result is not None

    def test_set_execution_costs(self):
        """Test that execution_costs can be set and retrieved."""
        params = ProtocolParameters.new()
        memory_prices = UnitInterval.new(577, 10000)
        steps_prices = UnitInterval.new(721, 10000000)
        ex_unit_prices = ExUnitPrices.new(memory_prices, steps_prices)
        params.execution_costs = ex_unit_prices
        result = params.execution_costs
        assert result is not None

    def test_get_max_tx_ex_units_default(self):
        """Test that max_tx_ex_units has a default value."""
        params = ProtocolParameters.new()
        result = params.max_tx_ex_units
        assert result is not None
        assert result.memory == 0
        assert result.cpu_steps == 0

    def test_set_max_tx_ex_units(self):
        """Test that max_tx_ex_units can be set and retrieved."""
        params = ProtocolParameters.new()
        ex_units = ExUnits.new(memory=10000000, cpu_steps=10000000000)
        params.max_tx_ex_units = ex_units
        result = params.max_tx_ex_units
        assert result is not None
        assert result.memory == 10000000
        assert result.cpu_steps == 10000000000

    def test_get_max_block_ex_units_default(self):
        """Test that max_block_ex_units has a default value."""
        params = ProtocolParameters.new()
        result = params.max_block_ex_units
        assert result is not None
        assert result.memory == 0
        assert result.cpu_steps == 0

    def test_set_max_block_ex_units(self):
        """Test that max_block_ex_units can be set and retrieved."""
        params = ProtocolParameters.new()
        ex_units = ExUnits.new(memory=50000000, cpu_steps=40000000000)
        params.max_block_ex_units = ex_units
        result = params.max_block_ex_units
        assert result is not None
        assert result.memory == 50000000
        assert result.cpu_steps == 40000000000

    def test_get_max_value_size_default_is_zero(self):
        """Test that max_value_size defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_value_size == 0

    def test_set_max_value_size(self):
        """Test that max_value_size can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_value_size = 5000
        assert params.max_value_size == 5000

    def test_get_collateral_percentage_default_is_zero(self):
        """Test that collateral_percentage defaults to zero."""
        params = ProtocolParameters.new()
        assert params.collateral_percentage == 0

    def test_set_collateral_percentage(self):
        """Test that collateral_percentage can be set and retrieved."""
        params = ProtocolParameters.new()
        params.collateral_percentage = 150
        assert params.collateral_percentage == 150

    def test_get_max_collateral_inputs_default_is_zero(self):
        """Test that max_collateral_inputs defaults to zero."""
        params = ProtocolParameters.new()
        assert params.max_collateral_inputs == 0

    def test_set_max_collateral_inputs(self):
        """Test that max_collateral_inputs can be set and retrieved."""
        params = ProtocolParameters.new()
        params.max_collateral_inputs = 3
        assert params.max_collateral_inputs == 3


class TestProtocolParametersGovernanceParameters:
    """Tests for governance-related parameters (Conway era)."""

    def test_get_pool_voting_thresholds_default(self):
        """Test that pool_voting_thresholds has a default value."""
        params = ProtocolParameters.new()
        result = params.pool_voting_thresholds
        assert result is not None

    def test_set_pool_voting_thresholds(self):
        """Test that pool_voting_thresholds can be set and retrieved."""
        params = ProtocolParameters.new()
        motion_no_confidence = UnitInterval.new(51, 100)
        committee_normal = UnitInterval.new(51, 100)
        committee_no_confidence = UnitInterval.new(51, 100)
        hard_fork_initiation = UnitInterval.new(51, 100)
        security_relevant_param = UnitInterval.new(51, 100)

        thresholds = PoolVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            hard_fork_initiation,
            security_relevant_param,
        )
        params.pool_voting_thresholds = thresholds
        result = params.pool_voting_thresholds
        assert result is not None

    def test_get_drep_voting_thresholds_default(self):
        """Test that drep_voting_thresholds has a default value."""
        params = ProtocolParameters.new()
        result = params.drep_voting_thresholds
        assert result is not None

    def test_set_drep_voting_thresholds(self):
        """Test that drep_voting_thresholds can be set and retrieved."""
        params = ProtocolParameters.new()
        motion_no_confidence = UnitInterval.new(67, 100)
        committee_normal = UnitInterval.new(67, 100)
        committee_no_confidence = UnitInterval.new(60, 100)
        update_constitution = UnitInterval.new(75, 100)
        hard_fork_initiation = UnitInterval.new(60, 100)
        pp_network_group = UnitInterval.new(67, 100)
        pp_economic_group = UnitInterval.new(67, 100)
        pp_technical_group = UnitInterval.new(67, 100)
        pp_governance_group = UnitInterval.new(75, 100)
        treasury_withdrawal = UnitInterval.new(67, 100)

        thresholds = DRepVotingThresholds.new(
            motion_no_confidence,
            committee_normal,
            committee_no_confidence,
            update_constitution,
            hard_fork_initiation,
            pp_network_group,
            pp_economic_group,
            pp_technical_group,
            pp_governance_group,
            treasury_withdrawal,
        )
        params.drep_voting_thresholds = thresholds
        result = params.drep_voting_thresholds
        assert result is not None

    def test_get_min_committee_size_default_is_zero(self):
        """Test that min_committee_size defaults to zero."""
        params = ProtocolParameters.new()
        assert params.min_committee_size == 0

    def test_set_min_committee_size(self):
        """Test that min_committee_size can be set and retrieved."""
        params = ProtocolParameters.new()
        params.min_committee_size = 7
        assert params.min_committee_size == 7

    def test_get_committee_term_limit_default_is_zero(self):
        """Test that committee_term_limit defaults to zero."""
        params = ProtocolParameters.new()
        assert params.committee_term_limit == 0

    def test_set_committee_term_limit(self):
        """Test that committee_term_limit can be set and retrieved."""
        params = ProtocolParameters.new()
        params.committee_term_limit = 146
        assert params.committee_term_limit == 146

    def test_get_governance_action_validity_period_default_is_zero(self):
        """Test that governance_action_validity_period defaults to zero."""
        params = ProtocolParameters.new()
        assert params.governance_action_validity_period == 0

    def test_set_governance_action_validity_period(self):
        """Test that governance_action_validity_period can be set and retrieved."""
        params = ProtocolParameters.new()
        params.governance_action_validity_period = 6
        assert params.governance_action_validity_period == 6

    def test_get_governance_action_deposit_default_is_zero(self):
        """Test that governance_action_deposit defaults to zero."""
        params = ProtocolParameters.new()
        assert params.governance_action_deposit == 0

    def test_set_governance_action_deposit(self):
        """Test that governance_action_deposit can be set and retrieved."""
        params = ProtocolParameters.new()
        params.governance_action_deposit = 100000000000
        assert params.governance_action_deposit == 100000000000

    def test_get_drep_deposit_default_is_zero(self):
        """Test that drep_deposit defaults to zero."""
        params = ProtocolParameters.new()
        assert params.drep_deposit == 0

    def test_set_drep_deposit(self):
        """Test that drep_deposit can be set and retrieved."""
        params = ProtocolParameters.new()
        params.drep_deposit = 500000000
        assert params.drep_deposit == 500000000

    def test_get_drep_inactivity_period_default_is_zero(self):
        """Test that drep_inactivity_period defaults to zero."""
        params = ProtocolParameters.new()
        assert params.drep_inactivity_period == 0

    def test_set_drep_inactivity_period(self):
        """Test that drep_inactivity_period can be set and retrieved."""
        params = ProtocolParameters.new()
        params.drep_inactivity_period = 20
        assert params.drep_inactivity_period == 20

    def test_get_ref_script_cost_per_byte_default(self):
        """Test that ref_script_cost_per_byte has a default value."""
        params = ProtocolParameters.new()
        result = params.ref_script_cost_per_byte
        assert result is not None
        assert result.numerator == 1
        assert result.denominator == 1

    def test_set_ref_script_cost_per_byte(self):
        """Test that ref_script_cost_per_byte can be set and retrieved."""
        params = ProtocolParameters.new()
        unit_interval = UnitInterval.new(15, 1)
        params.ref_script_cost_per_byte = unit_interval
        result = params.ref_script_cost_per_byte
        assert result is not None
        assert result.numerator == 15
        assert result.denominator == 1


class TestProtocolParametersInvalidArguments:
    """Tests for invalid arguments and error cases."""

    def test_set_min_fee_a_with_negative_value(self):
        """Test that setting min_fee_a with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.min_fee_a = -1

    def test_set_min_fee_b_with_negative_value(self):
        """Test that setting min_fee_b with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.min_fee_b = -1

    def test_set_max_block_body_size_with_negative_value(self):
        """Test that setting max_block_body_size with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.max_block_body_size = -1

    def test_set_max_tx_size_with_negative_value(self):
        """Test that setting max_tx_size with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.max_tx_size = -1

    def test_set_max_block_header_size_with_negative_value(self):
        """Test that setting max_block_header_size with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.max_block_header_size = -1

    def test_set_key_deposit_with_negative_value(self):
        """Test that setting key_deposit with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.key_deposit = -1

    def test_set_pool_deposit_with_negative_value(self):
        """Test that setting pool_deposit with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.pool_deposit = -1

    def test_set_max_epoch_with_negative_value(self):
        """Test that setting max_epoch with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.max_epoch = -1

    def test_set_n_opt_with_negative_value(self):
        """Test that setting n_opt with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.n_opt = -1

    def test_set_min_pool_cost_with_negative_value(self):
        """Test that setting min_pool_cost with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.min_pool_cost = -1

    def test_set_ada_per_utxo_byte_with_negative_value(self):
        """Test that setting ada_per_utxo_byte with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.ada_per_utxo_byte = -1

    def test_set_collateral_percentage_with_negative_value(self):
        """Test that setting collateral_percentage with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.collateral_percentage = -1

    def test_set_max_collateral_inputs_with_negative_value(self):
        """Test that setting max_collateral_inputs with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.max_collateral_inputs = -1

    def test_set_min_committee_size_with_negative_value(self):
        """Test that setting min_committee_size with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.min_committee_size = -1

    def test_set_committee_term_limit_with_negative_value(self):
        """Test that setting committee_term_limit with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.committee_term_limit = -1

    def test_set_governance_action_validity_period_with_negative_value(self):
        """Test that setting governance_action_validity_period with negative value raises error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.governance_action_validity_period = -1

    def test_set_governance_action_deposit_with_negative_value(self):
        """Test that setting governance_action_deposit with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.governance_action_deposit = -1

    def test_set_drep_deposit_with_negative_value(self):
        """Test that setting drep_deposit with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.drep_deposit = -1

    def test_set_drep_inactivity_period_with_negative_value(self):
        """Test that setting drep_inactivity_period with negative value raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            params.drep_inactivity_period = -1

    def test_set_pool_pledge_influence_with_invalid_type(self):
        """Test that setting pool_pledge_influence with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.pool_pledge_influence = "invalid"

    def test_set_expansion_rate_with_invalid_type(self):
        """Test that setting expansion_rate with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.expansion_rate = "invalid"

    def test_set_treasury_growth_rate_with_invalid_type(self):
        """Test that setting treasury_growth_rate with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.treasury_growth_rate = "invalid"

    def test_set_d_with_invalid_type(self):
        """Test that setting d with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.d = "invalid"

    def test_set_extra_entropy_with_invalid_type(self):
        """Test that setting extra_entropy with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.extra_entropy = "invalid"

    def test_set_protocol_version_with_invalid_type(self):
        """Test that setting protocol_version with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.protocol_version = "invalid"

    def test_set_cost_models_with_invalid_type(self):
        """Test that setting cost_models with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.cost_models = "invalid"

    def test_set_execution_costs_with_invalid_type(self):
        """Test that setting execution_costs with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.execution_costs = "invalid"

    def test_set_max_tx_ex_units_with_invalid_type(self):
        """Test that setting max_tx_ex_units with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.max_tx_ex_units = "invalid"

    def test_set_max_block_ex_units_with_invalid_type(self):
        """Test that setting max_block_ex_units with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.max_block_ex_units = "invalid"

    def test_set_pool_voting_thresholds_with_invalid_type(self):
        """Test that setting pool_voting_thresholds with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.pool_voting_thresholds = "invalid"

    def test_set_drep_voting_thresholds_with_invalid_type(self):
        """Test that setting drep_voting_thresholds with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.drep_voting_thresholds = "invalid"

    def test_set_ref_script_cost_per_byte_with_invalid_type(self):
        """Test that setting ref_script_cost_per_byte with invalid type raises an error."""
        params = ProtocolParameters.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            params.ref_script_cost_per_byte = "invalid"


class TestProtocolParametersMultipleProperties:
    """Tests for setting multiple properties together."""

    def test_can_set_all_integer_properties(self):
        """Test that all integer properties can be set together."""
        params = ProtocolParameters.new()
        params.min_fee_a = 44
        params.min_fee_b = 155381
        params.max_block_body_size = 65536
        params.max_tx_size = 16384
        params.max_block_header_size = 1100
        params.key_deposit = 2000000
        params.pool_deposit = 500000000
        params.max_epoch = 18
        params.n_opt = 500
        params.min_pool_cost = 340000000
        params.ada_per_utxo_byte = 4310
        params.max_value_size = 5000
        params.collateral_percentage = 150
        params.max_collateral_inputs = 3
        params.min_committee_size = 7
        params.committee_term_limit = 146
        params.governance_action_validity_period = 6
        params.governance_action_deposit = 100000000000
        params.drep_deposit = 500000000
        params.drep_inactivity_period = 20

        assert params.min_fee_a == 44
        assert params.min_fee_b == 155381
        assert params.max_block_body_size == 65536
        assert params.max_tx_size == 16384
        assert params.max_block_header_size == 1100
        assert params.key_deposit == 2000000
        assert params.pool_deposit == 500000000
        assert params.max_epoch == 18
        assert params.n_opt == 500
        assert params.min_pool_cost == 340000000
        assert params.ada_per_utxo_byte == 4310
        assert params.max_value_size == 5000
        assert params.collateral_percentage == 150
        assert params.max_collateral_inputs == 3
        assert params.min_committee_size == 7
        assert params.committee_term_limit == 146
        assert params.governance_action_validity_period == 6
        assert params.governance_action_deposit == 100000000000
        assert params.drep_deposit == 500000000
        assert params.drep_inactivity_period == 20

    def test_can_update_properties_multiple_times(self):
        """Test that properties can be updated multiple times."""
        params = ProtocolParameters.new()
        params.min_fee_a = 100
        assert params.min_fee_a == 100
        params.min_fee_a = 200
        assert params.min_fee_a == 200
        params.min_fee_a = 300
        assert params.min_fee_a == 300
