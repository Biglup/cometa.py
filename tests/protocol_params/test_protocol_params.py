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
    PlutusLanguageVersion,
    ExUnitPrices,
    CostModel,
    Costmdls,
    PoolVotingThresholds,
    DRepVotingThresholds,
    ProtocolParameters,
    UnitInterval,
    ExUnits,
    ProtocolVersion,
    CborWriter,
    CborReader,
)


class TestPlutusLanguageVersion:
    """Tests for PlutusLanguageVersion enum."""

    def test_values(self):
        """Test enum values."""
        assert PlutusLanguageVersion.V1 == 0
        assert PlutusLanguageVersion.V2 == 1
        assert PlutusLanguageVersion.V3 == 2

    def test_is_int_enum(self):
        """Test that PlutusLanguageVersion is an IntEnum."""
        assert isinstance(PlutusLanguageVersion.V1, int)

    def test_name(self):
        """Test name access."""
        assert PlutusLanguageVersion.V1.name == "V1"
        assert PlutusLanguageVersion.V2.name == "V2"
        assert PlutusLanguageVersion.V3.name == "V3"


class TestExUnitPrices:
    """Tests for ExUnitPrices class."""

    @pytest.fixture
    def memory_price(self):
        """Create a test memory price."""
        return UnitInterval.new(577, 10000)

    @pytest.fixture
    def steps_price(self):
        """Create a test steps price."""
        return UnitInterval.new(721, 10000000)

    def test_create(self, memory_price, steps_price):
        """Test creating ExUnitPrices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        assert prices is not None

    def test_get_memory_prices(self, memory_price, steps_price):
        """Test getting memory prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        mem = prices.memory_prices
        assert mem.numerator == 577
        assert mem.denominator == 10000

    def test_get_steps_prices(self, memory_price, steps_price):
        """Test getting steps prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        steps = prices.steps_prices
        assert steps.numerator == 721
        assert steps.denominator == 10000000

    def test_set_memory_prices(self, memory_price, steps_price):
        """Test setting memory prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        new_mem = UnitInterval.new(100, 1000)
        prices.memory_prices = new_mem
        assert prices.memory_prices.numerator == 100

    def test_set_steps_prices(self, memory_price, steps_price):
        """Test setting steps prices."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        new_steps = UnitInterval.new(200, 2000)
        prices.steps_prices = new_steps
        assert prices.steps_prices.numerator == 200

    def test_repr(self, memory_price, steps_price):
        """Test repr."""
        prices = ExUnitPrices.new(memory_price, steps_price)
        repr_str = repr(prices)
        assert "ExUnitPrices" in repr_str

    def test_cbor_roundtrip(self, memory_price, steps_price):
        """Test CBOR serialization/deserialization."""
        prices = ExUnitPrices.new(memory_price, steps_price)

        writer = CborWriter()
        prices.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        prices_restored = ExUnitPrices.from_cbor(reader)

        assert prices_restored.memory_prices.numerator == 577
        assert prices_restored.steps_prices.numerator == 721

    def test_context_manager(self, memory_price, steps_price):
        """Test context manager support."""
        with ExUnitPrices.new(memory_price, steps_price) as prices:
            assert prices is not None


class TestCostModel:
    """Tests for CostModel class."""

    @pytest.fixture
    def sample_costs(self):
        """Create sample costs array."""
        return [100000 + i * 1000 for i in range(166)]  # V1 has 166 parameters

    def test_create(self, sample_costs):
        """Test creating CostModel."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        assert model is not None

    def test_get_language(self, sample_costs):
        """Test getting language version."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        assert model.language == PlutusLanguageVersion.V1

    def test_len(self, sample_costs):
        """Test len."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        assert len(model) == 166

    def test_get_cost(self, sample_costs):
        """Test getting a specific cost."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        assert model.get_cost(0) == 100000
        assert model.get_cost(5) == 105000

    def test_set_cost(self, sample_costs):
        """Test setting a specific cost."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        model.set_cost(0, 999999)
        assert model.get_cost(0) == 999999

    def test_getitem(self, sample_costs):
        """Test dict-like getitem."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        assert model[0] == 100000
        assert model[10] == 110000

    def test_setitem(self, sample_costs):
        """Test dict-like setitem."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        model[0] = 888888
        assert model[0] == 888888

    def test_iter(self, sample_costs):
        """Test iteration."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        costs = list(model)
        assert len(costs) == 166
        assert costs[0] == 100000

    def test_get_costs(self, sample_costs):
        """Test get_costs returns list."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        costs = model.get_costs()
        assert len(costs) == 166
        assert costs[0] == 100000

    def test_repr(self, sample_costs):
        """Test repr."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)
        repr_str = repr(model)
        assert "CostModel" in repr_str
        assert "V1" in repr_str

    def test_cbor_roundtrip(self, sample_costs):
        """Test CBOR serialization/deserialization."""
        model = CostModel.new(PlutusLanguageVersion.V1, sample_costs)

        writer = CborWriter()
        model.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        model_restored = CostModel.from_cbor(reader)

        assert model_restored.language == PlutusLanguageVersion.V1
        assert len(model_restored) == 166


class TestCostmdls:
    """Tests for Costmdls collection."""

    @pytest.fixture
    def v1_costs(self):
        """Create V1 costs."""
        return [100000 + i * 1000 for i in range(166)]

    @pytest.fixture
    def v1_model(self, v1_costs):
        """Create a V1 cost model."""
        return CostModel.new(PlutusLanguageVersion.V1, v1_costs)

    def test_create_empty(self):
        """Test creating empty Costmdls."""
        costmdls = Costmdls.new()
        assert costmdls is not None

    def test_insert(self, v1_model):
        """Test inserting a cost model."""
        costmdls = Costmdls.new()
        costmdls.insert(v1_model)
        assert costmdls.has(PlutusLanguageVersion.V1)

    def test_get(self, v1_model):
        """Test getting a cost model."""
        costmdls = Costmdls.new()
        costmdls.insert(v1_model)
        retrieved = costmdls.get(PlutusLanguageVersion.V1)
        assert retrieved is not None
        assert retrieved.language == PlutusLanguageVersion.V1

    def test_get_not_found(self):
        """Test getting non-existent cost model."""
        costmdls = Costmdls.new()
        retrieved = costmdls.get(PlutusLanguageVersion.V2)
        assert retrieved is None

    def test_has(self, v1_model):
        """Test has method."""
        costmdls = Costmdls.new()
        assert not costmdls.has(PlutusLanguageVersion.V1)
        costmdls.insert(v1_model)
        assert costmdls.has(PlutusLanguageVersion.V1)

    def test_contains(self, v1_model):
        """Test __contains__."""
        costmdls = Costmdls.new()
        assert PlutusLanguageVersion.V1 not in costmdls
        costmdls.insert(v1_model)
        assert PlutusLanguageVersion.V1 in costmdls

    def test_getitem(self, v1_model):
        """Test dict-like getitem."""
        costmdls = Costmdls.new()
        costmdls.insert(v1_model)
        model = costmdls[PlutusLanguageVersion.V1]
        assert model.language == PlutusLanguageVersion.V1

    def test_getitem_not_found(self):
        """Test dict-like getitem raises KeyError."""
        costmdls = Costmdls.new()
        with pytest.raises(KeyError):
            _ = costmdls[PlutusLanguageVersion.V2]

    def test_repr(self, v1_model):
        """Test repr."""
        costmdls = Costmdls.new()
        costmdls.insert(v1_model)
        repr_str = repr(costmdls)
        assert "Costmdls" in repr_str
        assert "V1" in repr_str

    def test_cbor_roundtrip(self, v1_model):
        """Test CBOR serialization/deserialization."""
        costmdls = Costmdls.new()
        costmdls.insert(v1_model)

        writer = CborWriter()
        costmdls.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        costmdls_restored = Costmdls.from_cbor(reader)

        assert costmdls_restored.has(PlutusLanguageVersion.V1)

    def test_context_manager(self):
        """Test context manager support."""
        with Costmdls.new() as costmdls:
            assert costmdls is not None


class TestPoolVotingThresholds:
    """Tests for PoolVotingThresholds class."""

    @pytest.fixture
    def thresholds(self):
        """Create test thresholds."""
        return PoolVotingThresholds.new(
            motion_no_confidence=UnitInterval.new(51, 100),
            committee_normal=UnitInterval.new(60, 100),
            committee_no_confidence=UnitInterval.new(70, 100),
            hard_fork_initiation=UnitInterval.new(80, 100),
            security_relevant_param=UnitInterval.new(90, 100),
        )

    def test_create(self, thresholds):
        """Test creating PoolVotingThresholds."""
        assert thresholds is not None

    def test_motion_no_confidence(self, thresholds):
        """Test motion_no_confidence property."""
        val = thresholds.motion_no_confidence
        assert val.numerator == 51
        assert val.denominator == 100

    def test_committee_normal(self, thresholds):
        """Test committee_normal property."""
        val = thresholds.committee_normal
        assert val.numerator == 60

    def test_committee_no_confidence(self, thresholds):
        """Test committee_no_confidence property."""
        val = thresholds.committee_no_confidence
        assert val.numerator == 70

    def test_hard_fork_initiation(self, thresholds):
        """Test hard_fork_initiation property."""
        val = thresholds.hard_fork_initiation
        assert val.numerator == 80

    def test_security_relevant_param(self, thresholds):
        """Test security_relevant_param property."""
        val = thresholds.security_relevant_param
        assert val.numerator == 90

    def test_set_motion_no_confidence(self, thresholds):
        """Test setting motion_no_confidence."""
        thresholds.motion_no_confidence = UnitInterval.new(55, 100)
        assert thresholds.motion_no_confidence.numerator == 55

    def test_cbor_roundtrip(self, thresholds):
        """Test CBOR serialization/deserialization."""
        writer = CborWriter()
        thresholds.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        thresholds_restored = PoolVotingThresholds.from_cbor(reader)

        assert thresholds_restored.motion_no_confidence.numerator == 51

    def test_context_manager(self, thresholds):
        """Test context manager support."""
        with thresholds:
            assert thresholds is not None


class TestDRepVotingThresholds:
    """Tests for DRepVotingThresholds class."""

    @pytest.fixture
    def thresholds(self):
        """Create test thresholds."""
        return DRepVotingThresholds.new(
            motion_no_confidence=UnitInterval.new(51, 100),
            committee_normal=UnitInterval.new(60, 100),
            committee_no_confidence=UnitInterval.new(70, 100),
            update_constitution=UnitInterval.new(75, 100),
            hard_fork_initiation=UnitInterval.new(80, 100),
            pp_network_group=UnitInterval.new(65, 100),
            pp_economic_group=UnitInterval.new(66, 100),
            pp_technical_group=UnitInterval.new(67, 100),
            pp_governance_group=UnitInterval.new(68, 100),
            treasury_withdrawal=UnitInterval.new(50, 100),
        )

    def test_create(self, thresholds):
        """Test creating DRepVotingThresholds."""
        assert thresholds is not None

    def test_motion_no_confidence(self, thresholds):
        """Test motion_no_confidence property."""
        val = thresholds.motion_no_confidence
        assert val.numerator == 51

    def test_update_constitution(self, thresholds):
        """Test update_constitution property."""
        val = thresholds.update_constitution
        assert val.numerator == 75

    def test_pp_network_group(self, thresholds):
        """Test pp_network_group property."""
        val = thresholds.pp_network_group
        assert val.numerator == 65

    def test_pp_economic_group(self, thresholds):
        """Test pp_economic_group property."""
        val = thresholds.pp_economic_group
        assert val.numerator == 66

    def test_pp_technical_group(self, thresholds):
        """Test pp_technical_group property."""
        val = thresholds.pp_technical_group
        assert val.numerator == 67

    def test_pp_governance_group(self, thresholds):
        """Test pp_governance_group property."""
        val = thresholds.pp_governance_group
        assert val.numerator == 68

    def test_treasury_withdrawal(self, thresholds):
        """Test treasury_withdrawal property."""
        val = thresholds.treasury_withdrawal
        assert val.numerator == 50

    def test_set_treasury_withdrawal(self, thresholds):
        """Test setting treasury_withdrawal."""
        thresholds.treasury_withdrawal = UnitInterval.new(55, 100)
        assert thresholds.treasury_withdrawal.numerator == 55

    def test_cbor_roundtrip(self, thresholds):
        """Test CBOR serialization/deserialization."""
        writer = CborWriter()
        thresholds.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        thresholds_restored = DRepVotingThresholds.from_cbor(reader)

        assert thresholds_restored.motion_no_confidence.numerator == 51

    def test_context_manager(self, thresholds):
        """Test context manager support."""
        with thresholds:
            assert thresholds is not None


class TestProtocolParameters:
    """Tests for ProtocolParameters class."""

    def test_create_empty(self):
        """Test creating empty ProtocolParameters."""
        params = ProtocolParameters.new()
        assert params is not None

    def test_min_fee_a(self):
        """Test min_fee_a property."""
        params = ProtocolParameters.new()
        params.min_fee_a = 44
        assert params.min_fee_a == 44

    def test_min_fee_b(self):
        """Test min_fee_b property."""
        params = ProtocolParameters.new()
        params.min_fee_b = 155381
        assert params.min_fee_b == 155381

    def test_max_block_body_size(self):
        """Test max_block_body_size property."""
        params = ProtocolParameters.new()
        params.max_block_body_size = 90112
        assert params.max_block_body_size == 90112

    def test_max_tx_size(self):
        """Test max_tx_size property."""
        params = ProtocolParameters.new()
        params.max_tx_size = 16384
        assert params.max_tx_size == 16384

    def test_max_block_header_size(self):
        """Test max_block_header_size property."""
        params = ProtocolParameters.new()
        params.max_block_header_size = 1100
        assert params.max_block_header_size == 1100

    def test_key_deposit(self):
        """Test key_deposit property."""
        params = ProtocolParameters.new()
        params.key_deposit = 2000000
        assert params.key_deposit == 2000000

    def test_pool_deposit(self):
        """Test pool_deposit property."""
        params = ProtocolParameters.new()
        params.pool_deposit = 500000000
        assert params.pool_deposit == 500000000

    def test_max_epoch(self):
        """Test max_epoch property."""
        params = ProtocolParameters.new()
        params.max_epoch = 18
        assert params.max_epoch == 18

    def test_n_opt(self):
        """Test n_opt property."""
        params = ProtocolParameters.new()
        params.n_opt = 500
        assert params.n_opt == 500

    def test_pool_pledge_influence(self):
        """Test pool_pledge_influence property."""
        params = ProtocolParameters.new()
        pledge = UnitInterval.new(3, 10)
        params.pool_pledge_influence = pledge
        retrieved = params.pool_pledge_influence
        assert retrieved is not None
        assert retrieved.numerator == 3

    def test_expansion_rate(self):
        """Test expansion_rate property."""
        params = ProtocolParameters.new()
        rate = UnitInterval.new(3, 1000)
        params.expansion_rate = rate
        retrieved = params.expansion_rate
        assert retrieved is not None
        assert retrieved.numerator == 3

    def test_treasury_growth_rate(self):
        """Test treasury_growth_rate property."""
        params = ProtocolParameters.new()
        rate = UnitInterval.new(2, 10)
        params.treasury_growth_rate = rate
        retrieved = params.treasury_growth_rate
        assert retrieved is not None
        assert retrieved.numerator == 2

    def test_min_pool_cost(self):
        """Test min_pool_cost property."""
        params = ProtocolParameters.new()
        params.min_pool_cost = 340000000
        assert params.min_pool_cost == 340000000

    def test_ada_per_utxo_byte(self):
        """Test ada_per_utxo_byte property."""
        params = ProtocolParameters.new()
        params.ada_per_utxo_byte = 4310
        assert params.ada_per_utxo_byte == 4310

    def test_max_value_size(self):
        """Test max_value_size property."""
        params = ProtocolParameters.new()
        params.max_value_size = 5000
        assert params.max_value_size == 5000

    def test_collateral_percentage(self):
        """Test collateral_percentage property."""
        params = ProtocolParameters.new()
        params.collateral_percentage = 150
        assert params.collateral_percentage == 150

    def test_max_collateral_inputs(self):
        """Test max_collateral_inputs property."""
        params = ProtocolParameters.new()
        params.max_collateral_inputs = 3
        assert params.max_collateral_inputs == 3

    def test_min_committee_size(self):
        """Test min_committee_size property."""
        params = ProtocolParameters.new()
        params.min_committee_size = 7
        assert params.min_committee_size == 7

    def test_committee_term_limit(self):
        """Test committee_term_limit property."""
        params = ProtocolParameters.new()
        params.committee_term_limit = 146
        assert params.committee_term_limit == 146

    def test_governance_action_validity_period(self):
        """Test governance_action_validity_period property."""
        params = ProtocolParameters.new()
        params.governance_action_validity_period = 6
        assert params.governance_action_validity_period == 6

    def test_governance_action_deposit(self):
        """Test governance_action_deposit property."""
        params = ProtocolParameters.new()
        params.governance_action_deposit = 100000000000
        assert params.governance_action_deposit == 100000000000

    def test_drep_deposit(self):
        """Test drep_deposit property."""
        params = ProtocolParameters.new()
        params.drep_deposit = 500000000
        assert params.drep_deposit == 500000000

    def test_drep_inactivity_period(self):
        """Test drep_inactivity_period property."""
        params = ProtocolParameters.new()
        params.drep_inactivity_period = 20
        assert params.drep_inactivity_period == 20

    def test_protocol_version(self):
        """Test protocol_version property."""
        params = ProtocolParameters.new()
        version = ProtocolVersion.new(9, 0)
        params.protocol_version = version
        retrieved = params.protocol_version
        assert retrieved is not None
        assert retrieved.major == 9
        assert retrieved.minor == 0

    def test_cost_models(self):
        """Test cost_models property."""
        params = ProtocolParameters.new()
        costs = [100000 + i * 1000 for i in range(166)]
        model = CostModel.new(PlutusLanguageVersion.V1, costs)
        costmdls = Costmdls.new()
        costmdls.insert(model)

        params.cost_models = costmdls
        retrieved = params.cost_models
        assert retrieved is not None
        assert retrieved.has(PlutusLanguageVersion.V1)

    def test_execution_costs(self):
        """Test execution_costs property."""
        params = ProtocolParameters.new()
        mem_price = UnitInterval.new(577, 10000)
        steps_price = UnitInterval.new(721, 10000000)
        prices = ExUnitPrices.new(mem_price, steps_price)

        params.execution_costs = prices
        retrieved = params.execution_costs
        assert retrieved is not None
        assert retrieved.memory_prices.numerator == 577

    def test_max_tx_ex_units(self):
        """Test max_tx_ex_units property."""
        params = ProtocolParameters.new()
        ex_units = ExUnits.new(14000000, 10000000000)
        params.max_tx_ex_units = ex_units
        retrieved = params.max_tx_ex_units
        assert retrieved is not None
        assert retrieved.memory == 14000000

    def test_max_block_ex_units(self):
        """Test max_block_ex_units property."""
        params = ProtocolParameters.new()
        ex_units = ExUnits.new(62000000, 20000000000)
        params.max_block_ex_units = ex_units
        retrieved = params.max_block_ex_units
        assert retrieved is not None
        assert retrieved.memory == 62000000

    def test_pool_voting_thresholds(self):
        """Test pool_voting_thresholds property."""
        params = ProtocolParameters.new()
        thresholds = PoolVotingThresholds.new(
            motion_no_confidence=UnitInterval.new(51, 100),
            committee_normal=UnitInterval.new(60, 100),
            committee_no_confidence=UnitInterval.new(70, 100),
            hard_fork_initiation=UnitInterval.new(80, 100),
            security_relevant_param=UnitInterval.new(90, 100),
        )
        params.pool_voting_thresholds = thresholds
        retrieved = params.pool_voting_thresholds
        assert retrieved is not None
        assert retrieved.motion_no_confidence.numerator == 51

    def test_drep_voting_thresholds(self):
        """Test drep_voting_thresholds property."""
        params = ProtocolParameters.new()
        thresholds = DRepVotingThresholds.new(
            motion_no_confidence=UnitInterval.new(51, 100),
            committee_normal=UnitInterval.new(60, 100),
            committee_no_confidence=UnitInterval.new(70, 100),
            update_constitution=UnitInterval.new(75, 100),
            hard_fork_initiation=UnitInterval.new(80, 100),
            pp_network_group=UnitInterval.new(65, 100),
            pp_economic_group=UnitInterval.new(66, 100),
            pp_technical_group=UnitInterval.new(67, 100),
            pp_governance_group=UnitInterval.new(68, 100),
            treasury_withdrawal=UnitInterval.new(50, 100),
        )
        params.drep_voting_thresholds = thresholds
        retrieved = params.drep_voting_thresholds
        assert retrieved is not None
        assert retrieved.motion_no_confidence.numerator == 51

    def test_ref_script_cost_per_byte(self):
        """Test ref_script_cost_per_byte property."""
        params = ProtocolParameters.new()
        cost = UnitInterval.new(15, 1)
        params.ref_script_cost_per_byte = cost
        retrieved = params.ref_script_cost_per_byte
        assert retrieved is not None
        assert retrieved.numerator == 15

    def test_repr(self):
        """Test repr."""
        params = ProtocolParameters.new()
        repr_str = repr(params)
        assert "ProtocolParameters" in repr_str

    def test_context_manager(self):
        """Test context manager support."""
        with ProtocolParameters.new() as params:
            assert params is not None


class TestProtocolParamUpdate:
    """Tests for ProtocolParamUpdate class."""

    def test_create_new(self):
        """Test creating a new ProtocolParamUpdate."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update is not None

    def test_min_fee_a(self):
        """Test min_fee_a property - get and set."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        # Initially should be None (not set)
        assert update.min_fee_a is None
        # After setting, should return value
        update.min_fee_a = 44
        assert update.min_fee_a == 44

    def test_min_fee_b(self):
        """Test min_fee_b property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.min_fee_b is None
        update.min_fee_b = 155381
        assert update.min_fee_b == 155381

    def test_max_block_body_size(self):
        """Test max_block_body_size property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_block_body_size is None
        update.max_block_body_size = 90112
        assert update.max_block_body_size == 90112

    def test_max_tx_size(self):
        """Test max_tx_size property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_tx_size is None
        update.max_tx_size = 16384
        assert update.max_tx_size == 16384

    def test_max_block_header_size(self):
        """Test max_block_header_size property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_block_header_size is None
        update.max_block_header_size = 1100
        assert update.max_block_header_size == 1100

    def test_key_deposit(self):
        """Test key_deposit property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.key_deposit is None
        update.key_deposit = 2000000
        assert update.key_deposit == 2000000

    def test_pool_deposit(self):
        """Test pool_deposit property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.pool_deposit is None
        update.pool_deposit = 500000000
        assert update.pool_deposit == 500000000

    def test_max_epoch(self):
        """Test max_epoch property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_epoch is None
        update.max_epoch = 18
        assert update.max_epoch == 18

    def test_n_opt(self):
        """Test n_opt property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.n_opt is None
        update.n_opt = 500
        assert update.n_opt == 500

    def test_pool_pledge_influence(self):
        """Test pool_pledge_influence property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.pool_pledge_influence is None
        influence = UnitInterval.new(3, 10)
        update.pool_pledge_influence = influence
        retrieved = update.pool_pledge_influence
        assert retrieved is not None
        assert retrieved.numerator == 3

    def test_expansion_rate(self):
        """Test expansion_rate property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.expansion_rate is None
        rate = UnitInterval.new(3, 1000)
        update.expansion_rate = rate
        assert update.expansion_rate is not None

    def test_treasury_growth_rate(self):
        """Test treasury_growth_rate property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.treasury_growth_rate is None
        rate = UnitInterval.new(2, 10)
        update.treasury_growth_rate = rate
        assert update.treasury_growth_rate is not None

    def test_protocol_version(self):
        """Test protocol_version property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.protocol_version is None
        version = ProtocolVersion.new(9, 0)
        update.protocol_version = version
        retrieved = update.protocol_version
        assert retrieved is not None
        assert retrieved.major == 9

    def test_min_pool_cost(self):
        """Test min_pool_cost property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.min_pool_cost is None
        update.min_pool_cost = 340000000
        assert update.min_pool_cost == 340000000

    def test_ada_per_utxo_byte(self):
        """Test ada_per_utxo_byte property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.ada_per_utxo_byte is None
        update.ada_per_utxo_byte = 4310
        assert update.ada_per_utxo_byte == 4310

    def test_cost_models(self):
        """Test cost_models property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.cost_models is None
        costmdls = Costmdls.new()
        update.cost_models = costmdls
        assert update.cost_models is not None

    def test_execution_costs(self):
        """Test execution_costs property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.execution_costs is None
        mem_price = UnitInterval.new(577, 10000)
        step_price = UnitInterval.new(721, 10000000)
        prices = ExUnitPrices.new(mem_price, step_price)
        update.execution_costs = prices
        assert update.execution_costs is not None

    def test_max_tx_ex_units(self):
        """Test max_tx_ex_units property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_tx_ex_units is None
        ex_units = ExUnits.new(14000000, 10000000000)
        update.max_tx_ex_units = ex_units
        retrieved = update.max_tx_ex_units
        assert retrieved is not None
        assert retrieved.memory == 14000000

    def test_max_block_ex_units(self):
        """Test max_block_ex_units property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_block_ex_units is None
        ex_units = ExUnits.new(62000000, 20000000000)
        update.max_block_ex_units = ex_units
        assert update.max_block_ex_units is not None

    def test_max_value_size(self):
        """Test max_value_size property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_value_size is None
        update.max_value_size = 5000
        assert update.max_value_size == 5000

    def test_collateral_percentage(self):
        """Test collateral_percentage property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.collateral_percentage is None
        update.collateral_percentage = 150
        assert update.collateral_percentage == 150

    def test_max_collateral_inputs(self):
        """Test max_collateral_inputs property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.max_collateral_inputs is None
        update.max_collateral_inputs = 3
        assert update.max_collateral_inputs == 3

    def test_pool_voting_thresholds(self):
        """Test pool_voting_thresholds property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.pool_voting_thresholds is None
        thresholds = PoolVotingThresholds.new(
            UnitInterval.new(51, 100),
            UnitInterval.new(51, 100),
            UnitInterval.new(51, 100),
            UnitInterval.new(75, 100),
            UnitInterval.new(51, 100),
        )
        update.pool_voting_thresholds = thresholds
        assert update.pool_voting_thresholds is not None

    def test_drep_voting_thresholds(self):
        """Test drep_voting_thresholds property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.drep_voting_thresholds is None
        thresholds = DRepVotingThresholds.new(
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(75, 100),
            UnitInterval.new(60, 100),
            UnitInterval.new(67, 100),
            UnitInterval.new(67, 100),
        )
        update.drep_voting_thresholds = thresholds
        assert update.drep_voting_thresholds is not None

    def test_min_committee_size(self):
        """Test min_committee_size property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.min_committee_size is None
        update.min_committee_size = 7
        assert update.min_committee_size == 7

    def test_committee_term_limit(self):
        """Test committee_term_limit property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.committee_term_limit is None
        update.committee_term_limit = 146
        assert update.committee_term_limit == 146

    def test_governance_action_validity_period(self):
        """Test governance_action_validity_period property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.governance_action_validity_period is None
        update.governance_action_validity_period = 6
        assert update.governance_action_validity_period == 6

    def test_governance_action_deposit(self):
        """Test governance_action_deposit property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.governance_action_deposit is None
        update.governance_action_deposit = 100000000000
        assert update.governance_action_deposit == 100000000000

    def test_drep_deposit(self):
        """Test drep_deposit property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.drep_deposit is None
        update.drep_deposit = 500000000
        assert update.drep_deposit == 500000000

    def test_drep_inactivity_period(self):
        """Test drep_inactivity_period property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.drep_inactivity_period is None
        update.drep_inactivity_period = 20
        assert update.drep_inactivity_period == 20

    def test_ref_script_cost_per_byte(self):
        """Test ref_script_cost_per_byte property."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        assert update.ref_script_cost_per_byte is None
        cost = UnitInterval.new(15, 1)
        update.ref_script_cost_per_byte = cost
        assert update.ref_script_cost_per_byte is not None

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        update.min_fee_b = 155381
        update.max_tx_size = 16384

        writer = CborWriter()
        update.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        decoded = ProtocolParamUpdate.from_cbor(reader)
        assert decoded.min_fee_a == 44
        assert decoded.min_fee_b == 155381
        assert decoded.max_tx_size == 16384

    def test_repr(self):
        """Test repr."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        repr_str = repr(update)
        assert "ProtocolParamUpdate" in repr_str

    def test_context_manager(self):
        """Test context manager support."""
        from cometa import ProtocolParamUpdate

        with ProtocolParamUpdate.new() as update:
            assert update is not None

    def test_setting_none_is_noop(self):
        """Test that setting None does not modify the value."""
        from cometa import ProtocolParamUpdate

        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        update.min_fee_a = None  # Should be a no-op
        assert update.min_fee_a == 44


class TestProposedParamUpdates:
    """Tests for ProposedParamUpdates class."""

    @pytest.fixture
    def genesis_hash(self):
        """Create a test genesis delegate key hash."""
        from cometa import Blake2bHash

        return Blake2bHash.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )

    @pytest.fixture
    def genesis_hash2(self):
        """Create another test genesis delegate key hash."""
        from cometa import Blake2bHash

        return Blake2bHash.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002"
        )

    def test_create_new(self):
        """Test creating a new ProposedParamUpdates."""
        from cometa import ProposedParamUpdates

        updates = ProposedParamUpdates.new()
        assert updates is not None
        assert len(updates) == 0

    def test_insert_and_get(self, genesis_hash):
        """Test inserting and retrieving an update."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_a = 50

        updates.insert(genesis_hash, param_update)
        assert len(updates) == 1

        retrieved = updates.get(genesis_hash)
        assert retrieved is not None
        assert retrieved.min_fee_a == 50

    def test_getitem(self, genesis_hash):
        """Test dictionary-style access."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_b = 1000

        updates[genesis_hash] = param_update
        retrieved = updates[genesis_hash]
        assert retrieved.min_fee_b == 1000

    def test_getitem_key_error(self, genesis_hash):
        """Test KeyError on missing key."""
        from cometa import ProposedParamUpdates

        updates = ProposedParamUpdates.new()
        with pytest.raises(KeyError):
            _ = updates[genesis_hash]

    def test_contains(self, genesis_hash):
        """Test __contains__ (in operator)."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        assert genesis_hash not in updates

        param_update = ProtocolParamUpdate.new()
        updates.insert(genesis_hash, param_update)
        assert genesis_hash in updates

    def test_len(self, genesis_hash, genesis_hash2):
        """Test length."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        assert len(updates) == 0

        updates.insert(genesis_hash, ProtocolParamUpdate.new())
        assert len(updates) == 1

        updates.insert(genesis_hash2, ProtocolParamUpdate.new())
        assert len(updates) == 2

    def test_iteration(self, genesis_hash, genesis_hash2):
        """Test iteration over key-value pairs."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()

        update1 = ProtocolParamUpdate.new()
        update1.min_fee_a = 100
        updates.insert(genesis_hash, update1)

        update2 = ProtocolParamUpdate.new()
        update2.min_fee_a = 200
        updates.insert(genesis_hash2, update2)

        items = list(updates)
        assert len(items) == 2

    def test_keys(self, genesis_hash, genesis_hash2):
        """Test keys iterator."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        updates.insert(genesis_hash, ProtocolParamUpdate.new())
        updates.insert(genesis_hash2, ProtocolParamUpdate.new())

        keys = list(updates.keys())
        assert len(keys) == 2

    def test_values(self, genesis_hash, genesis_hash2):
        """Test values iterator."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()

        update1 = ProtocolParamUpdate.new()
        update1.min_fee_a = 111
        updates.insert(genesis_hash, update1)

        update2 = ProtocolParamUpdate.new()
        update2.min_fee_a = 222
        updates.insert(genesis_hash2, update2)

        values = list(updates.values())
        assert len(values) == 2
        fees = {v.min_fee_a for v in values}
        assert 111 in fees
        assert 222 in fees

    def test_items(self, genesis_hash):
        """Test items iterator."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_a = 333
        updates.insert(genesis_hash, param_update)

        items = list(updates.items())
        assert len(items) == 1
        key, value = items[0]
        assert value.min_fee_a == 333

    def test_get_key_at(self, genesis_hash):
        """Test get_key_at method."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        updates.insert(genesis_hash, ProtocolParamUpdate.new())

        key = updates.get_key_at(0)
        assert key is not None

        key_oob = updates.get_key_at(100)
        assert key_oob is None

    def test_get_value_at(self, genesis_hash):
        """Test get_value_at method."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.max_tx_size = 8192
        updates.insert(genesis_hash, param_update)

        value = updates.get_value_at(0)
        assert value is not None
        assert value.max_tx_size == 8192

        value_oob = updates.get_value_at(100)
        assert value_oob is None

    def test_cbor_roundtrip(self, genesis_hash):
        """Test CBOR serialization roundtrip."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate

        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_a = 44
        updates.insert(genesis_hash, param_update)

        writer = CborWriter()
        updates.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        decoded = ProposedParamUpdates.from_cbor(reader)
        assert len(decoded) == 1

    def test_repr(self):
        """Test repr."""
        from cometa import ProposedParamUpdates

        updates = ProposedParamUpdates.new()
        repr_str = repr(updates)
        assert "ProposedParamUpdates" in repr_str
        assert "size=0" in repr_str

    def test_context_manager(self):
        """Test context manager support."""
        from cometa import ProposedParamUpdates

        with ProposedParamUpdates.new() as updates:
            assert updates is not None


class TestUpdate:
    """Tests for Update class."""

    def _create_proposed_updates(self):
        """Helper to create proposed updates."""
        from cometa import ProposedParamUpdates, ProtocolParamUpdate, Blake2bHash

        genesis_hash = Blake2bHash.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_a = 44
        updates.insert(genesis_hash, param_update)
        return updates, genesis_hash

    def test_create_new(self):
        """Test creating a new Update."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)
        assert update is not None

    def test_get_epoch(self):
        """Test getting the epoch."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)
        assert update.epoch == 300

    def test_set_epoch(self):
        """Test setting the epoch."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)
        update.epoch = 350
        assert update.epoch == 350

    def test_get_proposed_parameters(self):
        """Test getting proposed parameters."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)
        params = update.proposed_parameters
        assert params is not None
        assert len(params) == 1

    def test_set_proposed_parameters(self):
        """Test setting proposed parameters."""
        from cometa import Update, ProposedParamUpdates, ProtocolParamUpdate, Blake2bHash

        proposed_updates, genesis_hash = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)

        new_updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        param_update.min_fee_b = 999
        new_updates.insert(genesis_hash, param_update)

        update.proposed_parameters = new_updates
        retrieved = update.proposed_parameters
        assert len(retrieved) == 1

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)

        writer = CborWriter()
        update.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        decoded = Update.from_cbor(reader)
        assert decoded.epoch == 300

    def test_repr(self):
        """Test repr."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        update = Update.new(300, proposed_updates)
        repr_str = repr(update)
        assert "Update" in repr_str
        assert "epoch=300" in repr_str

    def test_context_manager(self):
        """Test context manager support."""
        from cometa import Update

        proposed_updates, _ = self._create_proposed_updates()
        with Update.new(300, proposed_updates) as update:
            assert update is not None
