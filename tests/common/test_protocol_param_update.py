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
    ProtocolParamUpdate,
    CborReader,
    CborWriter,
    JsonWriter,
    UnitInterval,
    ProtocolVersion,
    ExUnits,
    Buffer,
    Costmdls,
    ExUnitPrices,
    PoolVotingThresholds,
    DRepVotingThresholds,
    CardanoError,
)


PROTOCOL_PARAM_UPDATE_CBOR = "b8210018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d018201913881821d81e82185902"
COSTMDLS_CBOR = "a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
EXECUTION_COSTS_CBOR = "82d81e820102d81e820103"
POOL_VOTING_THRESHOLDS_CBOR = "85d81e820000d81e820101d81e820202d81e820303d81e820404"
DREP_VOTING_THRESHOLDS_CBOR = "8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909"


class TestProtocolParamUpdateNew:
    """Tests for ProtocolParamUpdate.new() factory method."""

    def test_can_create_protocol_param_update(self):
        """Test that an empty ProtocolParamUpdate can be created."""
        update = ProtocolParamUpdate.new()
        assert update is not None

    def test_new_update_has_no_parameters_set(self):
        """Test that newly created update has all parameters unset (None)."""
        update = ProtocolParamUpdate.new()
        assert update.min_fee_a is None
        assert update.min_fee_b is None
        assert update.max_block_body_size is None
        assert update.max_tx_size is None
        assert update.max_block_header_size is None
        assert update.key_deposit is None
        assert update.pool_deposit is None
        assert update.max_epoch is None
        assert update.n_opt is None
        assert update.pool_pledge_influence is None
        assert update.expansion_rate is None
        assert update.treasury_growth_rate is None
        assert update.d is None
        assert update.extra_entropy is None
        assert update.protocol_version is None
        assert update.min_pool_cost is None
        assert update.ada_per_utxo_byte is None
        assert update.cost_models is None
        assert update.execution_costs is None
        assert update.max_tx_ex_units is None
        assert update.max_block_ex_units is None
        assert update.max_value_size is None
        assert update.collateral_percentage is None
        assert update.max_collateral_inputs is None
        assert update.pool_voting_thresholds is None
        assert update.drep_voting_thresholds is None
        assert update.min_committee_size is None
        assert update.committee_term_limit is None
        assert update.governance_action_validity_period is None
        assert update.governance_action_deposit is None
        assert update.drep_deposit is None
        assert update.drep_inactivity_period is None
        assert update.ref_script_cost_per_byte is None


class TestProtocolParamUpdateCbor:
    """Tests for CBOR serialization/deserialization."""

    def test_can_serialize_to_cbor(self):
        """Test that ProtocolParamUpdate can be serialized to CBOR."""
        reader = CborReader.from_hex(PROTOCOL_PARAM_UPDATE_CBOR)
        update = ProtocolParamUpdate.from_cbor(reader)

        writer = CborWriter()
        update.to_cbor(writer)
        result = writer.to_hex()

        assert result == PROTOCOL_PARAM_UPDATE_CBOR

    def test_can_deserialize_from_cbor(self):
        """Test that ProtocolParamUpdate can be deserialized from CBOR."""
        reader = CborReader.from_hex(PROTOCOL_PARAM_UPDATE_CBOR)
        update = ProtocolParamUpdate.from_cbor(reader)

        assert update is not None
        assert update.min_fee_a == 100
        assert update.min_fee_b == 200
        assert update.max_block_body_size == 300
        assert update.max_tx_size == 400
        assert update.max_block_header_size == 500

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        original = ProtocolParamUpdate.new()
        original.min_fee_a = 100
        original.min_fee_b = 200
        original.max_tx_size = 16384

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ProtocolParamUpdate.from_cbor(reader)

        assert deserialized.min_fee_a == 100
        assert deserialized.min_fee_b == 200
        assert deserialized.max_tx_size == 16384

    def test_from_cbor_raises_error_with_invalid_reader(self):
        """Test that from_cbor raises error with invalid reader."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProtocolParamUpdate.from_cbor(None)

    def test_to_cbor_raises_error_with_invalid_writer(self):
        """Test that to_cbor raises error with invalid writer."""
        update = ProtocolParamUpdate.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            update.to_cbor(None)

    def test_from_cbor_raises_error_with_duplicated_key(self):
        """Test that from_cbor raises error with duplicated CBOR map key."""
        reader = CborReader.from_hex("a200000000")
        with pytest.raises(CardanoError):
            ProtocolParamUpdate.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_entropy(self):
        """Test that from_cbor raises error with invalid entropy array."""
        reader = CborReader.from_hex("a10d830158200000000000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            ProtocolParamUpdate.from_cbor(reader)

    def test_from_cbor_can_read_empty_entropy(self):
        """Test that from_cbor can read empty entropy."""
        reader = CborReader.from_hex("a10d8100")
        update = ProtocolParamUpdate.from_cbor(reader)
        assert update is not None


class TestProtocolParamUpdateFeeParameters:
    """Tests for fee parameter properties (min_fee_a, min_fee_b)."""

    def test_can_set_and_get_min_fee_a(self):
        """Test setting and getting min_fee_a."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        assert update.min_fee_a == 44

    def test_can_set_and_get_min_fee_b(self):
        """Test setting and getting min_fee_b."""
        update = ProtocolParamUpdate.new()
        update.min_fee_b = 155381
        assert update.min_fee_b == 155381

    def test_min_fee_a_starts_as_none(self):
        """Test that min_fee_a starts as None."""
        update = ProtocolParamUpdate.new()
        assert update.min_fee_a is None

    def test_min_fee_b_starts_as_none(self):
        """Test that min_fee_b starts as None."""
        update = ProtocolParamUpdate.new()
        assert update.min_fee_b is None

    def test_can_set_min_fee_a_to_zero(self):
        """Test that min_fee_a can be set to zero."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 0
        assert update.min_fee_a == 0

    def test_can_set_min_fee_b_to_zero(self):
        """Test that min_fee_b can be set to zero."""
        update = ProtocolParamUpdate.new()
        update.min_fee_b = 0
        assert update.min_fee_b == 0

    def test_setting_min_fee_a_to_none_is_ignored(self):
        """Test that setting min_fee_a to None is ignored."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 100
        update.min_fee_a = None
        assert update.min_fee_a == 100

    def test_setting_min_fee_b_to_none_is_ignored(self):
        """Test that setting min_fee_b to None is ignored."""
        update = ProtocolParamUpdate.new()
        update.min_fee_b = 200
        update.min_fee_b = None
        assert update.min_fee_b == 200

    def test_min_fee_a_raises_error_for_negative(self):
        """Test that setting negative min_fee_a raises an error."""
        update = ProtocolParamUpdate.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            update.min_fee_a = -1

    def test_min_fee_b_raises_error_for_negative(self):
        """Test that setting negative min_fee_b raises an error."""
        update = ProtocolParamUpdate.new()
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            update.min_fee_b = -1


class TestProtocolParamUpdateSizeLimits:
    """Tests for size limit properties (max_block_body_size, max_tx_size, max_block_header_size)."""

    def test_can_set_and_get_max_block_body_size(self):
        """Test setting and getting max_block_body_size."""
        update = ProtocolParamUpdate.new()
        update.max_block_body_size = 90112
        assert update.max_block_body_size == 90112

    def test_can_set_and_get_max_tx_size(self):
        """Test setting and getting max_tx_size."""
        update = ProtocolParamUpdate.new()
        update.max_tx_size = 16384
        assert update.max_tx_size == 16384

    def test_can_set_and_get_max_block_header_size(self):
        """Test setting and getting max_block_header_size."""
        update = ProtocolParamUpdate.new()
        update.max_block_header_size = 1100
        assert update.max_block_header_size == 1100

    def test_setting_size_limits_to_none_is_ignored(self):
        """Test that setting size limits to None is ignored."""
        update = ProtocolParamUpdate.new()
        update.max_block_body_size = 100
        update.max_tx_size = 200
        update.max_block_header_size = 300

        update.max_block_body_size = None
        update.max_tx_size = None
        update.max_block_header_size = None

        assert update.max_block_body_size == 100
        assert update.max_tx_size == 200
        assert update.max_block_header_size == 300


class TestProtocolParamUpdateDepositParameters:
    """Tests for deposit parameter properties (key_deposit, pool_deposit)."""

    def test_can_set_and_get_key_deposit(self):
        """Test setting and getting key_deposit."""
        update = ProtocolParamUpdate.new()
        update.key_deposit = 2000000
        assert update.key_deposit == 2000000

    def test_can_set_and_get_pool_deposit(self):
        """Test setting and getting pool_deposit."""
        update = ProtocolParamUpdate.new()
        update.pool_deposit = 500000000
        assert update.pool_deposit == 500000000

    def test_deposit_parameters_start_as_none(self):
        """Test that deposit parameters start as None."""
        update = ProtocolParamUpdate.new()
        assert update.key_deposit is None
        assert update.pool_deposit is None


class TestProtocolParamUpdatePoolParameters:
    """Tests for pool parameter properties (max_epoch, n_opt, pool_pledge_influence, etc.)."""

    def test_can_set_and_get_max_epoch(self):
        """Test setting and getting max_epoch."""
        update = ProtocolParamUpdate.new()
        update.max_epoch = 18
        assert update.max_epoch == 18

    def test_can_set_and_get_n_opt(self):
        """Test setting and getting n_opt."""
        update = ProtocolParamUpdate.new()
        update.n_opt = 500
        assert update.n_opt == 500

    def test_can_set_and_get_pool_pledge_influence(self):
        """Test setting and getting pool_pledge_influence."""
        update = ProtocolParamUpdate.new()
        influence = UnitInterval.new(3, 10)
        update.pool_pledge_influence = influence
        result = update.pool_pledge_influence
        assert result is not None
        assert result.numerator == 3
        assert result.denominator == 10

    def test_can_set_and_get_expansion_rate(self):
        """Test setting and getting expansion_rate."""
        update = ProtocolParamUpdate.new()
        rate = UnitInterval.new(3, 1000)
        update.expansion_rate = rate
        result = update.expansion_rate
        assert result is not None
        assert result.numerator == 3
        assert result.denominator == 1000

    def test_can_set_and_get_treasury_growth_rate(self):
        """Test setting and getting treasury_growth_rate."""
        update = ProtocolParamUpdate.new()
        rate = UnitInterval.new(2, 10)
        update.treasury_growth_rate = rate
        result = update.treasury_growth_rate
        assert result is not None
        assert result.numerator == 2
        assert result.denominator == 10

    def test_can_set_and_get_d_parameter(self):
        """Test setting and getting d parameter."""
        update = ProtocolParamUpdate.new()
        d = UnitInterval.new(0, 1)
        update.d = d
        result = update.d
        assert result is not None
        assert result.numerator == 0
        assert result.denominator == 1

    def test_can_set_and_get_min_pool_cost(self):
        """Test setting and getting min_pool_cost."""
        update = ProtocolParamUpdate.new()
        update.min_pool_cost = 340000000
        assert update.min_pool_cost == 340000000

    def test_setting_unit_intervals_to_none_is_ignored(self):
        """Test that setting UnitInterval properties to None is ignored."""
        update = ProtocolParamUpdate.new()
        influence = UnitInterval.new(3, 10)
        update.pool_pledge_influence = influence

        update.pool_pledge_influence = None
        assert update.pool_pledge_influence is not None


class TestProtocolParamUpdateExtraEntropy:
    """Tests for extra_entropy property."""

    def test_can_set_and_get_extra_entropy(self):
        """Test setting and getting extra_entropy."""
        update = ProtocolParamUpdate.new()
        entropy = Buffer.from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        update.extra_entropy = entropy
        result = update.extra_entropy
        assert result is not None

    def test_extra_entropy_starts_as_none(self):
        """Test that extra_entropy starts as None."""
        update = ProtocolParamUpdate.new()
        assert update.extra_entropy is None

    def test_setting_extra_entropy_to_none_is_ignored(self):
        """Test that setting extra_entropy to None is ignored."""
        update = ProtocolParamUpdate.new()
        entropy = Buffer.from_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        update.extra_entropy = entropy
        update.extra_entropy = None
        assert update.extra_entropy is not None


class TestProtocolParamUpdateProtocolVersion:
    """Tests for protocol_version property."""

    def test_can_set_and_get_protocol_version(self):
        """Test setting and getting protocol_version."""
        update = ProtocolParamUpdate.new()
        version = ProtocolVersion.new(9, 0)
        update.protocol_version = version
        result = update.protocol_version
        assert result is not None
        assert result.major == 9
        assert result.minor == 0

    def test_protocol_version_starts_as_none(self):
        """Test that protocol_version starts as None."""
        update = ProtocolParamUpdate.new()
        assert update.protocol_version is None

    def test_setting_protocol_version_to_none_is_ignored(self):
        """Test that setting protocol_version to None is ignored."""
        update = ProtocolParamUpdate.new()
        version = ProtocolVersion.new(8, 0)
        update.protocol_version = version
        update.protocol_version = None
        assert update.protocol_version is not None


class TestProtocolParamUpdateUtxoParameters:
    """Tests for UTXO parameter properties (ada_per_utxo_byte)."""

    def test_can_set_and_get_ada_per_utxo_byte(self):
        """Test setting and getting ada_per_utxo_byte."""
        update = ProtocolParamUpdate.new()
        update.ada_per_utxo_byte = 4310
        assert update.ada_per_utxo_byte == 4310

    def test_ada_per_utxo_byte_starts_as_none(self):
        """Test that ada_per_utxo_byte starts as None."""
        update = ProtocolParamUpdate.new()
        assert update.ada_per_utxo_byte is None


class TestProtocolParamUpdatePlutusParameters:
    """Tests for Plutus parameter properties (cost_models, execution_costs, etc.)."""

    def test_can_set_and_get_cost_models(self):
        """Test setting and getting cost_models."""
        update = ProtocolParamUpdate.new()
        reader = CborReader.from_hex(COSTMDLS_CBOR)
        costmdls = Costmdls.from_cbor(reader)
        update.cost_models = costmdls
        result = update.cost_models
        assert result is not None

    def test_can_set_and_get_execution_costs(self):
        """Test setting and getting execution_costs."""
        update = ProtocolParamUpdate.new()
        reader = CborReader.from_hex(EXECUTION_COSTS_CBOR)
        ex_prices = ExUnitPrices.from_cbor(reader)
        update.execution_costs = ex_prices
        result = update.execution_costs
        assert result is not None

    def test_can_set_and_get_max_tx_ex_units(self):
        """Test setting and getting max_tx_ex_units."""
        update = ProtocolParamUpdate.new()
        ex_units = ExUnits.new(memory=10000000, cpu_steps=10000000000)
        update.max_tx_ex_units = ex_units
        result = update.max_tx_ex_units
        assert result is not None
        assert result.memory == 10000000
        assert result.cpu_steps == 10000000000

    def test_can_set_and_get_max_block_ex_units(self):
        """Test setting and getting max_block_ex_units."""
        update = ProtocolParamUpdate.new()
        ex_units = ExUnits.new(memory=62000000, cpu_steps=40000000000)
        update.max_block_ex_units = ex_units
        result = update.max_block_ex_units
        assert result is not None
        assert result.memory == 62000000
        assert result.cpu_steps == 40000000000

    def test_can_set_and_get_max_value_size(self):
        """Test setting and getting max_value_size."""
        update = ProtocolParamUpdate.new()
        update.max_value_size = 5000
        assert update.max_value_size == 5000

    def test_can_set_and_get_collateral_percentage(self):
        """Test setting and getting collateral_percentage."""
        update = ProtocolParamUpdate.new()
        update.collateral_percentage = 150
        assert update.collateral_percentage == 150

    def test_can_set_and_get_max_collateral_inputs(self):
        """Test setting and getting max_collateral_inputs."""
        update = ProtocolParamUpdate.new()
        update.max_collateral_inputs = 3
        assert update.max_collateral_inputs == 3

    def test_plutus_parameters_start_as_none(self):
        """Test that Plutus parameters start as None."""
        update = ProtocolParamUpdate.new()
        assert update.cost_models is None
        assert update.execution_costs is None
        assert update.max_tx_ex_units is None
        assert update.max_block_ex_units is None
        assert update.max_value_size is None
        assert update.collateral_percentage is None
        assert update.max_collateral_inputs is None


class TestProtocolParamUpdateGovernanceParameters:
    """Tests for governance parameter properties (Conway era)."""

    def test_can_set_and_get_pool_voting_thresholds(self):
        """Test setting and getting pool_voting_thresholds."""
        update = ProtocolParamUpdate.new()
        reader = CborReader.from_hex(POOL_VOTING_THRESHOLDS_CBOR)
        thresholds = PoolVotingThresholds.from_cbor(reader)
        update.pool_voting_thresholds = thresholds
        result = update.pool_voting_thresholds
        assert result is not None

    def test_can_set_and_get_drep_voting_thresholds(self):
        """Test setting and getting drep_voting_thresholds."""
        update = ProtocolParamUpdate.new()
        reader = CborReader.from_hex(DREP_VOTING_THRESHOLDS_CBOR)
        thresholds = DRepVotingThresholds.from_cbor(reader)
        update.drep_voting_thresholds = thresholds
        result = update.drep_voting_thresholds
        assert result is not None

    def test_can_set_and_get_min_committee_size(self):
        """Test setting and getting min_committee_size."""
        update = ProtocolParamUpdate.new()
        update.min_committee_size = 7
        assert update.min_committee_size == 7

    def test_can_set_and_get_committee_term_limit(self):
        """Test setting and getting committee_term_limit."""
        update = ProtocolParamUpdate.new()
        update.committee_term_limit = 146
        assert update.committee_term_limit == 146

    def test_can_set_and_get_governance_action_validity_period(self):
        """Test setting and getting governance_action_validity_period."""
        update = ProtocolParamUpdate.new()
        update.governance_action_validity_period = 6
        assert update.governance_action_validity_period == 6

    def test_can_set_and_get_governance_action_deposit(self):
        """Test setting and getting governance_action_deposit."""
        update = ProtocolParamUpdate.new()
        update.governance_action_deposit = 100000000000
        assert update.governance_action_deposit == 100000000000

    def test_can_set_and_get_drep_deposit(self):
        """Test setting and getting drep_deposit."""
        update = ProtocolParamUpdate.new()
        update.drep_deposit = 500000000
        assert update.drep_deposit == 500000000

    def test_can_set_and_get_drep_inactivity_period(self):
        """Test setting and getting drep_inactivity_period."""
        update = ProtocolParamUpdate.new()
        update.drep_inactivity_period = 20
        assert update.drep_inactivity_period == 20

    def test_can_set_and_get_ref_script_cost_per_byte(self):
        """Test setting and getting ref_script_cost_per_byte."""
        update = ProtocolParamUpdate.new()
        cost = UnitInterval.new(15, 1)
        update.ref_script_cost_per_byte = cost
        result = update.ref_script_cost_per_byte
        assert result is not None
        assert result.numerator == 15
        assert result.denominator == 1

    def test_governance_parameters_start_as_none(self):
        """Test that governance parameters start as None."""
        update = ProtocolParamUpdate.new()
        assert update.pool_voting_thresholds is None
        assert update.drep_voting_thresholds is None
        assert update.min_committee_size is None
        assert update.committee_term_limit is None
        assert update.governance_action_validity_period is None
        assert update.governance_action_deposit is None
        assert update.drep_deposit is None
        assert update.drep_inactivity_period is None
        assert update.ref_script_cost_per_byte is None


class TestProtocolParamUpdateJson:
    """Tests for JSON serialization (CIP-116)."""

    def test_can_convert_to_cip116_json(self):
        """Test conversion to CIP-116 JSON format."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        update.min_fee_b = 155381

        writer = JsonWriter()
        update.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0

    def test_to_cip116_json_with_full_update(self):
        """Test CIP-116 JSON with fully populated update."""
        reader = CborReader.from_hex(PROTOCOL_PARAM_UPDATE_CBOR)
        update = ProtocolParamUpdate.from_cbor(reader)

        writer = JsonWriter()
        update.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0

    def test_to_cip116_json_raises_error_with_invalid_writer(self):
        """Test that to_cip116_json raises error with invalid writer."""
        update = ProtocolParamUpdate.new()
        with pytest.raises((CardanoError, TypeError)):
            update.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_wrong_writer_type(self):
        """Test that to_cip116_json raises error with wrong writer type."""
        update = ProtocolParamUpdate.new()
        with pytest.raises((CardanoError, TypeError)):
            update.to_cip116_json("not a writer")


class TestProtocolParamUpdateMagicMethods:
    """Tests for magic methods (__repr__, __enter__, __exit__)."""

    def test_repr_returns_string(self):
        """Test that __repr__ returns a string."""
        update = ProtocolParamUpdate.new()
        repr_str = repr(update)
        assert "ProtocolParamUpdate" in repr_str

    def test_can_use_as_context_manager(self):
        """Test that ProtocolParamUpdate can be used as a context manager."""
        with ProtocolParamUpdate.new() as update:
            assert update is not None
            update.min_fee_a = 100
            assert update.min_fee_a == 100

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        update = ProtocolParamUpdate.new()
        with update:
            pass


class TestProtocolParamUpdateComplexScenarios:
    """Tests for complex scenarios and edge cases."""

    def test_can_set_multiple_parameters(self):
        """Test setting multiple parameters on the same update."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        update.min_fee_b = 155381
        update.max_tx_size = 16384
        update.key_deposit = 2000000
        update.pool_deposit = 500000000

        assert update.min_fee_a == 44
        assert update.min_fee_b == 155381
        assert update.max_tx_size == 16384
        assert update.key_deposit == 2000000
        assert update.pool_deposit == 500000000

    def test_can_update_parameters_multiple_times(self):
        """Test that parameters can be updated multiple times."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 100
        update.min_fee_a = 200
        update.min_fee_a = 300
        assert update.min_fee_a == 300

    def test_partial_update_roundtrip(self):
        """Test roundtrip with partially set update."""
        original = ProtocolParamUpdate.new()
        original.min_fee_a = 44
        original.max_tx_size = 16384

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ProtocolParamUpdate.from_cbor(reader)

        assert deserialized.min_fee_a == 44
        assert deserialized.max_tx_size == 16384
        assert deserialized.min_fee_b is None
        assert deserialized.pool_deposit is None

    def test_full_update_roundtrip(self):
        """Test roundtrip with all parameters set."""
        reader = CborReader.from_hex(PROTOCOL_PARAM_UPDATE_CBOR)
        original = ProtocolParamUpdate.from_cbor(reader)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = ProtocolParamUpdate.from_cbor(reader2)

        assert deserialized.min_fee_a == original.min_fee_a
        assert deserialized.min_fee_b == original.min_fee_b
        assert deserialized.max_tx_size == original.max_tx_size

    def test_empty_update_roundtrip(self):
        """Test roundtrip with no parameters set."""
        original = ProtocolParamUpdate.new()

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ProtocolParamUpdate.from_cbor(reader)

        assert deserialized is not None
        assert deserialized.min_fee_a is None
        assert deserialized.min_fee_b is None


class TestProtocolParamUpdateEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_can_set_max_uint64_values(self):
        """Test that maximum uint64 values can be set."""
        update = ProtocolParamUpdate.new()
        max_uint64 = 18446744073709551615
        update.min_fee_a = max_uint64
        update.min_fee_b = max_uint64
        assert update.min_fee_a == max_uint64
        assert update.min_fee_b == max_uint64

    def test_can_set_zero_values(self):
        """Test that zero values can be set."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 0
        update.min_fee_b = 0
        update.max_tx_size = 0
        assert update.min_fee_a == 0
        assert update.min_fee_b == 0
        assert update.max_tx_size == 0

    def test_mixed_parameter_types(self):
        """Test setting different types of parameters together."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 100
        update.pool_pledge_influence = UnitInterval.new(3, 10)
        update.protocol_version = ProtocolVersion.new(8, 0)
        update.max_tx_ex_units = ExUnits.new(memory=10000000, cpu_steps=10000000000)

        assert update.min_fee_a == 100
        assert update.pool_pledge_influence is not None
        assert update.protocol_version is not None
        assert update.max_tx_ex_units is not None

    def test_json_and_cbor_serialization_consistency(self):
        """Test that both JSON and CBOR serialization work on same object."""
        update = ProtocolParamUpdate.new()
        update.min_fee_a = 44
        update.min_fee_b = 155381

        cbor_writer = CborWriter()
        update.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        update.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert len(cbor_hex) > 0
        assert len(json_str) > 0
