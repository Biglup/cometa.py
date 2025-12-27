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
    CostModel,
    PlutusLanguageVersion,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)
from cometa.cbor import CborReaderState


COST_MODEL_V1_HEX = "98a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a"
COST_MODEL_V2_HEX = "98af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
COST_MODEL_V3_HEX = "98b31a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a01020304"

COST_MODEL_V1_CBOR_HEX = "0098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a"
COST_MODEL_V2_CBOR_HEX = "0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
COST_MODEL_V3_CBOR_HEX = "0298b31a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a01020304"


def hex_string_to_costs(hex_string):
    """
    Helper function to extract costs array from hex-encoded CBOR data.
    Adapted from the C++ test file.
    """
    reader = CborReader.from_hex(hex_string)
    array_len = reader.read_array_len()
    costs = []
    if array_len is not None:
        for _ in range(array_len):
            cost = reader.read_int()
            costs.append(cost)
    else:
        while reader.peek_state() != CborReaderState.END_ARRAY:
            cost = reader.read_int()
            costs.append(cost)
        reader.read_array_end()
    return costs


class TestCostModelNew:
    """Tests for CostModel.new() factory method."""

    def test_new_v1(self):
        """Test creating a V1 cost model."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V1
        assert len(cost_model) == 166

    def test_new_v2(self):
        """Test creating a V2 cost model."""
        costs = hex_string_to_costs(COST_MODEL_V2_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V2, costs)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V2
        assert len(cost_model) == 175

    def test_new_v3(self):
        """Test creating a V3 cost model."""
        costs = hex_string_to_costs(COST_MODEL_V3_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V3, costs)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V3
        assert len(cost_model) == 179

    def test_new_invalid_cost_count_v1(self):
        """Test creating V1 model with different number of costs."""
        costs = [100] * 200
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        assert len(cost_model) == 200

    def test_new_invalid_cost_count_v2(self):
        """Test creating V2 model with different number of costs."""
        costs = [100] * 200
        cost_model = CostModel.new(PlutusLanguageVersion.V2, costs)
        assert len(cost_model) == 200

    def test_new_invalid_cost_count_v3(self):
        """Test creating V3 model with different number of costs."""
        costs = [100] * 200
        cost_model = CostModel.new(PlutusLanguageVersion.V3, costs)
        assert len(cost_model) == 200

    def test_new_with_empty_costs(self):
        """Test creating model with empty costs."""
        cost_model = CostModel.new(PlutusLanguageVersion.V1, [])
        assert len(cost_model) == 0

    def test_new_with_negative_costs(self):
        """Test creating model with negative costs."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        costs[0] = -100
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        assert cost_model[0] == -100


class TestCostModelFromCbor:
    """Tests for CostModel.from_cbor() deserialization."""

    def test_from_cbor_v1(self):
        """Test deserializing a V1 cost model from CBOR."""
        reader = CborReader.from_hex(COST_MODEL_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V1
        assert len(cost_model) == 166

    def test_from_cbor_v2(self):
        """Test deserializing a V2 cost model from CBOR."""
        reader = CborReader.from_hex(COST_MODEL_V2_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V2
        assert len(cost_model) == 175

    def test_from_cbor_v3(self):
        """Test deserializing a V3 cost model from CBOR."""
        reader = CborReader.from_hex(COST_MODEL_V3_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V3
        assert len(cost_model) == 179

    def test_from_cbor_invalid_plutus_type(self):
        """Test error with invalid Plutus type."""
        reader = CborReader.from_hex("04")
        with pytest.raises(CardanoError):
            CostModel.from_cbor(reader)

    def test_from_cbor_invalid_costs_array(self):
        """Test error with malformed costs array."""
        reader = CborReader.from_hex("01fe")
        with pytest.raises(CardanoError):
            CostModel.from_cbor(reader)

    def test_from_cbor_invalid_costs_inside_array(self):
        """Test error with invalid costs inside array."""
        reader = CborReader.from_hex("0198af")
        with pytest.raises(CardanoError):
            CostModel.from_cbor(reader)

    def test_from_cbor_unexpected_start_array(self):
        """Test error with unexpected CBOR type."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            CostModel.from_cbor(reader)


class TestCostModelToCbor:
    """Tests for CostModel.to_cbor() serialization."""

    def test_to_cbor_v1(self):
        """Test serializing V1 cost model to CBOR."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        writer = CborWriter()
        cost_model.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == COST_MODEL_V1_CBOR_HEX

    def test_to_cbor_v2(self):
        """Test serializing V2 cost model to CBOR."""
        costs = hex_string_to_costs(COST_MODEL_V2_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V2, costs)
        writer = CborWriter()
        cost_model.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == COST_MODEL_V2_CBOR_HEX

    def test_to_cbor_v3(self):
        """Test serializing V3 cost model to CBOR."""
        costs = hex_string_to_costs(COST_MODEL_V3_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V3, costs)
        writer = CborWriter()
        cost_model.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == COST_MODEL_V3_CBOR_HEX

    def test_to_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        original = CostModel.new(PlutusLanguageVersion.V1, costs)
        writer = CborWriter()
        original.to_cbor(writer)
        reader = CborReader.from_hex(writer.to_hex())
        deserialized = CostModel.from_cbor(reader)
        assert deserialized.language == original.language
        assert len(deserialized) == len(original)
        assert list(deserialized) == list(original)


class TestCostModelLanguage:
    """Tests for CostModel.language property."""

    def test_language_v1(self):
        """Test getting language for V1 model."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        assert cost_model.language == PlutusLanguageVersion.V1
        assert cost_model.language.name == "V1"

    def test_language_v2(self):
        """Test getting language for V2 model."""
        costs = hex_string_to_costs(COST_MODEL_V2_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V2, costs)
        assert cost_model.language == PlutusLanguageVersion.V2
        assert cost_model.language.name == "V2"

    def test_language_v3(self):
        """Test getting language for V3 model."""
        costs = hex_string_to_costs(COST_MODEL_V3_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V3, costs)
        assert cost_model.language == PlutusLanguageVersion.V3
        assert cost_model.language.name == "V3"


class TestCostModelGetCost:
    """Tests for CostModel.get_cost() method."""

    @pytest.fixture
    def cost_model_v1(self):
        """Create a V1 cost model fixture."""
        reader = CborReader.from_hex(COST_MODEL_V1_CBOR_HEX)
        return CostModel.from_cbor(reader)

    def test_get_cost_first(self, cost_model_v1):
        """Test getting the first cost."""
        cost = cost_model_v1.get_cost(0)
        assert cost == 205665

    def test_get_cost_middle(self, cost_model_v1):
        """Test getting a middle cost."""
        cost = cost_model_v1.get_cost(5)
        assert cost is not None

    def test_get_cost_last(self, cost_model_v1):
        """Test getting the last cost."""
        size = len(cost_model_v1)
        cost = cost_model_v1.get_cost(size - 1)
        assert cost is not None

    def test_get_cost_out_of_bounds(self, cost_model_v1):
        """Test error when index is out of bounds."""
        with pytest.raises(CardanoError):
            cost_model_v1.get_cost(99999)


class TestCostModelSetCost:
    """Tests for CostModel.set_cost() method."""

    @pytest.fixture
    def cost_model_v1(self):
        """Create a V1 cost model fixture."""
        reader = CborReader.from_hex(COST_MODEL_V1_CBOR_HEX)
        return CostModel.from_cbor(reader)

    def test_set_cost(self, cost_model_v1):
        """Test setting a cost."""
        cost_model_v1.set_cost(0, 100)
        assert cost_model_v1.get_cost(0) == 100

    def test_set_cost_negative(self, cost_model_v1):
        """Test setting a negative cost."""
        cost_model_v1.set_cost(0, -500)
        assert cost_model_v1.get_cost(0) == -500

    def test_set_cost_zero(self, cost_model_v1):
        """Test setting cost to zero."""
        cost_model_v1.set_cost(0, 0)
        assert cost_model_v1.get_cost(0) == 0

    def test_set_cost_large_value(self, cost_model_v1):
        """Test setting a large cost value."""
        large_cost = 2**32
        cost_model_v1.set_cost(0, large_cost)
        assert cost_model_v1.get_cost(0) == large_cost

    def test_set_cost_out_of_bounds(self, cost_model_v1):
        """Test error when setting cost at invalid index."""
        with pytest.raises(CardanoError):
            cost_model_v1.set_cost(99999, 100)


class TestCostModelGetCosts:
    """Tests for CostModel.get_costs() method."""

    def test_get_costs_v1(self):
        """Test getting all costs from V1 model."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        retrieved_costs = cost_model.get_costs()
        assert len(retrieved_costs) == 166
        assert retrieved_costs == costs

    def test_get_costs_v2(self):
        """Test getting all costs from V2 model."""
        costs = hex_string_to_costs(COST_MODEL_V2_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V2, costs)
        retrieved_costs = cost_model.get_costs()
        assert len(retrieved_costs) == 175
        assert retrieved_costs == costs

    def test_get_costs_v3(self):
        """Test getting all costs from V3 model."""
        costs = hex_string_to_costs(COST_MODEL_V3_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V3, costs)
        retrieved_costs = cost_model.get_costs()
        assert len(retrieved_costs) == 179
        assert retrieved_costs == costs

    def test_get_costs_after_modification(self):
        """Test getting costs after modifying one."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        cost_model.set_cost(0, 999)
        retrieved_costs = cost_model.get_costs()
        assert retrieved_costs[0] == 999


class TestCostModelToCip116Json:
    """Tests for CostModel.to_cip116_json() method."""

    def test_to_cip116_json_simple(self):
        """Test converting simple cost model to CIP-116 JSON."""
        costs = [100, 200, -300]
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        writer = JsonWriter()
        cost_model.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"100"' in json_str
        assert '"200"' in json_str
        assert '"-300"' in json_str

    def test_to_cip116_json_v1(self):
        """Test converting V1 cost model to JSON."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        writer = JsonWriter()
        cost_model.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "[" in json_str

    def test_to_cip116_json_invalid_writer_type(self):
        """Test error with invalid writer type."""
        costs = [100, 200, 300]
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        with pytest.raises(TypeError):
            cost_model.to_cip116_json("not a writer")


class TestCostModelMagicMethods:
    """Tests for CostModel magic methods."""

    @pytest.fixture
    def cost_model(self):
        """Create a cost model fixture."""
        reader = CborReader.from_hex(COST_MODEL_V1_CBOR_HEX)
        return CostModel.from_cbor(reader)

    def test_len(self, cost_model):
        """Test __len__ magic method."""
        assert len(cost_model) == 166

    def test_repr(self, cost_model):
        """Test __repr__ magic method."""
        repr_str = repr(cost_model)
        assert "CostModel" in repr_str
        assert "language=V1" in repr_str
        assert "operations=166" in repr_str

    def test_iter(self, cost_model):
        """Test __iter__ magic method."""
        costs_list = list(cost_model)
        assert len(costs_list) == 166
        assert costs_list[0] == 205665

    def test_getitem(self, cost_model):
        """Test __getitem__ magic method."""
        assert cost_model[0] == 205665

    def test_getitem_out_of_bounds(self, cost_model):
        """Test __getitem__ with out of bounds index."""
        with pytest.raises(KeyError):
            _ = cost_model[99999]

    def test_setitem(self, cost_model):
        """Test __setitem__ magic method."""
        cost_model[0] = 500
        assert cost_model[0] == 500

    def test_setitem_out_of_bounds(self, cost_model):
        """Test __setitem__ with out of bounds index."""
        with pytest.raises(KeyError):
            cost_model[99999] = 100

    def test_context_manager(self):
        """Test using CostModel as a context manager."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        with CostModel.new(PlutusLanguageVersion.V1, costs) as cost_model:
            assert cost_model is not None
            assert cost_model.language == PlutusLanguageVersion.V1


class TestCostModelEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_modification_persistence(self):
        """Test that modifications persist correctly."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        original_cost = cost_model[0]
        cost_model[0] = 12345
        assert cost_model.get_cost(0) == 12345
        assert cost_model[0] == 12345
        assert cost_model.get_costs()[0] == 12345
        cost_model.set_cost(0, original_cost)
        assert cost_model[0] == original_cost

    def test_multiple_modifications(self):
        """Test multiple consecutive modifications."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        for i in range(min(10, len(cost_model))):
            cost_model[i] = i * 100
        for i in range(min(10, len(cost_model))):
            assert cost_model[i] == i * 100

    def test_costs_immutability_after_creation(self):
        """Test that original costs list doesn't affect created model."""
        costs = [100, 200, 300]
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        costs[0] = 999
        assert cost_model[0] == 100

    def test_iteration_consistency(self):
        """Test that multiple iterations produce consistent results."""
        costs = hex_string_to_costs(COST_MODEL_V1_HEX)
        cost_model = CostModel.new(PlutusLanguageVersion.V1, costs)
        first_iteration = list(cost_model)
        second_iteration = list(cost_model)
        assert first_iteration == second_iteration
