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
    Costmdls,
    CostModel,
    CborReader,
    CborWriter,
    JsonWriter,
    PlutusLanguageVersion,
    CardanoError,
)


COST_MODEL_V1_HEX = "98a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a"
COST_MODEL_V2_HEX = "98af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
COST_MODEL_V3_HEX = "98b31a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a01020304"
COST_MODE_V1_CBOR_HEX = "0098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a"
COST_MODE_V2_CBOR_HEX = "0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
COST_MODE_V3_CBOR_HEX = "0298b31a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a01020304"
COSTMDLS_CBOR = "a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a"
COSTMDLS_ALL_CBOR = "a30098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a0298b31a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a01020304"
PLUTUS_VASIL_LANGUAGE_VIEW = "a20198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a41005901b69f1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0aff"


class TestCostmdlsNew:
    """Tests for Costmdls.new() factory method."""

    def test_can_create_costmdls(self):
        """Test that an empty Costmdls collection can be created."""
        costmdls = Costmdls.new()
        assert costmdls is not None
        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert not costmdls.has(PlutusLanguageVersion.V2)
        assert not costmdls.has(PlutusLanguageVersion.V3)

    def test_repr_empty_costmdls(self):
        """Test repr for empty Costmdls."""
        costmdls = Costmdls.new()
        assert "Costmdls" in repr(costmdls)
        assert "versions=[]" in repr(costmdls)


class TestCostmdlsCbor:
    """Tests for CBOR serialization/deserialization."""

    def test_can_serialize_costmdls_with_v1_and_v2(self):
        """Test serialization of Costmdls with V1 and V2 models."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        reader_v2 = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        cost_model_v2 = CostModel.from_cbor(reader_v2)

        costmdls.insert(cost_model_v1)
        costmdls.insert(cost_model_v2)

        writer = CborWriter()
        costmdls.to_cbor(writer)
        result = writer.to_hex()

        assert result == COSTMDLS_CBOR

    def test_can_serialize_costmdls_with_all_versions(self):
        """Test serialization of Costmdls with all three versions."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        reader_v2 = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        reader_v3 = CborReader.from_hex(COST_MODE_V3_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        cost_model_v2 = CostModel.from_cbor(reader_v2)
        cost_model_v3 = CostModel.from_cbor(reader_v3)

        costmdls.insert(cost_model_v1)
        costmdls.insert(cost_model_v2)
        costmdls.insert(cost_model_v3)

        writer = CborWriter()
        costmdls.to_cbor(writer)
        result = writer.to_hex()

        assert result == COSTMDLS_ALL_CBOR

    def test_can_deserialize_costmdls(self):
        """Test deserialization of Costmdls from CBOR."""
        reader = CborReader.from_hex(COSTMDLS_CBOR)
        costmdls = Costmdls.from_cbor(reader)

        assert costmdls is not None
        assert costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)

    def test_can_deserialize_costmdls_with_all_versions(self):
        """Test deserialization of Costmdls with all versions."""
        reader = CborReader.from_hex(COSTMDLS_ALL_CBOR)
        costmdls = Costmdls.from_cbor(reader)

        assert costmdls is not None
        assert costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)
        assert costmdls.has(PlutusLanguageVersion.V3)

    def test_can_deserialize_empty_map(self):
        """Test deserialization of an empty Costmdls map."""
        reader = CborReader.from_hex("a0")
        costmdls = Costmdls.from_cbor(reader)

        assert costmdls is not None
        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert not costmdls.has(PlutusLanguageVersion.V2)
        assert not costmdls.has(PlutusLanguageVersion.V3)

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        original = Costmdls.new()
        original.insert(cost_model_v1)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = Costmdls.from_cbor(reader)

        assert deserialized.has(PlutusLanguageVersion.V1)
        assert not deserialized.has(PlutusLanguageVersion.V2)

    def test_raises_error_if_doesnt_start_with_map(self):
        """Test that invalid CBOR (not a map) raises an error."""
        reader = CborReader.from_hex("80")
        with pytest.raises(CardanoError):
            Costmdls.from_cbor(reader)

    def test_raises_error_for_invalid_cost_model(self):
        """Test that invalid cost model in CBOR raises an error."""
        reader = CborReader.from_hex("a10000")
        with pytest.raises(CardanoError):
            Costmdls.from_cbor(reader)


class TestCostmdlsInsert:
    """Tests for the insert method."""

    def test_can_insert_cost_model_v1(self):
        """Test inserting a V1 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)

        costmdls.insert(cost_model)

        assert costmdls.has(PlutusLanguageVersion.V1)
        assert not costmdls.has(PlutusLanguageVersion.V2)

    def test_can_insert_cost_model_v2(self):
        """Test inserting a V2 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)

        costmdls.insert(cost_model)

        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)

    def test_can_insert_cost_model_v3(self):
        """Test inserting a V3 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V3_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)

        costmdls.insert(cost_model)

        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert not costmdls.has(PlutusLanguageVersion.V2)
        assert costmdls.has(PlutusLanguageVersion.V3)

    def test_can_insert_multiple_cost_models(self):
        """Test inserting multiple cost models."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        reader_v2 = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        cost_model_v2 = CostModel.from_cbor(reader_v2)

        costmdls.insert(cost_model_v1)
        costmdls.insert(cost_model_v2)

        assert costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)

    def test_raises_error_for_none_cost_model(self):
        """Test that inserting None raises an error."""
        costmdls = Costmdls.new()
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            costmdls.insert(None)

    def test_repr_with_models(self):
        """Test repr with inserted models."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        costmdls.insert(cost_model_v1)

        repr_str = repr(costmdls)
        assert "Costmdls" in repr_str
        assert "V1" in repr_str


class TestCostmdlsGet:
    """Tests for the get method."""

    def test_can_get_cost_model_v1(self):
        """Test retrieving a V1 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model_original = CostModel.from_cbor(reader)
        costmdls.insert(cost_model_original)

        cost_model = costmdls.get(PlutusLanguageVersion.V1)

        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V1

    def test_can_get_cost_model_v2(self):
        """Test retrieving a V2 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model_original = CostModel.from_cbor(reader)
        costmdls.insert(cost_model_original)

        cost_model = costmdls.get(PlutusLanguageVersion.V2)

        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V2

    def test_can_get_cost_model_v3(self):
        """Test retrieving a V3 cost model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V3_CBOR_HEX)
        cost_model_original = CostModel.from_cbor(reader)
        costmdls.insert(cost_model_original)

        cost_model = costmdls.get(PlutusLanguageVersion.V3)

        assert cost_model is not None
        assert cost_model.language == PlutusLanguageVersion.V3

    def test_returns_none_for_nonexistent_model(self):
        """Test that get returns None for a non-existent model."""
        costmdls = Costmdls.new()
        cost_model = costmdls.get(PlutusLanguageVersion.V1)

        assert cost_model is None

    def test_returns_none_after_removing_all_models(self):
        """Test that get returns None after clearing models."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        costmdls_new = Costmdls.new()
        assert costmdls_new.get(PlutusLanguageVersion.V1) is None


class TestCostmdlsHas:
    """Tests for the has method."""

    def test_returns_false_for_empty_costmdls(self):
        """Test that has returns False for an empty collection."""
        costmdls = Costmdls.new()

        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert not costmdls.has(PlutusLanguageVersion.V2)
        assert not costmdls.has(PlutusLanguageVersion.V3)

    def test_returns_true_for_existing_model(self):
        """Test that has returns True for an existing model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        assert costmdls.has(PlutusLanguageVersion.V1)

    def test_returns_false_for_nonexistent_model(self):
        """Test that has returns False for a non-existent model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        assert not costmdls.has(PlutusLanguageVersion.V2)
        assert not costmdls.has(PlutusLanguageVersion.V3)

    def test_has_all_versions(self):
        """Test has with all three versions inserted."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        reader_v2 = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        reader_v3 = CborReader.from_hex(COST_MODE_V3_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        cost_model_v2 = CostModel.from_cbor(reader_v2)
        cost_model_v3 = CostModel.from_cbor(reader_v3)

        costmdls.insert(cost_model_v1)
        costmdls.insert(cost_model_v2)
        costmdls.insert(cost_model_v3)

        assert costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)
        assert costmdls.has(PlutusLanguageVersion.V3)


class TestCostmdlsContains:
    """Tests for the __contains__ magic method."""

    def test_contains_operator_works(self):
        """Test that the 'in' operator works correctly."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        assert PlutusLanguageVersion.V1 in costmdls
        assert PlutusLanguageVersion.V2 not in costmdls


class TestCostmdlsGetItem:
    """Tests for the __getitem__ magic method."""

    def test_getitem_returns_cost_model(self):
        """Test that dict-like access works."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        retrieved = costmdls[PlutusLanguageVersion.V1]

        assert retrieved is not None
        assert retrieved.language == PlutusLanguageVersion.V1

    def test_getitem_raises_keyerror_for_nonexistent(self):
        """Test that dict-like access raises KeyError for non-existent model."""
        costmdls = Costmdls.new()

        with pytest.raises(KeyError):
            _ = costmdls[PlutusLanguageVersion.V1]


class TestCostmdlsSetItem:
    """Tests for the __setitem__ magic method."""

    def test_setitem_inserts_cost_model(self):
        """Test that dict-like assignment works."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)

        costmdls[PlutusLanguageVersion.V1] = cost_model

        assert costmdls.has(PlutusLanguageVersion.V1)

    def test_setitem_ignores_key(self):
        """Test that setitem uses the model's language, not the key."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model_v2 = CostModel.from_cbor(reader)

        costmdls[PlutusLanguageVersion.V1] = cost_model_v2

        assert not costmdls.has(PlutusLanguageVersion.V1)
        assert costmdls.has(PlutusLanguageVersion.V2)


class TestCostmdlsLanguageViews:
    """Tests for get_language_views_encoding method."""

    def test_can_compute_language_views_v1_and_v2(self):
        """Test computing language views for V1 and V2."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        reader_v2 = CborReader.from_hex(COST_MODE_V2_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        cost_model_v2 = CostModel.from_cbor(reader_v2)
        costmdls.insert(cost_model_v1)
        costmdls.insert(cost_model_v2)

        views = costmdls.get_language_views_encoding()
        result = views.to_hex()

        assert result == PLUTUS_VASIL_LANGUAGE_VIEW

    def test_language_views_empty_costmdls(self):
        """Test computing language views for empty Costmdls."""
        costmdls = Costmdls.new()
        views = costmdls.get_language_views_encoding()

        assert views is not None

    def test_language_views_single_model(self):
        """Test computing language views with a single model."""
        costmdls = Costmdls.new()
        reader_v1 = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model_v1 = CostModel.from_cbor(reader_v1)
        costmdls.insert(cost_model_v1)

        views = costmdls.get_language_views_encoding()

        assert views is not None


class TestCostmdlsCip116Json:
    """Tests for to_cip116_json method."""

    def test_can_convert_to_cip116_json(self):
        """Test conversion to CIP-116 JSON format."""
        reader = CborReader.from_hex(COSTMDLS_ALL_CBOR)
        costmdls = Costmdls.from_cbor(reader)

        writer = JsonWriter()
        costmdls.to_cip116_json(writer)
        json_str = writer.encode()

        assert "plutus_v1" in json_str
        assert "plutus_v2" in json_str
        assert "plutus_v3" in json_str

    def test_can_convert_empty_costmdls_to_json(self):
        """Test conversion of empty Costmdls to JSON."""
        costmdls = Costmdls.new()
        writer = JsonWriter()
        costmdls.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == "{}"

    def test_can_convert_single_model_to_json(self):
        """Test conversion with a single model."""
        costmdls = Costmdls.new()
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)
        costmdls.insert(cost_model)

        writer = JsonWriter()
        costmdls.to_cip116_json(writer)
        json_str = writer.encode()

        assert "plutus_v1" in json_str
        assert "plutus_v2" not in json_str

    def test_raises_error_for_invalid_writer(self):
        """Test that invalid writer type raises an error."""
        costmdls = Costmdls.new()

        with pytest.raises(TypeError):
            costmdls.to_cip116_json("not a writer")

    def test_raises_error_for_none_writer(self):
        """Test that None writer raises an error."""
        costmdls = Costmdls.new()

        with pytest.raises((TypeError, CardanoError, AttributeError)):
            costmdls.to_cip116_json(None)


class TestCostmdlsContextManager:
    """Tests for context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that Costmdls works as a context manager."""
        with Costmdls.new() as costmdls:
            assert costmdls is not None
            assert not costmdls.has(PlutusLanguageVersion.V1)

    def test_context_manager_with_operations(self):
        """Test using context manager with operations."""
        reader = CborReader.from_hex(COST_MODE_V1_CBOR_HEX)
        cost_model = CostModel.from_cbor(reader)

        with Costmdls.new() as costmdls:
            costmdls.insert(cost_model)
            assert costmdls.has(PlutusLanguageVersion.V1)
