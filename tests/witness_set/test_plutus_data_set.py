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
from cometa.witness_set.plutus_data_set import PlutusDataSet
from cometa.plutus_data.plutus_data import PlutusData
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter, JsonFormat
from cometa.errors import CardanoError


CBOR = "d90102849f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff"
CBOR_WITHOUT_TAG = "849f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff"
PLUTUS_DATA1_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
PLUTUS_DATA2_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
PLUTUS_DATA3_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
PLUTUS_DATA4_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"


def create_plutus_data_from_cbor(cbor_hex: str) -> PlutusData:
    """Helper to create PlutusData from CBOR hex string."""
    reader = CborReader.from_hex(cbor_hex)
    data = PlutusData.from_cbor(reader)
    return data


class TestPlutusDataSetNew:
    """Tests for PlutusDataSet.__init__()."""

    def test_can_create_plutus_data_set(self):
        """Test creating a new PlutusDataSet."""
        data_set = PlutusDataSet()
        assert data_set is not None
        assert len(data_set) == 0



class TestPlutusDataSetFromCbor:
    """Tests for PlutusDataSet.from_cbor()."""

    def test_can_deserialize_plutus_data_set(self):
        """Test deserializing PlutusDataSet from CBOR."""
        reader = CborReader.from_hex(CBOR)
        data_set = PlutusDataSet.from_cbor(reader)

        assert data_set is not None
        assert len(data_set) == 4

        for i in range(4):
            element = data_set.get(i)
            assert element is not None

    def test_returns_error_if_reader_is_null(self):
        """Test from_cbor with None reader."""
        with pytest.raises((CardanoError, AttributeError)):
            PlutusDataSet.from_cbor(None)

    def test_returns_error_if_not_an_array(self):
        """Test from_cbor with invalid CBOR (not an array)."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            PlutusDataSet.from_cbor(reader)

    def test_returns_error_if_invalid_elements(self):
        """Test from_cbor with invalid element data."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            PlutusDataSet.from_cbor(reader)

    def test_returns_error_if_missing_end_array(self):
        """Test from_cbor with missing array end marker."""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            PlutusDataSet.from_cbor(reader)

    def test_returns_error_if_invalid_cbor(self):
        """Test from_cbor with completely invalid CBOR."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            PlutusDataSet.from_cbor(reader)


class TestPlutusDataSetFromList:
    """Tests for PlutusDataSet.from_list()."""

    def test_can_create_from_list(self):
        """Test creating PlutusDataSet from list of PlutusData."""
        data1 = PlutusData.from_int(123)
        data2 = PlutusData.from_bytes(b"\xaa")
        data3 = PlutusData.from_string("hello")

        data_set = PlutusDataSet.from_list([data1, data2, data3])

        assert len(data_set) == 3
        assert data_set[0] == data1
        assert data_set[1] == data2
        assert data_set[2] == data3

    def test_can_create_from_empty_list(self):
        """Test creating PlutusDataSet from empty list."""
        data_set = PlutusDataSet.from_list([])
        assert len(data_set) == 0


class TestPlutusDataSetToCbor:
    """Tests for PlutusDataSet.to_cbor()."""

    def test_can_serialize_empty_plutus_data_set(self):
        """Test serializing an empty PlutusDataSet."""
        data_set = PlutusDataSet()
        writer = CborWriter()

        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == "d9010280"

    def test_can_serialize_plutus_data_set(self):
        """Test serializing a PlutusDataSet with elements."""
        data_set = PlutusDataSet()

        plutus_datas = [PLUTUS_DATA1_CBOR, PLUTUS_DATA2_CBOR, PLUTUS_DATA3_CBOR, PLUTUS_DATA4_CBOR]
        for cbor_hex in plutus_datas:
            data = create_plutus_data_from_cbor(cbor_hex)
            data_set.add(data)

        writer = CborWriter()
        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR

    def test_returns_error_if_writer_is_none(self):
        """Test to_cbor with None writer."""
        data_set = PlutusDataSet()
        with pytest.raises((CardanoError, AttributeError)):
            data_set.to_cbor(None)

    def test_can_deserialize_and_reserialize_cbor(self):
        """Test deserializing and reserializing CBOR (without cache)."""
        reader = CborReader.from_hex(CBOR)
        data_set = PlutusDataSet.from_cbor(reader)

        data_set.clear_cbor_cache()

        writer = CborWriter()
        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR

    def test_can_deserialize_and_reserialize_cbor_from_cache(self):
        """Test deserializing and reserializing CBOR (with cache)."""
        reader = CborReader.from_hex(CBOR)
        data_set = PlutusDataSet.from_cbor(reader)

        writer = CborWriter()
        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR

    def test_can_deserialize_and_reserialize_cbor_without_tag(self):
        """Test deserializing and reserializing CBOR without tag (no cache)."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        data_set = PlutusDataSet.from_cbor(reader)

        data_set.clear_cbor_cache()

        writer = CborWriter()
        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR

    def test_can_deserialize_and_reserialize_cbor_without_tag_from_cache(self):
        """Test deserializing and reserializing CBOR without tag (with cache)."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        data_set = PlutusDataSet.from_cbor(reader)

        writer = CborWriter()
        data_set.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR_WITHOUT_TAG


class TestPlutusDataSetAdd:
    """Tests for PlutusDataSet.add()."""

    def test_can_add_element(self):
        """Test adding an element to PlutusDataSet."""
        data_set = PlutusDataSet()
        data = PlutusData.from_int(42)

        data_set.add(data)

        assert len(data_set) == 1
        assert data_set[0] == data

    def test_can_add_multiple_elements(self):
        """Test adding multiple elements."""
        data_set = PlutusDataSet()
        data1 = PlutusData.from_int(1)
        data2 = PlutusData.from_int(2)
        data3 = PlutusData.from_int(3)

        data_set.add(data1)
        data_set.add(data2)
        data_set.add(data3)

        assert len(data_set) == 3

    def test_returns_error_if_data_is_none(self):
        """Test add with None data."""
        data_set = PlutusDataSet()
        with pytest.raises((CardanoError, AttributeError)):
            data_set.add(None)


class TestPlutusDataSetGet:
    """Tests for PlutusDataSet.get()."""

    def test_can_get_element(self):
        """Test getting an element by index."""
        data_set = PlutusDataSet()
        data1 = PlutusData.from_int(123)
        data2 = PlutusData.from_bytes(b"\xaa")

        data_set.add(data1)
        data_set.add(data2)

        retrieved1 = data_set.get(0)
        retrieved2 = data_set.get(1)

        assert retrieved1 == data1
        assert retrieved2 == data2

    def test_raises_error_if_index_is_out_of_bounds(self):
        """Test get with out of bounds index."""
        data_set = PlutusDataSet()
        with pytest.raises(IndexError):
            data_set.get(0)

    def test_raises_error_if_negative_index(self):
        """Test get with negative index."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(42))
        with pytest.raises(IndexError):
            data_set.get(-1)


class TestPlutusDataSetLength:
    """Tests for PlutusDataSet.__len__()."""

    def test_returns_zero_if_empty(self):
        """Test length of empty set."""
        data_set = PlutusDataSet()
        assert len(data_set) == 0

    def test_returns_correct_length(self):
        """Test length after adding elements."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(1))
        data_set.add(PlutusData.from_int(2))
        data_set.add(PlutusData.from_int(3))

        assert len(data_set) == 3


class TestPlutusDataSetUseTag:
    """Tests for PlutusDataSet.use_tag property."""

    def test_can_get_use_tag(self):
        """Test getting use_tag property."""
        data_set = PlutusDataSet()
        use_tag = data_set.use_tag
        assert isinstance(use_tag, bool)

    def test_can_set_use_tag(self):
        """Test setting use_tag property."""
        data_set = PlutusDataSet()

        data_set.use_tag = True
        assert data_set.use_tag is True

        data_set.use_tag = False
        assert data_set.use_tag is False


class TestPlutusDataSetClearCborCache:
    """Tests for PlutusDataSet.clear_cbor_cache()."""

    def test_clear_cbor_cache_does_not_crash(self):
        """Test that clear_cbor_cache doesn't crash."""
        data_set = PlutusDataSet()
        data_set.clear_cbor_cache()

    def test_clear_cbor_cache_after_deserialization(self):
        """Test clearing cache after deserializing from CBOR."""
        reader = CborReader.from_hex(CBOR)
        data_set = PlutusDataSet.from_cbor(reader)

        data_set.clear_cbor_cache()

        writer = CborWriter()
        data_set.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output == CBOR


class TestPlutusDataSetIterator:
    """Tests for PlutusDataSet.__iter__()."""

    def test_can_iterate_over_elements(self):
        """Test iterating over PlutusDataSet elements."""
        data_set = PlutusDataSet()
        data1 = PlutusData.from_int(1)
        data2 = PlutusData.from_int(2)
        data3 = PlutusData.from_int(3)

        data_set.add(data1)
        data_set.add(data2)
        data_set.add(data3)

        elements = list(data_set)
        assert len(elements) == 3
        assert elements[0] == data1
        assert elements[1] == data2
        assert elements[2] == data3

    def test_iterate_over_empty_set(self):
        """Test iterating over empty set."""
        data_set = PlutusDataSet()
        elements = list(data_set)
        assert len(elements) == 0


class TestPlutusDataSetGetItem:
    """Tests for PlutusDataSet.__getitem__()."""

    def test_can_use_bracket_notation(self):
        """Test using bracket notation to access elements."""
        data_set = PlutusDataSet()
        data1 = PlutusData.from_int(42)
        data2 = PlutusData.from_int(99)

        data_set.add(data1)
        data_set.add(data2)

        assert data_set[0] == data1
        assert data_set[1] == data2


class TestPlutusDataSetBool:
    """Tests for PlutusDataSet.__bool__()."""

    def test_empty_set_is_falsy(self):
        """Test that empty set is falsy."""
        data_set = PlutusDataSet()
        assert not data_set

    def test_non_empty_set_is_truthy(self):
        """Test that non-empty set is truthy."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(42))
        assert data_set


class TestPlutusDataSetToCip116Json:
    """Tests for PlutusDataSet.to_cip116_json()."""

    def test_can_convert_set(self):
        """Test converting PlutusDataSet to CIP-116 JSON."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(123))
        data_set.add(PlutusData.from_bytes(b"\xaa"))

        writer = JsonWriter(JsonFormat.COMPACT)
        data_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert '[{"tag":"integer","value":"123"},{"tag":"bytes","value":"aa"}]' in json_str

    def test_can_convert_empty_set(self):
        """Test converting empty PlutusDataSet to CIP-116 JSON."""
        data_set = PlutusDataSet()

        writer = JsonWriter(JsonFormat.COMPACT)
        data_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == "[]"

    def test_returns_error_if_writer_is_invalid(self):
        """Test to_cip116_json with invalid writer."""
        data_set = PlutusDataSet()
        with pytest.raises(TypeError):
            data_set.to_cip116_json("not a writer")


class TestPlutusDataSetContains:
    """Tests for PlutusDataSet.__contains__()."""

    def test_contains_existing_element(self):
        """Test checking if element exists in set."""
        data_set = PlutusDataSet()
        data1 = PlutusData.from_int(42)
        data2 = PlutusData.from_int(99)

        data_set.add(data1)

        assert data1 in data_set
        assert data2 not in data_set

    def test_contains_returns_false_for_non_plutus_data(self):
        """Test contains with non-PlutusData object."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(42))

        assert 42 not in data_set
        assert "hello" not in data_set


class TestPlutusDataSetIsDisjoint:
    """Tests for PlutusDataSet.isdisjoint()."""

    def test_isdisjoint_with_disjoint_sets(self):
        """Test isdisjoint with truly disjoint sets."""
        data_set1 = PlutusDataSet()
        data_set1.add(PlutusData.from_int(1))
        data_set1.add(PlutusData.from_int(2))

        data_set2 = PlutusDataSet()
        data_set2.add(PlutusData.from_int(3))
        data_set2.add(PlutusData.from_int(4))

        assert data_set1.isdisjoint(data_set2)

    def test_isdisjoint_with_overlapping_sets(self):
        """Test isdisjoint with overlapping sets."""
        data1 = PlutusData.from_int(42)
        data2 = PlutusData.from_int(99)

        data_set1 = PlutusDataSet()
        data_set1.add(data1)
        data_set1.add(PlutusData.from_int(1))

        data_set2 = PlutusDataSet()
        data_set2.add(data1)
        data_set2.add(data2)

        assert not data_set1.isdisjoint(data_set2)

    def test_isdisjoint_with_empty_set(self):
        """Test isdisjoint with empty set."""
        data_set1 = PlutusDataSet()
        data_set1.add(PlutusData.from_int(42))

        data_set2 = PlutusDataSet()

        assert data_set1.isdisjoint(data_set2)


class TestPlutusDataSetRepr:
    """Tests for PlutusDataSet.__repr__()."""

    def test_repr_shows_length(self):
        """Test that repr shows the length."""
        data_set = PlutusDataSet()
        data_set.add(PlutusData.from_int(1))
        data_set.add(PlutusData.from_int(2))

        repr_str = repr(data_set)
        assert "len=2" in repr_str


class TestPlutusDataSetContextManager:
    """Tests for PlutusDataSet context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test using PlutusDataSet as context manager."""
        with PlutusDataSet() as data_set:
            data_set.add(PlutusData.from_int(42))
            assert len(data_set) == 1
