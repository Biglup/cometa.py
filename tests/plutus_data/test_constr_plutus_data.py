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
    PlutusData,
    PlutusDataKind,
    PlutusList,
    ConstrPlutusData,
    CborWriter,
    CborReader,
)


CONSTR_ALT0_CBOR = "d8799f0102030405ff"
CONSTR_ALT0_TAG121_CBOR = "d8799f0102030405ff"
CONSTR_GENERAL_FORM_CBOR = "d9055f9f0102030405ff"
CONSTR_TAG102_CBOR = "d8668218969f0102030405ff"
CONSTR_INDEFINITE_CBOR = "d8009f0102030405ff"


class TestConstrPlutusDataCreation:
    """Tests for ConstrPlutusData creation."""

    def test_create_with_alternative_only(self):
        """Test creating constructor with alternative only."""
        constr = ConstrPlutusData(0)
        assert constr.alternative == 0
        assert len(constr.data) == 0

    def test_create_with_alternative_1(self):
        """Test creating constructor with alternative 1."""
        constr = ConstrPlutusData(1)
        assert constr.alternative == 1
        assert len(constr.data) == 0

    def test_create_with_plutus_list(self):
        """Test creating constructor with PlutusList."""
        args = PlutusList()
        args.append(42)
        args.append("hello")
        constr = ConstrPlutusData(0, args)
        assert constr.alternative == 0
        assert len(constr.data) == 2

    def test_create_with_python_list(self):
        """Test creating constructor with Python list."""
        constr = ConstrPlutusData(0, [42, "hello", b"\x01\x02"])
        assert constr.alternative == 0
        assert len(constr.data) == 3
        assert constr.data[0].to_int() == 42
        assert constr.data[1].to_string() == "hello"
        assert constr.data[2].to_bytes() == b"\x01\x02"

    def test_create_with_high_alternative(self):
        """Test creating constructor with high alternative value."""
        constr = ConstrPlutusData(127)
        assert constr.alternative == 127

    def test_create_with_very_high_alternative(self):
        """Test creating constructor with very high alternative (>127)."""
        constr = ConstrPlutusData(1000)
        assert constr.alternative == 1000

    def test_create_with_data_list(self):
        """Test creating constructor with list of integers."""
        constr = ConstrPlutusData(0, [1, 2, 3, 4, 5])
        assert constr.alternative == 0
        assert len(constr.data) == 5
        for i, item in enumerate(constr.data):
            assert item.to_int() == i + 1


class TestConstrPlutusDataCbor:
    """Tests for ConstrPlutusData CBOR serialization."""

    def test_serialize_alternative_0(self):
        """Test CBOR serialization with alternative 0."""
        constr = ConstrPlutusData(0, [1, 2, 3, 4, 5])
        writer = CborWriter()
        constr.to_cbor(writer)
        assert writer.to_hex() == CONSTR_ALT0_CBOR

    def test_deserialize_alternative_0(self):
        """Test CBOR deserialization with alternative 0."""
        reader = CborReader.from_hex(CONSTR_ALT0_CBOR)
        constr = ConstrPlutusData.from_cbor(reader)
        constr.clear_cbor_cache()
        assert constr.alternative == 0
        assert len(constr.data) == 5
        for i, item in enumerate(constr.data):
            assert item.to_int() == i + 1

    def test_deserialize_tag_121_127(self):
        """Test that alternatives 0-6 use tags 121-127."""
        for alt in range(7):
            constr = ConstrPlutusData(alt, [42])
            writer = CborWriter()
            constr.to_cbor(writer)
            cbor_hex = writer.to_hex()
            reader = CborReader.from_hex(cbor_hex)
            restored = ConstrPlutusData.from_cbor(reader)
            assert restored.alternative == alt

    def test_deserialize_general_form(self):
        """Test CBOR deserialization of general form (tag 102)."""
        reader = CborReader.from_hex(CONSTR_GENERAL_FORM_CBOR)
        constr = ConstrPlutusData.from_cbor(reader)
        constr.clear_cbor_cache()
        assert len(constr.data) == 5

    def test_roundtrip_cbor(self):
        """Test CBOR roundtrip preserves data."""
        constr = ConstrPlutusData(5, [100, "test", b"\xde\xad"])
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = ConstrPlutusData.from_cbor(reader)

        assert restored.alternative == 5
        assert len(restored.data) == 3
        assert restored.data[0].to_int() == 100
        assert restored.data[1].to_string() == "test"
        assert restored.data[2].to_bytes() == b"\xde\xad"

    def test_deserialize_indefinite_array(self):
        """Test CBOR deserialization with indefinite array encoding."""
        reader = CborReader.from_hex(CONSTR_INDEFINITE_CBOR)
        constr = ConstrPlutusData.from_cbor(reader)
        assert len(constr.data) == 5

    def test_from_cbor_not_a_constr_raises(self):
        """Test that deserializing non-constructor CBOR raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(Exception):
            ConstrPlutusData.from_cbor(reader)


class TestConstrPlutusDataProperties:
    """Tests for ConstrPlutusData property access."""

    def test_get_alternative(self):
        """Test getting alternative."""
        constr = ConstrPlutusData(42)
        assert constr.alternative == 42

    def test_set_alternative(self):
        """Test setting alternative."""
        constr = ConstrPlutusData(0)
        constr.alternative = 99
        assert constr.alternative == 99

    def test_get_data(self):
        """Test getting data."""
        constr = ConstrPlutusData(0, [1, 2, 3])
        data = constr.data
        assert isinstance(data, PlutusList)
        assert len(data) == 3

    def test_set_data_with_plutus_list(self):
        """Test setting data with PlutusList."""
        constr = ConstrPlutusData(0)
        new_data = PlutusList()
        new_data.append(99)
        new_data.append(100)
        constr.data = new_data
        assert len(constr.data) == 2
        assert constr.data[0].to_int() == 99

    def test_set_data_with_python_list(self):
        """Test setting data with Python list."""
        constr = ConstrPlutusData(0)
        constr.data = [1, 2, 3, 4]
        assert len(constr.data) == 4
        assert constr.data[0].to_int() == 1
        assert constr.data[3].to_int() == 4


class TestConstrPlutusDataEquality:
    """Tests for ConstrPlutusData equality."""

    def test_equality_same_alternative_same_data(self):
        """Test equality with same alternative and data."""
        constr1 = ConstrPlutusData(0, [42])
        constr2 = ConstrPlutusData(0, [42])
        assert constr1 == constr2

    def test_equality_different_alternative(self):
        """Test inequality with different alternative."""
        constr1 = ConstrPlutusData(0, [42])
        constr2 = ConstrPlutusData(1, [42])
        assert constr1 != constr2

    def test_equality_different_data(self):
        """Test inequality with different data."""
        constr1 = ConstrPlutusData(0, [42])
        constr2 = ConstrPlutusData(0, [99])
        assert constr1 != constr2

    def test_equality_different_data_length(self):
        """Test inequality with different data length."""
        constr1 = ConstrPlutusData(0, [1, 2])
        constr2 = ConstrPlutusData(0, [1])
        assert constr1 != constr2

    def test_equality_empty_data(self):
        """Test equality with empty data."""
        constr1 = ConstrPlutusData(0)
        constr2 = ConstrPlutusData(0)
        assert constr1 == constr2

    def test_equality_with_non_constr(self):
        """Test inequality with non-ConstrPlutusData."""
        constr = ConstrPlutusData(0)
        assert constr != 42
        assert constr != "test"
        assert constr != PlutusList()


class TestConstrPlutusDataRepr:
    """Tests for ConstrPlutusData string representation."""

    def test_repr_empty_data(self):
        """Test repr with empty data."""
        constr = ConstrPlutusData(5)
        repr_str = repr(constr)
        assert "ConstrPlutusData" in repr_str
        assert "alternative=5" in repr_str
        assert "args=0" in repr_str

    def test_repr_with_data(self):
        """Test repr with data."""
        constr = ConstrPlutusData(0, [1, 2, 3])
        repr_str = repr(constr)
        assert "ConstrPlutusData" in repr_str
        assert "alternative=0" in repr_str
        assert "args=3" in repr_str


class TestConstrPlutusDataContextManager:
    """Tests for ConstrPlutusData context manager."""

    def test_context_manager(self):
        """Test using ConstrPlutusData as context manager."""
        with ConstrPlutusData(0) as constr:
            constr.data = [42]
            assert len(constr.data) == 1


class TestConstrPlutusDataEdgeCases:
    """Tests for ConstrPlutusData edge cases."""

    def test_alternative_zero(self):
        """Test constructor with alternative zero."""
        constr = ConstrPlutusData(0)
        assert constr.alternative == 0

    def test_alternative_boundary_6(self):
        """Test constructor with alternative 6 (boundary for tag 121-127)."""
        constr = ConstrPlutusData(6)
        assert constr.alternative == 6
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = ConstrPlutusData.from_cbor(reader)
        assert restored.alternative == 6

    def test_alternative_7(self):
        """Test constructor with alternative 7 (uses different encoding)."""
        constr = ConstrPlutusData(7)
        assert constr.alternative == 7
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = ConstrPlutusData.from_cbor(reader)
        assert restored.alternative == 7

    def test_alternative_127(self):
        """Test constructor with alternative 127 (boundary for tags 1280-1400)."""
        constr = ConstrPlutusData(127)
        assert constr.alternative == 127
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = ConstrPlutusData.from_cbor(reader)
        assert restored.alternative == 127

    def test_alternative_large(self):
        """Test constructor with large alternative (uses general form)."""
        constr = ConstrPlutusData(10000)
        assert constr.alternative == 10000
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = ConstrPlutusData.from_cbor(reader)
        assert restored.alternative == 10000

    def test_nested_constructor(self):
        """Test constructor containing another constructor."""
        inner = ConstrPlutusData(1, ["inner"])
        outer_data = PlutusList()
        outer_data.add(PlutusData.from_constr(inner))
        outer = ConstrPlutusData(0, outer_data)

        assert outer.alternative == 0
        assert len(outer.data) == 1
        inner_restored = outer.data[0].to_constr()
        assert inner_restored.alternative == 1

    def test_constructor_with_list_data(self):
        """Test constructor containing a list."""
        plist = PlutusList()
        plist.extend([1, 2, 3])
        constr_data = PlutusList()
        constr_data.add(PlutusData.from_list(plist))
        constr = ConstrPlutusData(0, constr_data)

        assert len(constr.data) == 1
        assert constr.data[0].kind == PlutusDataKind.LIST

    def test_constructor_with_map_data(self):
        """Test constructor containing a map."""
        from cometa import PlutusMap
        pmap = PlutusMap()
        pmap["key"] = 42
        constr_data = PlutusList()
        constr_data.add(PlutusData.from_map(pmap))
        constr = ConstrPlutusData(0, constr_data)

        assert len(constr.data) == 1
        assert constr.data[0].kind == PlutusDataKind.MAP

    def test_constructor_with_large_data(self):
        """Test constructor with many elements."""
        data = [i for i in range(100)]
        constr = ConstrPlutusData(0, data)
        assert len(constr.data) == 100
        assert constr.data[99].to_int() == 99

    def test_constructor_with_mixed_types(self):
        """Test constructor with mixed data types."""
        constr = ConstrPlutusData(0, [
            42,
            "hello",
            b"\xde\xad",
            -999,
            2**128,
        ])
        assert len(constr.data) == 5
        assert constr.data[0].to_int() == 42
        assert constr.data[1].to_string() == "hello"
        assert constr.data[2].to_bytes() == b"\xde\xad"
        assert constr.data[3].to_int() == -999
        assert constr.data[4].to_int() == 2**128


class TestConstrPlutusDataCip116Json:
    """Tests for ConstrPlutusData CIP-116 JSON serialization."""

    def test_to_cip116_json_basic(self):
        """Test CIP-116 JSON serialization."""
        from cometa import JsonWriter, JsonFormat
        constr = ConstrPlutusData(0, [42])
        writer = JsonWriter(JsonFormat.COMPACT)
        constr.to_cip116_json(writer)
        json_str = writer.encode()
        assert "constr" in json_str
        assert "0" in json_str

    def test_to_cip116_json_invalid_writer_raises(self):
        """Test that invalid writer raises TypeError."""
        constr = ConstrPlutusData(0)
        with pytest.raises(TypeError):
            constr.to_cip116_json("not a writer")
