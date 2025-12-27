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
    PlutusMap,
    ConstrPlutusData,
    CborWriter,
    CborReader,
    BigInt,
)


COMPLEX_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"


class TestPlutusDataKind:
    """Tests for PlutusDataKind enum."""

    def test_enum_values(self):
        """Test that all enum values are defined correctly."""
        assert PlutusDataKind.CONSTR == 0
        assert PlutusDataKind.MAP == 1
        assert PlutusDataKind.LIST == 2
        assert PlutusDataKind.INTEGER == 3
        assert PlutusDataKind.BYTES == 4

    def test_enum_names(self):
        """Test that enum names are correct."""
        assert PlutusDataKind.CONSTR.name == "CONSTR"
        assert PlutusDataKind.MAP.name == "MAP"
        assert PlutusDataKind.LIST.name == "LIST"
        assert PlutusDataKind.INTEGER.name == "INTEGER"
        assert PlutusDataKind.BYTES.name == "BYTES"


class TestPlutusDataInteger:
    """Tests for PlutusData integer type."""

    def test_from_int_positive(self):
        """Test creating PlutusData from positive int."""
        data = PlutusData.from_int(42)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 42

    def test_from_int_negative(self):
        """Test creating PlutusData from negative int."""
        data = PlutusData.from_int(-123)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == -123

    def test_from_int_zero(self):
        """Test creating PlutusData from zero."""
        data = PlutusData.from_int(0)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 0

    def test_from_int_large_positive(self):
        """Test creating PlutusData from large positive int."""
        large_num = 2**128
        data = PlutusData.from_int(large_num)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == large_num

    def test_from_int_large_negative(self):
        """Test creating PlutusData from large negative int."""
        large_neg = -(2**128)
        data = PlutusData.from_int(large_neg)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == large_neg

    def test_from_int_very_large(self):
        """Test creating PlutusData from very large int (arbitrary precision)."""
        huge_num = 2**256 + 12345
        data = PlutusData.from_int(huge_num)
        assert data.to_int() == huge_num

    def test_from_bigint(self):
        """Test creating PlutusData from BigInt."""
        bigint = BigInt.from_int(99999)
        data = PlutusData.from_bigint(bigint)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 99999

    def test_to_integer_returns_bigint(self):
        """Test that to_integer returns BigInt."""
        data = PlutusData.from_int(42)
        bigint = data.to_integer()
        assert isinstance(bigint, BigInt)
        assert int(bigint) == 42

    def test_integer_cbor_roundtrip(self):
        """Test CBOR roundtrip for integer."""
        original = PlutusData.from_int(12345)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.to_int() == 12345


class TestPlutusDataBytes:
    """Tests for PlutusData bytes type."""

    def test_from_bytes(self):
        """Test creating PlutusData from bytes."""
        data = PlutusData.from_bytes(b"\x01\x02\x03")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_bytes() == b"\x01\x02\x03"

    def test_from_empty_bytes(self):
        """Test creating PlutusData from empty bytes."""
        data = PlutusData.from_bytes(b"")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_bytes() == b""

    def test_from_string(self):
        """Test creating PlutusData from string (UTF-8 encoded)."""
        data = PlutusData.from_string("hello")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_string() == "hello"
        assert data.to_bytes() == b"hello"

    def test_from_string_unicode(self):
        """Test creating PlutusData from unicode string."""
        data = PlutusData.from_string("héllo wörld")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_string() == "héllo wörld"

    def test_from_string_emoji(self):
        """Test creating PlutusData from string with emoji."""
        data = PlutusData.from_string("hello 🌍")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_string() == "hello 🌍"

    def test_from_hex(self):
        """Test creating PlutusData from hex string."""
        data = PlutusData.from_hex("deadbeef")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_bytes() == bytes.fromhex("deadbeef")

    def test_from_hex_uppercase(self):
        """Test creating PlutusData from uppercase hex string."""
        data = PlutusData.from_hex("DEADBEEF")
        assert data.to_bytes() == bytes.fromhex("deadbeef")

    def test_from_hex_empty(self):
        """Test creating PlutusData from empty hex string."""
        data = PlutusData.from_hex("")
        assert data.to_bytes() == b""

    def test_bytes_cbor_roundtrip(self):
        """Test CBOR roundtrip for bytes."""
        original = PlutusData.from_bytes(b"test data \x00\xff")
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.to_bytes() == b"test data \x00\xff"


class TestPlutusDataList:
    """Tests for PlutusData list type."""

    def test_from_list_plutus_list(self):
        """Test creating PlutusData from PlutusList."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        data = PlutusData.from_list(plist)
        assert data.kind == PlutusDataKind.LIST
        restored_list = data.to_list()
        assert len(restored_list) == 2

    def test_from_list_python_list(self):
        """Test creating PlutusData from Python list."""
        data = PlutusData.from_list([1, "hello", b"\x01"])
        assert data.kind == PlutusDataKind.LIST
        restored_list = data.to_list()
        assert len(restored_list) == 3
        assert restored_list[0].to_int() == 1
        assert restored_list[1].to_string() == "hello"
        assert restored_list[2].to_bytes() == b"\x01"

    def test_from_list_empty(self):
        """Test creating PlutusData from empty list."""
        data = PlutusData.from_list([])
        assert data.kind == PlutusDataKind.LIST
        assert len(data.to_list()) == 0

    def test_list_cbor_roundtrip(self):
        """Test CBOR roundtrip for list."""
        plist = PlutusList()
        plist.extend([1, 2, 3])
        original = PlutusData.from_list(plist)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.kind == PlutusDataKind.LIST


class TestPlutusDataMap:
    """Tests for PlutusData map type."""

    def test_from_map(self):
        """Test creating PlutusData from PlutusMap."""
        pmap = PlutusMap()
        pmap["key"] = 42
        data = PlutusData.from_map(pmap)
        assert data.kind == PlutusDataKind.MAP
        restored_map = data.to_map()
        assert len(restored_map) == 1

    def test_from_map_empty(self):
        """Test creating PlutusData from empty map."""
        pmap = PlutusMap()
        data = PlutusData.from_map(pmap)
        assert data.kind == PlutusDataKind.MAP
        assert len(data.to_map()) == 0

    def test_map_cbor_roundtrip(self):
        """Test CBOR roundtrip for map."""
        pmap = PlutusMap()
        pmap[1] = "one"
        pmap[2] = "two"
        original = PlutusData.from_map(pmap)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.kind == PlutusDataKind.MAP


class TestPlutusDataConstr:
    """Tests for PlutusData constructor type."""

    def test_from_constr(self):
        """Test creating PlutusData from ConstrPlutusData."""
        constr = ConstrPlutusData(0, [42])
        data = PlutusData.from_constr(constr)
        assert data.kind == PlutusDataKind.CONSTR
        restored_constr = data.to_constr()
        assert restored_constr.alternative == 0

    def test_from_constr_empty(self):
        """Test creating PlutusData from empty constructor."""
        constr = ConstrPlutusData(5)
        data = PlutusData.from_constr(constr)
        assert data.kind == PlutusDataKind.CONSTR
        restored = data.to_constr()
        assert restored.alternative == 5
        assert len(restored.data) == 0

    def test_constr_cbor_roundtrip(self):
        """Test CBOR roundtrip for constructor."""
        constr = ConstrPlutusData(1, ["test", 42])
        original = PlutusData.from_constr(constr)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.kind == PlutusDataKind.CONSTR


class TestPlutusDataConversion:
    """Tests for PlutusData native type conversion."""

    def test_to_plutus_data_passthrough(self):
        """Test that PlutusData passes through unchanged."""
        original = PlutusData.from_int(42)
        result = PlutusData.to_plutus_data(original)
        assert result == original

    def test_to_plutus_data_int(self):
        """Test converting int to PlutusData."""
        result = PlutusData.to_plutus_data(42)
        assert result.kind == PlutusDataKind.INTEGER
        assert result.to_int() == 42

    def test_to_plutus_data_str(self):
        """Test converting str to PlutusData."""
        result = PlutusData.to_plutus_data("hello")
        assert result.kind == PlutusDataKind.BYTES
        assert result.to_string() == "hello"

    def test_to_plutus_data_bytes(self):
        """Test converting bytes to PlutusData."""
        result = PlutusData.to_plutus_data(b"\x01\x02")
        assert result.kind == PlutusDataKind.BYTES
        assert result.to_bytes() == b"\x01\x02"

    def test_to_plutus_data_plutus_list(self):
        """Test converting PlutusList to PlutusData."""
        plist = PlutusList()
        plist.append(1)
        result = PlutusData.to_plutus_data(plist)
        assert result.kind == PlutusDataKind.LIST

    def test_to_plutus_data_plutus_map(self):
        """Test converting PlutusMap to PlutusData."""
        pmap = PlutusMap()
        pmap["key"] = 1
        result = PlutusData.to_plutus_data(pmap)
        assert result.kind == PlutusDataKind.MAP

    def test_to_plutus_data_constr(self):
        """Test converting ConstrPlutusData to PlutusData."""
        constr = ConstrPlutusData(0)
        result = PlutusData.to_plutus_data(constr)
        assert result.kind == PlutusDataKind.CONSTR

    def test_to_plutus_data_invalid_type(self):
        """Test that invalid types raise TypeError."""
        with pytest.raises(TypeError):
            PlutusData.to_plutus_data([1, 2, 3])
        with pytest.raises(TypeError):
            PlutusData.to_plutus_data({"a": 1})
        with pytest.raises(TypeError):
            PlutusData.to_plutus_data(3.14)


class TestPlutusDataEquality:
    """Tests for PlutusData equality."""

    def test_equality_integers(self):
        """Test integer PlutusData equality."""
        data1 = PlutusData.from_int(42)
        data2 = PlutusData.from_int(42)
        data3 = PlutusData.from_int(43)
        assert data1 == data2
        assert data1 != data3

    def test_equality_bytes(self):
        """Test bytes PlutusData equality."""
        data1 = PlutusData.from_bytes(b"test")
        data2 = PlutusData.from_bytes(b"test")
        data3 = PlutusData.from_bytes(b"other")
        assert data1 == data2
        assert data1 != data3

    def test_equality_different_kinds(self):
        """Test inequality between different kinds."""
        int_data = PlutusData.from_int(1)
        bytes_data = PlutusData.from_bytes(b"\x01")
        assert int_data != bytes_data

    def test_equality_with_non_plutus_data(self):
        """Test inequality with non-PlutusData."""
        data = PlutusData.from_int(42)
        assert data != 42
        assert data != "42"
        assert data is not None


class TestPlutusDataRepr:
    """Tests for PlutusData string representation."""

    def test_repr_integer(self):
        """Test repr of integer PlutusData."""
        data = PlutusData.from_int(42)
        assert repr(data) == "PlutusData(kind=INTEGER)"

    def test_repr_bytes(self):
        """Test repr of bytes PlutusData."""
        data = PlutusData.from_bytes(b"test")
        assert repr(data) == "PlutusData(kind=BYTES)"

    def test_repr_list(self):
        """Test repr of list PlutusData."""
        data = PlutusData.from_list([1, 2, 3])
        assert repr(data) == "PlutusData(kind=LIST)"

    def test_repr_map(self):
        """Test repr of map PlutusData."""
        pmap = PlutusMap()
        data = PlutusData.from_map(pmap)
        assert repr(data) == "PlutusData(kind=MAP)"

    def test_repr_constr(self):
        """Test repr of constructor PlutusData."""
        constr = ConstrPlutusData(0)
        data = PlutusData.from_constr(constr)
        assert repr(data) == "PlutusData(kind=CONSTR)"


class TestPlutusDataContextManager:
    """Tests for PlutusData context manager."""

    def test_context_manager(self):
        """Test using PlutusData as context manager."""
        with PlutusData.from_int(42) as data:
            assert data.to_int() == 42


class TestPlutusDataCborCache:
    """Tests for PlutusData CBOR cache."""

    def test_clear_cbor_cache(self):
        """Test clearing CBOR cache."""
        reader = CborReader.from_hex("01")
        data = PlutusData.from_cbor(reader)
        data.clear_cbor_cache()
        writer = CborWriter()
        data.to_cbor(writer)
        assert writer.to_hex() == "01"


class TestPlutusDataCip116Json:
    """Tests for PlutusData CIP-116 JSON serialization."""

    def test_to_cip116_json_integer(self):
        """Test CIP-116 JSON for integer."""
        from cometa import JsonWriter, JsonFormat
        data = PlutusData.from_int(42)
        writer = JsonWriter(JsonFormat.COMPACT)
        data.to_cip116_json(writer)
        json_str = writer.encode()
        assert "integer" in json_str
        assert "42" in json_str

    def test_to_cip116_json_bytes(self):
        """Test CIP-116 JSON for bytes."""
        from cometa import JsonWriter, JsonFormat
        data = PlutusData.from_hex("aa")
        writer = JsonWriter(JsonFormat.COMPACT)
        data.to_cip116_json(writer)
        json_str = writer.encode()
        assert "bytes" in json_str
        assert "aa" in json_str

    def test_to_cip116_json_invalid_writer_raises(self):
        """Test that invalid writer raises TypeError."""
        data = PlutusData.from_int(42)
        with pytest.raises(TypeError):
            data.to_cip116_json("not a writer")


class TestPlutusDataComplexCbor:
    """Tests for complex PlutusData CBOR scenarios."""

    def test_deserialize_complex_nested(self):
        """Test deserializing complex nested structure."""
        reader = CborReader.from_hex(COMPLEX_CBOR)
        data = PlutusData.from_cbor(reader)
        data.clear_cbor_cache()

        assert data.kind == PlutusDataKind.LIST
        plist = data.to_list()
        assert len(plist) == 5

        assert plist[0].to_int() == 1
        assert plist[1].to_int() == 2
        assert plist[2].kind == PlutusDataKind.LIST
        assert plist[3].kind == PlutusDataKind.LIST
        assert plist[4].to_int() == 5


class TestPlutusDataEdgeCases:
    """Tests for PlutusData edge cases."""

    def test_cannot_create_directly(self):
        """Test that PlutusData cannot be created directly."""
        with pytest.raises(Exception):
            PlutusData()

    def test_to_int_on_non_integer_raises(self):
        """Test that to_int on non-integer raises error."""
        data = PlutusData.from_bytes(b"test")
        with pytest.raises(Exception):
            data.to_int()

    def test_to_bytes_on_non_bytes_raises(self):
        """Test that to_bytes on non-bytes raises error."""
        data = PlutusData.from_int(42)
        with pytest.raises(Exception):
            data.to_bytes()

    def test_to_list_on_non_list_raises(self):
        """Test that to_list on non-list raises error."""
        data = PlutusData.from_int(42)
        with pytest.raises(Exception):
            data.to_list()

    def test_to_map_on_non_map_raises(self):
        """Test that to_map on non-map raises error."""
        data = PlutusData.from_int(42)
        with pytest.raises(Exception):
            data.to_map()

    def test_to_constr_on_non_constr_raises(self):
        """Test that to_constr on non-constructor raises error."""
        data = PlutusData.from_int(42)
        with pytest.raises(Exception):
            data.to_constr()

    def test_deeply_nested_structure(self):
        """Test deeply nested data structure."""
        inner = PlutusData.from_int(42)
        for _ in range(10):
            plist = PlutusList()
            plist.add(inner)
            inner = PlutusData.from_list(plist)

        assert inner.kind == PlutusDataKind.LIST

        writer = CborWriter()
        inner.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.kind == PlutusDataKind.LIST


class TestPlutusDataCborVectors:
    """Tests using CBOR test vectors from C tests."""

    def test_cbor_negative_integer(self):
        """Test decoding negative integer from CBOR."""
        reader = CborReader.from_hex("24")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == -5

    def test_cbor_big_positive_integer(self):
        """Test decoding big positive integer from CBOR."""
        reader = CborReader.from_hex("c249000100000000000000")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 72057594037927936

    def test_cbor_big_negative_integer(self):
        """Test decoding big negative integer from CBOR."""
        reader = CborReader.from_hex("c349000100000000000000")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == -72057594037927936

    def test_cbor_bytes_vector(self):
        """Test decoding bytes from CBOR."""
        reader = CborReader.from_hex("450102030405")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_bytes() == b"\x01\x02\x03\x04\x05"

    def test_cbor_list_vector(self):
        """Test decoding list from CBOR."""
        reader = CborReader.from_hex("9f0102030405ff")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.LIST
        plist = data.to_list()
        assert len(plist) == 5
        assert plist[0].to_int() == 1
        assert plist[1].to_int() == 2
        assert plist[2].to_int() == 3
        assert plist[3].to_int() == 4
        assert plist[4].to_int() == 5

    def test_cbor_map_vector(self):
        """Test decoding map from CBOR."""
        reader = CborReader.from_hex("a3010402050306")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.MAP
        pmap = data.to_map()
        assert len(pmap) == 3

    def test_cbor_constructor_vector(self):
        """Test decoding constructor from CBOR."""
        reader = CborReader.from_hex("d8799f0102ff")
        data = PlutusData.from_cbor(reader)
        assert data.kind == PlutusDataKind.CONSTR
        constr = data.to_constr()
        assert constr.alternative == 0
        assert len(constr.data) == 2


class TestPlutusDataInvalidInputs:
    """Tests for invalid inputs to PlutusData functions."""

    def test_from_hex_odd_length(self):
        """Test that odd length hex string raises error."""
        with pytest.raises(Exception):
            PlutusData.from_hex("abc")

    def test_to_string_invalid_utf8(self):
        """Test that to_string on invalid UTF-8 raises error."""
        data = PlutusData.from_bytes(b"\xff\xfe")
        with pytest.raises(UnicodeDecodeError):
            data.to_string()

    def test_from_cbor_invalid_cbor(self):
        """Test that invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(Exception):
            PlutusData.from_cbor(reader)


class TestPlutusDataLargeIntegers:
    """Tests for very large integers using test vectors from C tests."""

    def test_very_large_positive_integer(self):
        """Test creating PlutusData from very large positive integer."""
        large_num_str = "1093929156918367016766069563027239416446778893307251997971794948729105062347369330146869223033199554831433128491376164494134119896793625745623928731109781036903510617119765359815723399113165600284443934720"
        large_num = int(large_num_str)
        data = PlutusData.from_int(large_num)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == large_num

    def test_very_large_negative_integer(self):
        """Test creating PlutusData from very large negative integer."""
        large_num_str = "-1093929156918367016766069563027239416446778893307251997971794948729105062347369330146869223033199554831433128491376164494134119896793625745623928731109781036903510617119765359815723399113165600284443934720"
        large_num = int(large_num_str)
        data = PlutusData.from_int(large_num)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == large_num

    def test_multiple_large_numbers_roundtrip(self):
        """Test CBOR roundtrip with multiple large numbers."""
        test_numbers = [
            "2768491094397106413284351268798781278061973163918667373508176781108678876832888565950388553255499815619207549146245084281150783450096035638439655721496227482399093555200000000000000000000000000000000000000",
            "-2768491094397106413284351268798781278061973163918667373508176781108678876832888565950388553255499815619207549146245084281150783450096035638439655721496227482399093555200000000000000000000000000000000000000",
        ]

        for num_str in test_numbers:
            num = int(num_str)
            original = PlutusData.from_int(num)
            writer = CborWriter()
            original.to_cbor(writer)
            cbor_bytes = writer.encode()

            reader = CborReader.from_bytes(cbor_bytes)
            restored = PlutusData.from_cbor(reader)
            assert restored.to_int() == num
