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
)


class TestPlutusDataKind:
    """Tests for PlutusDataKind enum."""

    def test_enum_values(self):
        """Test that all enum values are defined correctly."""
        assert PlutusDataKind.CONSTR == 0
        assert PlutusDataKind.MAP == 1
        assert PlutusDataKind.LIST == 2
        assert PlutusDataKind.INTEGER == 3
        assert PlutusDataKind.BYTES == 4


class TestPlutusDataInteger:
    """Tests for PlutusData integer type."""

    def test_from_int(self):
        """Test creating PlutusData from int."""
        data = PlutusData.from_int(42)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 42

    def test_from_negative_int(self):
        """Test creating PlutusData from negative int."""
        data = PlutusData.from_int(-123)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == -123

    def test_from_zero(self):
        """Test creating PlutusData from zero."""
        data = PlutusData.from_int(0)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == 0

    def test_from_large_int(self):
        """Test creating PlutusData from large int (arbitrary precision)."""
        large_num = 2**128
        data = PlutusData.from_int(large_num)
        assert data.kind == PlutusDataKind.INTEGER
        assert data.to_int() == large_num

    def test_integer_equality(self):
        """Test integer PlutusData equality."""
        data1 = PlutusData.from_int(42)
        data2 = PlutusData.from_int(42)
        data3 = PlutusData.from_int(43)
        assert data1 == data2
        assert data1 != data3


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

    def test_from_hex(self):
        """Test creating PlutusData from hex string."""
        data = PlutusData.from_hex("deadbeef")
        assert data.kind == PlutusDataKind.BYTES
        assert data.to_bytes() == bytes.fromhex("deadbeef")

    def test_bytes_equality(self):
        """Test bytes PlutusData equality."""
        data1 = PlutusData.from_bytes(b"test")
        data2 = PlutusData.from_bytes(b"test")
        data3 = PlutusData.from_bytes(b"other")
        assert data1 == data2
        assert data1 != data3


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

    def test_to_plutus_data_invalid_type(self):
        """Test that invalid types raise TypeError."""
        with pytest.raises(TypeError):
            PlutusData.to_plutus_data([1, 2, 3])


class TestPlutusDataCbor:
    """Tests for PlutusData CBOR serialization."""

    def test_roundtrip_integer(self):
        """Test CBOR roundtrip for integer."""
        original = PlutusData.from_int(12345)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.to_int() == 12345

    def test_roundtrip_bytes(self):
        """Test CBOR roundtrip for bytes."""
        original = PlutusData.from_bytes(b"test data")
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusData.from_cbor(reader)
        assert restored.to_bytes() == b"test data"


class TestPlutusList:
    """Tests for PlutusList."""

    def test_create_empty_list(self):
        """Test creating an empty PlutusList."""
        plist = PlutusList()
        assert len(plist) == 0
        assert not plist  # bool(empty) is False

    def test_append_and_len(self):
        """Test appending elements and checking length."""
        plist = PlutusList()
        plist.append(42)
        plist.append("hello")
        plist.append(b"\x01\x02")
        assert len(plist) == 3
        assert plist  # bool(non-empty) is True

    def test_getitem_positive_index(self):
        """Test getting items by positive index."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        assert plist[0].to_int() == 1
        assert plist[1].to_int() == 2
        assert plist[2].to_int() == 3

    def test_getitem_negative_index(self):
        """Test getting items by negative index."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        assert plist[-1].to_int() == 3
        assert plist[-2].to_int() == 2
        assert plist[-3].to_int() == 1

    def test_getitem_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        plist = PlutusList()
        plist.append(1)
        with pytest.raises(IndexError):
            _ = plist[5]

    def test_slicing(self):
        """Test list slicing."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        plist.append(4)
        slice_result = plist[1:3]
        assert len(slice_result) == 2
        assert slice_result[0].to_int() == 2
        assert slice_result[1].to_int() == 3

    def test_iteration(self):
        """Test iterating over list."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        values = [item.to_int() for item in plist]
        assert values == [1, 2, 3]

    def test_reversed_iteration(self):
        """Test reversed iteration."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        values = [item.to_int() for item in reversed(plist)]
        assert values == [3, 2, 1]

    def test_contains(self):
        """Test membership testing."""
        plist = PlutusList()
        plist.append(42)
        plist.append("hello")
        assert 42 in plist
        assert "hello" in plist
        assert 999 not in plist

    def test_extend(self):
        """Test extending list."""
        plist = PlutusList()
        plist.append(1)
        plist.extend([2, 3, 4])
        assert len(plist) == 4
        assert plist[3].to_int() == 4

    def test_concatenation(self):
        """Test list concatenation with +."""
        plist1 = PlutusList()
        plist1.append(1)
        plist2 = PlutusList()
        plist2.append(2)
        combined = plist1 + plist2
        assert len(combined) == 2
        assert combined[0].to_int() == 1
        assert combined[1].to_int() == 2

    def test_inplace_concatenation(self):
        """Test list concatenation with +=."""
        plist = PlutusList()
        plist.append(1)
        plist += [2, 3]
        assert len(plist) == 3
        assert plist[2].to_int() == 3

    def test_index(self):
        """Test finding index of element."""
        plist = PlutusList()
        plist.append(10)
        plist.append(20)
        plist.append(30)
        assert plist.index(20) == 1

    def test_count(self):
        """Test counting occurrences."""
        plist = PlutusList()
        plist.append(42)
        plist.append(99)
        plist.append(42)
        assert plist.count(42) == 2
        assert plist.count(99) == 1
        assert plist.count(0) == 0

    def test_copy(self):
        """Test copying list."""
        plist1 = PlutusList()
        plist1.append(1)
        plist1.append(2)
        plist2 = plist1.copy()
        assert len(plist2) == 2
        assert plist2[0].to_int() == 1

    def test_equality(self):
        """Test list equality."""
        plist1 = PlutusList()
        plist1.append(1)
        plist1.append(2)
        plist2 = PlutusList()
        plist2.append(1)
        plist2.append(2)
        plist3 = PlutusList()
        plist3.append(1)
        plist3.append(3)
        assert plist1 == plist2
        assert plist1 != plist3

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        plist = PlutusList()
        plist.append(42)
        plist.append("test")
        writer = CborWriter()
        plist.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusList.from_cbor(reader)
        assert len(restored) == 2
        assert restored[0].to_int() == 42


class TestPlutusMap:
    """Tests for PlutusMap."""

    def test_create_empty_map(self):
        """Test creating an empty PlutusMap."""
        pmap = PlutusMap()
        assert len(pmap) == 0
        assert not pmap  # bool(empty) is False

    def test_setitem_and_getitem(self):
        """Test setting and getting items."""
        pmap = PlutusMap()
        pmap["key1"] = 42
        pmap[1] = "value"
        assert pmap["key1"].to_int() == 42
        assert pmap[1].to_string() == "value"
        assert len(pmap) == 2
        assert pmap  # bool(non-empty) is True

    def test_getitem_missing_key(self):
        """Test that missing key raises KeyError."""
        pmap = PlutusMap()
        pmap["exists"] = 1
        with pytest.raises(KeyError):
            _ = pmap["missing"]

    def test_contains(self):
        """Test membership testing."""
        pmap = PlutusMap()
        pmap["key"] = 42
        assert "key" in pmap
        assert "missing" not in pmap

    def test_get_with_default(self):
        """Test get method with default value."""
        pmap = PlutusMap()
        pmap["key"] = 42
        assert pmap.get("key").to_int() == 42
        assert pmap.get("missing") is None
        default = PlutusData.from_int(99)
        assert pmap.get("missing", default).to_int() == 99

    def test_keys_iteration(self):
        """Test iterating over keys."""
        pmap = PlutusMap()
        pmap[1] = "one"
        pmap[2] = "two"
        keys = list(pmap.keys())
        assert len(keys) == 2

    def test_values_iteration(self):
        """Test iterating over values."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        values = list(pmap.values())
        assert len(values) == 2

    def test_items_iteration(self):
        """Test iterating over items."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap["b"] = 2
        items = list(pmap.items())
        assert len(items) == 2

    def test_update_from_dict(self):
        """Test updating from a dict."""
        pmap = PlutusMap()
        pmap["a"] = 1
        pmap.update({"b": 2, "c": 3})
        assert len(pmap) == 3
        assert pmap["b"].to_int() == 2

    def test_setdefault(self):
        """Test setdefault method."""
        pmap = PlutusMap()
        pmap["existing"] = 1
        # Should return existing value
        result = pmap.setdefault("existing", 99)
        assert result.to_int() == 1
        # Should insert and return default
        result = pmap.setdefault("new", 42)
        assert result.to_int() == 42
        assert pmap["new"].to_int() == 42

    def test_copy(self):
        """Test copying map."""
        pmap1 = PlutusMap()
        pmap1["key"] = 42
        pmap2 = pmap1.copy()
        assert len(pmap2) == 1
        assert pmap2["key"].to_int() == 42

    def test_equality(self):
        """Test map equality."""
        pmap1 = PlutusMap()
        pmap1["a"] = 1
        pmap2 = PlutusMap()
        pmap2["a"] = 1
        pmap3 = PlutusMap()
        pmap3["a"] = 2
        assert pmap1 == pmap2
        assert pmap1 != pmap3

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        pmap = PlutusMap()
        pmap["key"] = 42
        writer = CborWriter()
        pmap.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusMap.from_cbor(reader)
        assert len(restored) == 1


class TestConstrPlutusData:
    """Tests for ConstrPlutusData."""

    def test_create_with_alternative(self):
        """Test creating constructor with alternative only."""
        constr = ConstrPlutusData(0)
        assert constr.alternative == 0
        assert len(constr.data) == 0

    def test_create_with_data(self):
        """Test creating constructor with alternative and data."""
        args = PlutusList()
        args.append(42)
        args.append("hello")
        constr = ConstrPlutusData(1, args)
        assert constr.alternative == 1
        assert len(constr.data) == 2

    def test_new_factory_method(self):
        """Test the new() factory method."""
        constr = ConstrPlutusData.new(0, 42, "hello", b"\x01")
        assert constr.alternative == 0
        assert len(constr.data) == 3
        assert constr.data[0].to_int() == 42
        assert constr.data[1].to_string() == "hello"
        assert constr.data[2].to_bytes() == b"\x01"

    def test_set_alternative(self):
        """Test setting alternative."""
        constr = ConstrPlutusData(0)
        constr.alternative = 5
        assert constr.alternative == 5

    def test_set_data(self):
        """Test setting data."""
        constr = ConstrPlutusData(0)
        new_data = PlutusList()
        new_data.append(99)
        constr.data = new_data
        assert len(constr.data) == 1
        assert constr.data[0].to_int() == 99

    def test_equality(self):
        """Test constructor equality."""
        constr1 = ConstrPlutusData.new(0, 42)
        constr2 = ConstrPlutusData.new(0, 42)
        constr3 = ConstrPlutusData.new(1, 42)
        constr4 = ConstrPlutusData.new(0, 99)
        assert constr1 == constr2
        assert constr1 != constr3  # Different alternative
        assert constr1 != constr4  # Different data

    def test_repr(self):
        """Test string representation."""
        constr = ConstrPlutusData.new(0, 1, 2, 3)
        repr_str = repr(constr)
        assert "ConstrPlutusData" in repr_str
        assert "alternative=0" in repr_str
        assert "args=3" in repr_str

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        constr = ConstrPlutusData.new(0, 42, "test")
        writer = CborWriter()
        constr.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = ConstrPlutusData.from_cbor(reader)
        assert restored.alternative == 0
        assert len(restored.data) == 2


class TestPlutusDataComposite:
    """Tests for composite PlutusData operations."""

    def test_plutus_data_from_list(self):
        """Test creating PlutusData from PlutusList."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        data = PlutusData.from_list(plist)
        assert data.kind == PlutusDataKind.LIST
        restored_list = data.to_list()
        assert len(restored_list) == 2

    def test_plutus_data_from_map(self):
        """Test creating PlutusData from PlutusMap."""
        pmap = PlutusMap()
        pmap["key"] = 42
        data = PlutusData.from_map(pmap)
        assert data.kind == PlutusDataKind.MAP
        restored_map = data.to_map()
        assert len(restored_map) == 1

    def test_plutus_data_from_constr(self):
        """Test creating PlutusData from ConstrPlutusData."""
        constr = ConstrPlutusData.new(0, 42)
        data = PlutusData.from_constr(constr)
        assert data.kind == PlutusDataKind.CONSTR
        restored_constr = data.to_constr()
        assert restored_constr.alternative == 0

    def test_nested_list_in_list(self):
        """Test nested lists."""
        inner = PlutusList()
        inner.append(1)
        inner.append(2)

        outer = PlutusList()
        outer.add(PlutusData.from_list(inner))
        outer.append(3)

        assert len(outer) == 2
        inner_data = outer[0]
        assert inner_data.kind == PlutusDataKind.LIST

    def test_map_with_complex_values(self):
        """Test map with list and constructor values."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)

        constr = ConstrPlutusData.new(0, "test")

        pmap = PlutusMap()
        pmap.insert(PlutusData.from_string("list_key"), PlutusData.from_list(plist))
        pmap.insert(PlutusData.from_string("constr_key"), PlutusData.from_constr(constr))

        assert len(pmap) == 2
        list_value = pmap["list_key"]
        assert list_value.kind == PlutusDataKind.LIST
