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
    CborWriter,
    CborReader,
    JsonWriter,
    CardanoError,
)


SIMPLE_LIST_CBOR = "9f0102030405ff"
NESTED_LIST_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
EMPTY_LIST_CBOR = "80"


class TestPlutusListCreation:
    """Tests for PlutusList creation."""

    def test_create_empty_list(self):
        """Test creating an empty PlutusList."""
        plist = PlutusList()
        assert len(plist) == 0
        assert not plist

    def test_from_list_factory(self):
        """Test creating PlutusList from a Python list."""
        plist = PlutusList.from_list([1, 2, 3, 4, 5])
        assert len(plist) == 5
        for i, item in enumerate(plist):
            assert item.to_int() == i + 1

    def test_from_list_with_mixed_types(self):
        """Test creating PlutusList from mixed types."""
        plist = PlutusList.from_list([42, "hello", b"\x01\x02"])
        assert len(plist) == 3
        assert plist[0].to_int() == 42
        assert plist[1].to_string() == "hello"
        assert plist[2].to_bytes() == b"\x01\x02"

    def test_from_list_with_plutus_data(self):
        """Test creating PlutusList from PlutusData objects."""
        data1 = PlutusData.from_int(10)
        data2 = PlutusData.from_bytes(b"test")
        plist = PlutusList.from_list([data1, data2])
        assert len(plist) == 2
        assert plist[0].to_int() == 10
        assert plist[1].to_bytes() == b"test"


class TestPlutusListCbor:
    """Tests for PlutusList CBOR serialization."""

    def test_serialize_empty_list(self):
        """Test CBOR serialization of empty list."""
        plist = PlutusList()
        writer = CborWriter()
        plist.to_cbor(writer)
        assert writer.to_hex() == EMPTY_LIST_CBOR

    def test_serialize_simple_list(self):
        """Test CBOR serialization of simple list."""
        plist = PlutusList()
        for i in range(1, 6):
            plist.append(i)
        writer = CborWriter()
        plist.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_LIST_CBOR

    def test_deserialize_simple_list(self):
        """Test CBOR deserialization of simple list."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        plist = PlutusList.from_cbor(reader)
        assert len(plist) == 5
        for i, item in enumerate(plist):
            assert item.kind == PlutusDataKind.INTEGER
            assert item.to_int() == i + 1

    def test_serialize_nested_list(self):
        """Test CBOR serialization of nested list."""
        inner = PlutusList()
        for i in range(1, 6):
            inner.append(i)

        outer = PlutusList()
        outer.append(1)
        outer.append(2)
        outer.add(PlutusData.from_list(inner))
        outer.add(PlutusData.from_list(inner))
        outer.append(5)

        writer = CborWriter()
        outer.to_cbor(writer)
        assert writer.to_hex() == NESTED_LIST_CBOR

    def test_deserialize_nested_list(self):
        """Test CBOR deserialization of nested list."""
        reader = CborReader.from_hex(NESTED_LIST_CBOR)
        plist = PlutusList.from_cbor(reader)
        plist.clear_cbor_cache()

        assert len(plist) == 5
        assert plist[0].kind == PlutusDataKind.INTEGER
        assert plist[0].to_int() == 1
        assert plist[1].kind == PlutusDataKind.INTEGER
        assert plist[1].to_int() == 2
        assert plist[2].kind == PlutusDataKind.LIST
        assert plist[3].kind == PlutusDataKind.LIST
        assert plist[4].kind == PlutusDataKind.INTEGER
        assert plist[4].to_int() == 5

        inner_list = plist[2].to_list()
        assert len(inner_list) == 5
        for i, item in enumerate(inner_list):
            assert item.to_int() == i + 1

    def test_roundtrip_cbor(self):
        """Test CBOR roundtrip preserves data."""
        plist = PlutusList()
        plist.append(42)
        plist.append("test")
        plist.append(b"\xde\xad\xbe\xef")

        writer = CborWriter()
        plist.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = PlutusList.from_cbor(reader)

        assert len(restored) == 3
        assert restored[0].to_int() == 42
        assert restored[1].to_string() == "test"
        assert restored[2].to_bytes() == b"\xde\xad\xbe\xef"

    def test_deserialize_and_reserialize_preserves_cbor(self):
        """Test that deserialize/reserialize preserves original CBOR."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        plist = PlutusList.from_cbor(reader)
        plist.clear_cbor_cache()

        writer = CborWriter()
        plist.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_LIST_CBOR

    def test_from_cbor_not_an_array_raises(self):
        """Test that deserializing non-array CBOR raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(Exception):
            PlutusList.from_cbor(reader)


class TestPlutusListAccess:
    """Tests for PlutusList element access."""

    def test_getitem_positive_index(self):
        """Test getting items by positive index."""
        plist = PlutusList()
        plist.append(10)
        plist.append(20)
        plist.append(30)
        assert plist[0].to_int() == 10
        assert plist[1].to_int() == 20
        assert plist[2].to_int() == 30

    def test_getitem_negative_index(self):
        """Test getting items by negative index."""
        plist = PlutusList()
        plist.append(1)
        plist.append(2)
        plist.append(3)
        assert plist[-1].to_int() == 3
        assert plist[-2].to_int() == 2
        assert plist[-3].to_int() == 1

    def test_getitem_out_of_bounds_raises(self):
        """Test that out of bounds index raises IndexError."""
        plist = PlutusList()
        plist.append(1)
        with pytest.raises(IndexError):
            _ = plist[5]
        with pytest.raises(IndexError):
            _ = plist[-5]

    def test_slicing_basic(self):
        """Test basic list slicing."""
        plist = PlutusList()
        for i in range(5):
            plist.append(i)
        slice_result = plist[1:4]
        assert len(slice_result) == 3
        assert slice_result[0].to_int() == 1
        assert slice_result[1].to_int() == 2
        assert slice_result[2].to_int() == 3

    def test_slicing_step(self):
        """Test slicing with step."""
        plist = PlutusList()
        for i in range(10):
            plist.append(i)
        slice_result = plist[::2]
        assert len(slice_result) == 5
        assert [item.to_int() for item in slice_result] == [0, 2, 4, 6, 8]

    def test_slicing_negative(self):
        """Test slicing with negative indices."""
        plist = PlutusList()
        for i in range(5):
            plist.append(i)
        slice_result = plist[-3:]
        assert len(slice_result) == 3
        assert [item.to_int() for item in slice_result] == [2, 3, 4]


class TestPlutusListIteration:
    """Tests for PlutusList iteration."""

    def test_iteration(self):
        """Test forward iteration."""
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

    def test_iteration_empty_list(self):
        """Test iteration over empty list."""
        plist = PlutusList()
        values = list(plist)
        assert values == []


class TestPlutusListModification:
    """Tests for PlutusList modification operations."""

    def test_append_int(self):
        """Test appending integers."""
        plist = PlutusList()
        plist.append(42)
        assert len(plist) == 1
        assert plist[0].to_int() == 42

    def test_append_string(self):
        """Test appending strings."""
        plist = PlutusList()
        plist.append("hello")
        assert len(plist) == 1
        assert plist[0].to_string() == "hello"

    def test_append_bytes(self):
        """Test appending bytes."""
        plist = PlutusList()
        plist.append(b"\x01\x02\x03")
        assert len(plist) == 1
        assert plist[0].to_bytes() == b"\x01\x02\x03"

    def test_add_plutus_data(self):
        """Test adding PlutusData directly."""
        plist = PlutusList()
        data = PlutusData.from_int(99)
        plist.add(data)
        assert len(plist) == 1
        assert plist[0].to_int() == 99

    def test_extend_from_list(self):
        """Test extending with a Python list."""
        plist = PlutusList()
        plist.append(1)
        plist.extend([2, 3, 4])
        assert len(plist) == 4
        assert [item.to_int() for item in plist] == [1, 2, 3, 4]

    def test_extend_from_plutus_list(self):
        """Test extending with another PlutusList via iadd."""
        plist1 = PlutusList()
        plist1.append(1)
        plist2 = PlutusList()
        plist2.append(2)
        plist2.append(3)
        plist1 += plist2
        assert len(plist1) == 3
        assert [item.to_int() for item in plist1] == [1, 2, 3]


class TestPlutusListConcatenation:
    """Tests for PlutusList concatenation."""

    def test_concatenation_add(self):
        """Test list concatenation with +."""
        plist1 = PlutusList()
        plist1.append(1)
        plist1.append(2)
        plist2 = PlutusList()
        plist2.append(3)
        plist2.append(4)
        combined = plist1 + plist2
        assert len(combined) == 4
        assert [item.to_int() for item in combined] == [1, 2, 3, 4]

    def test_concatenation_iadd(self):
        """Test list concatenation with +=."""
        plist = PlutusList()
        plist.append(1)
        plist += [2, 3]
        assert len(plist) == 3
        assert [item.to_int() for item in plist] == [1, 2, 3]

    def test_concatenation_with_iterable(self):
        """Test concatenation with generic iterable."""
        plist = PlutusList()
        plist.append(1)
        combined = plist + [2, 3]
        assert len(combined) == 3


class TestPlutusListSearch:
    """Tests for PlutusList search operations."""

    def test_contains_int(self):
        """Test membership testing with int."""
        plist = PlutusList()
        plist.append(42)
        plist.append(99)
        assert 42 in plist
        assert 99 in plist
        assert 0 not in plist

    def test_contains_string(self):
        """Test membership testing with string."""
        plist = PlutusList()
        plist.append("hello")
        plist.append("world")
        assert "hello" in plist
        assert "missing" not in plist

    def test_contains_bytes(self):
        """Test membership testing with bytes."""
        plist = PlutusList()
        plist.append(b"\x01\x02")
        assert b"\x01\x02" in plist
        assert b"\x03\x04" not in plist

    def test_index_found(self):
        """Test finding index of element."""
        plist = PlutusList()
        plist.append(10)
        plist.append(20)
        plist.append(30)
        assert plist.index(20) == 1

    def test_index_not_found_raises(self):
        """Test that index raises ValueError for missing element."""
        plist = PlutusList()
        plist.append(1)
        with pytest.raises(ValueError):
            plist.index(999)

    def test_index_with_start_stop(self):
        """Test index with start and stop parameters."""
        plist = PlutusList()
        plist.extend([1, 2, 3, 2, 4])
        assert plist.index(2) == 1
        assert plist.index(2, 2) == 3

    def test_count(self):
        """Test counting occurrences."""
        plist = PlutusList()
        plist.extend([42, 99, 42, 100, 42])
        assert plist.count(42) == 3
        assert plist.count(99) == 1
        assert plist.count(0) == 0


class TestPlutusListCopy:
    """Tests for PlutusList copy operations."""

    def test_copy(self):
        """Test copying list."""
        plist1 = PlutusList()
        plist1.append(1)
        plist1.append(2)
        plist2 = plist1.copy()
        assert len(plist2) == 2
        assert plist2[0].to_int() == 1
        assert plist2[1].to_int() == 2

    def test_copy_is_independent(self):
        """Test that copy creates an independent list."""
        plist1 = PlutusList()
        plist1.append(1)
        plist2 = plist1.copy()
        plist2.append(2)
        assert len(plist1) == 1
        assert len(plist2) == 2


class TestPlutusListEquality:
    """Tests for PlutusList equality."""

    def test_equality_empty_lists(self):
        """Test equality of empty lists."""
        plist1 = PlutusList()
        plist2 = PlutusList()
        assert plist1 == plist2

    def test_equality_same_elements(self):
        """Test equality with same elements."""
        plist1 = PlutusList()
        plist1.append(1)
        plist1.append(2)
        plist2 = PlutusList()
        plist2.append(1)
        plist2.append(2)
        assert plist1 == plist2

    def test_equality_different_elements(self):
        """Test inequality with different elements."""
        plist1 = PlutusList()
        plist1.append(1)
        plist2 = PlutusList()
        plist2.append(2)
        assert plist1 != plist2

    def test_equality_different_lengths(self):
        """Test inequality with different lengths."""
        plist1 = PlutusList()
        plist1.append(1)
        plist2 = PlutusList()
        plist2.append(1)
        plist2.append(2)
        assert plist1 != plist2

    def test_equality_with_non_list(self):
        """Test inequality with non-PlutusList."""
        plist = PlutusList()
        assert plist != [1, 2, 3]
        assert plist != "test"
        assert plist != 42


class TestPlutusListBool:
    """Tests for PlutusList bool conversion."""

    def test_bool_empty_is_false(self):
        """Test that empty list is falsy."""
        plist = PlutusList()
        assert not plist
        assert bool(plist) is False

    def test_bool_non_empty_is_true(self):
        """Test that non-empty list is truthy."""
        plist = PlutusList()
        plist.append(1)
        assert plist
        assert bool(plist) is True


class TestPlutusListRepr:
    """Tests for PlutusList string representation."""

    def test_repr_empty(self):
        """Test repr of empty list."""
        plist = PlutusList()
        assert repr(plist) == "PlutusList(len=0)"

    def test_repr_with_elements(self):
        """Test repr of list with elements."""
        plist = PlutusList()
        plist.extend([1, 2, 3])
        assert repr(plist) == "PlutusList(len=3)"


class TestPlutusListContextManager:
    """Tests for PlutusList context manager."""

    def test_context_manager(self):
        """Test using PlutusList as context manager."""
        with PlutusList() as plist:
            plist.append(42)
            assert len(plist) == 1


class TestPlutusListEdgeCases:
    """Tests for PlutusList edge cases."""

    def test_large_list(self):
        """Test creating a large list."""
        plist = PlutusList()
        for i in range(1000):
            plist.append(i)
        assert len(plist) == 1000
        assert plist[999].to_int() == 999

    def test_nested_lists_deep(self):
        """Test deeply nested lists."""
        plist = PlutusList()
        plist.append(1)
        for _ in range(5):
            outer = PlutusList()
            outer.add(PlutusData.from_list(plist))
            plist = outer
        assert len(plist) == 1
        assert plist[0].kind == PlutusDataKind.LIST

    def test_list_with_empty_strings(self):
        """Test list containing empty strings."""
        plist = PlutusList()
        plist.append("")
        plist.append("hello")
        plist.append("")
        assert len(plist) == 3
        assert plist[0].to_string() == ""
        assert plist[1].to_string() == "hello"

    def test_list_with_empty_bytes(self):
        """Test list containing empty bytes."""
        plist = PlutusList()
        plist.append(b"")
        plist.append(b"test")
        assert len(plist) == 2
        assert plist[0].to_bytes() == b""

    def test_list_with_zero(self):
        """Test list containing zero."""
        plist = PlutusList()
        plist.append(0)
        assert len(plist) == 1
        assert plist[0].to_int() == 0
        assert 0 in plist

    def test_list_with_negative_integers(self):
        """Test list containing negative integers."""
        plist = PlutusList()
        plist.extend([-1, -100, -999999])
        assert len(plist) == 3
        assert plist[0].to_int() == -1
        assert plist[1].to_int() == -100
        assert plist[2].to_int() == -999999

    def test_list_with_large_integers(self):
        """Test list containing large integers (arbitrary precision)."""
        large_num = 2**128 + 1
        plist = PlutusList()
        plist.append(large_num)
        assert len(plist) == 1
        assert plist[0].to_int() == large_num


class TestPlutusListErrorCases:
    """Tests for PlutusList error handling."""

    def test_from_cbor_with_none_reader_raises(self):
        """Test that from_cbor with None reader raises error."""
        with pytest.raises((TypeError, AttributeError)):
            PlutusList.from_cbor(None)

    def test_to_cbor_with_none_writer_raises(self):
        """Test that to_cbor with None writer raises error."""
        plist = PlutusList()
        with pytest.raises((TypeError, AttributeError)):
            plist.to_cbor(None)

    def test_get_with_invalid_index_raises(self):
        """Test that get with out of bounds index raises error."""
        plist = PlutusList()
        with pytest.raises(IndexError):
            plist.get(0)

    def test_add_with_none_raises(self):
        """Test that add with None raises error."""
        plist = PlutusList()
        with pytest.raises((TypeError, AttributeError)):
            plist.add(None)


class TestPlutusListJson:
    """Tests for PlutusList CIP-116 JSON serialization."""

    def test_to_cip116_json_empty_list(self):
        """Test CIP-116 JSON serialization of empty list."""
        plist = PlutusList()
        writer = JsonWriter()
        plist.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"list"' in result
        assert '"contents":[]' in result

    def test_to_cip116_json_with_integer(self):
        """Test CIP-116 JSON serialization with integer."""
        plist = PlutusList()
        plist.append(1)
        writer = JsonWriter()
        plist.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"list"' in result
        assert '"tag":"integer"' in result
        assert '"value":"1"' in result

    def test_to_cip116_json_with_bytes(self):
        """Test CIP-116 JSON serialization with bytes."""
        plist = PlutusList()
        plist.append(b"\xaa")
        writer = JsonWriter()
        plist.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"list"' in result
        assert '"tag":"bytes"' in result
        assert '"value":"aa"' in result

    def test_to_cip116_json_with_mixed_types(self):
        """Test CIP-116 JSON serialization with mixed types."""
        plist = PlutusList()
        plist.append(1)
        plist.append(b"\xaa")
        writer = JsonWriter()
        plist.to_cip116_json(writer)
        result = writer.encode()
        assert '"tag":"list"' in result
        assert '"tag":"integer"' in result
        assert '"tag":"bytes"' in result

    def test_to_cip116_json_with_invalid_writer_raises(self):
        """Test that to_cip116_json with invalid writer raises error."""
        plist = PlutusList()
        with pytest.raises(TypeError):
            plist.to_cip116_json("not a writer")

    def test_to_cip116_json_with_none_writer_raises(self):
        """Test that to_cip116_json with None writer raises error."""
        plist = PlutusList()
        with pytest.raises((TypeError, AttributeError)):
            plist.to_cip116_json(None)


class TestPlutusListCborCache:
    """Tests for PlutusList CBOR cache functionality."""

    def test_clear_cbor_cache(self):
        """Test clearing CBOR cache."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        plist = PlutusList.from_cbor(reader)
        plist.clear_cbor_cache()
        writer = CborWriter()
        plist.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_LIST_CBOR

    def test_cbor_cache_preserves_original_encoding(self):
        """Test that CBOR cache preserves the original encoding."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        plist = PlutusList.from_cbor(reader)
        writer = CborWriter()
        plist.to_cbor(writer)
        assert writer.to_hex() == SIMPLE_LIST_CBOR


class TestPlutusListGetMethod:
    """Tests for PlutusList get method."""

    def test_get_returns_element(self):
        """Test that get returns correct element."""
        plist = PlutusList()
        plist.append(42)
        element = plist.get(0)
        assert element.to_int() == 42

    def test_get_negative_index(self):
        """Test get with negative index."""
        plist = PlutusList()
        plist.extend([1, 2, 3])
        element = plist.get(-1)
        assert element.to_int() == 3

    def test_get_out_of_bounds_raises(self):
        """Test get with out of bounds index raises IndexError."""
        plist = PlutusList()
        with pytest.raises(IndexError):
            plist.get(10)


class TestPlutusListInvalidTypes:
    """Tests for PlutusList with invalid types."""

    def test_append_unsupported_type_raises(self):
        """Test that appending unsupported type raises error."""
        plist = PlutusList()
        with pytest.raises((TypeError, ValueError)):
            plist.append({"dict": "value"})

    def test_extend_with_unsupported_types_raises(self):
        """Test that extending with unsupported types raises error."""
        plist = PlutusList()
        with pytest.raises((TypeError, ValueError)):
            plist.extend([{"dict": "value"}])
