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
    MetadatumList,
    Metadatum,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


METADATUM_LIST_CBOR = "9f01029f0102030405ff9f0102030405ff05ff"
SIMPLE_LIST_CBOR = "9f0102030405ff"
EMPTY_LIST_CBOR = "80"
TWO_ELEMENT_LIST_CBOR = "9f0102ff"


class TestMetadatumListNew:
    """Tests for MetadatumList constructor."""

    def test_can_create_empty_list(self):
        """Test that an empty MetadatumList can be created."""
        meta_list = MetadatumList()
        assert meta_list is not None
        assert len(meta_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        meta_list = MetadatumList()
        assert not meta_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        meta_list = MetadatumList()
        meta_list.add(1)
        assert meta_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        meta_list = MetadatumList()
        meta_list.add(1)
        meta_list.add(2)
        assert "len=2" in repr(meta_list)

    def test_context_manager(self):
        """Test that MetadatumList works as a context manager."""
        with MetadatumList() as meta_list:
            meta_list.add(42)
            assert len(meta_list) == 1


class TestMetadatumListFromList:
    """Tests for MetadatumList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that MetadatumList can be created from an empty list."""
        meta_list = MetadatumList.from_list([])
        assert len(meta_list) == 0

    def test_can_create_from_int_list(self):
        """Test that MetadatumList can be created from a list of integers."""
        meta_list = MetadatumList.from_list([1, 2, 3, 4, 5])
        assert len(meta_list) == 5

    def test_can_create_from_string_list(self):
        """Test that MetadatumList can be created from a list of strings."""
        meta_list = MetadatumList.from_list(["hello", "world"])
        assert len(meta_list) == 2

    def test_can_create_from_bytes_list(self):
        """Test that MetadatumList can be created from a list of bytes."""
        meta_list = MetadatumList.from_list([b"\xde\xad", b"\xbe\xef"])
        assert len(meta_list) == 2

    def test_can_create_from_mixed_list(self):
        """Test that MetadatumList can be created from mixed types."""
        meta_list = MetadatumList.from_list([1, "hello", b"\xde\xad"])
        assert len(meta_list) == 3

    def test_can_create_from_metadatum_list(self):
        """Test that MetadatumList can be created from Metadatum objects."""
        meta1 = Metadatum.from_int(1)
        meta2 = Metadatum.from_string("test")
        meta_list = MetadatumList.from_list([meta1, meta2])
        assert len(meta_list) == 2


class TestMetadatumListFromCbor:
    """Tests for MetadatumList.from_cbor() method."""

    def test_can_deserialize_empty_list(self):
        """Test that an empty list can be deserialized from CBOR."""
        reader = CborReader.from_hex(EMPTY_LIST_CBOR)
        meta_list = MetadatumList.from_cbor(reader)
        assert len(meta_list) == 0

    def test_can_deserialize_simple_list(self):
        """Test that a simple list can be deserialized from CBOR."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        meta_list = MetadatumList.from_cbor(reader)
        assert len(meta_list) == 5

    def test_can_deserialize_nested_list(self):
        """Test that a nested list can be deserialized from CBOR."""
        reader = CborReader.from_hex(METADATUM_LIST_CBOR)
        meta_list = MetadatumList.from_cbor(reader)
        assert len(meta_list) == 5

    def test_cbor_roundtrip_empty_list(self):
        """Test CBOR serialization/deserialization roundtrip for empty list."""
        original = MetadatumList()
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        restored = MetadatumList.from_cbor(reader)
        assert restored == original

    def test_cbor_roundtrip_simple_list(self):
        """Test CBOR serialization/deserialization roundtrip for simple list."""
        original = MetadatumList.from_list([1, 2])
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        restored = MetadatumList.from_cbor(reader)
        assert restored == original

    def test_raises_error_for_invalid_cbor(self):
        """Test that invalid CBOR raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MetadatumList.from_cbor(reader)

    def test_raises_error_for_invalid_metadatum_elements(self):
        """Test that invalid metadatum elements raise an error."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            MetadatumList.from_cbor(reader)

    def test_raises_error_for_truncated_cbor(self):
        """Test that truncated CBOR raises an error."""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            MetadatumList.from_cbor(reader)


class TestMetadatumListAdd:
    """Tests for MetadatumList.add() method."""

    def test_can_add_int(self):
        """Test that an integer can be added to the list."""
        meta_list = MetadatumList()
        meta_list.add(42)
        assert len(meta_list) == 1

    def test_can_add_string(self):
        """Test that a string can be added to the list."""
        meta_list = MetadatumList()
        meta_list.add("hello")
        assert len(meta_list) == 1

    def test_can_add_bytes(self):
        """Test that bytes can be added to the list."""
        meta_list = MetadatumList()
        meta_list.add(b"\xde\xad")
        assert len(meta_list) == 1

    def test_can_add_bytearray(self):
        """Test that bytearray can be added to the list."""
        meta_list = MetadatumList()
        meta_list.add(bytearray(b"\xde\xad"))
        assert len(meta_list) == 1

    def test_can_add_metadatum(self):
        """Test that a Metadatum can be added to the list."""
        meta_list = MetadatumList()
        meta = Metadatum.from_int(42)
        meta_list.add(meta)
        assert len(meta_list) == 1

    def test_can_add_multiple_elements(self):
        """Test that multiple elements can be added."""
        meta_list = MetadatumList()
        for i in range(5):
            meta_list.add(i + 1)
        assert len(meta_list) == 5

    def test_raises_error_for_invalid_type(self):
        """Test that adding invalid type raises TypeError."""
        meta_list = MetadatumList()
        with pytest.raises(TypeError):
            meta_list.add([1, 2, 3])

    def test_raises_error_for_none(self):
        """Test that adding None raises TypeError."""
        meta_list = MetadatumList()
        with pytest.raises(TypeError):
            meta_list.add(None)


class TestMetadatumListAppend:
    """Tests for MetadatumList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        meta_list = MetadatumList()
        meta_list.append(42)
        assert len(meta_list) == 1

    def test_can_append_multiple(self):
        """Test that multiple elements can be appended."""
        meta_list = MetadatumList()
        meta_list.append(1)
        meta_list.append("hello")
        meta_list.append(b"\xde\xad")
        assert len(meta_list) == 3


class TestMetadatumListGet:
    """Tests for MetadatumList.get() method."""

    def test_can_get_element_by_index(self):
        """Test that an element can be retrieved by index."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        element = meta_list.get(1)
        assert element is not None

    def test_can_get_first_element(self):
        """Test that the first element can be retrieved."""
        meta_list = MetadatumList.from_list([42, 43, 44])
        element = meta_list.get(0)
        assert element is not None

    def test_can_get_last_element(self):
        """Test that the last element can be retrieved."""
        meta_list = MetadatumList.from_list([42, 43, 44])
        element = meta_list.get(2)
        assert element is not None

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(IndexError):
            meta_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(IndexError):
            meta_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError."""
        meta_list = MetadatumList()
        with pytest.raises(IndexError):
            meta_list.get(0)


class TestMetadatumListGetItem:
    """Tests for MetadatumList.__getitem__() method (bracket notation)."""

    def test_can_get_by_positive_index(self):
        """Test that elements can be accessed with positive indices."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        element = meta_list[0]
        assert element is not None

    def test_can_get_by_negative_index(self):
        """Test that elements can be accessed with negative indices."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        element = meta_list[-1]
        assert element is not None

    def test_negative_index_gets_correct_element(self):
        """Test that negative indices return correct elements."""
        meta_list = MetadatumList.from_list([10, 20, 30])
        last = meta_list[-1]
        second_last = meta_list[-2]
        assert last is not None
        assert second_last is not None

    def test_raises_index_error_for_out_of_bounds_positive(self):
        """Test that positive out of bounds index raises IndexError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(IndexError):
            _ = meta_list[10]

    def test_raises_index_error_for_out_of_bounds_negative(self):
        """Test that negative out of bounds index raises IndexError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(IndexError):
            _ = meta_list[-10]


class TestMetadatumListLen:
    """Tests for MetadatumList.__len__() method."""

    def test_len_of_empty_list(self):
        """Test that length of empty list is 0."""
        meta_list = MetadatumList()
        assert len(meta_list) == 0

    def test_len_after_adding_elements(self):
        """Test that length increases after adding elements."""
        meta_list = MetadatumList()
        meta_list.add(1)
        meta_list.add(2)
        assert len(meta_list) == 2

    def test_len_of_list_from_cbor(self):
        """Test length of list deserialized from CBOR."""
        reader = CborReader.from_hex(SIMPLE_LIST_CBOR)
        meta_list = MetadatumList.from_cbor(reader)
        assert len(meta_list) == 5


class TestMetadatumListIter:
    """Tests for MetadatumList.__iter__() method."""

    def test_can_iterate_empty_list(self):
        """Test that empty list can be iterated."""
        meta_list = MetadatumList()
        count = 0
        for _ in meta_list:
            count += 1
        assert count == 0

    def test_can_iterate_list(self):
        """Test that list can be iterated."""
        meta_list = MetadatumList.from_list([1, 2, 3, 4, 5])
        count = 0
        for _ in meta_list:
            count += 1
        assert count == 5

    def test_iterator_returns_metadatum_objects(self):
        """Test that iterator returns Metadatum objects."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        for element in meta_list:
            assert isinstance(element, Metadatum)

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        meta_list = MetadatumList.from_list([1, 2, 3, 4, 5])
        elements = [elem for elem in meta_list]
        assert len(elements) == 5


class TestMetadatumListReversed:
    """Tests for MetadatumList.__reversed__() method."""

    def test_can_reverse_list(self):
        """Test that list can be reversed."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        reversed_list = list(reversed(meta_list))
        assert len(reversed_list) == 3

    def test_reversed_order_is_correct(self):
        """Test that reversed order is correct."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        reversed_list = list(reversed(meta_list))
        assert len(reversed_list) == 3

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        meta_list = MetadatumList()
        reversed_list = list(reversed(meta_list))
        assert len(reversed_list) == 0


class TestMetadatumListContains:
    """Tests for MetadatumList.__contains__() method."""

    def test_contains_int(self):
        """Test that int membership check works."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        assert 1 in meta_list

    def test_contains_string(self):
        """Test that string membership check works."""
        meta_list = MetadatumList.from_list(["hello", "world"])
        assert "hello" in meta_list

    def test_contains_bytes(self):
        """Test that bytes membership check works."""
        meta_list = MetadatumList.from_list([b"\xde\xad", b"\xbe\xef"])
        assert b"\xde\xad" in meta_list

    def test_contains_metadatum(self):
        """Test that Metadatum membership check works."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        assert 42 in meta_list

    def test_not_contains(self):
        """Test that non-existent element returns False."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        assert 99 not in meta_list

    def test_contains_on_empty_list(self):
        """Test that contains on empty list returns False."""
        meta_list = MetadatumList()
        assert 1 not in meta_list


class TestMetadatumListIndex:
    """Tests for MetadatumList.index() method."""

    def test_can_find_index_of_element(self):
        """Test that index of element can be found."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(3))
        index = meta_list.index(meta)
        assert index == 1

    def test_index_returns_first_occurrence(self):
        """Test that index returns first occurrence."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(meta)
        index = meta_list.index(meta)
        assert index == 0

    def test_index_with_start_parameter(self):
        """Test that index works with start parameter."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(meta)
        index = meta_list.index(meta, 1)
        assert index == 2

    def test_index_with_start_and_stop(self):
        """Test that index works with start and stop parameters."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(meta)
        index = meta_list.index(meta, 0, 2)
        assert index == 0

    def test_index_raises_value_error_if_not_found(self):
        """Test that index raises ValueError if element not found."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        with pytest.raises(ValueError):
            meta_list.index(meta)

    def test_index_raises_value_error_outside_range(self):
        """Test that index raises ValueError if element outside range."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(2))
        with pytest.raises(ValueError):
            meta_list.index(meta, 1)


class TestMetadatumListCount:
    """Tests for MetadatumList.count() method."""

    def test_count_returns_zero_for_missing_element(self):
        """Test that count returns 0 for missing element."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        count = meta_list.count(meta)
        assert count == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        count = meta_list.count(meta)
        assert count == 1

    def test_count_returns_correct_for_multiple_occurrences(self):
        """Test that count returns correct count for multiple occurrences."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        meta_list.add(meta)
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(meta)
        meta_list.add(meta)
        count = meta_list.count(meta)
        assert count == 3

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        meta = Metadatum.from_int(42)
        meta_list = MetadatumList()
        count = meta_list.count(meta)
        assert count == 0


class TestMetadatumListEquals:
    """Tests for MetadatumList.__eq__() method."""

    def test_empty_lists_are_equal(self):
        """Test that two empty lists are equal."""
        list1 = MetadatumList()
        list2 = MetadatumList()
        assert list1 == list2

    def test_lists_with_same_elements_are_equal(self):
        """Test that lists with same elements are equal."""
        list1 = MetadatumList.from_list([1, 2, 3])
        list2 = MetadatumList.from_list([1, 2, 3])
        assert list1 == list2

    def test_lists_with_different_elements_are_not_equal(self):
        """Test that lists with different elements are not equal."""
        list1 = MetadatumList.from_list([1, 2, 3])
        list2 = MetadatumList.from_list([1, 2, 4])
        assert list1 != list2

    def test_lists_with_different_lengths_are_not_equal(self):
        """Test that lists with different lengths are not equal."""
        list1 = MetadatumList.from_list([1, 2, 3])
        list2 = MetadatumList.from_list([1, 2])
        assert list1 != list2

    def test_list_not_equal_to_other_types(self):
        """Test that list is not equal to other types."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        assert meta_list != [1, 2, 3]
        assert meta_list != "list"
        assert meta_list != 42
        assert meta_list != None


class TestMetadatumListToCbor:
    """Tests for MetadatumList.to_cbor() method."""

    def test_can_serialize_empty_list(self):
        """Test that empty list can be serialized to CBOR."""
        meta_list = MetadatumList()
        writer = CborWriter()
        meta_list.to_cbor(writer)
        cbor_bytes = writer.encode()
        cbor_hex = cbor_bytes.hex()
        assert cbor_hex == EMPTY_LIST_CBOR

    def test_can_serialize_simple_list(self):
        """Test that simple list can be serialized to CBOR."""
        meta_list = MetadatumList()
        for i in range(5):
            meta_list.add(i + 1)
        writer = CborWriter()
        meta_list.to_cbor(writer)
        cbor_bytes = writer.encode()
        cbor_hex = cbor_bytes.hex()
        assert cbor_hex == SIMPLE_LIST_CBOR

    def test_can_serialize_nested_list(self):
        """Test that nested list can be serialized to CBOR."""
        inner_list = MetadatumList()
        for i in range(5):
            inner_list.add(i + 1)
        inner_meta = Metadatum.from_list(inner_list)

        outer_list = MetadatumList()
        outer_list.add(1)
        outer_list.add(2)
        outer_list.add(inner_meta)
        outer_list.add(inner_meta)
        outer_list.add(5)

        writer = CborWriter()
        outer_list.to_cbor(writer)
        cbor_bytes = writer.encode()
        cbor_hex = cbor_bytes.hex()
        assert cbor_hex == METADATUM_LIST_CBOR


class TestMetadatumListToCip116Json:
    """Tests for MetadatumList.to_cip116_json() method."""

    def test_can_serialize_to_cip116_json(self):
        """Test that list can be serialized to CIP-116 JSON."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        writer = JsonWriter()
        meta_list.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert len(json_str) > 0

    def test_can_serialize_empty_list_to_json(self):
        """Test that empty list can be serialized to CIP-116 JSON."""
        meta_list = MetadatumList()
        writer = JsonWriter()
        meta_list.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises TypeError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(TypeError):
            meta_list.to_cip116_json(None)

    def test_raises_error_if_writer_is_invalid_type(self):
        """Test that invalid writer type raises TypeError."""
        meta_list = MetadatumList.from_list([1, 2, 3])
        with pytest.raises(TypeError):
            meta_list.to_cip116_json("not a writer")


class TestMetadatumListEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_large_list(self):
        """Test that large lists can be handled."""
        meta_list = MetadatumList()
        for i in range(1000):
            meta_list.add(i)
        assert len(meta_list) == 1000

    def test_deeply_nested_lists(self):
        """Test that deeply nested lists can be handled."""
        innermost = MetadatumList.from_list([1, 2, 3])
        level2 = MetadatumList()
        level2.add(Metadatum.from_list(innermost))
        level3 = MetadatumList()
        level3.add(Metadatum.from_list(level2))
        assert len(level3) == 1

    def test_list_with_mixed_types(self):
        """Test list with various data types."""
        meta_list = MetadatumList()
        meta_list.add(42)
        meta_list.add("text")
        meta_list.add(b"\xde\xad\xbe\xef")
        meta_list.add(-100)
        assert len(meta_list) == 4

    def test_unicode_strings(self):
        """Test that unicode strings are handled correctly."""
        meta_list = MetadatumList.from_list(["Hello", "世界", "🌍"])
        assert len(meta_list) == 3

    def test_large_integers(self):
        """Test that large integers are handled correctly."""
        meta_list = MetadatumList()
        meta_list.add(9223372036854775807)
        meta_list.add(-9223372036854775808)
        assert len(meta_list) == 2

    def test_empty_strings_and_bytes(self):
        """Test that empty strings and bytes are handled."""
        meta_list = MetadatumList()
        meta_list.add("")
        meta_list.add(b"")
        assert len(meta_list) == 2
