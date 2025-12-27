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
from cometa import MetadatumLabelList, CardanoError


class TestMetadatumLabelListNew:
    """Tests for MetadatumLabelList constructor."""

    def test_can_create_empty_list(self):
        """Test that an empty MetadatumLabelList can be created."""
        label_list = MetadatumLabelList()
        assert label_list is not None
        assert len(label_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        label_list = MetadatumLabelList()
        assert not label_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert label_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        label_list.add(674)
        assert "len=2" in repr(label_list)

    def test_context_manager(self):
        """Test that MetadatumLabelList works as a context manager."""
        with MetadatumLabelList() as label_list:
            label_list.add(721)
            assert len(label_list) == 1

    def test_raises_error_for_null_pointer(self):
        """Test that passing NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            MetadatumLabelList(ffi.NULL)


class TestMetadatumLabelListFromList:
    """Tests for MetadatumLabelList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that MetadatumLabelList can be created from an empty list."""
        label_list = MetadatumLabelList.from_list([])
        assert len(label_list) == 0

    def test_can_create_from_single_label(self):
        """Test that MetadatumLabelList can be created from a single label."""
        label_list = MetadatumLabelList.from_list([721])
        assert len(label_list) == 1

    def test_can_create_from_multiple_labels(self):
        """Test that MetadatumLabelList can be created from multiple labels."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert len(label_list) == 3

    def test_can_create_from_common_nft_labels(self):
        """Test creation with common NFT metadata labels."""
        label_list = MetadatumLabelList.from_list([721, 20])
        assert len(label_list) == 2

    def test_can_create_from_tuple(self):
        """Test that MetadatumLabelList can be created from a tuple."""
        label_list = MetadatumLabelList.from_list((725, 800))
        assert len(label_list) == 2

    def test_can_create_from_generator(self):
        """Test that MetadatumLabelList can be created from a generator."""
        label_list = MetadatumLabelList.from_list(x for x in [100, 200, 300])
        assert len(label_list) == 3


class TestMetadatumLabelListAdd:
    """Tests for MetadatumLabelList.add() method."""

    def test_can_add_label(self):
        """Test that a label can be added to the list."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert len(label_list) == 1

    def test_can_add_multiple_labels(self):
        """Test that multiple labels can be added."""
        label_list = MetadatumLabelList()
        label_list.add(725)
        label_list.add(800)
        assert len(label_list) == 2

    def test_can_add_nft_label(self):
        """Test adding common NFT metadata label (CIP-25)."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert len(label_list) == 1

    def test_can_add_zero_label(self):
        """Test that zero label can be added."""
        label_list = MetadatumLabelList()
        label_list.add(0)
        assert len(label_list) == 1
        assert label_list.get(0) == 0

    def test_can_add_max_uint64_label(self):
        """Test that maximum uint64 value can be added."""
        label_list = MetadatumLabelList()
        max_uint64 = 18446744073709551615
        label_list.add(max_uint64)
        assert len(label_list) == 1
        assert label_list.get(0) == max_uint64

    def test_can_add_duplicate_labels(self):
        """Test that duplicate labels can be added."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        label_list.add(721)
        assert len(label_list) == 2


class TestMetadatumLabelListAppend:
    """Tests for MetadatumLabelList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        label_list = MetadatumLabelList()
        label_list.append(721)
        assert len(label_list) == 1

    def test_can_append_multiple(self):
        """Test that multiple labels can be appended."""
        label_list = MetadatumLabelList()
        label_list.append(721)
        label_list.append(674)
        label_list.append(755)
        assert len(label_list) == 3


class TestMetadatumLabelListGet:
    """Tests for MetadatumLabelList.get() method."""

    def test_can_get_label_by_index(self):
        """Test that a label can be retrieved by index."""
        label_list = MetadatumLabelList.from_list([725, 800])
        label = label_list.get(0)
        assert label == 725

    def test_can_get_first_label(self):
        """Test that the first label can be retrieved."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        label = label_list.get(0)
        assert label == 674

    def test_can_get_last_label(self):
        """Test that the last label can be retrieved."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        label = label_list.get(2)
        assert label == 755

    def test_can_get_middle_label(self):
        """Test that a middle label can be retrieved."""
        label_list = MetadatumLabelList.from_list([725, 800, 999])
        label = label_list.get(1)
        assert label == 800

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(IndexError):
            label_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(IndexError):
            label_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError."""
        label_list = MetadatumLabelList()
        with pytest.raises(IndexError):
            label_list.get(0)


class TestMetadatumLabelListGetItem:
    """Tests for MetadatumLabelList.__getitem__() method (bracket notation)."""

    def test_can_get_by_positive_index(self):
        """Test that labels can be accessed with positive indices."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert label_list[0] == 674
        assert label_list[1] == 721
        assert label_list[2] == 755

    def test_can_get_by_negative_index(self):
        """Test that labels can be accessed with negative indices."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert label_list[-1] == 755
        assert label_list[-2] == 721
        assert label_list[-3] == 674

    def test_negative_index_gets_correct_element(self):
        """Test that negative indices return correct labels."""
        label_list = MetadatumLabelList.from_list([725, 800])
        assert label_list[-1] == 800
        assert label_list[-2] == 725

    def test_raises_index_error_for_out_of_bounds_positive(self):
        """Test that positive out of bounds index raises IndexError."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(IndexError):
            _ = label_list[10]

    def test_raises_index_error_for_out_of_bounds_negative(self):
        """Test that negative out of bounds index raises IndexError."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(IndexError):
            _ = label_list[-10]


class TestMetadatumLabelListLen:
    """Tests for MetadatumLabelList.__len__() method."""

    def test_len_of_empty_list(self):
        """Test that length of empty list is 0."""
        label_list = MetadatumLabelList()
        assert len(label_list) == 0

    def test_len_after_adding_labels(self):
        """Test that length increases after adding labels."""
        label_list = MetadatumLabelList()
        label_list.add(721)
        label_list.add(674)
        assert len(label_list) == 2

    def test_len_of_list_from_list(self):
        """Test length of list created from list."""
        label_list = MetadatumLabelList.from_list([725, 800, 999, 1000, 2000])
        assert len(label_list) == 5


class TestMetadatumLabelListIter:
    """Tests for MetadatumLabelList.__iter__() method."""

    def test_can_iterate_empty_list(self):
        """Test that empty list can be iterated."""
        label_list = MetadatumLabelList()
        count = 0
        for _ in label_list:
            count += 1
        assert count == 0

    def test_can_iterate_list(self):
        """Test that list can be iterated."""
        label_list = MetadatumLabelList.from_list([721, 674, 755, 800, 999])
        count = 0
        for _ in label_list:
            count += 1
        assert count == 5

    def test_iterator_returns_correct_values(self):
        """Test that iterator returns correct label values."""
        labels = [721, 674, 755]
        label_list = MetadatumLabelList.from_list(labels)
        iterated_labels = list(label_list)
        assert iterated_labels == sorted(labels)

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        label_list = MetadatumLabelList.from_list([721, 674, 755, 800, 999])
        labels = [label for label in label_list]
        assert len(labels) == 5

    def test_iterator_returns_ints(self):
        """Test that iterator returns int objects."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        for label in label_list:
            assert isinstance(label, int)


class TestMetadatumLabelListReversed:
    """Tests for MetadatumLabelList.__reversed__() method."""

    def test_can_reverse_list(self):
        """Test that list can be reversed."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        reversed_list = list(reversed(label_list))
        assert len(reversed_list) == 3

    def test_reversed_order_is_correct(self):
        """Test that reversed order is correct."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        reversed_list = list(reversed(label_list))
        assert reversed_list == [755, 721, 674]

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        label_list = MetadatumLabelList()
        reversed_list = list(reversed(label_list))
        assert len(reversed_list) == 0

    def test_reversed_single_element(self):
        """Test that reversing single element list works."""
        label_list = MetadatumLabelList.from_list([721])
        reversed_list = list(reversed(label_list))
        assert reversed_list == [721]


class TestMetadatumLabelListContains:
    """Tests for MetadatumLabelList.__contains__() method."""

    def test_contains_existing_label(self):
        """Test that existing label is found."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert 721 in label_list
        assert 674 in label_list
        assert 755 in label_list

    def test_not_contains_missing_label(self):
        """Test that non-existent label returns False."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert 999 not in label_list

    def test_contains_on_empty_list(self):
        """Test that contains on empty list returns False."""
        label_list = MetadatumLabelList()
        assert 721 not in label_list

    def test_contains_zero(self):
        """Test that zero can be found."""
        label_list = MetadatumLabelList.from_list([0, 721, 674])
        assert 0 in label_list

    def test_contains_max_uint64(self):
        """Test that max uint64 can be found."""
        max_uint64 = 18446744073709551615
        label_list = MetadatumLabelList.from_list([721, max_uint64])
        assert max_uint64 in label_list


class TestMetadatumLabelListIndex:
    """Tests for MetadatumLabelList.index() method."""

    def test_can_find_index_of_label(self):
        """Test that index of label can be found."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        index = label_list.index(674)
        assert index == 0

    def test_index_returns_first_occurrence(self):
        """Test that index returns first occurrence."""
        label_list = MetadatumLabelList.from_list([721, 674, 721])
        index = label_list.index(721)
        assert index == 1

    def test_index_with_start_parameter(self):
        """Test that index works with start parameter."""
        label_list = MetadatumLabelList.from_list([721, 674, 721])
        index = label_list.index(721, 2)
        assert index == 2

    def test_index_with_start_and_stop(self):
        """Test that index works with start and stop parameters."""
        label_list = MetadatumLabelList.from_list([721, 674, 721, 755])
        index = label_list.index(674, 0, 2)
        assert index == 0

    def test_index_raises_value_error_if_not_found(self):
        """Test that index raises ValueError if label not found."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(ValueError):
            label_list.index(999)

    def test_index_raises_value_error_outside_range(self):
        """Test that index raises ValueError if label outside range."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        with pytest.raises(ValueError):
            label_list.index(674, 1)

    def test_index_of_zero(self):
        """Test finding index of zero label."""
        label_list = MetadatumLabelList.from_list([0, 721, 674])
        index = label_list.index(0)
        assert index == 0


class TestMetadatumLabelListCount:
    """Tests for MetadatumLabelList.count() method."""

    def test_count_returns_zero_for_missing_label(self):
        """Test that count returns 0 for missing label."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        count = label_list.count(999)
        assert count == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        count = label_list.count(721)
        assert count == 1

    def test_count_returns_correct_for_multiple_occurrences(self):
        """Test that count returns correct count for multiple occurrences."""
        label_list = MetadatumLabelList.from_list([721, 674, 721, 755, 721])
        count = label_list.count(721)
        assert count == 3

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        label_list = MetadatumLabelList()
        count = label_list.count(721)
        assert count == 0

    def test_count_of_zero(self):
        """Test counting zero labels."""
        label_list = MetadatumLabelList.from_list([0, 721, 0, 674])
        count = label_list.count(0)
        assert count == 2


class TestMetadatumLabelListEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_large_list(self):
        """Test that large lists can be handled."""
        label_list = MetadatumLabelList()
        for i in range(1000):
            label_list.add(i)
        assert len(label_list) == 1000

    def test_all_same_labels(self):
        """Test list with all identical labels."""
        label_list = MetadatumLabelList.from_list([721] * 100)
        assert len(label_list) == 100
        assert label_list.count(721) == 100

    def test_labels_are_sorted(self):
        """Test that labels are automatically sorted."""
        labels = [999, 721, 500, 800, 100]
        label_list = MetadatumLabelList.from_list(labels)
        assert list(label_list) == sorted(labels)

    def test_common_metadata_labels(self):
        """Test with common Cardano metadata labels."""
        common_labels = [
            721,
            20,
            674,
            1967,
            1968,
        ]
        label_list = MetadatumLabelList.from_list(common_labels)
        assert len(label_list) == 5
        for label in common_labels:
            assert label in label_list

    def test_boundary_values(self):
        """Test with boundary uint64 values."""
        label_list = MetadatumLabelList()
        label_list.add(0)
        label_list.add(1)
        label_list.add(18446744073709551614)
        label_list.add(18446744073709551615)
        assert len(label_list) == 4

    def test_large_sequential_labels(self):
        """Test with sequential large labels."""
        start = 18446744073709551600
        labels = list(range(start, start + 10))
        label_list = MetadatumLabelList.from_list(labels)
        assert len(label_list) == 10
        assert list(label_list) == labels


class TestMetadatumLabelListBool:
    """Tests for MetadatumLabelList.__bool__() method."""

    def test_empty_list_is_falsy(self):
        """Test that empty list is falsy."""
        label_list = MetadatumLabelList()
        assert not label_list
        assert bool(label_list) is False

    def test_non_empty_list_is_truthy(self):
        """Test that non-empty list is truthy."""
        label_list = MetadatumLabelList.from_list([721])
        assert label_list
        assert bool(label_list) is True

    def test_list_becomes_truthy_after_add(self):
        """Test that list becomes truthy after adding element."""
        label_list = MetadatumLabelList()
        assert not label_list
        label_list.add(721)
        assert label_list


class TestMetadatumLabelListSequenceProtocol:
    """Tests for Sequence protocol compliance."""

    def test_is_sequence(self):
        """Test that MetadatumLabelList is a Sequence."""
        from collections.abc import Sequence
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert isinstance(label_list, Sequence)

    def test_supports_len(self):
        """Test that len() is supported."""
        label_list = MetadatumLabelList.from_list([721, 674])
        assert len(label_list) == 2

    def test_supports_indexing(self):
        """Test that indexing is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert label_list[0] == 674
        assert label_list[1] == 721

    def test_supports_iteration(self):
        """Test that iteration is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        labels = [label for label in label_list]
        assert labels == [674, 721, 755]

    def test_supports_contains(self):
        """Test that 'in' operator is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert 721 in label_list
        assert 999 not in label_list

    def test_supports_reversed(self):
        """Test that reversed() is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        reversed_labels = list(reversed(label_list))
        assert reversed_labels == [755, 721, 674]

    def test_supports_index_method(self):
        """Test that index() method is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 755])
        assert label_list.index(674) == 0

    def test_supports_count_method(self):
        """Test that count() method is supported."""
        label_list = MetadatumLabelList.from_list([721, 674, 721])
        assert label_list.count(721) == 2
