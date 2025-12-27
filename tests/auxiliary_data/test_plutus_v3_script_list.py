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
    PlutusV3ScriptList,
    PlutusV3Script,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR = "844e4d010000332222200512001200114e4d010001332222200512001200114e4d010002332222200512001200114e4d01000333222220051200120011"
PLUTUS_V3_SCRIPT1_CBOR = "4e4d01000033222220051200120011"
PLUTUS_V3_SCRIPT2_CBOR = "4e4d01000133222220051200120011"
PLUTUS_V3_SCRIPT3_CBOR = "4e4d01000233222220051200120011"
PLUTUS_V3_SCRIPT4_CBOR = "4e4d01000333222220051200120011"
EMPTY_LIST_CBOR = "80"


def create_test_script(cbor_hex: str) -> PlutusV3Script:
    """Helper function to create a PlutusV3Script from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return PlutusV3Script.from_cbor(reader)


class TestPlutusV3ScriptListNew:
    """Tests for PlutusV3ScriptList constructor."""

    def test_can_create_empty_list(self):
        """Test that an empty PlutusV3ScriptList can be created."""
        script_list = PlutusV3ScriptList()
        assert script_list is not None
        assert len(script_list) == 0

    def test_list_is_false_when_empty(self):
        """Test that empty list evaluates to False."""
        script_list = PlutusV3ScriptList()
        assert not script_list

    def test_list_is_true_when_not_empty(self):
        """Test that non-empty list evaluates to True."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)
        assert script_list

    def test_repr_shows_length(self):
        """Test that __repr__ shows the list length."""
        script_list = PlutusV3ScriptList()
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)
        script_list.add(script1)
        script_list.add(script2)
        assert "len=2" in repr(script_list)

    def test_context_manager(self):
        """Test that PlutusV3ScriptList works as a context manager."""
        with PlutusV3ScriptList() as script_list:
            script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
            script_list.add(script)
            assert len(script_list) == 1

    def test_invalid_handle_raises_error(self):
        """Test that creating with NULL pointer raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            PlutusV3ScriptList(ffi.NULL)


class TestPlutusV3ScriptListFromList:
    """Tests for PlutusV3ScriptList.from_list() factory method."""

    def test_can_create_from_empty_list(self):
        """Test that PlutusV3ScriptList can be created from an empty list."""
        script_list = PlutusV3ScriptList.from_list([])
        assert len(script_list) == 0

    def test_can_create_from_single_script(self):
        """Test that PlutusV3ScriptList can be created from a single script."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList.from_list([script])
        assert len(script_list) == 1

    def test_can_create_from_multiple_scripts(self):
        """Test that PlutusV3ScriptList can be created from multiple scripts."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)
        assert len(script_list) == 3

    def test_can_create_from_four_scripts(self):
        """Test that PlutusV3ScriptList can be created from four scripts."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT4_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)
        assert len(script_list) == 4


class TestPlutusV3ScriptListFromCbor:
    """Tests for PlutusV3ScriptList.from_cbor() method."""

    def test_can_deserialize_empty_list(self):
        """Test that an empty list can be deserialized from CBOR."""
        script_list = PlutusV3ScriptList.from_cbor(EMPTY_LIST_CBOR)
        assert len(script_list) == 0

    def test_can_deserialize_script_list(self):
        """Test that a script list can be deserialized from CBOR."""
        script_list = PlutusV3ScriptList.from_cbor(CBOR)
        assert len(script_list) == 4

    def test_deserialized_scripts_match_expected(self):
        """Test that deserialized scripts match expected CBOR."""
        script_list = PlutusV3ScriptList.from_cbor(CBOR)
        expected_cbors = [
            PLUTUS_V3_SCRIPT1_CBOR,
            PLUTUS_V3_SCRIPT2_CBOR,
            PLUTUS_V3_SCRIPT3_CBOR,
            PLUTUS_V3_SCRIPT4_CBOR,
        ]

        for i, expected_cbor in enumerate(expected_cbors):
            script = script_list.get(i)
            writer = CborWriter()
            script.to_cbor(writer)
            actual_cbor = writer.encode().hex()
            assert actual_cbor == expected_cbor

    def test_cbor_roundtrip_empty_list(self):
        """Test CBOR serialization/deserialization roundtrip for empty list."""
        original = PlutusV3ScriptList()
        cbor_hex = original.to_cbor()
        restored = PlutusV3ScriptList.from_cbor(cbor_hex)
        assert len(restored) == len(original)

    def test_cbor_roundtrip_with_scripts(self):
        """Test CBOR serialization/deserialization roundtrip with scripts."""
        original = PlutusV3ScriptList()
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)
        original.add(script1)
        original.add(script2)

        cbor_hex = original.to_cbor()
        restored = PlutusV3ScriptList.from_cbor(cbor_hex)
        assert len(restored) == len(original)

    def test_raises_error_for_invalid_cbor(self):
        """Test that invalid CBOR raises an error."""
        with pytest.raises(CardanoError):
            PlutusV3ScriptList.from_cbor("01")

    def test_raises_error_for_non_array_cbor(self):
        """Test that non-array CBOR raises an error."""
        with pytest.raises(CardanoError):
            PlutusV3ScriptList.from_cbor("ff")

    def test_raises_error_for_invalid_elements(self):
        """Test that invalid script elements raise an error."""
        with pytest.raises(CardanoError):
            PlutusV3ScriptList.from_cbor("9ffeff")


class TestPlutusV3ScriptListToCbor:
    """Tests for PlutusV3ScriptList.to_cbor() method."""

    def test_can_serialize_empty_list(self):
        """Test that empty list can be serialized to CBOR."""
        script_list = PlutusV3ScriptList()
        cbor_hex = script_list.to_cbor()
        assert cbor_hex == EMPTY_LIST_CBOR

    def test_can_serialize_script_list(self):
        """Test that script list can be serialized to CBOR."""
        script_list = PlutusV3ScriptList()
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT4_CBOR),
        ]
        for script in scripts:
            script_list.add(script)

        cbor_hex = script_list.to_cbor()
        assert cbor_hex == CBOR

    def test_serialization_matches_c_implementation(self):
        """Test that serialization matches C implementation."""
        script_list = PlutusV3ScriptList.from_cbor(CBOR)
        cbor_hex = script_list.to_cbor()
        assert cbor_hex == CBOR


class TestPlutusV3ScriptListAdd:
    """Tests for PlutusV3ScriptList.add() method."""

    def test_can_add_script(self):
        """Test that a script can be added to the list."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)
        assert len(script_list) == 1

    def test_can_add_multiple_scripts(self):
        """Test that multiple scripts can be added."""
        script_list = PlutusV3ScriptList()
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        for script in scripts:
            script_list.add(script)
        assert len(script_list) == 3

    def test_length_increases_after_add(self):
        """Test that length increases after each add."""
        script_list = PlutusV3ScriptList()
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)

        script_list.add(script1)
        assert len(script_list) == 1

        script_list.add(script2)
        assert len(script_list) == 2


class TestPlutusV3ScriptListAppend:
    """Tests for PlutusV3ScriptList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.append(script)
        assert len(script_list) == 1

    def test_can_append_multiple_scripts(self):
        """Test that multiple scripts can be appended."""
        script_list = PlutusV3ScriptList()
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)
        script_list.append(script1)
        script_list.append(script2)
        assert len(script_list) == 2


class TestPlutusV3ScriptListGet:
    """Tests for PlutusV3ScriptList.get() method."""

    def test_can_get_script_by_index(self):
        """Test that a script can be retrieved by index."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        script = script_list.get(1)
        assert script is not None

    def test_can_get_first_script(self):
        """Test that the first script can be retrieved."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        script = script_list.get(0)
        assert script is not None

    def test_can_get_last_script(self):
        """Test that the last script can be retrieved."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        script = script_list.get(2)
        assert script is not None

    def test_raises_index_error_for_negative_index(self):
        """Test that negative index raises IndexError."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)

        with pytest.raises(IndexError):
            script_list.get(-1)

    def test_raises_index_error_for_out_of_bounds(self):
        """Test that out of bounds index raises IndexError."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)

        with pytest.raises(IndexError):
            script_list.get(10)

    def test_raises_index_error_for_empty_list(self):
        """Test that accessing empty list raises IndexError."""
        script_list = PlutusV3ScriptList()
        with pytest.raises(IndexError):
            script_list.get(0)


class TestPlutusV3ScriptListGetItem:
    """Tests for PlutusV3ScriptList.__getitem__() method (bracket notation)."""

    def test_can_get_by_positive_index(self):
        """Test that scripts can be accessed with positive indices."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        script = script_list[0]
        assert script is not None

    def test_can_get_by_negative_index(self):
        """Test that scripts can be accessed with negative indices."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        script = script_list[-1]
        assert script is not None

    def test_negative_index_gets_correct_script(self):
        """Test that negative indices return correct scripts."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        last = script_list[-1]
        second_last = script_list[-2]
        assert last is not None
        assert second_last is not None

    def test_raises_index_error_for_out_of_bounds_positive(self):
        """Test that positive out of bounds index raises IndexError."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)

        with pytest.raises(IndexError):
            _ = script_list[10]

    def test_raises_index_error_for_out_of_bounds_negative(self):
        """Test that negative out of bounds index raises IndexError."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list.add(script)

        with pytest.raises(IndexError):
            _ = script_list[-10]


class TestPlutusV3ScriptListLen:
    """Tests for PlutusV3ScriptList.__len__() method."""

    def test_len_of_empty_list(self):
        """Test that length of empty list is 0."""
        script_list = PlutusV3ScriptList()
        assert len(script_list) == 0

    def test_len_after_adding_scripts(self):
        """Test that length increases after adding scripts."""
        script_list = PlutusV3ScriptList()
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)
        script_list.add(script1)
        script_list.add(script2)
        assert len(script_list) == 2

    def test_len_of_list_from_cbor(self):
        """Test length of list deserialized from CBOR."""
        script_list = PlutusV3ScriptList.from_cbor(CBOR)
        assert len(script_list) == 4


class TestPlutusV3ScriptListIter:
    """Tests for PlutusV3ScriptList.__iter__() method."""

    def test_can_iterate_empty_list(self):
        """Test that empty list can be iterated."""
        script_list = PlutusV3ScriptList()
        count = 0
        for _ in script_list:
            count += 1
        assert count == 0

    def test_can_iterate_list(self):
        """Test that list can be iterated."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        count = 0
        for _ in script_list:
            count += 1
        assert count == 3

    def test_iterator_returns_plutus_v3_script_objects(self):
        """Test that iterator returns PlutusV3Script objects."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        for script in script_list:
            assert isinstance(script, PlutusV3Script)

    def test_can_use_list_comprehension(self):
        """Test that list comprehension works."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        elements = [script for script in script_list]
        assert len(elements) == 3


class TestPlutusV3ScriptListReversed:
    """Tests for PlutusV3ScriptList.__reversed__() method."""

    def test_can_reverse_list(self):
        """Test that list can be reversed."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        reversed_list = list(reversed(script_list))
        assert len(reversed_list) == 3

    def test_reversed_order_is_correct(self):
        """Test that reversed order is correct."""
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
        ]
        script_list = PlutusV3ScriptList.from_list(scripts)

        reversed_list = list(reversed(script_list))
        assert len(reversed_list) == 3

    def test_reversed_empty_list(self):
        """Test that reversing empty list works."""
        script_list = PlutusV3ScriptList()
        reversed_list = list(reversed(script_list))
        assert len(reversed_list) == 0


class TestPlutusV3ScriptListIndex:
    """Tests for PlutusV3ScriptList.index() method."""

    def test_can_find_index_of_script(self):
        """Test that index of script can be found."""
        script1 = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script2 = create_test_script(PLUTUS_V3_SCRIPT2_CBOR)
        script3 = create_test_script(PLUTUS_V3_SCRIPT3_CBOR)

        script_list = PlutusV3ScriptList()
        script_list.add(script1)
        script_list.add(script2)
        script_list.add(script3)

        index = script_list.index(script2)
        assert index == 1

    def test_index_returns_first_occurrence(self):
        """Test that index returns first occurrence."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))
        script_list.add(script)

        index = script_list.index(script)
        assert index == 0

    def test_index_with_start_parameter(self):
        """Test that index works with start parameter."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))
        script_list.add(script)

        index = script_list.index(script, 1)
        assert index == 2

    def test_index_with_start_and_stop(self):
        """Test that index works with start and stop parameters."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))
        script_list.add(script)

        index = script_list.index(script, 0, 2)
        assert index == 0

    def test_index_raises_value_error_if_not_found(self):
        """Test that index raises ValueError if script not found."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT3_CBOR))

        with pytest.raises(ValueError):
            script_list.index(script)

    def test_index_raises_value_error_outside_range(self):
        """Test that index raises ValueError if script outside range."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))

        with pytest.raises(ValueError):
            script_list.index(script, 1)


class TestPlutusV3ScriptListCount:
    """Tests for PlutusV3ScriptList.count() method."""

    def test_count_returns_zero_for_missing_script(self):
        """Test that count returns 0 for missing script."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))

        count = script_list.count(script)
        assert count == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)

        count = script_list.count(script)
        assert count == 1

    def test_count_returns_correct_for_multiple_occurrences(self):
        """Test that count returns correct count for multiple occurrences."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()
        script_list.add(script)
        script_list.add(create_test_script(PLUTUS_V3_SCRIPT2_CBOR))
        script_list.add(script)
        script_list.add(script)

        count = script_list.count(script)
        assert count == 3

    def test_count_on_empty_list(self):
        """Test that count on empty list returns 0."""
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)
        script_list = PlutusV3ScriptList()

        count = script_list.count(script)
        assert count == 0


class TestPlutusV3ScriptListEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_large_list(self):
        """Test that large lists can be handled."""
        script_list = PlutusV3ScriptList()
        script = create_test_script(PLUTUS_V3_SCRIPT1_CBOR)

        for _ in range(100):
            script_list.add(script)

        assert len(script_list) == 100

    def test_multiple_adds_and_gets(self):
        """Test multiple add and get operations."""
        script_list = PlutusV3ScriptList()
        scripts = [
            create_test_script(PLUTUS_V3_SCRIPT1_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT2_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT3_CBOR),
            create_test_script(PLUTUS_V3_SCRIPT4_CBOR),
        ]

        for script in scripts:
            script_list.add(script)

        for i in range(len(scripts)):
            retrieved = script_list.get(i)
            assert retrieved is not None
