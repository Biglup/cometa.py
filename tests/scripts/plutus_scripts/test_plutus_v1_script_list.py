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
    PlutusV1ScriptList,
    PlutusV1Script,
    CardanoError,
    JsonWriter,
    JsonFormat,
    CborReader,
    CborWriter,
)


CBOR = "844e4d010000332222200512001200114e4d010001332222200512001200114e4d010002332222200512001200114e4d01000333222220051200120011"
PLUTUS_V1_SCRIPT1_CBOR = "4e4d01000033222220051200120011"
PLUTUS_V1_SCRIPT2_CBOR = "4e4d01000133222220051200120011"
PLUTUS_V1_SCRIPT3_CBOR = "4e4d01000233222220051200120011"
PLUTUS_V1_SCRIPT4_CBOR = "4e4d01000333222220051200120011"
EMPTY_LIST_CBOR = "80"


def new_default_plutus_v1_script(cbor_hex: str) -> PlutusV1Script:
    """Creates a new PlutusV1Script from CBOR hex string."""
    reader = CborReader.from_hex(cbor_hex)
    return PlutusV1Script.from_cbor(reader)


class TestPlutusV1ScriptListNew:
    """Tests for PlutusV1ScriptList.__init__() constructor."""

    def test_can_create_empty_list(self):
        """Test that an empty PlutusV1ScriptList can be created."""
        script_list = PlutusV1ScriptList()
        assert script_list is not None
        assert len(script_list) == 0

    def test_new_list_has_zero_length(self):
        """Test that a new list has zero length."""
        script_list = PlutusV1ScriptList()
        assert len(script_list) == 0

    def test_new_list_is_empty(self):
        """Test that a new list evaluates to False (empty)."""
        script_list = PlutusV1ScriptList()
        assert not script_list

    def test_can_create_multiple_independent_lists(self):
        """Test that multiple independent lists can be created."""
        list1 = PlutusV1ScriptList()
        list2 = PlutusV1ScriptList()
        assert list1 is not None
        assert list2 is not None
        assert list1 is not list2


class TestPlutusV1ScriptListFromList:
    """Tests for PlutusV1ScriptList.from_list() factory method."""

    def test_can_create_from_empty_python_list(self):
        """Test that PlutusV1ScriptList can be created from empty list."""
        script_list = PlutusV1ScriptList.from_list([])
        assert script_list is not None
        assert len(script_list) == 0

    def test_can_create_from_single_script(self):
        """Test that PlutusV1ScriptList can be created from single script."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList.from_list([script])
        assert len(script_list) == 1

    def test_can_create_from_multiple_scripts(self):
        """Test that PlutusV1ScriptList can be created from multiple scripts."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)
        assert len(script_list) == 3

    def test_from_list_preserves_order(self):
        """Test that from_list preserves the order of scripts."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)
        assert script_list[0] == scripts[0]
        assert script_list[1] == scripts[1]


class TestPlutusV1ScriptListFromCbor:
    """Tests for PlutusV1ScriptList.from_cbor() factory method."""

    def test_can_deserialize_empty_list(self):
        """Test that empty list can be deserialized from CBOR."""
        script_list = PlutusV1ScriptList.from_cbor(EMPTY_LIST_CBOR)
        assert script_list is not None
        assert len(script_list) == 0

    def test_can_deserialize_list_with_four_scripts(self):
        """Test that list with four scripts can be deserialized."""
        script_list = PlutusV1ScriptList.from_cbor(CBOR)
        assert len(script_list) == 4

    def test_deserialized_scripts_match_expected_cbor(self):
        """Test that deserialized scripts match expected CBOR."""
        script_list = PlutusV1ScriptList.from_cbor(CBOR)

        expected_cbors = [
            PLUTUS_V1_SCRIPT1_CBOR,
            PLUTUS_V1_SCRIPT2_CBOR,
            PLUTUS_V1_SCRIPT3_CBOR,
            PLUTUS_V1_SCRIPT4_CBOR,
        ]

        for i, expected_cbor in enumerate(expected_cbors):
            writer = CborWriter()
            script_list[i].to_cbor(writer)
            assert writer.to_hex() == expected_cbor

    def test_raises_error_if_cbor_is_none(self):
        """Test that deserializing with None CBOR raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1ScriptList.from_cbor(None)

    def test_raises_error_if_not_an_array(self):
        """Test that deserializing non-array CBOR raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1ScriptList.from_cbor("01")

    def test_raises_error_if_invalid_elements(self):
        """Test that deserializing invalid elements raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1ScriptList.from_cbor("9ffeff")

    def test_raises_error_if_invalid_cbor(self):
        """Test that deserializing invalid CBOR raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1ScriptList.from_cbor("ff")


class TestPlutusV1ScriptListToCbor:
    """Tests for PlutusV1ScriptList.to_cbor() method."""

    def test_can_serialize_empty_list(self):
        """Test that empty list can be serialized to CBOR."""
        script_list = PlutusV1ScriptList()
        cbor_hex = script_list.to_cbor()
        assert cbor_hex == EMPTY_LIST_CBOR

    def test_can_serialize_list_with_four_scripts(self):
        """Test that list with four scripts can be serialized."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT4_CBOR))

        cbor_hex = script_list.to_cbor()
        assert cbor_hex == CBOR

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        script_list = PlutusV1ScriptList.from_cbor(CBOR)
        cbor_hex = script_list.to_cbor()
        assert cbor_hex == CBOR


class TestPlutusV1ScriptListAdd:
    """Tests for PlutusV1ScriptList.add() method."""

    def test_can_add_script_to_empty_list(self):
        """Test that script can be added to empty list."""
        script_list = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list.add(script)
        assert len(script_list) == 1

    def test_can_add_multiple_scripts(self):
        """Test that multiple scripts can be added."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR))
        assert len(script_list) == 3

    def test_add_increases_length(self):
        """Test that add increases the length of the list."""
        script_list = PlutusV1ScriptList()
        assert len(script_list) == 0
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert len(script_list) == 1
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        assert len(script_list) == 2

    def test_raises_error_if_script_is_none(self):
        """Test that adding None script raises an error."""
        script_list = PlutusV1ScriptList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            script_list.add(None)


class TestPlutusV1ScriptListAppend:
    """Tests for PlutusV1ScriptList.append() method."""

    def test_can_append_script(self):
        """Test that script can be appended to list."""
        script_list = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list.append(script)
        assert len(script_list) == 1

    def test_append_is_alias_for_add(self):
        """Test that append behaves the same as add."""
        list1 = PlutusV1ScriptList()
        list2 = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)

        list1.add(script)
        list2.append(script)

        assert len(list1) == len(list2)


class TestPlutusV1ScriptListGet:
    """Tests for PlutusV1ScriptList.get() method."""

    def test_can_get_script_at_index(self):
        """Test that script can be retrieved by index."""
        script_list = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list.add(script)

        retrieved = script_list.get(0)
        assert retrieved == script

    def test_can_get_all_scripts_by_index(self):
        """Test that all scripts can be retrieved by index."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        for i, script in enumerate(scripts):
            assert script_list.get(i) == script

    def test_raises_error_if_index_out_of_bounds(self):
        """Test that getting with out-of-bounds index raises an error."""
        script_list = PlutusV1ScriptList()
        with pytest.raises(IndexError):
            script_list.get(0)

    def test_raises_error_if_negative_index_out_of_bounds(self):
        """Test that getting with negative out-of-bounds index raises an error."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        with pytest.raises(IndexError):
            script_list.get(-2)


class TestPlutusV1ScriptListLen:
    """Tests for PlutusV1ScriptList.__len__() method."""

    def test_empty_list_has_zero_length(self):
        """Test that empty list has zero length."""
        script_list = PlutusV1ScriptList()
        assert len(script_list) == 0

    def test_length_reflects_number_of_scripts(self):
        """Test that length reflects the number of scripts."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert len(script_list) == 1
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        assert len(script_list) == 2

    def test_length_after_from_cbor(self):
        """Test that length is correct after from_cbor."""
        script_list = PlutusV1ScriptList.from_cbor(CBOR)
        assert len(script_list) == 4


class TestPlutusV1ScriptListIter:
    """Tests for PlutusV1ScriptList.__iter__() method."""

    def test_can_iterate_over_empty_list(self):
        """Test that iteration over empty list works."""
        script_list = PlutusV1ScriptList()
        items = list(script_list)
        assert len(items) == 0

    def test_can_iterate_over_list_with_scripts(self):
        """Test that iteration over list with scripts works."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        items = list(script_list)
        assert len(items) == 3
        for i, item in enumerate(items):
            assert item == scripts[i]

    def test_iteration_preserves_order(self):
        """Test that iteration preserves the order of scripts."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        for i, script in enumerate(script_list):
            assert script == scripts[i]

    def test_can_use_in_for_loop(self):
        """Test that list can be used in for loop."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))

        count = 0
        for script in script_list:
            assert script is not None
            count += 1
        assert count == 2


class TestPlutusV1ScriptListGetItem:
    """Tests for PlutusV1ScriptList.__getitem__() method."""

    def test_can_access_by_positive_index(self):
        """Test that scripts can be accessed by positive index."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        assert script_list[0] == scripts[0]
        assert script_list[1] == scripts[1]

    def test_can_access_by_negative_index(self):
        """Test that scripts can be accessed by negative index."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        assert script_list[-1] == scripts[1]
        assert script_list[-2] == scripts[0]

    def test_raises_error_if_index_out_of_bounds(self):
        """Test that accessing out-of-bounds index raises an error."""
        script_list = PlutusV1ScriptList()
        with pytest.raises(IndexError):
            _ = script_list[0]

    def test_negative_index_out_of_bounds_raises_error(self):
        """Test that negative out-of-bounds index raises an error."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        with pytest.raises(IndexError):
            _ = script_list[-2]


class TestPlutusV1ScriptListBool:
    """Tests for PlutusV1ScriptList.__bool__() method."""

    def test_empty_list_is_falsy(self):
        """Test that empty list evaluates to False."""
        script_list = PlutusV1ScriptList()
        assert not script_list

    def test_non_empty_list_is_truthy(self):
        """Test that non-empty list evaluates to True."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert script_list

    def test_can_use_in_if_statement(self):
        """Test that list can be used in if statement."""
        empty_list = PlutusV1ScriptList()
        if empty_list:
            pytest.fail("Empty list should be falsy")

        non_empty_list = PlutusV1ScriptList()
        non_empty_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        if not non_empty_list:
            pytest.fail("Non-empty list should be truthy")


class TestPlutusV1ScriptListIndex:
    """Tests for PlutusV1ScriptList.index() method."""

    def test_can_find_index_of_script(self):
        """Test that index of script can be found."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)

        assert script_list.index(script) == 0

    def test_index_returns_first_occurrence(self):
        """Test that index returns the first occurrence."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        script_list.add(script)

        assert script_list.index(script) == 0

    def test_index_with_start_parameter(self):
        """Test that index respects start parameter."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        script_list.add(script)

        assert script_list.index(script, 1) == 2

    def test_index_with_stop_parameter(self):
        """Test that index respects stop parameter."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        with pytest.raises(ValueError):
            script_list.index(scripts[2], 0, 2)

    def test_raises_value_error_if_not_found(self):
        """Test that ValueError is raised if script is not found."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        script_to_find = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR)

        with pytest.raises(ValueError):
            script_list.index(script_to_find)


class TestPlutusV1ScriptListCount:
    """Tests for PlutusV1ScriptList.count() method."""

    def test_count_returns_zero_for_empty_list(self):
        """Test that count returns zero for empty list."""
        script_list = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        assert script_list.count(script) == 0

    def test_count_returns_zero_if_not_found(self):
        """Test that count returns zero if script is not in list."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        script_to_count = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR)
        assert script_list.count(script_to_count) == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns one for single occurrence."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        assert script_list.count(script) == 1

    def test_count_returns_correct_number_for_duplicates(self):
        """Test that count returns correct number for duplicates."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))
        script_list.add(script)
        script_list.add(script)
        assert script_list.count(script) == 3


class TestPlutusV1ScriptListReversed:
    """Tests for PlutusV1ScriptList.__reversed__() method."""

    def test_can_reverse_empty_list(self):
        """Test that empty list can be reversed."""
        script_list = PlutusV1ScriptList()
        items = list(reversed(script_list))
        assert len(items) == 0

    def test_can_reverse_list_with_scripts(self):
        """Test that list with scripts can be reversed."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT3_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        reversed_items = list(reversed(script_list))
        assert len(reversed_items) == 3
        assert reversed_items[0] == scripts[2]
        assert reversed_items[1] == scripts[1]
        assert reversed_items[2] == scripts[0]

    def test_reversed_preserves_original_list(self):
        """Test that reversing doesn't modify the original list."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)

        list(reversed(script_list))

        assert script_list[0] == scripts[0]
        assert script_list[1] == scripts[1]


class TestPlutusV1ScriptListRepr:
    """Tests for PlutusV1ScriptList.__repr__() method."""

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains the class name."""
        script_list = PlutusV1ScriptList()
        repr_str = repr(script_list)
        assert "PlutusV1ScriptList" in repr_str

    def test_repr_contains_length(self):
        """Test that __repr__ contains the length."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        repr_str = repr(script_list)
        assert "len=1" in repr_str

    def test_repr_updates_with_length(self):
        """Test that __repr__ updates as length changes."""
        script_list = PlutusV1ScriptList()
        assert "len=0" in repr(script_list)

        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert "len=1" in repr(script_list)


class TestPlutusV1ScriptListContextManager:
    """Tests for PlutusV1ScriptList context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that PlutusV1ScriptList can be used as a context manager."""
        with PlutusV1ScriptList() as script_list:
            assert script_list is not None
            assert len(script_list) == 0

    def test_list_is_usable_within_context(self):
        """Test that list is usable within context manager."""
        with PlutusV1ScriptList() as script_list:
            script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
            script_list.add(script)
            assert len(script_list) == 1

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        script_list = PlutusV1ScriptList()
        with script_list:
            pass


class TestPlutusV1ScriptListEdgeCases:
    """Tests for edge cases and various scenarios."""

    def test_can_add_many_scripts(self):
        """Test that many scripts can be added to the list."""
        script_list = PlutusV1ScriptList()
        for _ in range(100):
            script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert len(script_list) == 100

    def test_multiple_lists_are_independent(self):
        """Test that multiple lists maintain independent data."""
        list1 = PlutusV1ScriptList()
        list2 = PlutusV1ScriptList()

        list1.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert len(list1) == 1
        assert len(list2) == 0

    def test_can_create_list_from_existing_list(self):
        """Test that list can be created from existing list's scripts."""
        list1 = PlutusV1ScriptList()
        list1.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        list1.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))

        list2 = PlutusV1ScriptList.from_list(list(list1))
        assert len(list2) == 2

    def test_cbor_roundtrip_preserves_all_scripts(self):
        """Test that CBOR roundtrip preserves all scripts."""
        original = PlutusV1ScriptList()
        original.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        original.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR))

        cbor_hex = original.to_cbor()
        deserialized = PlutusV1ScriptList.from_cbor(cbor_hex)

        assert len(deserialized) == len(original)
        for i in range(len(original)):
            assert original[i] == deserialized[i]


class TestPlutusV1ScriptListJsonSerialization:
    """Tests for PlutusV1ScriptList CIP-116 JSON serialization."""

    def test_empty_list_serializes_to_empty_json_array(self):
        """Test that empty list serializes to empty JSON array."""
        script_list = PlutusV1ScriptList()
        writer = JsonWriter(JsonFormat.COMPACT)
        writer.write_start_object()
        writer.write_property_name("scripts")
        script_list.to_cip116_json(writer)
        writer.write_end_object()
        json_str = writer.encode()
        assert '"scripts":[]' in json_str

    def test_single_script_serializes_correctly(self):
        """Test that single script serializes correctly to JSON."""
        script_list = PlutusV1ScriptList()
        script_bytes = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        script = PlutusV1Script.new(script_bytes)
        script_list.add(script)

        writer = JsonWriter(JsonFormat.COMPACT)
        script_list.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"language":"plutus_v1"' in json_str
        assert '"bytes":"deadbeef"' in json_str

    def test_multiple_scripts_serialize_correctly(self):
        """Test that multiple scripts serialize correctly to JSON."""
        script_list = PlutusV1ScriptList()
        script1 = PlutusV1Script.new(bytes([0x00, 0x01]))
        script2 = PlutusV1Script.new(bytes([0xAA, 0xBB, 0xCC]))
        script_list.add(script1)
        script_list.add(script2)

        writer = JsonWriter(JsonFormat.COMPACT)
        script_list.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"bytes":"0001"' in json_str
        assert '"bytes":"aabbcc"' in json_str

    def test_raises_error_if_writer_is_none(self):
        """Test that serializing with None writer raises an error."""
        script_list = PlutusV1ScriptList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            script_list.to_cip116_json(None)


class TestPlutusV1ScriptListSequenceCompliance:
    """Tests for Sequence protocol compliance."""

    def test_supports_len(self):
        """Test that list supports len()."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        assert len(script_list) == 1

    def test_supports_iteration(self):
        """Test that list supports iteration."""
        script_list = PlutusV1ScriptList()
        script_list.add(new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR))
        for script in script_list:
            assert script is not None

    def test_supports_indexing(self):
        """Test that list supports indexing."""
        script_list = PlutusV1ScriptList()
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list.add(script)
        assert script_list[0] == script

    def test_supports_contains(self):
        """Test that list supports 'in' operator."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        assert script in script_list

    def test_supports_reversed(self):
        """Test that list supports reversed()."""
        scripts = [
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR),
            new_default_plutus_v1_script(PLUTUS_V1_SCRIPT2_CBOR),
        ]
        script_list = PlutusV1ScriptList.from_list(scripts)
        reversed_items = list(reversed(script_list))
        assert reversed_items[0] == scripts[1]
        assert reversed_items[1] == scripts[0]

    def test_supports_index(self):
        """Test that list supports index() method."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        assert script_list.index(script) == 0

    def test_supports_count(self):
        """Test that list supports count() method."""
        script = new_default_plutus_v1_script(PLUTUS_V1_SCRIPT1_CBOR)
        script_list = PlutusV1ScriptList()
        script_list.add(script)
        script_list.add(script)
        assert script_list.count(script) == 2
