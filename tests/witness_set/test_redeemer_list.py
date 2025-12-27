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
from cometa.witness_set.redeemer_list import RedeemerList
from cometa.witness_set.redeemer import Redeemer
from cometa.witness_set.redeemer_tag import RedeemerTag
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter
from cometa.json.json_format import JsonFormat
from cometa.errors import CardanoError


CBOR = "a482000082d8799f0102030405ff821821182c82010182d8799f0102030405ff821821182c82030382d8799f0102030405ff821821182c82040482d8799f0102030405ff821821182c"
CBOR2 = "a482000182d8799f0102030405ff821821182c82000082d8799f0102030405ff821821182c82000182d8799f0102030405ff821821182c82000382d8799f0102030405ff821821182c82000482d8799f0102030405ff821821182c"
CBOR_LEGACY = "84840000d8799f0102030405ff821821182c840101d8799f0102030405ff821821182c840303d8799f0102030405ff821821182c840404d8799f0102030405ff821821182c"
REDEEMER1_CBOR = "840000d8799f0102030405ff821821182c"
REDEEMER2_CBOR = "840404d8799f0102030405ff821821182c"
REDEEMER3_CBOR = "840303d8799f0102030405ff821821182c"
REDEEMER4_CBOR = "840101d8799f0102030405ff821821182c"
REDEEMER5_CBOR = "840000d8799f0102030405ff821821182c"
REDEEMER6_CBOR = "840004d8799f0102030405ff821821182c"
REDEEMER7_CBOR = "840003d8799f0102030405ff821821182c"
REDEEMER8_CBOR = "840001d8799f0102030405ff821821182c"


def create_redeemer_from_cbor(cbor_hex: str) -> Redeemer:
    """Helper function to create a redeemer from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    redeemer = Redeemer.from_cbor(reader)
    redeemer.clear_cbor_cache()
    return redeemer


@pytest.fixture
def empty_list():
    """Create an empty RedeemerList."""
    return RedeemerList()


@pytest.fixture
def populated_list():
    """Create a RedeemerList with four redeemers."""
    redeemer_list = RedeemerList()
    redeemers = [REDEEMER1_CBOR, REDEEMER2_CBOR, REDEEMER3_CBOR, REDEEMER4_CBOR]
    for cbor_hex in redeemers:
        redeemer = create_redeemer_from_cbor(cbor_hex)
        redeemer_list.add(redeemer)
    return redeemer_list


class TestRedeemerListInit:
    """Tests for RedeemerList.__init__()."""

    def test_init_creates_empty_list(self):
        """Test that __init__() creates an empty list."""
        redeemer_list = RedeemerList()
        assert redeemer_list is not None
        assert len(redeemer_list) == 0

    def test_init_with_null_ptr_raises_error(self):
        """Test that __init__() with NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            RedeemerList(ffi.NULL)


class TestRedeemerListFromCbor:
    """Tests for RedeemerList.from_cbor()."""

    def test_from_cbor_deserializes_list(self):
        """Test that from_cbor() deserializes a redeemer list."""
        reader = CborReader.from_hex(CBOR)
        redeemer_list = RedeemerList.from_cbor(reader)
        assert redeemer_list is not None
        assert len(redeemer_list) == 4

    def test_from_cbor_deserializes_empty_list(self):
        """Test that from_cbor() deserializes an empty redeemer list."""
        reader = CborReader.from_hex("a0")
        redeemer_list = RedeemerList.from_cbor(reader)
        assert redeemer_list is not None
        assert len(redeemer_list) == 0

    def test_from_cbor_deserializes_cbor2(self):
        """Test that from_cbor() deserializes CBOR2 format."""
        reader = CborReader.from_hex(CBOR2)
        redeemer_list = RedeemerList.from_cbor(reader)
        assert redeemer_list is not None
        assert len(redeemer_list) == 4

    def test_from_cbor_deserializes_legacy(self):
        """Test that from_cbor() deserializes legacy CBOR format."""
        reader = CborReader.from_hex(CBOR_LEGACY)
        redeemer_list = RedeemerList.from_cbor(reader)
        assert redeemer_list is not None
        assert len(redeemer_list) == 4

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that from_cbor() with invalid CBOR raises CardanoError."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            RedeemerList.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test that from_cbor() with non-array CBOR raises CardanoError."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            RedeemerList.from_cbor(reader)

    def test_from_cbor_with_invalid_redeemer_raises_error(self):
        """Test that from_cbor() with invalid redeemer raises CardanoError."""
        reader = CborReader.from_hex("818404040404")
        with pytest.raises(CardanoError):
            RedeemerList.from_cbor(reader)


class TestRedeemerListFromList:
    """Tests for RedeemerList.from_list()."""

    def test_from_list_creates_list_from_iterable(self):
        """Test that from_list() creates a list from an iterable."""
        redeemers = [
            create_redeemer_from_cbor(REDEEMER1_CBOR),
            create_redeemer_from_cbor(REDEEMER2_CBOR),
        ]
        redeemer_list = RedeemerList.from_list(redeemers)
        assert redeemer_list is not None
        assert len(redeemer_list) == 2

    def test_from_list_creates_empty_list(self):
        """Test that from_list() creates an empty list from empty iterable."""
        redeemer_list = RedeemerList.from_list([])
        assert redeemer_list is not None
        assert len(redeemer_list) == 0

    def test_from_list_with_generator(self):
        """Test that from_list() works with a generator."""
        def redeemer_generator():
            for cbor_hex in [REDEEMER1_CBOR, REDEEMER2_CBOR]:
                yield create_redeemer_from_cbor(cbor_hex)

        redeemer_list = RedeemerList.from_list(redeemer_generator())
        assert len(redeemer_list) == 2


class TestRedeemerListToCbor:
    """Tests for RedeemerList.to_cbor()."""

    def test_to_cbor_serializes_empty_list(self, empty_list):
        """Test that to_cbor() serializes an empty list."""
        writer = CborWriter()
        empty_list.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == "a0"

    def test_to_cbor_serializes_populated_list(self, populated_list):
        """Test that to_cbor() serializes a populated list."""
        writer = CborWriter()
        populated_list.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_roundtrip(self):
        """Test that CBOR can be deserialized and reserialized."""
        reader = CborReader.from_hex(CBOR)
        redeemer_list = RedeemerList.from_cbor(reader)
        writer = CborWriter()
        redeemer_list.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_legacy_roundtrip_with_cache(self):
        """Test that legacy CBOR uses cached version."""
        reader = CborReader.from_hex(CBOR_LEGACY)
        redeemer_list = RedeemerList.from_cbor(reader)
        writer = CborWriter()
        redeemer_list.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_LEGACY

    def test_to_cbor_legacy_roundtrip_without_cache(self):
        """Test that legacy CBOR without cache converts to new format."""
        reader = CborReader.from_hex(CBOR_LEGACY)
        redeemer_list = RedeemerList.from_cbor(reader)
        redeemer_list.clear_cbor_cache()
        writer = CborWriter()
        redeemer_list.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR


class TestRedeemerListAdd:
    """Tests for RedeemerList.add()."""

    def test_add_adds_redeemer(self, empty_list):
        """Test that add() adds a redeemer to the list."""
        redeemer = create_redeemer_from_cbor(REDEEMER1_CBOR)
        empty_list.add(redeemer)
        assert len(empty_list) == 1

    def test_add_multiple_redeemers(self, empty_list):
        """Test that add() can add multiple redeemers."""
        for cbor_hex in [REDEEMER1_CBOR, REDEEMER2_CBOR, REDEEMER3_CBOR]:
            redeemer = create_redeemer_from_cbor(cbor_hex)
            empty_list.add(redeemer)
        assert len(empty_list) == 3


class TestRedeemerListGet:
    """Tests for RedeemerList.get()."""

    def test_get_retrieves_redeemer(self, populated_list):
        """Test that get() retrieves a redeemer at index."""
        redeemer = populated_list.get(0)
        assert redeemer is not None
        assert isinstance(redeemer, Redeemer)

    def test_get_with_valid_indices(self, populated_list):
        """Test that get() works for all valid indices."""
        for i in range(len(populated_list)):
            redeemer = populated_list.get(i)
            assert redeemer is not None

    def test_get_with_negative_index_raises_error(self, populated_list):
        """Test that get() with negative index raises IndexError."""
        with pytest.raises(IndexError):
            populated_list.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self, populated_list):
        """Test that get() with out of bounds index raises IndexError."""
        with pytest.raises(IndexError):
            populated_list.get(100)

    def test_get_on_empty_list_raises_error(self, empty_list):
        """Test that get() on empty list raises IndexError."""
        with pytest.raises(IndexError):
            empty_list.get(0)


class TestRedeemerListSetExUnits:
    """Tests for RedeemerList.set_ex_units()."""

    def test_set_ex_units_updates_redeemer(self, populated_list):
        """Test that set_ex_units() updates execution units."""
        populated_list.set_ex_units(RedeemerTag.SPEND, 0, 1000, 2000)
        redeemer = populated_list.get(0)
        ex_units = redeemer.ex_units
        assert ex_units.memory == 1000
        assert ex_units.cpu_steps == 2000

    def test_set_ex_units_with_different_tags(self, populated_list):
        """Test that set_ex_units() works with different tags."""
        populated_list.set_ex_units(RedeemerTag.MINT, 1, 500, 750)
        redeemer = populated_list.get(1)
        ex_units = redeemer.ex_units
        assert ex_units.memory == 500
        assert ex_units.cpu_steps == 750

    def test_set_ex_units_with_nonexistent_tag_raises_error(self, populated_list):
        """Test that set_ex_units() with nonexistent tag/index raises CardanoError."""
        with pytest.raises(CardanoError):
            populated_list.set_ex_units(RedeemerTag.SPEND, 99, 1000, 2000)

    def test_set_ex_units_on_empty_list_raises_error(self, empty_list):
        """Test that set_ex_units() on empty list raises CardanoError."""
        with pytest.raises(CardanoError):
            empty_list.set_ex_units(RedeemerTag.SPEND, 0, 1000, 2000)


class TestRedeemerListClone:
    """Tests for RedeemerList.clone()."""

    def test_clone_creates_copy(self, populated_list):
        """Test that clone() creates a copy of the list."""
        cloned = populated_list.clone()
        assert cloned is not None
        assert len(cloned) == len(populated_list)
        assert cloned is not populated_list

    def test_clone_creates_deep_copy(self, populated_list):
        """Test that clone() creates a deep copy."""
        cloned = populated_list.clone()
        original_redeemer = populated_list.get(0)
        cloned_redeemer = cloned.get(0)
        assert original_redeemer is not cloned_redeemer

    def test_clone_empty_list(self, empty_list):
        """Test that clone() works on empty list."""
        cloned = empty_list.clone()
        assert cloned is not None
        assert len(cloned) == 0


class TestRedeemerListClearCborCache:
    """Tests for RedeemerList.clear_cbor_cache()."""

    def test_clear_cbor_cache_on_deserialized_list(self):
        """Test that clear_cbor_cache() clears the cached CBOR."""
        reader = CborReader.from_hex(CBOR_LEGACY)
        redeemer_list = RedeemerList.from_cbor(reader)

        writer1 = CborWriter()
        redeemer_list.to_cbor(writer1)
        cbor_hex1 = writer1.to_hex()
        assert cbor_hex1 == CBOR_LEGACY

        redeemer_list.clear_cbor_cache()

        writer2 = CborWriter()
        redeemer_list.to_cbor(writer2)
        cbor_hex2 = writer2.to_hex()
        assert cbor_hex2 == CBOR
        assert cbor_hex2 != CBOR_LEGACY

    def test_clear_cbor_cache_on_new_list(self, empty_list):
        """Test that clear_cbor_cache() can be called on new list."""
        empty_list.clear_cbor_cache()
        assert len(empty_list) == 0


class TestRedeemerListLen:
    """Tests for RedeemerList.__len__()."""

    def test_len_returns_zero_for_empty_list(self, empty_list):
        """Test that len() returns 0 for empty list."""
        assert len(empty_list) == 0

    def test_len_returns_count_for_populated_list(self, populated_list):
        """Test that len() returns correct count for populated list."""
        assert len(populated_list) == 4

    def test_len_updates_after_add(self, empty_list):
        """Test that len() updates after adding redeemers."""
        assert len(empty_list) == 0
        redeemer = create_redeemer_from_cbor(REDEEMER1_CBOR)
        empty_list.add(redeemer)
        assert len(empty_list) == 1


class TestRedeemerListIter:
    """Tests for RedeemerList.__iter__()."""

    def test_iter_iterates_over_redeemers(self, populated_list):
        """Test that __iter__() iterates over all redeemers."""
        count = 0
        for redeemer in populated_list:
            assert isinstance(redeemer, Redeemer)
            count += 1
        assert count == 4

    def test_iter_on_empty_list(self, empty_list):
        """Test that __iter__() on empty list yields nothing."""
        count = 0
        for _ in empty_list:
            count += 1
        assert count == 0


class TestRedeemerListGetItem:
    """Tests for RedeemerList.__getitem__()."""

    def test_getitem_retrieves_redeemer(self, populated_list):
        """Test that __getitem__() retrieves a redeemer."""
        redeemer = populated_list[0]
        assert redeemer is not None
        assert isinstance(redeemer, Redeemer)

    def test_getitem_with_all_indices(self, populated_list):
        """Test that __getitem__() works for all indices."""
        for i in range(len(populated_list)):
            redeemer = populated_list[i]
            assert redeemer is not None

    def test_getitem_with_negative_index_raises_error(self, populated_list):
        """Test that __getitem__() with negative index raises IndexError."""
        with pytest.raises(IndexError):
            _ = populated_list[-1]

    def test_getitem_with_out_of_bounds_raises_error(self, populated_list):
        """Test that __getitem__() with out of bounds index raises IndexError."""
        with pytest.raises(IndexError):
            _ = populated_list[100]


class TestRedeemerListBool:
    """Tests for RedeemerList.__bool__()."""

    def test_bool_returns_false_for_empty_list(self, empty_list):
        """Test that __bool__() returns False for empty list."""
        assert not empty_list

    def test_bool_returns_true_for_populated_list(self, populated_list):
        """Test that __bool__() returns True for populated list."""
        assert populated_list


class TestRedeemerListToCip116Json:
    """Tests for RedeemerList.to_cip116_json()."""

    def test_to_cip116_json_serializes_list(self, populated_list):
        """Test that to_cip116_json() serializes a list."""
        writer = JsonWriter(JsonFormat.COMPACT)
        populated_list.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert '"tag":"spend"' in json_str
        assert '"tag":"mint"' in json_str
        assert '"tag":"reward"' in json_str
        assert '"tag":"voting"' in json_str

    def test_to_cip116_json_serializes_empty_list(self, empty_list):
        """Test that to_cip116_json() serializes an empty list."""
        writer = JsonWriter(JsonFormat.COMPACT)
        empty_list.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "[]"

    def test_to_cip116_json_with_invalid_writer_raises_error(self, populated_list):
        """Test that to_cip116_json() with invalid writer raises TypeError."""
        with pytest.raises(TypeError, match="writer must be a JsonWriter instance"):
            populated_list.to_cip116_json("not a writer")


class TestRedeemerListIndex:
    """Tests for RedeemerList.index()."""

    def test_index_method_exists(self, populated_list):
        """Test that index() method exists and can be called."""
        assert hasattr(populated_list, 'index')
        assert callable(populated_list.index)

    def test_index_with_nonexistent_redeemer_raises_error(self, populated_list):
        """Test that index() with nonexistent redeemer raises ValueError."""
        other_redeemer = create_redeemer_from_cbor(REDEEMER1_CBOR)
        with pytest.raises(ValueError, match="is not in list"):
            populated_list.index(other_redeemer)


class TestRedeemerListCount:
    """Tests for RedeemerList.count()."""

    def test_count_method_exists(self, populated_list):
        """Test that count() method exists and can be called."""
        assert hasattr(populated_list, 'count')
        assert callable(populated_list.count)

    def test_count_returns_zero_for_nonexistent_redeemer(self, populated_list):
        """Test that count() returns 0 for nonexistent redeemer."""
        other_redeemer = create_redeemer_from_cbor(REDEEMER5_CBOR)
        count = populated_list.count(other_redeemer)
        assert count == 0

    def test_count_on_empty_list(self, empty_list):
        """Test that count() returns 0 on empty list."""
        redeemer = create_redeemer_from_cbor(REDEEMER1_CBOR)
        count = empty_list.count(redeemer)
        assert count == 0


class TestRedeemerListReversed:
    """Tests for RedeemerList.__reversed__()."""

    def test_reversed_iterates_in_reverse(self, populated_list):
        """Test that __reversed__() iterates in reverse order."""
        forward = []
        for redeemer in populated_list:
            forward.append((redeemer.tag, redeemer.index))

        backward = []
        for redeemer in reversed(populated_list):
            backward.append((redeemer.tag, redeemer.index))

        assert len(forward) == len(backward)
        for i in range(len(forward)):
            assert forward[i] == backward[-(i+1)]

    def test_reversed_on_empty_list(self, empty_list):
        """Test that __reversed__() on empty list yields nothing."""
        count = 0
        for _ in reversed(empty_list):
            count += 1
        assert count == 0


class TestRedeemerListRepr:
    """Tests for RedeemerList.__repr__()."""

    def test_repr_contains_length(self, populated_list):
        """Test that __repr__() contains the length."""
        repr_str = repr(populated_list)
        assert "RedeemerList" in repr_str
        assert "len=4" in repr_str

    def test_repr_empty_list(self, empty_list):
        """Test that __repr__() works for empty list."""
        repr_str = repr(empty_list)
        assert "RedeemerList" in repr_str
        assert "len=0" in repr_str


class TestRedeemerListContextManager:
    """Tests for RedeemerList context manager."""

    def test_context_manager_enter_exit(self):
        """Test that RedeemerList works as context manager."""
        with RedeemerList() as redeemer_list:
            assert redeemer_list is not None
            assert len(redeemer_list) == 0

    def test_context_manager_allows_operations(self):
        """Test that operations work within context manager."""
        with RedeemerList() as redeemer_list:
            redeemer = create_redeemer_from_cbor(REDEEMER1_CBOR)
            redeemer_list.add(redeemer)
            assert len(redeemer_list) == 1
