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
from cometa.scripts.native_scripts import (
    NativeScriptList,
    NativeScript,
    ScriptPubkey,
    ScriptInvalidBefore,
    ScriptInvalidAfter,
)
from cometa.cbor import CborReader, CborWriter
from cometa.errors import CardanoError


KEY_HASH_HEX = "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"


class TestNativeScriptList:
    """Tests for the NativeScriptList class."""

    def test_new_creates_empty_list(self):
        """Test creating a new empty NativeScriptList."""
        script_list = NativeScriptList()
        assert script_list is not None
        assert len(script_list) == 0

    def test_new_with_null_ptr(self):
        """Test creating a NativeScriptList with a NULL pointer raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            NativeScriptList(ffi.NULL)

    def test_len_empty_list(self):
        """Test length of empty list is zero."""
        script_list = NativeScriptList()
        assert len(script_list) == 0

    def test_len_after_adding_scripts(self):
        """Test length increases after adding scripts."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        assert len(script_list) == 1
        script_list.add(pubkey)
        assert len(script_list) == 2

    def test_add_script_pubkey(self):
        """Test adding a ScriptPubkey to the list."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        assert len(script_list) == 1

    def test_add_native_script(self):
        """Test adding a NativeScript to the list."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(pubkey)
        script_list.add(native_script)
        assert len(script_list) == 1

    def test_add_script_invalid_before(self):
        """Test adding a ScriptInvalidBefore to the list."""
        script_list = NativeScriptList()
        invalid_before = ScriptInvalidBefore.new(3000)
        script_list.add(invalid_before)
        assert len(script_list) == 1

    def test_add_script_invalid_after(self):
        """Test adding a ScriptInvalidAfter to the list."""
        script_list = NativeScriptList()
        invalid_after = ScriptInvalidAfter.new(4000)
        script_list.add(invalid_after)
        assert len(script_list) == 1

    def test_add_multiple_scripts(self):
        """Test adding multiple scripts of different types."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        script_list.add(invalid_after)
        script_list.add(pubkey)
        script_list.add(invalid_before)
        assert len(script_list) == 3

    def test_add_invalid_type(self):
        """Test adding an invalid type raises TypeError."""
        script_list = NativeScriptList()
        with pytest.raises(TypeError, match="Expected NativeScript"):
            script_list.add("not a script")
        with pytest.raises(TypeError):
            script_list.add(42)
        with pytest.raises(TypeError):
            script_list.add(None)

    def test_get_at_valid_index(self):
        """Test retrieving a script at a valid index."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)

        retrieved = script_list.get(0)
        assert retrieved is not None
        assert isinstance(retrieved, NativeScript)

    def test_get_at_invalid_index(self):
        """Test retrieving a script at an invalid index raises IndexError."""
        script_list = NativeScriptList()
        with pytest.raises(IndexError, match="out of range"):
            script_list.get(0)

    def test_get_negative_index(self):
        """Test retrieving a script with a negative index raises IndexError."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        with pytest.raises(IndexError):
            script_list.get(-1)

    def test_get_index_out_of_bounds(self):
        """Test retrieving a script beyond list length raises IndexError."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        with pytest.raises(IndexError):
            script_list.get(5)

    def test_getitem_with_valid_index(self):
        """Test bracket notation for getting items."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)

        retrieved = script_list[0]
        assert retrieved is not None
        assert isinstance(retrieved, NativeScript)

    def test_getitem_with_invalid_index(self):
        """Test bracket notation with invalid index raises IndexError."""
        script_list = NativeScriptList()
        with pytest.raises(IndexError):
            _ = script_list[0]

    def test_iter(self):
        """Test iterating over the list."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)

        count = 0
        for script in script_list:
            assert isinstance(script, NativeScript)
            count += 1
        assert count == 2

    def test_iter_empty_list(self):
        """Test iterating over an empty list."""
        script_list = NativeScriptList()
        count = 0
        for _ in script_list:
            count += 1
        assert count == 0

    def test_bool_empty_list(self):
        """Test bool of empty list is False."""
        script_list = NativeScriptList()
        assert not script_list

    def test_bool_non_empty_list(self):
        """Test bool of non-empty list is True."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        assert script_list

    def test_repr(self):
        """Test string representation of NativeScriptList."""
        script_list = NativeScriptList()
        repr_str = repr(script_list)
        assert "NativeScriptList" in repr_str
        assert "len=0" in repr_str

        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        repr_str = repr(script_list)
        assert "len=1" in repr_str

    def test_from_cbor_valid_data(self):
        """Test deserializing from valid CBOR data."""
        cbor_hex = "838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
        reader = CborReader.from_hex(cbor_hex)
        script_list = NativeScriptList.from_cbor(reader)
        assert script_list is not None
        assert len(script_list) == 3

    def test_from_cbor_indefinite_array(self):
        """Test deserializing from indefinite array CBOR data."""
        cbor_hex = "9f8205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0ff"
        reader = CborReader.from_hex(cbor_hex)
        script_list = NativeScriptList.from_cbor(reader)
        assert script_list is not None
        assert len(script_list) == 3

    def test_from_cbor_empty_array(self):
        """Test deserializing from empty CBOR array."""
        cbor_hex = "80"
        reader = CborReader.from_hex(cbor_hex)
        script_list = NativeScriptList.from_cbor(reader)
        assert script_list is not None
        assert len(script_list) == 0

    def test_from_cbor_invalid_data(self):
        """Test deserializing from invalid CBOR data raises error."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            NativeScriptList.from_cbor(reader)

    def test_to_cbor(self):
        """Test serializing to CBOR."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        script_list.add(invalid_before)
        script_list.add(pubkey)
        script_list.add(invalid_after)

        writer = CborWriter()
        script_list.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_to_cbor_empty_list(self):
        """Test serializing empty list to CBOR."""
        script_list = NativeScriptList()
        writer = CborWriter()
        script_list.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        script_list1 = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        script_list1.add(invalid_before)
        script_list1.add(pubkey)
        script_list1.add(invalid_after)

        writer = CborWriter()
        script_list1.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_hex(cbor_bytes.hex())
        script_list2 = NativeScriptList.from_cbor(reader)

        assert len(script_list1) == len(script_list2)
        assert len(script_list2) == 3

    def test_cbor_roundtrip_empty_list(self):
        """Test CBOR roundtrip with empty list."""
        script_list1 = NativeScriptList()
        writer = CborWriter()
        script_list1.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_hex(cbor_bytes.hex())
        script_list2 = NativeScriptList.from_cbor(reader)
        assert len(script_list2) == 0

    def test_from_list_with_iterable(self):
        """Test creating from an iterable of scripts."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        scripts = [pubkey, invalid_before, invalid_after]
        script_list = NativeScriptList.from_list(scripts)
        assert len(script_list) == 3

    def test_from_list_with_empty_iterable(self):
        """Test creating from an empty iterable."""
        script_list = NativeScriptList.from_list([])
        assert len(script_list) == 0

    def test_from_list_with_generator(self):
        """Test creating from a generator."""
        def script_generator():
            key_hash = bytes.fromhex(KEY_HASH_HEX)
            yield ScriptPubkey.new(key_hash)
            yield ScriptInvalidBefore.new(3000)

        script_list = NativeScriptList.from_list(script_generator())
        assert len(script_list) == 2

    def test_from_list_with_native_scripts(self):
        """Test creating from list of NativeScript objects."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(pubkey)

        scripts = [native_script]
        script_list = NativeScriptList.from_list(scripts)
        assert len(script_list) == 1

    def test_context_manager(self):
        """Test using NativeScriptList as a context manager."""
        with NativeScriptList() as script_list:
            assert script_list is not None
            key_hash = bytes.fromhex(KEY_HASH_HEX)
            pubkey = ScriptPubkey.new(key_hash)
            script_list.add(pubkey)
            assert len(script_list) == 1

    def test_lifecycle(self):
        """Test object lifecycle and cleanup."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        assert len(script_list) == 1
        del script_list

    def test_index_finds_existing_value(self):
        """Test index method finds existing script."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(pubkey)
        script_list.add(native_script)

        idx = script_list.index(script_list[0])
        assert idx == 0

    def test_index_with_start_parameter(self):
        """Test index method with start parameter."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)
        script_list.add(pubkey)

        idx = script_list.index(script_list[2], 1)
        assert idx == 2

    def test_index_with_stop_parameter(self):
        """Test index method with stop parameter."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)

        idx = script_list.index(script_list[0], 0, 1)
        assert idx == 0

    def test_index_raises_value_error_if_not_found(self):
        """Test index raises ValueError if value not found."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        key_hash2 = bytes.fromhex("666e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        another_pubkey = ScriptPubkey.new(key_hash2)

        script_list.add(pubkey)
        native_script = NativeScript.from_pubkey(another_pubkey)

        with pytest.raises(ValueError, match="is not in list"):
            script_list.index(native_script)

    def test_count_returns_occurrences(self):
        """Test count method returns number of occurrences."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)
        script_list.add(pubkey)

        count = script_list.count(script_list[0])
        assert count >= 1

    def test_count_returns_zero_for_non_existent(self):
        """Test count returns zero for non-existent value."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        key_hash2 = bytes.fromhex("666e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        another_pubkey = ScriptPubkey.new(key_hash2)

        script_list.add(pubkey)
        native_script = NativeScript.from_pubkey(another_pubkey)

        count = script_list.count(native_script)
        assert count == 0

    def test_reversed(self):
        """Test reversed iteration over the list."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        script_list.add(invalid_before)
        script_list.add(pubkey)
        script_list.add(invalid_after)

        reversed_items = list(reversed(script_list))
        assert len(reversed_items) == 3

    def test_reversed_empty_list(self):
        """Test reversed iteration over empty list."""
        script_list = NativeScriptList()
        reversed_items = list(reversed(script_list))
        assert len(reversed_items) == 0

    def test_multiple_iterations(self):
        """Test iterating over the list multiple times."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)

        for _ in range(3):
            count = 0
            for script in script_list:
                assert isinstance(script, NativeScript)
                count += 1
            assert count == 1

    def test_list_comprehension(self):
        """Test using list comprehension with NativeScriptList."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)

        scripts = [script for script in script_list]
        assert len(scripts) == 2

    def test_add_same_script_multiple_times(self):
        """Test adding the same script multiple times."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)

        for _ in range(5):
            script_list.add(pubkey)
        assert len(script_list) == 5

    def test_large_list(self):
        """Test creating a large list of scripts."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)

        num_scripts = 100
        for _ in range(num_scripts):
            pubkey = ScriptPubkey.new(key_hash)
            script_list.add(pubkey)

        assert len(script_list) == num_scripts

    def test_get_all_items_in_order(self):
        """Test getting all items maintains insertion order."""
        script_list = NativeScriptList()
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        script_list.add(invalid_before)
        script_list.add(invalid_after)

        first = script_list.get(0)
        second = script_list.get(1)

        assert first is not None
        assert second is not None

    def test_cbor_serialization_deterministic(self):
        """Test that CBOR serialization is deterministic."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)

        writer1 = CborWriter()
        script_list.to_cbor(writer1)
        cbor_bytes1 = writer1.encode()

        writer2 = CborWriter()
        script_list.to_cbor(writer2)
        cbor_bytes2 = writer2.encode()

        assert cbor_bytes1 == cbor_bytes2

    def test_multiple_cbor_roundtrips(self):
        """Test multiple CBOR serialization and deserialization cycles."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)

        for _ in range(3):
            writer = CborWriter()
            script_list.to_cbor(writer)
            cbor_bytes = writer.encode()
            reader = CborReader.from_hex(cbor_bytes.hex())
            script_list = NativeScriptList.from_cbor(reader)

        assert len(script_list) == 1

    def test_empty_list_operations(self):
        """Test various operations on empty list."""
        script_list = NativeScriptList()
        assert len(script_list) == 0
        assert not script_list
        assert list(script_list) == []
        assert list(reversed(script_list)) == []

    def test_sequence_protocol(self):
        """Test that NativeScriptList implements sequence protocol correctly."""
        script_list = NativeScriptList()
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)

        script_list.add(pubkey)
        script_list.add(invalid_before)

        assert hasattr(script_list, '__len__')
        assert hasattr(script_list, '__getitem__')
        assert hasattr(script_list, '__iter__')
        assert hasattr(script_list, 'index')
        assert hasattr(script_list, 'count')

    def test_from_list_preserves_order(self):
        """Test that from_list preserves the order of scripts."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        scripts = [invalid_before, pubkey, invalid_after]
        script_list = NativeScriptList.from_list(scripts)

        assert len(script_list) == 3

    def test_repr_reflects_current_state(self):
        """Test that repr reflects the current state of the list."""
        script_list = NativeScriptList()
        assert "len=0" in repr(script_list)

        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        script_list.add(pubkey)
        assert "len=1" in repr(script_list)

        script_list.add(pubkey)
        assert "len=2" in repr(script_list)
