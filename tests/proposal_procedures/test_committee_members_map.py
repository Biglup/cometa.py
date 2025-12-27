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
    CborReader,
    CborWriter,
    CommitteeMembersMap,
    Credential,
    CredentialType,
    CredentialSet,
    JsonWriter,
    CardanoError,
)

CBOR = "a48200581c00000000000000000000000000000000000000000000000000000000008200581c10000000000000000000000000000000000000000000000000000000018200581c20000000000000000000000000000000000000000000000000000000028200581c3000000000000000000000000000000000000000000000000000000003"
CREDENTIAL1_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL2_CBOR = "8200581c10000000000000000000000000000000000000000000000000000000"
CREDENTIAL3_CBOR = "8200581c20000000000000000000000000000000000000000000000000000000"
CREDENTIAL4_CBOR = "8200581c30000000000000000000000000000000000000000000000000000000"


def create_credential(cbor_hex):
    """
    Helper function to create a credential from CBOR hex.
    """
    reader = CborReader.from_hex(cbor_hex)
    return Credential.from_cbor(reader)


class TestCommitteeMembersMapConstruction:
    """
    Tests for CommitteeMembersMap construction methods.
    """

    def test_new_creates_empty_map(self):
        """
        Test that new() creates an empty CommitteeMembersMap.
        """
        committee_map = CommitteeMembersMap()
        assert committee_map is not None
        assert len(committee_map) == 0

    def test_new_with_none_ptr(self):
        """
        Test that new() works with explicit None ptr.
        """
        committee_map = CommitteeMembersMap(None)
        assert committee_map is not None
        assert len(committee_map) == 0

    def test_new_with_null_ptr_raises_error(self):
        """
        Test that passing ffi.NULL raises CardanoError.
        """
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            CommitteeMembersMap(ffi.NULL)


class TestCommitteeMembersMapCborSerialization:
    """
    Tests for CBOR serialization and deserialization.
    """

    def test_to_cbor_empty_map(self):
        """
        Test serialization of an empty map.
        """
        committee_map = CommitteeMembersMap()
        writer = CborWriter()
        committee_map.to_cbor(writer)
        assert writer.to_hex() == "a0"

    def test_from_cbor_valid_data(self):
        """
        Test deserialization from valid CBOR data.
        """
        reader = CborReader.from_hex(CBOR)
        committee_map = CommitteeMembersMap.from_cbor(reader)
        assert committee_map is not None
        assert len(committee_map) == 4

    def test_from_cbor_and_to_cbor_roundtrip(self):
        """
        Test that deserialize and serialize roundtrips correctly.
        """
        reader = CborReader.from_hex(CBOR)
        committee_map = CommitteeMembersMap.from_cbor(reader)
        writer = CborWriter()
        committee_map.to_cbor(writer)
        assert writer.to_hex() == CBOR

    def test_from_cbor_with_invalid_map(self):
        """
        Test that from_cbor raises error with invalid map.
        """
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            CommitteeMembersMap.from_cbor(reader)

    def test_from_cbor_with_invalid_member(self):
        """
        Test that from_cbor raises error with invalid member.
        """
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            CommitteeMembersMap.from_cbor(reader)

    def test_from_cbor_with_invalid_epoch(self):
        """
        Test that from_cbor raises error with invalid epoch value.
        """
        invalid_cbor = "a48200581c00000000000000000000000000000000000000000000000000000000fe8200581c10000000000000000000000000000000000000000000000000000000018200581c20000000000000000000000000000000000000000000000000000000028200581c3000000000000000000000000000000000000000000000000000000003"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            CommitteeMembersMap.from_cbor(reader)

    def test_to_cbor_with_none_writer_raises_error(self):
        """
        Test that to_cbor raises error when writer is None.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises((TypeError, AttributeError)):
            committee_map.to_cbor(None)


class TestCommitteeMembersMapInsert:
    """
    Tests for inserting elements into the map.
    """

    def test_insert_single_element(self):
        """
        Test inserting a single credential-epoch pair.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 65)
        assert len(committee_map) == 1

    def test_insert_multiple_elements(self):
        """
        Test inserting multiple credential-epoch pairs.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        credential3 = create_credential(CREDENTIAL3_CBOR)
        credential4 = create_credential(CREDENTIAL4_CBOR)

        committee_map.insert(credential1, 0)
        committee_map.insert(credential2, 1)
        committee_map.insert(credential3, 2)
        committee_map.insert(credential4, 3)

        assert len(committee_map) == 4

    def test_insert_keeps_elements_sorted(self):
        """
        Test that insert maintains elements sorted by credential.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        credential3 = create_credential(CREDENTIAL3_CBOR)
        credential4 = create_credential(CREDENTIAL4_CBOR)

        committee_map.insert(credential3, 2)
        committee_map.insert(credential1, 0)
        committee_map.insert(credential4, 3)
        committee_map.insert(credential2, 1)

        writer = CborWriter()
        committee_map.to_cbor(writer)
        assert writer.to_hex() == CBOR

    def test_insert_with_bracket_notation(self):
        """
        Test inserting using bracket notation.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map[credential] = 100
        assert len(committee_map) == 1
        assert committee_map[credential] == 100

    def test_insert_with_invalid_credential_raises_error(self):
        """
        Test that inserting with None credential raises error.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises((TypeError, AttributeError, CardanoError)):
            committee_map.insert(None, 5)


class TestCommitteeMembersMapGet:
    """
    Tests for retrieving elements from the map.
    """

    def test_get_existing_element(self):
        """
        Test getting an element that exists.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 65)
        value = committee_map.get(credential)
        assert value == 65

    def test_get_with_default_for_missing_element(self):
        """
        Test getting with default value for non-existent key.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        value = committee_map.get(credential, 999)
        assert value == 999

    def test_get_missing_element_returns_none(self):
        """
        Test that getting non-existent key returns None by default.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        value = committee_map.get(credential)
        assert value is None

    def test_get_with_bracket_notation(self):
        """
        Test getting using bracket notation.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 42)
        assert committee_map[credential] == 42

    def test_get_correct_element_with_multiple_entries(self):
        """
        Test getting the correct element when multiple exist.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)
        assert committee_map.get(credential1) == 1
        assert committee_map.get(credential2) == 2


class TestCommitteeMembersMapGetKeys:
    """
    Tests for retrieving keys from the map.
    """

    def test_get_keys_empty_map(self):
        """
        Test get_keys on empty map.
        """
        committee_map = CommitteeMembersMap()
        keys = committee_map.get_keys()
        assert keys is not None
        assert len(keys) == 0

    def test_get_keys_with_elements(self):
        """
        Test get_keys returns all keys.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        keys = committee_map.get_keys()
        assert len(keys) == 2


class TestCommitteeMembersMapGetKeyAt:
    """
    Tests for retrieving keys by index.
    """

    def test_get_key_at_valid_index(self):
        """
        Test get_key_at with valid index.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        key = committee_map.get_key_at(0)
        assert key is not None

    def test_get_key_at_out_of_bounds_raises_error(self):
        """
        Test get_key_at with out of bounds index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises(IndexError):
            committee_map.get_key_at(0)

    def test_get_key_at_negative_index_raises_error(self):
        """
        Test get_key_at with negative index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        with pytest.raises(IndexError):
            committee_map.get_key_at(-1)


class TestCommitteeMembersMapGetValueAt:
    """
    Tests for retrieving values by index.
    """

    def test_get_value_at_valid_index(self):
        """
        Test get_value_at with valid index.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 2)

        value = committee_map.get_value_at(0)
        assert value == 2

    def test_get_value_at_out_of_bounds_raises_error(self):
        """
        Test get_value_at with out of bounds index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises(IndexError):
            committee_map.get_value_at(0)

    def test_get_value_at_negative_index_raises_error(self):
        """
        Test get_value_at with negative index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        with pytest.raises(IndexError):
            committee_map.get_value_at(-1)


class TestCommitteeMembersMapGetKeyValueAt:
    """
    Tests for retrieving key-value pairs by index.
    """

    def test_get_key_value_at_valid_index(self):
        """
        Test get_key_value_at with valid index.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 10)

        key, value = committee_map.get_key_value_at(0)
        assert key is not None
        assert value == 10

    def test_get_key_value_at_out_of_bounds_raises_error(self):
        """
        Test get_key_value_at with out of bounds index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises(IndexError):
            committee_map.get_key_value_at(0)

    def test_get_key_value_at_negative_index_raises_error(self):
        """
        Test get_key_value_at with negative index raises IndexError.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        with pytest.raises(IndexError):
            committee_map.get_key_value_at(-1)


class TestCommitteeMembersMapLength:
    """
    Tests for map length operations.
    """

    def test_len_empty_map(self):
        """
        Test len() on empty map returns 0.
        """
        committee_map = CommitteeMembersMap()
        assert len(committee_map) == 0

    def test_len_with_elements(self):
        """
        Test len() returns correct count.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        credential3 = create_credential(CREDENTIAL3_CBOR)

        committee_map.insert(credential1, 5)
        committee_map.insert(credential2, 5)
        committee_map.insert(credential3, 5)

        assert len(committee_map) == 3


class TestCommitteeMembersMapIteration:
    """
    Tests for iteration over the map.
    """

    def test_iter_keys(self):
        """
        Test iteration over keys.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        keys = list(committee_map)
        assert len(keys) == 2

    def test_keys_method(self):
        """
        Test keys() method.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        keys = list(committee_map.keys())
        assert len(keys) == 2

    def test_values_method(self):
        """
        Test values() method.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        values = list(committee_map.values())
        assert len(values) == 2
        assert 1 in values
        assert 2 in values

    def test_items_method(self):
        """
        Test items() method.
        """
        committee_map = CommitteeMembersMap()
        credential1 = create_credential(CREDENTIAL1_CBOR)
        credential2 = create_credential(CREDENTIAL2_CBOR)
        committee_map.insert(credential1, 1)
        committee_map.insert(credential2, 2)

        items = list(committee_map.items())
        assert len(items) == 2
        assert all(isinstance(item, tuple) for item in items)
        assert all(len(item) == 2 for item in items)


class TestCommitteeMembersMapContains:
    """
    Tests for membership checking.
    """

    def test_contains_existing_key(self):
        """
        Test __contains__ returns True for existing key.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        assert credential in committee_map

    def test_contains_missing_key(self):
        """
        Test __contains__ returns False for missing key.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        assert credential not in committee_map


class TestCommitteeMembersMapBool:
    """
    Tests for boolean conversion.
    """

    def test_bool_empty_map(self):
        """
        Test bool() on empty map returns False.
        """
        committee_map = CommitteeMembersMap()
        assert not committee_map

    def test_bool_non_empty_map(self):
        """
        Test bool() on non-empty map returns True.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        assert committee_map


class TestCommitteeMembersMapRepr:
    """
    Tests for string representation.
    """

    def test_repr(self):
        """
        Test __repr__ returns proper representation.
        """
        committee_map = CommitteeMembersMap()
        credential = create_credential(CREDENTIAL1_CBOR)
        committee_map.insert(credential, 1)
        repr_str = repr(committee_map)
        assert "CommitteeMembersMap" in repr_str
        assert "len=1" in repr_str


class TestCommitteeMembersMapContextManager:
    """
    Tests for context manager protocol.
    """

    def test_context_manager(self):
        """
        Test that map works as context manager.
        """
        with CommitteeMembersMap() as committee_map:
            credential = create_credential(CREDENTIAL1_CBOR)
            committee_map.insert(credential, 1)
            assert len(committee_map) == 1


class TestCommitteeMembersMapJsonSerialization:
    """
    Tests for JSON serialization.
    """

    def test_to_cip116_json_empty_map(self):
        """
        Test serializing empty map to CIP-116 JSON.
        """
        committee_map = CommitteeMembersMap()
        writer = JsonWriter()
        committee_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "[]"

    def test_to_cip116_json_with_element(self):
        """
        Test serializing map with element to CIP-116 JSON.
        """
        from cometa import Blake2bHash
        committee_map = CommitteeMembersMap()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000000")
        credential = Credential.from_hash(hash_obj, CredentialType.KEY_HASH)
        committee_map.insert(credential, 1000000)
        writer = JsonWriter()
        committee_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert "pubkey_hash" in json_str
        assert "1000000" in json_str

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """
        Test that to_cip116_json raises error with invalid writer.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises((TypeError, CardanoError)):
            committee_map.to_cip116_json(None)

    def test_to_cip116_json_with_non_json_writer_raises_error(self):
        """
        Test that to_cip116_json raises error with non-JsonWriter.
        """
        committee_map = CommitteeMembersMap()
        with pytest.raises(TypeError):
            committee_map.to_cip116_json("not a writer")
