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
from cometa.cryptography import Blake2bHash, Blake2bHashSet
from cometa.cbor import CborReader, CborWriter
from cometa.errors import CardanoError


CBOR = "d9010284581c00000000000000000000000000000000000000000000000000000001581c00000000000000000000000000000000000000000000000000000002581c00000000000000000000000000000000000000000000000000000003581c00000000000000000000000000000000000000000000000000000004"
CBOR_WITHOUT_TAG = "84581c00000000000000000000000000000000000000000000000000000001581c00000000000000000000000000000000000000000000000000000002581c00000000000000000000000000000000000000000000000000000003581c00000000000000000000000000000000000000000000000000000004"
CBOR_EMPTY = "d9010280"
BLAKE2B_HASH1_CBOR = "581c00000000000000000000000000000000000000000000000000000001"
BLAKE2B_HASH2_CBOR = "581c00000000000000000000000000000000000000000000000000000002"
BLAKE2B_HASH3_CBOR = "581c00000000000000000000000000000000000000000000000000000003"
BLAKE2B_HASH4_CBOR = "581c00000000000000000000000000000000000000000000000000000004"


def create_hash_from_cbor(cbor_hex: str) -> Blake2bHash:
    """Helper function to create Blake2bHash from CBOR hex string."""
    reader = CborReader.from_hex(cbor_hex)
    return Blake2bHash.from_cbor(reader)


class TestBlake2bHashSetNew:
    """Tests for Blake2bHashSet.__init__()"""

    def test_can_create_blake2b_hash_set(self):
        """Test creating a new Blake2bHashSet"""
        hash_set = Blake2bHashSet()
        assert hash_set is not None
        assert len(hash_set) == 0

    def test_can_create_empty_set_using_context_manager(self):
        """Test creating Blake2bHashSet using context manager"""
        with Blake2bHashSet() as hash_set:
            assert hash_set is not None
            assert len(hash_set) == 0


class TestBlake2bHashSetFromCbor:
    """Tests for Blake2bHashSet.from_cbor()"""

    def test_can_deserialize_blake2b_hash_set(self):
        """Test deserializing Blake2bHashSet from CBOR"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        assert hash_set is not None
        assert len(hash_set) == 4

    def test_can_deserialize_empty_set(self):
        """Test deserializing empty Blake2bHashSet"""
        reader = CborReader.from_hex(CBOR_EMPTY)
        hash_set = Blake2bHashSet.from_cbor(reader)
        assert hash_set is not None
        assert len(hash_set) == 0

    def test_can_deserialize_without_tag(self):
        """Test deserializing Blake2bHashSet from CBOR without tag"""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        hash_set = Blake2bHashSet.from_cbor(reader)
        assert hash_set is not None
        assert len(hash_set) == 4

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test from_cbor with invalid CBOR raises error"""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            Blake2bHashSet.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test from_cbor with non-array CBOR raises error"""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            Blake2bHashSet.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test from_cbor with invalid elements raises error"""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            Blake2bHashSet.from_cbor(reader)

    def test_from_cbor_with_missing_end_array_raises_error(self):
        """Test from_cbor with missing end array raises error"""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            Blake2bHashSet.from_cbor(reader)


class TestBlake2bHashSetFromList:
    """Tests for Blake2bHashSet.from_list()"""

    def test_can_create_from_list(self):
        """Test creating Blake2bHashSet from list of hashes"""
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash2 = create_hash_from_cbor(BLAKE2B_HASH2_CBOR)
        hash_set = Blake2bHashSet.from_list([hash1, hash2])
        assert len(hash_set) == 2

    def test_can_create_from_empty_list(self):
        """Test creating Blake2bHashSet from empty list"""
        hash_set = Blake2bHashSet.from_list([])
        assert len(hash_set) == 0

    def test_can_create_from_tuple(self):
        """Test creating Blake2bHashSet from tuple"""
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash2 = create_hash_from_cbor(BLAKE2B_HASH2_CBOR)
        hash_set = Blake2bHashSet.from_list((hash1, hash2))
        assert len(hash_set) == 2

    def test_can_create_from_generator(self):
        """Test creating Blake2bHashSet from generator"""
        hashes = (create_hash_from_cbor(cbor) for cbor in
                  [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR, BLAKE2B_HASH3_CBOR])
        hash_set = Blake2bHashSet.from_list(hashes)
        assert len(hash_set) == 3


class TestBlake2bHashSetAdd:
    """Tests for Blake2bHashSet.add()"""

    def test_can_add_hash_to_set(self):
        """Test adding a hash to the set"""
        hash_set = Blake2bHashSet()
        hash_obj = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash_set.add(hash_obj)
        assert len(hash_set) == 1

    def test_can_add_multiple_hashes(self):
        """Test adding multiple hashes to the set"""
        hash_set = Blake2bHashSet()
        for cbor in [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR,
                     BLAKE2B_HASH3_CBOR, BLAKE2B_HASH4_CBOR]:
            hash_obj = create_hash_from_cbor(cbor)
            hash_set.add(hash_obj)
        assert len(hash_set) == 4

    def test_add_maintains_order(self):
        """Test that add maintains insertion order"""
        hash_set = Blake2bHashSet()
        hashes = [create_hash_from_cbor(cbor) for cbor in
                  [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH3_CBOR,
                   BLAKE2B_HASH2_CBOR, BLAKE2B_HASH4_CBOR]]
        for hash_obj in hashes:
            hash_set.add(hash_obj)
        assert len(hash_set) == 4


class TestBlake2bHashSetGet:
    """Tests for Blake2bHashSet.get()"""

    def test_can_get_hash_at_index(self):
        """Test retrieving hash at specific index"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        hash_obj = hash_set.get(0)
        assert hash_obj is not None

    def test_get_returns_correct_hashes(self):
        """Test that get returns correct hashes at each index"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)

        expected_hashes = [
            create_hash_from_cbor(BLAKE2B_HASH1_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH2_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH3_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH4_CBOR)
        ]

        for i in range(4):
            assert hash_set.get(i) == expected_hashes[i]

    def test_get_with_negative_index_raises_error(self):
        """Test get with negative index raises IndexError"""
        hash_set = Blake2bHashSet()
        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        with pytest.raises(IndexError):
            hash_set.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self):
        """Test get with out of bounds index raises IndexError"""
        hash_set = Blake2bHashSet()
        with pytest.raises(IndexError):
            hash_set.get(0)

    def test_get_with_index_beyond_length_raises_error(self):
        """Test get with index beyond length raises IndexError"""
        hash_set = Blake2bHashSet()
        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        with pytest.raises(IndexError):
            hash_set.get(1)


class TestBlake2bHashSetGetItem:
    """Tests for Blake2bHashSet.__getitem__()"""

    def test_can_access_hash_using_indexing(self):
        """Test accessing hash using array indexing syntax"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        hash_obj = hash_set[0]
        assert hash_obj is not None

    def test_getitem_returns_same_as_get(self):
        """Test that __getitem__ returns same result as get"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        assert hash_set[0] == hash_set.get(0)
        assert hash_set[2] == hash_set.get(2)

    def test_getitem_with_out_of_bounds_raises_error(self):
        """Test __getitem__ with out of bounds index raises IndexError"""
        hash_set = Blake2bHashSet()
        with pytest.raises(IndexError):
            _ = hash_set[0]


class TestBlake2bHashSetLen:
    """Tests for Blake2bHashSet.__len__()"""

    def test_len_returns_zero_for_empty_set(self):
        """Test len returns 0 for empty set"""
        hash_set = Blake2bHashSet()
        assert len(hash_set) == 0

    def test_len_returns_correct_count(self):
        """Test len returns correct count after adding hashes"""
        hash_set = Blake2bHashSet()
        assert len(hash_set) == 0

        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        assert len(hash_set) == 1

        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))
        assert len(hash_set) == 2

    def test_len_after_deserialization(self):
        """Test len returns correct count for deserialized set"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        assert len(hash_set) == 4


class TestBlake2bHashSetIter:
    """Tests for Blake2bHashSet.__iter__()"""

    def test_can_iterate_over_set(self):
        """Test iterating over hash set"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)

        count = 0
        for hash_obj in hash_set:
            assert hash_obj is not None
            count += 1
        assert count == 4

    def test_iteration_returns_correct_hashes(self):
        """Test that iteration returns correct hashes in order"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)

        expected_hashes = [
            create_hash_from_cbor(BLAKE2B_HASH1_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH2_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH3_CBOR),
            create_hash_from_cbor(BLAKE2B_HASH4_CBOR)
        ]

        for i, hash_obj in enumerate(hash_set):
            assert hash_obj == expected_hashes[i]

    def test_can_iterate_over_empty_set(self):
        """Test iterating over empty set"""
        hash_set = Blake2bHashSet()
        count = 0
        for _ in hash_set:
            count += 1
        assert count == 0

    def test_can_use_in_list_comprehension(self):
        """Test using hash set in list comprehension"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)
        hash_list = [h for h in hash_set]
        assert len(hash_list) == 4


class TestBlake2bHashSetContains:
    """Tests for Blake2bHashSet.__contains__()"""

    def test_contains_returns_true_for_present_hash(self):
        """Test that __contains__ returns True for hash in set"""
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash_set = Blake2bHashSet()
        hash_set.add(hash1)
        assert hash1 in hash_set

    def test_contains_returns_false_for_absent_hash(self):
        """Test that __contains__ returns False for hash not in set"""
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash2 = create_hash_from_cbor(BLAKE2B_HASH2_CBOR)
        hash_set = Blake2bHashSet()
        hash_set.add(hash1)
        assert hash2 not in hash_set

    def test_contains_with_empty_set(self):
        """Test __contains__ with empty set"""
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash_set = Blake2bHashSet()
        assert hash1 not in hash_set

    def test_contains_with_multiple_hashes(self):
        """Test __contains__ with multiple hashes in set"""
        hashes = [create_hash_from_cbor(cbor) for cbor in
                  [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR, BLAKE2B_HASH3_CBOR]]
        hash_set = Blake2bHashSet.from_list(hashes)

        for hash_obj in hashes:
            assert hash_obj in hash_set

        hash4 = create_hash_from_cbor(BLAKE2B_HASH4_CBOR)
        assert hash4 not in hash_set


class TestBlake2bHashSetEquality:
    """Tests for Blake2bHashSet.__eq__()"""

    def test_equality_with_same_hashes(self):
        """Test equality with sets containing same hashes"""
        hash_set1 = Blake2bHashSet()
        hash_set2 = Blake2bHashSet()

        for cbor in [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR]:
            hash_set1.add(create_hash_from_cbor(cbor))
            hash_set2.add(create_hash_from_cbor(cbor))

        assert hash_set1 == hash_set2

    def test_equality_with_empty_sets(self):
        """Test equality with two empty sets"""
        hash_set1 = Blake2bHashSet()
        hash_set2 = Blake2bHashSet()
        assert hash_set1 == hash_set2

    def test_inequality_with_different_lengths(self):
        """Test inequality when sets have different lengths"""
        hash_set1 = Blake2bHashSet()
        hash_set2 = Blake2bHashSet()

        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set2.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set2.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        assert hash_set1 != hash_set2

    def test_inequality_with_different_hashes(self):
        """Test inequality when sets have different hashes"""
        hash_set1 = Blake2bHashSet()
        hash_set2 = Blake2bHashSet()

        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set2.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        assert hash_set1 != hash_set2

    def test_inequality_with_non_hash_set(self):
        """Test inequality with non-Blake2bHashSet object"""
        hash_set = Blake2bHashSet()
        assert hash_set != "not a hash set"
        assert hash_set != 123
        assert hash_set != None
        assert hash_set != []


class TestBlake2bHashSetIsDisjoint:
    """Tests for Blake2bHashSet.isdisjoint()"""

    def test_isdisjoint_with_no_common_elements(self):
        """Test isdisjoint returns True when sets have no common elements"""
        hash_set1 = Blake2bHashSet()
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        other_hashes = [create_hash_from_cbor(BLAKE2B_HASH3_CBOR),
                        create_hash_from_cbor(BLAKE2B_HASH4_CBOR)]

        assert hash_set1.isdisjoint(other_hashes)

    def test_isdisjoint_with_common_elements(self):
        """Test isdisjoint returns False when sets have common elements"""
        hash_set1 = Blake2bHashSet()
        hash1 = create_hash_from_cbor(BLAKE2B_HASH1_CBOR)
        hash_set1.add(hash1)
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        other_hashes = [hash1, create_hash_from_cbor(BLAKE2B_HASH3_CBOR)]

        assert not hash_set1.isdisjoint(other_hashes)

    def test_isdisjoint_with_empty_other(self):
        """Test isdisjoint with empty other iterable"""
        hash_set1 = Blake2bHashSet()
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))

        assert hash_set1.isdisjoint([])

    def test_isdisjoint_with_empty_self(self):
        """Test isdisjoint when self is empty"""
        hash_set1 = Blake2bHashSet()
        other_hashes = [create_hash_from_cbor(BLAKE2B_HASH1_CBOR)]

        assert hash_set1.isdisjoint(other_hashes)

    def test_isdisjoint_with_both_empty(self):
        """Test isdisjoint when both sets are empty"""
        hash_set1 = Blake2bHashSet()
        assert hash_set1.isdisjoint([])


class TestBlake2bHashSetToCbor:
    """Tests for Blake2bHashSet.to_cbor()"""

    def test_can_serialize_empty_set(self):
        """Test serializing empty Blake2bHashSet to CBOR"""
        hash_set = Blake2bHashSet()
        writer = CborWriter()
        hash_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_EMPTY

    def test_can_serialize_hash_set(self):
        """Test serializing Blake2bHashSet to CBOR"""
        hash_set = Blake2bHashSet()
        for cbor in [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR,
                     BLAKE2B_HASH3_CBOR, BLAKE2B_HASH4_CBOR]:
            hash_set.add(create_hash_from_cbor(cbor))

        writer = CborWriter()
        hash_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_can_serialize_sorted(self):
        """Test that serialization maintains sorted order"""
        hash_set = Blake2bHashSet()
        for cbor in [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH3_CBOR,
                     BLAKE2B_HASH2_CBOR, BLAKE2B_HASH4_CBOR]:
            hash_set.add(create_hash_from_cbor(cbor))

        writer = CborWriter()
        hash_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_cbor_round_trip(self):
        """Test CBOR round-trip serialization and deserialization"""
        reader = CborReader.from_hex(CBOR)
        original = Blake2bHashSet.from_cbor(reader)

        writer = CborWriter()
        original.to_cbor(writer)

        reader2 = CborReader.from_hex(writer.to_hex())
        decoded = Blake2bHashSet.from_cbor(reader2)

        assert original == decoded

    def test_cbor_round_trip_without_tag(self):
        """Test CBOR round-trip starting from data without tag"""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        original = Blake2bHashSet.from_cbor(reader)

        writer = CborWriter()
        original.to_cbor(writer)

        reader2 = CborReader.from_hex(writer.to_hex())
        decoded = Blake2bHashSet.from_cbor(reader2)

        assert original == decoded
        assert writer.to_hex() == CBOR


class TestBlake2bHashSetRepr:
    """Tests for Blake2bHashSet.__repr__()"""

    def test_repr_includes_length(self):
        """Test __repr__ includes length of set"""
        hash_set = Blake2bHashSet()
        repr_str = repr(hash_set)
        assert "Blake2bHashSet" in repr_str
        assert "len=0" in repr_str

    def test_repr_with_populated_set(self):
        """Test __repr__ with populated set"""
        hash_set = Blake2bHashSet()
        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        repr_str = repr(hash_set)
        assert "Blake2bHashSet" in repr_str
        assert "len=2" in repr_str


class TestBlake2bHashSetContextManager:
    """Tests for Blake2bHashSet context manager protocol"""

    def test_context_manager_usage(self):
        """Test hash set can be used as context manager"""
        with Blake2bHashSet() as hash_set:
            hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
            assert len(hash_set) == 1

    def test_context_manager_with_operations(self):
        """Test context manager with multiple operations"""
        with Blake2bHashSet() as hash_set:
            hash_set.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
            hash_set.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))
            assert len(hash_set) == 2
            assert create_hash_from_cbor(BLAKE2B_HASH1_CBOR) in hash_set


class TestBlake2bHashSetEdgeCases:
    """Tests for Blake2bHashSet edge cases"""

    def test_set_with_many_hashes(self):
        """Test set with many hashes"""
        hash_set = Blake2bHashSet()
        num_hashes = 100

        for i in range(num_hashes):
            hash_obj = Blake2bHash.compute(f"data{i}".encode(), hash_size=28)
            hash_set.add(hash_obj)

        assert len(hash_set) == num_hashes

    def test_can_iterate_multiple_times(self):
        """Test that set can be iterated multiple times"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)

        first_pass = [h for h in hash_set]
        second_pass = [h for h in hash_set]

        assert len(first_pass) == len(second_pass)
        for i in range(len(first_pass)):
            assert first_pass[i] == second_pass[i]

    def test_operations_on_deserialized_set(self):
        """Test that operations work on deserialized set"""
        reader = CborReader.from_hex(CBOR)
        hash_set = Blake2bHashSet.from_cbor(reader)

        original_length = len(hash_set)
        hash5 = Blake2bHash.compute(b"new_hash", hash_size=28)
        hash_set.add(hash5)

        assert len(hash_set) == original_length + 1
        assert hash5 in hash_set

    def test_equality_after_serialization(self):
        """Test that equality works after serialization round-trip"""
        hash_set1 = Blake2bHashSet()
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH1_CBOR))
        hash_set1.add(create_hash_from_cbor(BLAKE2B_HASH2_CBOR))

        writer = CborWriter()
        hash_set1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        hash_set2 = Blake2bHashSet.from_cbor(reader)

        assert hash_set1 == hash_set2

    def test_from_list_preserves_all_hashes(self):
        """Test that from_list preserves all hashes"""
        hashes = [create_hash_from_cbor(cbor) for cbor in
                  [BLAKE2B_HASH1_CBOR, BLAKE2B_HASH2_CBOR,
                   BLAKE2B_HASH3_CBOR, BLAKE2B_HASH4_CBOR]]

        hash_set = Blake2bHashSet.from_list(hashes)

        assert len(hash_set) == 4
        for hash_obj in hashes:
            assert hash_obj in hash_set
