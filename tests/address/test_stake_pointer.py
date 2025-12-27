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
from cometa import StakePointer


class TestStakePointerCreation:
    """Tests for StakePointer initialization."""

    def test_can_create_with_valid_values(self):
        """Test that StakePointer can be created with valid positive values."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        assert pointer is not None
        assert pointer.slot == 2498243
        assert pointer.tx_index == 7
        assert pointer.cert_index == 0

    def test_can_create_with_zero_values(self):
        """Test that StakePointer can be created with all zero values."""
        pointer = StakePointer(slot=0, tx_index=0, cert_index=0)
        assert pointer is not None
        assert pointer.slot == 0
        assert pointer.tx_index == 0
        assert pointer.cert_index == 0

    def test_can_create_with_large_values(self):
        """Test that StakePointer can be created with large values."""
        pointer = StakePointer(slot=5756214, tx_index=999999, cert_index=65535)
        assert pointer is not None
        assert pointer.slot == 5756214
        assert pointer.tx_index == 999999
        assert pointer.cert_index == 65535

    def test_can_create_with_max_uint64_slot(self):
        """Test that StakePointer can be created with maximum uint64 slot value."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=max_uint64, tx_index=0, cert_index=0)
        assert pointer is not None
        assert pointer.slot == max_uint64

    def test_can_create_with_max_uint64_tx_index(self):
        """Test that StakePointer can be created with maximum uint64 tx_index value."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=0, tx_index=max_uint64, cert_index=0)
        assert pointer is not None
        assert pointer.tx_index == max_uint64

    def test_can_create_with_max_uint64_cert_index(self):
        """Test that StakePointer can be created with maximum uint64 cert_index value."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=0, tx_index=0, cert_index=max_uint64)
        assert pointer is not None
        assert pointer.cert_index == max_uint64

    def test_can_create_with_all_max_values(self):
        """Test that StakePointer can be created with all max uint64 values."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=max_uint64, tx_index=max_uint64, cert_index=max_uint64)
        assert pointer is not None
        assert pointer.slot == max_uint64
        assert pointer.tx_index == max_uint64
        assert pointer.cert_index == max_uint64


class TestStakePointerValidation:
    """Tests for StakePointer validation in __post_init__."""

    def test_raises_error_for_negative_slot(self):
        """Test that negative slot raises ValueError."""
        with pytest.raises(ValueError, match="slot must be non-negative"):
            StakePointer(slot=-1, tx_index=0, cert_index=0)

    def test_raises_error_for_negative_tx_index(self):
        """Test that negative tx_index raises ValueError."""
        with pytest.raises(ValueError, match="tx_index must be non-negative"):
            StakePointer(slot=0, tx_index=-1, cert_index=0)

    def test_raises_error_for_negative_cert_index(self):
        """Test that negative cert_index raises ValueError."""
        with pytest.raises(ValueError, match="cert_index must be non-negative"):
            StakePointer(slot=0, tx_index=0, cert_index=-1)

    def test_raises_error_for_all_negative_values(self):
        """Test that all negative values raise ValueError."""
        with pytest.raises(ValueError):
            StakePointer(slot=-1, tx_index=-1, cert_index=-1)

    def test_raises_error_for_large_negative_slot(self):
        """Test that large negative slot raises ValueError."""
        with pytest.raises(ValueError, match="slot must be non-negative"):
            StakePointer(slot=-999999, tx_index=0, cert_index=0)

    def test_raises_error_for_large_negative_tx_index(self):
        """Test that large negative tx_index raises ValueError."""
        with pytest.raises(ValueError, match="tx_index must be non-negative"):
            StakePointer(slot=0, tx_index=-999999, cert_index=0)

    def test_raises_error_for_large_negative_cert_index(self):
        """Test that large negative cert_index raises ValueError."""
        with pytest.raises(ValueError, match="cert_index must be non-negative"):
            StakePointer(slot=0, tx_index=0, cert_index=-999999)


class TestStakePointerEquality:
    """Tests for StakePointer equality comparison."""

    def test_equality_for_same_values(self):
        """Test that two StakePointers with same values are equal."""
        pointer1 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        pointer2 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        assert pointer1 == pointer2

    def test_equality_for_zero_values(self):
        """Test that two StakePointers with all zero values are equal."""
        pointer1 = StakePointer(slot=0, tx_index=0, cert_index=0)
        pointer2 = StakePointer(slot=0, tx_index=0, cert_index=0)
        assert pointer1 == pointer2

    def test_inequality_for_different_slots(self):
        """Test that StakePointers with different slots are not equal."""
        pointer1 = StakePointer(slot=100, tx_index=0, cert_index=0)
        pointer2 = StakePointer(slot=101, tx_index=0, cert_index=0)
        assert pointer1 != pointer2

    def test_inequality_for_different_tx_indexes(self):
        """Test that StakePointers with different tx_indexes are not equal."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=6, cert_index=0)
        assert pointer1 != pointer2

    def test_inequality_for_different_cert_indexes(self):
        """Test that StakePointers with different cert_indexes are not equal."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=5, cert_index=1)
        assert pointer1 != pointer2

    def test_inequality_with_non_stake_pointer(self):
        """Test that StakePointer is not equal to non-StakePointer objects."""
        pointer = StakePointer(slot=100, tx_index=5, cert_index=0)
        assert pointer != "not a stake pointer"
        assert pointer != 123
        assert pointer is not None
        assert pointer != (100, 5, 0)


class TestStakePointerHashing:
    """Tests for StakePointer hashing."""

    def test_hash_consistency(self):
        """Test that hash is consistent for the same object."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        hash1 = hash(pointer)
        hash2 = hash(pointer)
        assert hash1 == hash2

    def test_hash_equality_for_equal_objects(self):
        """Test that equal StakePointers have the same hash."""
        pointer1 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        pointer2 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        assert hash(pointer1) == hash(pointer2)

    def test_hash_inequality_for_different_slots(self):
        """Test that different slots produce different hashes."""
        pointer1 = StakePointer(slot=100, tx_index=0, cert_index=0)
        pointer2 = StakePointer(slot=101, tx_index=0, cert_index=0)
        assert hash(pointer1) != hash(pointer2)

    def test_hash_inequality_for_different_tx_indexes(self):
        """Test that different tx_indexes produce different hashes."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=6, cert_index=0)
        assert hash(pointer1) != hash(pointer2)

    def test_hash_inequality_for_different_cert_indexes(self):
        """Test that different cert_indexes produce different hashes."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=5, cert_index=1)
        assert hash(pointer1) != hash(pointer2)

    def test_can_use_in_set(self):
        """Test that StakePointers can be used in a set."""
        pointer1 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        pointer2 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        pointer3 = StakePointer(slot=5756214, tx_index=1, cert_index=0)

        pointer_set = {pointer1, pointer2, pointer3}
        assert len(pointer_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that StakePointers can be used as dictionary keys."""
        pointer1 = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        pointer2 = StakePointer(slot=2498243, tx_index=7, cert_index=0)

        pointer_dict = {pointer1: "value1"}
        pointer_dict[pointer2] = "value2"

        assert len(pointer_dict) == 1
        assert pointer_dict[pointer1] == "value2"


class TestStakePointerRepr:
    """Tests for StakePointer string representation."""

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains the class name."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        repr_str = repr(pointer)
        assert "StakePointer" in repr_str

    def test_repr_contains_slot(self):
        """Test that __repr__ contains the slot value."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        repr_str = repr(pointer)
        assert "slot=2498243" in repr_str

    def test_repr_contains_tx_index(self):
        """Test that __repr__ contains the tx_index value."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        repr_str = repr(pointer)
        assert "tx_index=7" in repr_str

    def test_repr_contains_cert_index(self):
        """Test that __repr__ contains the cert_index value."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        repr_str = repr(pointer)
        assert "cert_index=0" in repr_str

    def test_repr_with_zero_values(self):
        """Test __repr__ with all zero values."""
        pointer = StakePointer(slot=0, tx_index=0, cert_index=0)
        repr_str = repr(pointer)
        assert "slot=0" in repr_str
        assert "tx_index=0" in repr_str
        assert "cert_index=0" in repr_str

    def test_repr_with_large_values(self):
        """Test __repr__ with large values."""
        pointer = StakePointer(slot=5756214, tx_index=999999, cert_index=65535)
        repr_str = repr(pointer)
        assert "slot=5756214" in repr_str
        assert "tx_index=999999" in repr_str
        assert "cert_index=65535" in repr_str


class TestStakePointerFrozen:
    """Tests for StakePointer frozen dataclass behavior."""

    def test_cannot_modify_slot(self):
        """Test that slot cannot be modified after creation (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            pointer.slot = 9999

    def test_cannot_modify_tx_index(self):
        """Test that tx_index cannot be modified after creation (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            pointer.tx_index = 9999

    def test_cannot_modify_cert_index(self):
        """Test that cert_index cannot be modified after creation (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            pointer.cert_index = 9999

    def test_cannot_add_new_attribute(self):
        """Test that new attributes cannot be added (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            pointer.new_attr = "value"

    def test_cannot_delete_slot(self):
        """Test that slot cannot be deleted (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            del pointer.slot

    def test_cannot_delete_tx_index(self):
        """Test that tx_index cannot be deleted (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            del pointer.tx_index

    def test_cannot_delete_cert_index(self):
        """Test that cert_index cannot be deleted (frozen)."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        with pytest.raises(AttributeError):
            del pointer.cert_index


class TestStakePointerEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_can_create_multiple_instances(self):
        """Test that multiple independent instances can be created."""
        pointer1 = StakePointer(slot=100, tx_index=1, cert_index=0)
        pointer2 = StakePointer(slot=200, tx_index=2, cert_index=1)
        pointer3 = StakePointer(slot=300, tx_index=3, cert_index=2)

        assert pointer1.slot == 100
        assert pointer2.slot == 200
        assert pointer3.slot == 300

    def test_different_combinations_of_values(self):
        """Test various combinations of slot, tx_index, and cert_index values."""
        test_cases = [
            (0, 0, 0),
            (1, 0, 0),
            (0, 1, 0),
            (0, 0, 1),
            (1, 1, 0),
            (1, 0, 1),
            (0, 1, 1),
            (1, 1, 1),
            (5756214, 1, 0),
            (2498243, 7, 0),
            (12345, 67890, 24680),
        ]
        for slot, tx_index, cert_index in test_cases:
            pointer = StakePointer(slot=slot, tx_index=tx_index, cert_index=cert_index)
            assert pointer.slot == slot
            assert pointer.tx_index == tx_index
            assert pointer.cert_index == cert_index

    def test_field_access_order_independence(self):
        """Test that fields can be accessed in any order."""
        pointer = StakePointer(slot=2498243, tx_index=7, cert_index=0)
        assert pointer.cert_index == 0
        assert pointer.slot == 2498243
        assert pointer.tx_index == 7
        assert pointer.slot == 2498243
        assert pointer.cert_index == 0

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=5, cert_index=0)
        assert pointer1 == pointer2
        assert pointer2 == pointer1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        pointer1 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer2 = StakePointer(slot=100, tx_index=5, cert_index=0)
        pointer3 = StakePointer(slot=100, tx_index=5, cert_index=0)
        assert pointer1 == pointer2
        assert pointer2 == pointer3
        assert pointer1 == pointer3

    def test_slot_boundary_value(self):
        """Test slot with boundary value (one less than max)."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=max_uint64 - 1, tx_index=0, cert_index=0)
        assert pointer.slot == max_uint64 - 1

    def test_tx_index_boundary_value(self):
        """Test tx_index with boundary value (one less than max)."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=0, tx_index=max_uint64 - 1, cert_index=0)
        assert pointer.tx_index == max_uint64 - 1

    def test_cert_index_boundary_value(self):
        """Test cert_index with boundary value (one less than max)."""
        max_uint64 = 18446744073709551615
        pointer = StakePointer(slot=0, tx_index=0, cert_index=max_uint64 - 1)
        assert pointer.cert_index == max_uint64 - 1

    def test_typical_mainnet_values(self):
        """Test with typical mainnet stake pointer values."""
        pointer = StakePointer(slot=5756214, tx_index=1, cert_index=0)
        assert pointer.slot == 5756214
        assert pointer.tx_index == 1
        assert pointer.cert_index == 0

    def test_early_blockchain_values(self):
        """Test with early blockchain slot values."""
        pointer = StakePointer(slot=100, tx_index=0, cert_index=0)
        assert pointer.slot == 100
        assert pointer.tx_index == 0
        assert pointer.cert_index == 0
