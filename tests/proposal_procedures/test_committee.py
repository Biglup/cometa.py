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
    Committee,
    Credential,
    CredentialSet,
    UnitInterval,
    CborReader,
    CborWriter,
    CardanoError
)


CBOR = "82a48200581c00000000000000000000000000000000000000000000000000000000008200581c10000000000000000000000000000000000000000000000000000000018200581c20000000000000000000000000000000000000000000000000000000028200581c3000000000000000000000000000000000000000000000000000000003d81e820502"
CREDENTIAL1_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL2_CBOR = "8200581c10000000000000000000000000000000000000000000000000000000"
CREDENTIAL3_CBOR = "8200581c20000000000000000000000000000000000000000000000000000000"
CREDENTIAL4_CBOR = "8200581c30000000000000000000000000000000000000000000000000000000"


def create_credential_from_cbor(cbor_hex: str) -> Credential:
    """Helper function to create a credential from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return Credential.from_cbor(reader)


def create_default_committee() -> Committee:
    """Helper function to create a default committee from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return Committee.from_cbor(reader)


class TestCommittee:
    """Tests for the Committee class."""

    def test_new_creates_committee(self):
        """Test creating a new committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        assert committee is not None

    def test_new_with_null_quorum_threshold_raises_error(self):
        """Test that creating committee with null quorum threshold raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Committee.new(None)

    def test_from_cbor_deserializes_committee(self):
        """Test deserializing a committee from CBOR."""
        reader = CborReader.from_hex(CBOR)
        committee = Committee.from_cbor(reader)

        assert committee is not None

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Committee.from_cbor(None)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that invalid CBOR raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            Committee.from_cbor(reader)

    def test_from_cbor_with_invalid_array_size_raises_error(self):
        """Test that invalid array size raises error."""
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            Committee.from_cbor(reader)

    def test_from_cbor_with_invalid_map_raises_error(self):
        """Test that invalid map in CBOR raises error."""
        reader = CborReader.from_hex("82ef")

        with pytest.raises(CardanoError):
            Committee.from_cbor(reader)

    def test_from_cbor_with_invalid_threshold_raises_error(self):
        """Test that invalid threshold in CBOR raises error."""
        reader = CborReader.from_hex("82a0ef")

        with pytest.raises(CardanoError):
            Committee.from_cbor(reader)

    def test_to_cbor_serializes_committee(self):
        """Test serializing a committee to CBOR."""
        committee = create_default_committee()
        writer = CborWriter()
        committee.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that serializing with null writer raises error."""
        committee = create_default_committee()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            committee.to_cbor(None)

    def test_cbor_round_trip(self):
        """Test that CBOR serialization and deserialization are inverses."""
        reader = CborReader.from_hex(CBOR)
        committee = Committee.from_cbor(reader)

        writer = CborWriter()
        committee.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_get_quorum_threshold(self):
        """Test getting the quorum threshold."""
        committee = create_default_committee()
        quorum_threshold = committee.quorum_threshold

        assert quorum_threshold is not None

    def test_set_quorum_threshold(self):
        """Test setting the quorum threshold."""
        committee = create_default_committee()
        new_threshold = UnitInterval.new(3, 5)

        committee.quorum_threshold = new_threshold

        retrieved = committee.quorum_threshold
        assert retrieved.numerator == 3
        assert retrieved.denominator == 5

    def test_set_quorum_threshold_with_null_raises_error(self):
        """Test that setting quorum threshold with null raises error."""
        committee = create_default_committee()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            committee.quorum_threshold = None

    def test_members_keys_returns_credential_set(self):
        """Test getting members keys returns a credential set."""
        committee = create_default_committee()
        keys = committee.members_keys()

        assert keys is not None
        assert isinstance(keys, CredentialSet)

    def test_members_keys_returns_correct_count(self):
        """Test that members_keys returns correct number of members."""
        committee = create_default_committee()
        keys = committee.members_keys()

        assert len(keys) == 4

    def test_add_member_adds_credential(self):
        """Test adding a member to the committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)

        committee.add_member(credential, 100)

        keys = committee.members_keys()
        assert len(keys) == 1

    def test_add_member_with_null_committee_raises_error(self):
        """Test that adding member with null credential raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            committee.add_member(None, 100)

    def test_add_multiple_members(self):
        """Test adding multiple members to the committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        credential1 = create_credential_from_cbor(CREDENTIAL1_CBOR)
        credential2 = create_credential_from_cbor(CREDENTIAL2_CBOR)

        committee.add_member(credential1, 100)
        committee.add_member(credential2, 200)

        keys = committee.members_keys()
        assert len(keys) == 2

    def test_get_member_epoch_returns_correct_epoch(self):
        """Test getting member epoch returns correct value."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        expected_epoch = 123

        committee.add_member(credential, expected_epoch)
        actual_epoch = committee.get_member_epoch(credential)

        assert actual_epoch == expected_epoch

    def test_get_member_epoch_returns_zero_for_missing_credential(self):
        """Test that getting epoch for missing credential returns zero."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential1 = create_credential_from_cbor(CREDENTIAL1_CBOR)
        credential2 = create_credential_from_cbor(CREDENTIAL2_CBOR)

        committee.add_member(credential1, 100)
        epoch = committee.get_member_epoch(credential2)

        assert epoch == 0

    def test_get_key_at_returns_credential(self):
        """Test getting credential by index."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential1 = create_credential_from_cbor(CREDENTIAL1_CBOR)
        credential2 = create_credential_from_cbor(CREDENTIAL2_CBOR)

        committee.add_member(credential1, 100)
        committee.add_member(credential2, 200)

        retrieved = committee.get_key_at(0)
        assert retrieved is not None

    def test_get_key_at_with_invalid_index_raises_error(self):
        """Test that getting key with invalid index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        with pytest.raises(CardanoError):
            committee.get_key_at(0)

    def test_get_key_at_with_out_of_bounds_raises_error(self):
        """Test that getting key with out of bounds index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        committee.add_member(credential, 100)

        with pytest.raises(CardanoError):
            committee.get_key_at(1)

    def test_get_value_at_returns_epoch(self):
        """Test getting epoch by index."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        expected_epoch = 250

        committee.add_member(credential, expected_epoch)
        actual_epoch = committee.get_value_at(0)

        assert actual_epoch == expected_epoch

    def test_get_value_at_with_invalid_index_raises_error(self):
        """Test that getting value with invalid index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        with pytest.raises(CardanoError):
            committee.get_value_at(0)

    def test_get_value_at_with_out_of_bounds_raises_error(self):
        """Test that getting value with out of bounds index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        committee.add_member(credential, 100)

        with pytest.raises(CardanoError):
            committee.get_value_at(1)

    def test_get_key_value_at_returns_pair(self):
        """Test getting key-value pair by index."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        expected_epoch = 300

        committee.add_member(credential, expected_epoch)
        retrieved_cred, retrieved_epoch = committee.get_key_value_at(0)

        assert retrieved_cred is not None
        assert retrieved_epoch == expected_epoch

    def test_get_key_value_at_with_invalid_index_raises_error(self):
        """Test that getting key-value pair with invalid index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        with pytest.raises(CardanoError):
            committee.get_key_value_at(0)

    def test_get_key_value_at_with_out_of_bounds_raises_error(self):
        """Test that getting key-value pair with out of bounds index raises error."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        committee.add_member(credential, 100)

        with pytest.raises(CardanoError):
            committee.get_key_value_at(1)

    def test_iter_iterates_over_credentials(self):
        """Test iterating over committee members."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        committee.add_member(create_credential_from_cbor(CREDENTIAL1_CBOR), 100)
        committee.add_member(create_credential_from_cbor(CREDENTIAL2_CBOR), 200)
        committee.add_member(create_credential_from_cbor(CREDENTIAL3_CBOR), 300)

        count = 0
        for cred in committee:
            assert cred is not None
            count += 1

        assert count == 3

    def test_items_returns_credential_epoch_pairs(self):
        """Test that items() returns credential-epoch pairs."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        committee.add_member(create_credential_from_cbor(CREDENTIAL1_CBOR), 100)
        committee.add_member(create_credential_from_cbor(CREDENTIAL2_CBOR), 200)

        items = list(committee.items())
        assert len(items) == 2

        cred1, epoch1 = items[0]
        assert cred1 is not None
        assert epoch1 == 100

        cred2, epoch2 = items[1]
        assert cred2 is not None
        assert epoch2 == 200

    def test_context_manager(self):
        """Test using committee as context manager."""
        quorum_threshold = UnitInterval.new(2, 5)

        with Committee.new(quorum_threshold) as committee:
            assert committee is not None
            credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
            committee.add_member(credential, 100)
            keys = committee.members_keys()
            assert len(keys) == 1

    def test_repr(self):
        """Test __repr__ method."""
        committee = create_default_committee()
        repr_str = repr(committee)

        assert "Committee" in repr_str

    def test_committee_lifecycle(self):
        """Test committee creation and cleanup."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        committee.add_member(credential, 100)
        keys = committee.members_keys()
        length = len(keys)
        del committee

        new_committee = Committee.new(quorum_threshold)
        new_committee.add_member(create_credential_from_cbor(CREDENTIAL1_CBOR), 100)
        new_keys = new_committee.members_keys()
        assert len(new_keys) == length

    def test_multiple_committees_independent(self):
        """Test that multiple committees are independent."""
        quorum_threshold1 = UnitInterval.new(2, 5)
        quorum_threshold2 = UnitInterval.new(3, 5)

        committee1 = Committee.new(quorum_threshold1)
        committee2 = Committee.new(quorum_threshold2)

        committee1.add_member(create_credential_from_cbor(CREDENTIAL1_CBOR), 100)

        keys1 = committee1.members_keys()
        keys2 = committee2.members_keys()

        assert len(keys1) == 1
        assert len(keys2) == 0

    def test_deserialized_committee_has_correct_members(self):
        """Test that deserialized committee has correct member count."""
        reader = CborReader.from_hex(CBOR)
        committee = Committee.from_cbor(reader)

        keys = committee.members_keys()
        assert len(keys) == 4

    def test_deserialized_committee_has_correct_epochs(self):
        """Test that deserialized committee has correct epoch values."""
        reader = CborReader.from_hex(CBOR)
        committee = Committee.from_cbor(reader)

        epoch0 = committee.get_value_at(0)
        epoch1 = committee.get_value_at(1)
        epoch2 = committee.get_value_at(2)
        epoch3 = committee.get_value_at(3)

        assert epoch0 == 0
        assert epoch1 == 1
        assert epoch2 == 2
        assert epoch3 == 3

    def test_empty_committee_iteration(self):
        """Test iterating over an empty committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        count = 0
        for _ in committee:
            count += 1

        assert count == 0

    def test_empty_committee_items(self):
        """Test items() on an empty committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        items = list(committee.items())
        assert len(items) == 0

    def test_quorum_threshold_property_read_write(self):
        """Test quorum threshold property can be read and written."""
        quorum_threshold = UnitInterval.new(1, 2)
        committee = Committee.new(quorum_threshold)

        retrieved = committee.quorum_threshold
        assert retrieved.numerator == 1
        assert retrieved.denominator == 2

        new_threshold = UnitInterval.new(3, 4)
        committee.quorum_threshold = new_threshold

        retrieved = committee.quorum_threshold
        assert retrieved.numerator == 3
        assert retrieved.denominator == 4

    def test_add_member_with_zero_epoch(self):
        """Test adding a member with zero epoch."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)

        committee.add_member(credential, 0)
        epoch = committee.get_member_epoch(credential)

        assert epoch == 0

    def test_add_member_with_large_epoch(self):
        """Test adding a member with large epoch value."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)
        large_epoch = 999999999

        committee.add_member(credential, large_epoch)
        epoch = committee.get_member_epoch(credential)

        assert epoch == large_epoch

    def test_members_keys_returns_empty_for_new_committee(self):
        """Test that members_keys returns empty set for new committee."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        keys = committee.members_keys()
        assert len(keys) == 0

    def test_get_key_at_multiple_indices(self):
        """Test getting keys at multiple indices."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        credential1 = create_credential_from_cbor(CREDENTIAL1_CBOR)
        credential2 = create_credential_from_cbor(CREDENTIAL2_CBOR)
        credential3 = create_credential_from_cbor(CREDENTIAL3_CBOR)

        committee.add_member(credential1, 100)
        committee.add_member(credential2, 200)
        committee.add_member(credential3, 300)

        key0 = committee.get_key_at(0)
        key1 = committee.get_key_at(1)
        key2 = committee.get_key_at(2)

        assert key0 is not None
        assert key1 is not None
        assert key2 is not None

    def test_get_value_at_multiple_indices(self):
        """Test getting values at multiple indices."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)

        committee.add_member(create_credential_from_cbor(CREDENTIAL1_CBOR), 100)
        committee.add_member(create_credential_from_cbor(CREDENTIAL2_CBOR), 200)
        committee.add_member(create_credential_from_cbor(CREDENTIAL3_CBOR), 300)

        assert committee.get_value_at(0) == 100
        assert committee.get_value_at(1) == 200
        assert committee.get_value_at(2) == 300

    def test_committee_with_duplicate_credentials(self):
        """Test adding the same credential multiple times with different epochs."""
        quorum_threshold = UnitInterval.new(2, 5)
        committee = Committee.new(quorum_threshold)
        credential = create_credential_from_cbor(CREDENTIAL1_CBOR)

        committee.add_member(credential, 100)
        committee.add_member(credential, 200)

        keys = committee.members_keys()
        assert len(keys) == 2
