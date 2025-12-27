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
    CredentialSet,
    Credential,
    CredentialType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "d90102848200581c000000000000000000000000000000000000000000000000000000008200581c100000000000000000000000000000000000000000000000000000008200581c200000000000000000000000000000000000000000000000000000008200581c30000000000000000000000000000000000000000000000000000000"
CBOR_WITHOUT_TAG = "848200581c000000000000000000000000000000000000000000000000000000008200581c100000000000000000000000000000000000000000000000000000008200581c200000000000000000000000000000000000000000000000000000008200581c30000000000000000000000000000000000000000000000000000000"
CREDENTIAL1_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL2_CBOR = "8200581c10000000000000000000000000000000000000000000000000000000"
CREDENTIAL3_CBOR = "8200581c20000000000000000000000000000000000000000000000000000000"
CREDENTIAL4_CBOR = "8200581c30000000000000000000000000000000000000000000000000000000"
EMPTY_SET_CBOR = "d9010280"

CREDENTIAL1_HEX = "00000000000000000000000000000000000000000000000000000000"
CREDENTIAL2_HEX = "10000000000000000000000000000000000000000000000000000000"
CREDENTIAL3_HEX = "20000000000000000000000000000000000000000000000000000000"
CREDENTIAL4_HEX = "30000000000000000000000000000000000000000000000000000000"


def create_credential_from_cbor(cbor_hex: str) -> Credential:
    """Helper function to create a credential from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return Credential.from_cbor(reader)


class TestCredentialSet:
    """Tests for the CredentialSet class."""

    def test_new_creates_empty_set(self):
        """Test creating a new empty credential set."""
        cred_set = CredentialSet()
        assert cred_set is not None
        assert len(cred_set) == 0

    def test_to_cbor_empty_set(self):
        """Test serializing an empty credential set to CBOR."""
        cred_set = CredentialSet()
        writer = CborWriter()
        cred_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == EMPTY_SET_CBOR

    def test_to_cbor_with_credentials(self):
        """Test serializing a credential set with credentials to CBOR."""
        cred_set = CredentialSet()

        credentials = [
            create_credential_from_cbor(CREDENTIAL1_CBOR),
            create_credential_from_cbor(CREDENTIAL2_CBOR),
            create_credential_from_cbor(CREDENTIAL3_CBOR),
            create_credential_from_cbor(CREDENTIAL4_CBOR)
        ]

        for cred in credentials:
            cred_set.add(cred)

        writer = CborWriter()
        cred_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that serializing with null writer raises error."""
        cred_set = CredentialSet()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            cred_set.to_cbor(None)

    def test_from_cbor_deserializes_set(self):
        """Test deserializing a credential set from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cred_set = CredentialSet.from_cbor(reader)

        assert cred_set is not None
        assert len(cred_set) == 4

    def test_from_cbor_deserializes_empty_set(self):
        """Test deserializing an empty credential set from CBOR."""
        reader = CborReader.from_hex(EMPTY_SET_CBOR)
        cred_set = CredentialSet.from_cbor(reader)

        assert cred_set is not None
        assert len(cred_set) == 0

    def test_from_cbor_with_tag(self):
        """Test deserializing a credential set from CBOR with tag."""
        reader = CborReader.from_hex(CBOR)
        cred_set = CredentialSet.from_cbor(reader)

        assert cred_set is not None
        assert len(cred_set) == 4

    def test_from_cbor_without_tag(self):
        """Test deserializing a credential set from CBOR without tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        cred_set = CredentialSet.from_cbor(reader)

        assert cred_set is not None
        assert len(cred_set) == 4

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")

        with pytest.raises(CardanoError):
            CredentialSet.from_cbor(reader)

    def test_from_cbor_with_invalid_array_raises_error(self):
        """Test that invalid CBOR array raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            CredentialSet.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test that invalid credential elements raise error."""
        reader = CborReader.from_hex("9ffeff")

        with pytest.raises(CardanoError):
            CredentialSet.from_cbor(reader)

    def test_from_cbor_with_missing_end_array_raises_error(self):
        """Test that missing end array raises error."""
        reader = CborReader.from_hex("9f01")

        with pytest.raises(CardanoError):
            CredentialSet.from_cbor(reader)

    def test_cbor_round_trip(self):
        """Test that CBOR serialization and deserialization are inverses."""
        reader = CborReader.from_hex(CBOR)
        cred_set = CredentialSet.from_cbor(reader)

        writer = CborWriter()
        cred_set.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_cbor_round_trip_without_tag(self):
        """Test CBOR round trip with input without tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        cred_set = CredentialSet.from_cbor(reader)

        writer = CborWriter()
        cred_set.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_add_credential(self):
        """Test adding a credential to the set."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)

        cred_set.add(cred)

        assert len(cred_set) == 1

    def test_add_multiple_credentials(self):
        """Test adding multiple credentials to the set."""
        cred_set = CredentialSet()

        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred2 = Credential.from_key_hash(CREDENTIAL2_HEX)
        cred3 = Credential.from_key_hash(CREDENTIAL3_HEX)

        cred_set.add(cred1)
        cred_set.add(cred2)
        cred_set.add(cred3)

        assert len(cred_set) == 3

    def test_add_null_credential_raises_error(self):
        """Test that adding null credential raises error."""
        cred_set = CredentialSet()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            cred_set.add(None)

    def test_get_credential_by_index(self):
        """Test retrieving a credential by index."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred)

        retrieved = cred_set.get(0)

        assert retrieved is not None
        assert retrieved.hash_hex == CREDENTIAL1_HEX

    def test_get_with_invalid_index_raises_error(self):
        """Test that getting with invalid index raises error."""
        cred_set = CredentialSet()

        with pytest.raises(IndexError):
            cred_set.get(0)

    def test_get_with_negative_index_raises_error(self):
        """Test that getting with negative index raises error."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred)

        with pytest.raises(IndexError):
            cred_set.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self):
        """Test that getting with out of bounds index raises error."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred)

        with pytest.raises(IndexError):
            cred_set.get(1)

    def test_len_returns_size(self):
        """Test that len() returns correct size."""
        cred_set = CredentialSet()
        assert len(cred_set) == 0

        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
        assert len(cred_set) == 1

        cred_set.add(Credential.from_key_hash(CREDENTIAL2_HEX))
        assert len(cred_set) == 2

    def test_iter_iterates_over_credentials(self):
        """Test iterating over credentials in the set."""
        cred_set = CredentialSet()
        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
        cred_set.add(Credential.from_key_hash(CREDENTIAL2_HEX))
        cred_set.add(Credential.from_key_hash(CREDENTIAL3_HEX))

        count = 0
        for cred in cred_set:
            assert cred is not None
            count += 1

        assert count == 3

    def test_getitem_bracket_notation(self):
        """Test getting credential using bracket notation."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred)

        retrieved = cred_set[0]

        assert retrieved is not None
        assert retrieved.hash_hex == CREDENTIAL1_HEX

    def test_getitem_with_invalid_index_raises_error(self):
        """Test that bracket notation with invalid index raises error."""
        cred_set = CredentialSet()

        with pytest.raises(IndexError):
            _ = cred_set[0]

    def test_bool_returns_true_for_non_empty_set(self):
        """Test that bool() returns True for non-empty set."""
        cred_set = CredentialSet()
        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        assert bool(cred_set) is True

    def test_bool_returns_false_for_empty_set(self):
        """Test that bool() returns False for empty set."""
        cred_set = CredentialSet()

        assert bool(cred_set) is False

    def test_contains_finds_credential(self):
        """Test that __contains__ finds credential in set."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred)

        assert cred in cred_set

    def test_contains_returns_false_for_missing_credential(self):
        """Test that __contains__ returns False for missing credential."""
        cred_set = CredentialSet()
        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred2 = Credential.from_key_hash(CREDENTIAL2_HEX)
        cred_set.add(cred1)

        assert cred2 not in cred_set

    def test_contains_with_non_credential_returns_false(self):
        """Test that __contains__ returns False for non-Credential object."""
        cred_set = CredentialSet()
        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        assert "not a credential" not in cred_set
        assert 123 not in cred_set
        assert None not in cred_set

    def test_isdisjoint_with_disjoint_sets(self):
        """Test isdisjoint with disjoint sets."""
        cred_set1 = CredentialSet()
        cred_set1.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        cred_set2 = CredentialSet()
        cred_set2.add(Credential.from_key_hash(CREDENTIAL2_HEX))

        assert cred_set1.isdisjoint(cred_set2) is True

    def test_isdisjoint_with_overlapping_sets(self):
        """Test isdisjoint with overlapping sets."""
        cred_set1 = CredentialSet()
        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set1.add(cred1)

        cred_set2 = CredentialSet()
        cred_set2.add(cred1)
        cred_set2.add(Credential.from_key_hash(CREDENTIAL2_HEX))

        assert cred_set1.isdisjoint(cred_set2) is False

    def test_isdisjoint_with_empty_set(self):
        """Test isdisjoint with empty set."""
        cred_set1 = CredentialSet()
        cred_set1.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        cred_set2 = CredentialSet()

        assert cred_set1.isdisjoint(cred_set2) is True

    def test_isdisjoint_with_list(self):
        """Test isdisjoint with Python list."""
        cred_set = CredentialSet()
        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred_set.add(cred1)

        cred_list = [Credential.from_key_hash(CREDENTIAL2_HEX)]

        assert cred_set.isdisjoint(cred_list) is True

    def test_from_list_creates_set_from_iterable(self):
        """Test creating a credential set from a list."""
        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred2 = Credential.from_key_hash(CREDENTIAL2_HEX)

        cred_set = CredentialSet.from_list([cred1, cred2])

        assert cred_set is not None
        assert len(cred_set) == 2

    def test_from_list_with_empty_list(self):
        """Test creating a credential set from an empty list."""
        cred_set = CredentialSet.from_list([])

        assert cred_set is not None
        assert len(cred_set) == 0

    def test_from_list_with_generator(self):
        """Test creating a credential set from a generator."""
        def cred_generator():
            yield Credential.from_key_hash(CREDENTIAL1_HEX)
            yield Credential.from_key_hash(CREDENTIAL2_HEX)

        cred_set = CredentialSet.from_list(cred_generator())

        assert cred_set is not None
        assert len(cred_set) == 2

    def test_to_cip116_json_with_credentials(self):
        """Test converting credential set to CIP-116 JSON."""
        cred_set = CredentialSet()

        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred2 = Credential.from_script_hash(
            bytes.fromhex("0d93bffbd38c1a5da47b6e93471f7e3c5ae52da6c12b687b11e2d3d1")
        )

        cred_set.add(cred1)
        cred_set.add(cred2)

        writer = JsonWriter()
        cred_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"pubkey_hash"' in json_str
        assert f'"value":"{CREDENTIAL1_HEX}"' in json_str
        assert '"tag":"script_hash"' in json_str
        assert '"value":"0d93bffbd38c1a5da47b6e93471f7e3c5ae52da6c12b687b11e2d3d1"' in json_str

    def test_to_cip116_json_with_empty_set(self):
        """Test converting empty credential set to CIP-116 JSON."""
        cred_set = CredentialSet()

        writer = JsonWriter()
        cred_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == "[]"

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that passing invalid writer to to_cip116_json raises error."""
        cred_set = CredentialSet()

        with pytest.raises(TypeError):
            cred_set.to_cip116_json("not a writer")

    def test_to_cip116_json_with_null_writer_raises_error(self):
        """Test that passing null writer to to_cip116_json raises error."""
        cred_set = CredentialSet()

        with pytest.raises((TypeError, AttributeError)):
            cred_set.to_cip116_json(None)

    def test_repr(self):
        """Test __repr__ method."""
        cred_set = CredentialSet()
        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        repr_str = repr(cred_set)

        assert "CredentialSet" in repr_str
        assert "len=1" in repr_str

    def test_repr_empty_set(self):
        """Test __repr__ for empty set."""
        cred_set = CredentialSet()

        repr_str = repr(cred_set)

        assert "CredentialSet" in repr_str
        assert "len=0" in repr_str

    def test_context_manager(self):
        """Test using credential set as context manager."""
        with CredentialSet() as cred_set:
            assert cred_set is not None
            cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
            assert len(cred_set) == 1

    def test_credential_set_lifecycle(self):
        """Test credential set creation and cleanup."""
        cred_set = CredentialSet()
        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
        length = len(cred_set)
        del cred_set

        new_set = CredentialSet()
        new_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
        assert len(new_set) == length

    def test_credentials_from_deserialized_set_match_original(self):
        """Test that credentials from deserialized set match original."""
        reader = CborReader.from_hex(CBOR)
        cred_set = CredentialSet.from_cbor(reader)

        credentials = [
            CREDENTIAL1_CBOR,
            CREDENTIAL2_CBOR,
            CREDENTIAL3_CBOR,
            CREDENTIAL4_CBOR
        ]

        for i, expected_cbor in enumerate(credentials):
            cred = cred_set.get(i)
            writer = CborWriter()
            cred.to_cbor(writer)
            assert writer.to_hex() == expected_cbor

    def test_multiple_sets_independent(self):
        """Test that multiple credential sets are independent."""
        cred_set1 = CredentialSet()
        cred_set2 = CredentialSet()

        cred_set1.add(Credential.from_key_hash(CREDENTIAL1_HEX))

        assert len(cred_set1) == 1
        assert len(cred_set2) == 0

    def test_set_with_mixed_credential_types(self):
        """Test credential set with mixed key hash and script hash credentials."""
        cred_set = CredentialSet()

        cred_set.add(Credential.from_key_hash(CREDENTIAL1_HEX))
        cred_set.add(Credential.from_script_hash(CREDENTIAL2_HEX))

        assert len(cred_set) == 2
        assert cred_set[0].type == CredentialType.KEY_HASH
        assert cred_set[1].type == CredentialType.SCRIPT_HASH

    def test_iterate_empty_set(self):
        """Test iterating over an empty set."""
        cred_set = CredentialSet()

        count = 0
        for _ in cred_set:
            count += 1

        assert count == 0

    def test_add_same_credential_multiple_times(self):
        """Test adding the same credential multiple times."""
        cred_set = CredentialSet()
        cred = Credential.from_key_hash(CREDENTIAL1_HEX)

        cred_set.add(cred)
        cred_set.add(cred)

        assert len(cred_set) == 2

    def test_large_credential_set(self):
        """Test creating a large credential set."""
        cred_set = CredentialSet()

        for i in range(100):
            hash_hex = f"{i:056x}"
            cred = Credential.from_key_hash(hash_hex)
            cred_set.add(cred)

        assert len(cred_set) == 100

    def test_from_list_preserves_order(self):
        """Test that from_list preserves order of credentials."""
        cred1 = Credential.from_key_hash(CREDENTIAL1_HEX)
        cred2 = Credential.from_key_hash(CREDENTIAL2_HEX)
        cred3 = Credential.from_key_hash(CREDENTIAL3_HEX)

        cred_set = CredentialSet.from_list([cred1, cred2, cred3])

        assert cred_set[0].hash_hex == CREDENTIAL1_HEX
        assert cred_set[1].hash_hex == CREDENTIAL2_HEX
        assert cred_set[2].hash_hex == CREDENTIAL3_HEX
