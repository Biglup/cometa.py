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
    Voter,
    VoterType,
    Credential,
    CredentialType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CBOR_2 = "8200581c00000000000000000000000000000000000000000000000000000001"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"


class TestVoter:
    """Tests for the Voter class."""

    @pytest.fixture
    def default_voter(self):
        """Create a default voter from CBOR for testing."""
        reader = CborReader.from_hex(CBOR)
        return Voter.from_cbor(reader)

    @pytest.fixture
    def default_voter2(self):
        """Create a second default voter from CBOR for testing."""
        reader = CborReader.from_hex(CBOR_2)
        return Voter.from_cbor(reader)

    @pytest.fixture
    def default_credential(self):
        """Create a default credential from CBOR for testing."""
        reader = CborReader.from_hex(CREDENTIAL_CBOR)
        return Credential.from_cbor(reader)

    def test_new_creates_voter(self, default_credential):
        """Test that new() creates a valid voter instance."""
        voter = Voter.new(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, default_credential)
        assert voter is not None
        assert isinstance(voter, Voter)

    def test_new_with_invalid_credential_raises_error(self):
        """Test that new() raises error when credential is None."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            Voter.new(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, None)

    def test_from_cbor_deserializes_voter(self):
        """Test that from_cbor() deserializes a voter correctly."""
        reader = CborReader.from_hex(CBOR)
        voter = Voter.from_cbor(reader)
        assert voter is not None
        assert isinstance(voter, Voter)

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that from_cbor() raises error with None reader."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            Voter.from_cbor(None)

    def test_from_cbor_with_invalid_data_not_array(self):
        """Test from_cbor() fails when data doesn't start with array."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            Voter.from_cbor(reader)

    def test_from_cbor_with_invalid_array_size(self):
        """Test from_cbor() fails with invalid array size."""
        reader = CborReader.from_hex("8100")
        with pytest.raises(CardanoError):
            Voter.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_as_type(self):
        """Test from_cbor() fails with invalid uint as type."""
        reader = CborReader.from_hex("82ef")
        with pytest.raises(CardanoError):
            Voter.from_cbor(reader)

    def test_from_cbor_with_invalid_credential(self):
        """Test from_cbor() fails with invalid credential data."""
        reader = CborReader.from_hex("8200ef1c00000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            Voter.from_cbor(reader)

    def test_to_cbor_serializes_voter(self, default_voter):
        """Test that to_cbor() serializes voter correctly."""
        writer = CborWriter()
        default_voter.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_to_cbor_with_null_writer_raises_error(self, default_voter):
        """Test that to_cbor() raises error with None writer."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            default_voter.to_cbor(None)

    def test_voter_type_getter(self, default_voter):
        """Test voter_type property getter."""
        voter_type = default_voter.voter_type
        assert voter_type == VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH

    def test_voter_type_setter(self, default_voter):
        """Test voter_type property setter."""
        default_voter.voter_type = VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert default_voter.voter_type == VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH

    def test_credential_getter(self, default_voter):
        """Test credential property getter."""
        cred = default_voter.credential
        assert cred is not None
        assert isinstance(cred, Credential)

    def test_credential_setter(self, default_voter, default_credential):
        """Test credential property setter."""
        default_voter.credential = default_credential
        cred = default_voter.credential
        assert cred is not None

    def test_credential_setter_with_none_raises_error(self, default_voter):
        """Test that setting credential to None raises error."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            default_voter.credential = None

    def test_equals_returns_true_for_same_voters(self, default_voter):
        """Test that equals returns True for identical voters."""
        reader = CborReader.from_hex(CBOR)
        voter2 = Voter.from_cbor(reader)
        assert default_voter == voter2

    def test_equals_returns_false_for_different_voters(self, default_voter):
        """Test that equals returns False for different voters."""
        reader = CborReader.from_hex(CBOR)
        voter2 = Voter.from_cbor(reader)
        voter2.voter_type = VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH
        assert default_voter != voter2

    def test_equals_returns_false_for_none(self, default_voter):
        """Test that equals returns False when comparing with None."""
        assert default_voter != None

    def test_equals_returns_false_for_different_type(self, default_voter):
        """Test that equals returns False when comparing with different type."""
        assert default_voter != "not a voter"

    def test_hash_is_consistent(self, default_voter):
        """Test that hash returns consistent values."""
        hash1 = hash(default_voter)
        hash2 = hash(default_voter)
        assert hash1 == hash2

    def test_hash_for_equal_voters_is_same(self):
        """Test that hash is same for equal voters."""
        reader1 = CborReader.from_hex(CBOR)
        voter1 = Voter.from_cbor(reader1)
        reader2 = CborReader.from_hex(CBOR)
        voter2 = Voter.from_cbor(reader2)
        assert hash(voter1) == hash(voter2)

    def test_repr_contains_type_and_credential(self, default_voter):
        """Test that repr contains voter type and credential info."""
        repr_str = repr(default_voter)
        assert "Voter" in repr_str
        assert "type=" in repr_str
        assert "credential=" in repr_str

    def test_context_manager_enter(self, default_voter):
        """Test that voter can be used as context manager."""
        with default_voter as voter:
            assert voter is default_voter

    def test_context_manager_exit(self, default_voter):
        """Test that voter context manager exit doesn't raise."""
        with default_voter:
            pass

    def test_to_cip116_json_drep_key_hash(self):
        """Test CIP-116 JSON serialization for DRep with key hash."""
        cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.KEY_HASH
        )
        voter = Voter.new(VoterType.DREP_KEY_HASH, cred)
        writer = JsonWriter()
        voter.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"drep_credential"' in json_str
        assert '"credential"' in json_str
        assert '"tag":"pubkey_hash"' in json_str
        assert '"value":"00000000000000000000000000000000000000000000000000000000"' in json_str

    def test_to_cip116_json_drep_script_hash(self):
        """Test CIP-116 JSON serialization for DRep with script hash."""
        cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.SCRIPT_HASH
        )
        voter = Voter.new(VoterType.DREP_SCRIPT_HASH, cred)
        writer = JsonWriter()
        voter.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"drep_credential"' in json_str
        assert '"credential"' in json_str
        assert '"tag":"script_hash"' in json_str
        assert '"value":"00000000000000000000000000000000000000000000000000000000"' in json_str

    def test_to_cip116_json_cc_key_hash(self):
        """Test CIP-116 JSON serialization for Constitutional Committee with key hash."""
        cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.KEY_HASH
        )
        voter = Voter.new(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, cred)
        writer = JsonWriter()
        voter.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"cc_credential"' in json_str
        assert '"credential"' in json_str
        assert '"tag":"pubkey_hash"' in json_str
        assert '"value":"00000000000000000000000000000000000000000000000000000000"' in json_str

    def test_to_cip116_json_cc_script_hash(self):
        """Test CIP-116 JSON serialization for Constitutional Committee with script hash."""
        cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.SCRIPT_HASH
        )
        voter = Voter.new(VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH, cred)
        writer = JsonWriter()
        voter.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"cc_credential"' in json_str
        assert '"credential"' in json_str
        assert '"tag":"script_hash"' in json_str
        assert '"value":"00000000000000000000000000000000000000000000000000000000"' in json_str

    def test_to_cip116_json_spo_key_hash(self):
        """Test CIP-116 JSON serialization for SPO with key hash."""
        cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.KEY_HASH
        )
        voter = Voter.new(VoterType.STAKE_POOL_KEY_HASH, cred)
        writer = JsonWriter()
        voter.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"spo_keyhash"' in json_str
        assert '"pubkey_hash":"00000000000000000000000000000000000000000000000000000000"' in json_str

    def test_to_cip116_json_with_invalid_writer_raises_error(self, default_voter):
        """Test that to_cip116_json raises error with invalid writer."""
        with pytest.raises((CardanoError, TypeError)):
            default_voter.to_cip116_json("not a writer")

    def test_to_cip116_json_with_none_writer_raises_error(self, default_voter):
        """Test that to_cip116_json raises error with None writer."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            default_voter.to_cip116_json(None)

    def test_voter_can_be_used_in_set(self):
        """Test that voter instances can be used in sets."""
        reader1 = CborReader.from_hex(CBOR)
        voter1 = Voter.from_cbor(reader1)
        reader2 = CborReader.from_hex(CBOR)
        voter2 = Voter.from_cbor(reader2)
        reader3 = CborReader.from_hex(CBOR_2)
        voter3 = Voter.from_cbor(reader3)

        voter_set = {voter1, voter2, voter3}
        assert len(voter_set) == 2

    def test_voter_can_be_used_as_dict_key(self):
        """Test that voter instances can be used as dictionary keys."""
        reader = CborReader.from_hex(CBOR)
        voter = Voter.from_cbor(reader)
        voter_dict = {voter: "test_value"}
        assert voter_dict[voter] == "test_value"

    def test_new_voter_with_all_voter_types(self, default_credential):
        """Test creating voters with all voter types."""
        for voter_type in VoterType:
            voter = Voter.new(voter_type, default_credential)
            assert voter is not None
            assert voter.voter_type == voter_type

    def test_voter_type_roundtrip(self, default_voter):
        """Test that voter type can be set and retrieved."""
        original_type = default_voter.voter_type
        default_voter.voter_type = VoterType.DREP_KEY_HASH
        assert default_voter.voter_type == VoterType.DREP_KEY_HASH
        default_voter.voter_type = original_type
        assert default_voter.voter_type == original_type

    def test_cbor_roundtrip(self, default_voter):
        """Test CBOR serialization and deserialization roundtrip."""
        writer = CborWriter()
        default_voter.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        voter2 = Voter.from_cbor(reader)

        assert default_voter == voter2
        assert default_voter.voter_type == voter2.voter_type

    def test_voter_with_different_credentials(self):
        """Test voters with different credential types."""
        key_cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.KEY_HASH
        )
        script_cred = Credential.from_hex(
            "00000000000000000000000000000000000000000000000000000000",
            CredentialType.SCRIPT_HASH
        )

        voter_key = Voter.new(VoterType.DREP_KEY_HASH, key_cred)
        voter_script = Voter.new(VoterType.DREP_SCRIPT_HASH, script_cred)

        assert voter_key.credential.type == CredentialType.KEY_HASH
        assert voter_script.credential.type == CredentialType.SCRIPT_HASH

    def test_voter_equality_with_same_type_different_hash(self, default_voter, default_voter2):
        """Test that voters with same type but different hashes are not equal."""
        assert default_voter != default_voter2
        assert default_voter.voter_type == default_voter2.voter_type

    def test_repr_format(self, default_voter):
        """Test that repr has expected format."""
        repr_str = repr(default_voter)
        assert repr_str.startswith("Voter(")
        assert repr_str.endswith(")")
        assert "CONSTITUTIONAL_COMMITTEE_KEY_HASH" in repr_str
