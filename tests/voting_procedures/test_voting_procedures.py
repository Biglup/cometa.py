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
import json
from cometa import (
    Vote,
    VoterType,
    Voter,
    VotingProcedure,
    VotingProcedures,
    Credential,
    CredentialType,
    Blake2bHash,
    GovernanceActionId,
    Anchor,
    CborWriter,
    CborReader,
    JsonWriter,
    JsonFormat,
    CardanoError,
)


class TestVote:
    """Tests for Vote enum."""

    def test_values(self):
        """Test vote enum values."""
        assert Vote.NO == 0
        assert Vote.YES == 1
        assert Vote.ABSTAIN == 2

    def test_is_int_enum(self):
        """Test that Vote is an IntEnum."""
        assert isinstance(Vote.YES, int)

    def test_name(self):
        """Test vote name access."""
        assert Vote.YES.name == "YES"
        assert Vote.NO.name == "NO"
        assert Vote.ABSTAIN.name == "ABSTAIN"


class TestVoterType:
    """Tests for VoterType enum."""

    def test_values(self):
        """Test voter type enum values."""
        assert VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH == 0
        assert VoterType.CONSTITUTIONAL_COMMITTEE_SCRIPT_HASH == 1
        assert VoterType.DREP_KEY_HASH == 2
        assert VoterType.DREP_SCRIPT_HASH == 3
        assert VoterType.STAKE_POOL_KEY_HASH == 4

    def test_is_int_enum(self):
        """Test that VoterType is an IntEnum."""
        assert isinstance(VoterType.DREP_KEY_HASH, int)


class TestVoter:
    """Tests for Voter class."""

    @pytest.fixture
    def key_hash(self):
        """Create a test key hash (28 bytes)."""
        return Blake2bHash.from_hex("aa" * 28)

    @pytest.fixture
    def credential(self, key_hash):
        """Create a test credential."""
        return Credential.from_key_hash(key_hash)

    def test_create_drep_voter(self, credential):
        """Test creating a DRep voter."""
        voter = Voter.new(VoterType.DREP_KEY_HASH, credential)
        assert voter.voter_type == VoterType.DREP_KEY_HASH
        assert voter.credential is not None

    def test_create_cc_voter(self, credential):
        """Test creating a Constitutional Committee voter."""
        voter = Voter.new(VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH, credential)
        assert voter.voter_type == VoterType.CONSTITUTIONAL_COMMITTEE_KEY_HASH

    def test_create_spo_voter(self, credential):
        """Test creating a Stake Pool Operator voter."""
        voter = Voter.new(VoterType.STAKE_POOL_KEY_HASH, credential)
        assert voter.voter_type == VoterType.STAKE_POOL_KEY_HASH

    def test_set_voter_type(self, credential):
        """Test setting voter type."""
        voter = Voter.new(VoterType.DREP_KEY_HASH, credential)
        voter.voter_type = VoterType.DREP_SCRIPT_HASH
        assert voter.voter_type == VoterType.DREP_SCRIPT_HASH

    def test_equality(self, credential):
        """Test voter equality."""
        voter1 = Voter.new(VoterType.DREP_KEY_HASH, credential)
        voter2 = Voter.new(VoterType.DREP_KEY_HASH, credential)
        assert voter1 == voter2

    def test_inequality_different_type(self, credential):
        """Test voter inequality with different types."""
        voter1 = Voter.new(VoterType.DREP_KEY_HASH, credential)
        voter2 = Voter.new(VoterType.STAKE_POOL_KEY_HASH, credential)
        assert voter1 != voter2

    def test_hash(self, credential):
        """Test voter is hashable."""
        voter = Voter.new(VoterType.DREP_KEY_HASH, credential)
        h = hash(voter)
        assert isinstance(h, int)

    def test_repr(self, credential):
        """Test voter repr."""
        voter = Voter.new(VoterType.DREP_KEY_HASH, credential)
        repr_str = repr(voter)
        assert "Voter" in repr_str
        assert "DREP_KEY_HASH" in repr_str

    def test_cbor_roundtrip(self, credential):
        """Test CBOR serialization/deserialization."""
        voter = Voter.new(VoterType.DREP_KEY_HASH, credential)

        writer = CborWriter()
        voter.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        voter_restored = Voter.from_cbor(reader)

        assert voter_restored.voter_type == VoterType.DREP_KEY_HASH


class TestVotingProcedure:
    """Tests for VotingProcedure class."""

    def test_create_with_yes_vote(self):
        """Test creating a procedure with YES vote."""
        procedure = VotingProcedure.new(Vote.YES)
        assert procedure.vote == Vote.YES
        assert procedure.anchor is None

    def test_create_with_no_vote(self):
        """Test creating a procedure with NO vote."""
        procedure = VotingProcedure.new(Vote.NO)
        assert procedure.vote == Vote.NO

    def test_create_with_abstain_vote(self):
        """Test creating a procedure with ABSTAIN vote."""
        procedure = VotingProcedure.new(Vote.ABSTAIN)
        assert procedure.vote == Vote.ABSTAIN

    def test_create_with_anchor(self):
        """Test creating a procedure with anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        anchor = Anchor.new("https://example.com/rationale.json", hash_val)
        procedure = VotingProcedure.new(Vote.YES, anchor=anchor)
        assert procedure.vote == Vote.YES
        assert procedure.anchor is not None
        assert procedure.anchor.url == "https://example.com/rationale.json"

    def test_set_vote(self):
        """Test setting vote."""
        procedure = VotingProcedure.new(Vote.YES)
        procedure.vote = Vote.NO
        assert procedure.vote == Vote.NO

    def test_set_anchor(self):
        """Test setting anchor."""
        procedure = VotingProcedure.new(Vote.YES)
        assert procedure.anchor is None

        hash_val = Blake2bHash.from_hex("cc" * 32)
        anchor = Anchor.new("https://example.com/rationale.json", hash_val)
        procedure.anchor = anchor
        assert procedure.anchor is not None

    def test_repr_without_anchor(self):
        """Test repr without anchor."""
        procedure = VotingProcedure.new(Vote.YES)
        repr_str = repr(procedure)
        assert "VotingProcedure" in repr_str
        assert "YES" in repr_str

    def test_repr_with_anchor(self):
        """Test repr with anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        anchor = Anchor.new("https://example.com/rationale.json", hash_val)
        procedure = VotingProcedure.new(Vote.NO, anchor=anchor)
        repr_str = repr(procedure)
        assert "VotingProcedure" in repr_str
        assert "NO" in repr_str
        assert "example.com" in repr_str

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        procedure = VotingProcedure.new(Vote.YES)

        writer = CborWriter()
        procedure.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        procedure_restored = VotingProcedure.from_cbor(reader)

        assert procedure_restored.vote == Vote.YES

    def test_cbor_roundtrip_with_anchor(self):
        """Test CBOR roundtrip with anchor."""
        hash_val = Blake2bHash.from_hex("cc" * 32)
        anchor = Anchor.new("https://example.com/rationale.json", hash_val)
        procedure = VotingProcedure.new(Vote.NO, anchor=anchor)

        writer = CborWriter()
        procedure.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        procedure_restored = VotingProcedure.from_cbor(reader)

        assert procedure_restored.vote == Vote.NO
        assert procedure_restored.anchor is not None


class TestVotingProcedures:
    """Tests for VotingProcedures collection."""

    @pytest.fixture
    def key_hash(self):
        """Create a test key hash (28 bytes)."""
        return Blake2bHash.from_hex("aa" * 28)

    @pytest.fixture
    def tx_hash(self):
        """Create a test transaction hash (32 bytes)."""
        return Blake2bHash.from_hex("bb" * 32)

    @pytest.fixture
    def credential(self, key_hash):
        """Create a test credential."""
        return Credential.from_key_hash(key_hash)

    @pytest.fixture
    def voter(self, credential):
        """Create a test voter."""
        return Voter.new(VoterType.DREP_KEY_HASH, credential)

    @pytest.fixture
    def governance_action_id(self, tx_hash):
        """Create a test governance action ID."""
        return GovernanceActionId.new(tx_hash, 0)

    @pytest.fixture
    def procedure(self):
        """Create a test voting procedure."""
        return VotingProcedure.new(Vote.YES)

    def test_create_empty(self):
        """Test creating empty voting procedures."""
        procedures = VotingProcedures.new()
        voters = procedures.get_voters()
        assert len(voters) == 0

    def test_insert(self, voter, governance_action_id, procedure):
        """Test inserting a voting procedure."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        voters = procedures.get_voters()
        assert len(voters) == 1

    def test_get(self, voter, governance_action_id, procedure):
        """Test getting a voting procedure."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        retrieved = procedures.get(voter, governance_action_id)
        assert retrieved is not None
        assert retrieved.vote == Vote.YES

    def test_get_not_found(self, voter, governance_action_id):
        """Test getting a non-existent voting procedure."""
        procedures = VotingProcedures.new()
        retrieved = procedures.get(voter, governance_action_id)
        assert retrieved is None

    def test_dict_like_setitem(self, voter, governance_action_id, procedure):
        """Test dict-like setitem syntax."""
        procedures = VotingProcedures.new()
        procedures[voter, governance_action_id] = procedure

        voters = procedures.get_voters()
        assert len(voters) == 1

    def test_dict_like_getitem(self, voter, governance_action_id, procedure):
        """Test dict-like getitem syntax."""
        procedures = VotingProcedures.new()
        procedures[voter, governance_action_id] = procedure

        retrieved = procedures[voter, governance_action_id]
        assert retrieved.vote == Vote.YES

    def test_dict_like_getitem_not_found(self, voter, governance_action_id):
        """Test dict-like getitem raises KeyError when not found."""
        procedures = VotingProcedures.new()

        with pytest.raises(KeyError):
            _ = procedures[voter, governance_action_id]

    def test_get_voters(self, voter, governance_action_id, procedure):
        """Test getting list of voters."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        voters = procedures.get_voters()
        assert len(voters) == 1
        assert voters[0].voter_type == VoterType.DREP_KEY_HASH

    def test_get_governance_action_ids_by_voter(
        self, voter, governance_action_id, procedure
    ):
        """Test getting governance action IDs for a voter."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        action_ids = procedures.get_governance_action_ids_by_voter(voter)
        assert len(action_ids) == 1

    def test_items_iterator(self, voter, governance_action_id, procedure):
        """Test items iterator."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        items = list(procedures.items())
        assert len(items) == 1
        v, action_id, proc = items[0]
        assert proc.vote == Vote.YES

    def test_multiple_procedures(self, credential, tx_hash):
        """Test multiple voting procedures."""
        procedures = VotingProcedures.new()

        # Create multiple voters and actions
        voter1 = Voter.new(VoterType.DREP_KEY_HASH, credential)

        key_hash2 = Blake2bHash.from_hex("bb" * 28)
        cred2 = Credential.from_key_hash(key_hash2)
        voter2 = Voter.new(VoterType.STAKE_POOL_KEY_HASH, cred2)

        action1 = GovernanceActionId.new(tx_hash, 0)
        action2 = GovernanceActionId.new(tx_hash, 1)

        # Insert multiple procedures
        procedures.insert(voter1, action1, VotingProcedure.new(Vote.YES))
        procedures.insert(voter1, action2, VotingProcedure.new(Vote.NO))
        procedures.insert(voter2, action1, VotingProcedure.new(Vote.ABSTAIN))

        voters = procedures.get_voters()
        assert len(voters) == 2

        # Check voter1's action IDs
        voter1_actions = procedures.get_governance_action_ids_by_voter(voter1)
        assert len(voter1_actions) == 2

    def test_repr(self, voter, governance_action_id, procedure):
        """Test repr."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        repr_str = repr(procedures)
        assert "VotingProcedures" in repr_str
        assert "voters=1" in repr_str

    def test_cbor_roundtrip(self, voter, governance_action_id, procedure):
        """Test CBOR serialization/deserialization."""
        procedures = VotingProcedures.new()
        procedures.insert(voter, governance_action_id, procedure)

        writer = CborWriter()
        procedures.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        procedures_restored = VotingProcedures.from_cbor(reader)

        voters = procedures_restored.get_voters()
        assert len(voters) == 1

    def test_context_manager(self):
        """Test context manager support."""
        with VotingProcedures.new() as procedures:
            assert procedures is not None


class TestVotingProceduresCBOR:
    """Tests for VotingProcedures CBOR serialization/deserialization."""

    CBOR = "a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR = "8202581c10000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR_2 = "8203581c20000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR_3 = "8200581c20000000000000000000000000000000000000000000000000000001"
    VOTER_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
    GOVERNANCE_ACTION_ID_CBOR_1 = "825820100000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_2 = "825820200000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_3 = "825820300000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_4 = "825820300000000000000000000000000000000000000000000000000000000000000002"
    GOVERNANCE_ACTION_ID_CBOR_5 = "825820200000000000000000000000000000000000000000000000000000000000000000"
    VOTING_PROCEDURE_CBOR = "8200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"

    @pytest.fixture
    def default_procedures(self):
        """Create a default voting procedures instance from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        return VotingProcedures.from_cbor(reader)

    def test_from_cbor(self, default_procedures):
        """Test deserialization from CBOR."""
        assert default_procedures is not None
        voters = default_procedures.get_voters()
        assert len(voters) == 2

    def test_to_cbor(self, default_procedures):
        """Test serialization to CBOR."""
        writer = CborWriter()
        default_procedures.to_cbor(writer)
        encoded = writer.to_hex()
        assert encoded == self.CBOR

    def test_cbor_roundtrip(self, default_procedures):
        """Test CBOR serialization/deserialization roundtrip."""
        writer = CborWriter()
        default_procedures.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        procedures_restored = VotingProcedures.from_cbor(reader)

        voters = procedures_restored.get_voters()
        assert len(voters) == 2

    def test_from_cbor_invalid_reader_null(self):
        """Test that from_cbor raises error with None reader."""
        with pytest.raises((CardanoError, AttributeError)):
            VotingProcedures.from_cbor(None)

    def test_from_cbor_invalid_voter(self):
        """Test that from_cbor raises error with invalid voter."""
        invalid_cbor = "a2ef02581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            VotingProcedures.from_cbor(reader)

    def test_from_cbor_invalid_nested_map(self):
        """Test that from_cbor raises error with invalid nested map."""
        invalid_cbor = "a28202581c10000000000000000000000000000000000000000000000000000000ef8258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            VotingProcedures.from_cbor(reader)

    def test_from_cbor_invalid_governance_id(self):
        """Test that from_cbor raises error with invalid governance action ID."""
        invalid_cbor = "a28202581c10000000000000000000000000000000000000000000000000000000a3ef58201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            VotingProcedures.from_cbor(reader)

    def test_from_cbor_invalid_voting_procedure(self):
        """Test that from_cbor raises error with invalid voting procedure."""
        invalid_cbor = "a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f5ef000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            VotingProcedures.from_cbor(reader)

    def test_to_cbor_null_writer(self):
        """Test that to_cbor raises error with None writer."""
        procedures = VotingProcedures.new()
        with pytest.raises((CardanoError, AttributeError)):
            procedures.to_cbor(None)


class TestVotingProceduresInsert:
    """Tests for VotingProcedures.insert method."""

    VOTER_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR = "8202581c10000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR_2 = "8203581c20000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR_3 = "8200581c20000000000000000000000000000000000000000000000000000001"
    GOVERNANCE_ACTION_ID_CBOR_1 = "825820100000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_2 = "825820200000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_3 = "825820300000000000000000000000000000000000000000000000000000000000000003"
    GOVERNANCE_ACTION_ID_CBOR_4 = "825820300000000000000000000000000000000000000000000000000000000000000002"
    GOVERNANCE_ACTION_ID_CBOR_5 = "825820200000000000000000000000000000000000000000000000000000000000000000"
    VOTING_PROCEDURE_CBOR = "8200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"

    def test_insert_single(self):
        """Test inserting a single voting procedure."""
        procedures = VotingProcedures.new()
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.VOTING_PROCEDURE_CBOR)
        procedure = VotingProcedure.from_cbor(reader)

        procedures.insert(voter, gov_action, procedure)

        voters = procedures.get_voters()
        assert len(voters) == 1

    def test_insert_keeps_elements_sorted(self):
        """Test that insert keeps elements sorted by voter and governance action ID."""
        procedures = VotingProcedures.new()

        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR)
        voter1 = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR_2)
        voter2 = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR_3)
        voter3 = Voter.from_cbor(reader)

        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action1 = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_2)
        gov_action2 = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_3)
        gov_action3 = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_4)
        gov_action4 = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_5)
        gov_action5 = GovernanceActionId.from_cbor(reader)

        reader = CborReader.from_hex(self.VOTING_PROCEDURE_CBOR)
        voting_procedure = VotingProcedure.from_cbor(reader)

        procedures.insert(voter, gov_action3, voting_procedure)
        procedures.insert(voter, gov_action1, voting_procedure)
        procedures.insert(voter, gov_action2, voting_procedure)

        procedures.insert(voter1, gov_action5, voting_procedure)
        procedures.insert(voter1, gov_action3, voting_procedure)
        procedures.insert(voter1, gov_action1, voting_procedure)

        procedures.insert(voter2, gov_action3, voting_procedure)
        procedures.insert(voter2, gov_action2, voting_procedure)
        procedures.insert(voter2, gov_action1, voting_procedure)
        procedures.insert(voter2, gov_action4, voting_procedure)
        procedures.insert(voter2, gov_action5, voting_procedure)

        procedures.insert(voter3, gov_action3, voting_procedure)
        procedures.insert(voter3, gov_action1, voting_procedure)
        procedures.insert(voter3, gov_action5, voting_procedure)

        writer = CborWriter()
        procedures.to_cbor(writer)
        encoded = writer.to_hex()

        expected = "a48200581c00000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000001a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000008200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000008200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a58258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000008200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000028200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
        assert encoded == expected

    def test_insert_invalid_procedures_null(self):
        """Test that insert raises error with None procedures."""
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.VOTING_PROCEDURE_CBOR)
        procedure = VotingProcedure.from_cbor(reader)

        with pytest.raises((CardanoError, AttributeError)):
            None.insert(voter, gov_action, procedure)

    def test_insert_invalid_voter_null(self):
        """Test that insert raises error with None voter."""
        procedures = VotingProcedures.new()
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)
        reader = CborReader.from_hex(self.VOTING_PROCEDURE_CBOR)
        procedure = VotingProcedure.from_cbor(reader)

        with pytest.raises((CardanoError, AttributeError)):
            procedures.insert(None, gov_action, procedure)

    def test_insert_invalid_gov_action_null(self):
        """Test that insert raises error with None governance action ID."""
        procedures = VotingProcedures.new()
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.VOTING_PROCEDURE_CBOR)
        procedure = VotingProcedure.from_cbor(reader)

        with pytest.raises((CardanoError, AttributeError)):
            procedures.insert(voter, None, procedure)

    def test_insert_invalid_procedure_null(self):
        """Test that insert raises error with None voting procedure."""
        procedures = VotingProcedures.new()
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)

        with pytest.raises((CardanoError, AttributeError)):
            procedures.insert(voter, gov_action, None)


class TestVotingProceduresGet:
    """Tests for VotingProcedures.get method."""

    CBOR = "a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR = "8202581c10000000000000000000000000000000000000000000000000000000"
    VOTER_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
    GOVERNANCE_ACTION_ID_CBOR_1 = "825820100000000000000000000000000000000000000000000000000000000000000003"
    VOTING_PROCEDURE_CBOR = "8200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"

    @pytest.fixture
    def default_procedures(self):
        """Create a default voting procedures instance from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        return VotingProcedures.from_cbor(reader)

    def test_get_returns_procedure_when_found(self, default_procedures):
        """Test that get returns a voting procedure when found."""
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)

        result = default_procedures.get(voter, gov_action)
        assert result is not None

        writer = CborWriter()
        result.to_cbor(writer)
        encoded = writer.to_hex()
        assert encoded == self.VOTING_PROCEDURE_CBOR

    def test_get_returns_none_when_not_found(self, default_procedures):
        """Test that get returns None when voting procedure doesn't exist."""
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)

        result = default_procedures.get(voter, gov_action)
        assert result is None

    def test_get_invalid_procedures_null(self):
        """Test that get returns None with None procedures."""
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)

        result = None
        try:
            result = None.get(voter, gov_action)
        except AttributeError:
            pass
        assert result is None

    def test_get_invalid_voter_null(self, default_procedures):
        """Test that get returns None with None voter."""
        reader = CborReader.from_hex(self.GOVERNANCE_ACTION_ID_CBOR_1)
        gov_action = GovernanceActionId.from_cbor(reader)

        result = None
        try:
            result = default_procedures.get(None, gov_action)
        except (CardanoError, AttributeError):
            pass
        assert result is None

    def test_get_invalid_gov_action_null(self, default_procedures):
        """Test that get returns None with None governance action ID."""
        reader = CborReader.from_hex(self.VOTER_CBOR)
        voter = Voter.from_cbor(reader)

        result = None
        try:
            result = default_procedures.get(voter, None)
        except (CardanoError, AttributeError):
            pass
        assert result is None


class TestVotingProceduresGetGovernanceIdsByVoter:
    """Tests for VotingProcedures.get_governance_action_ids_by_voter method."""

    CBOR = "a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR = "8202581c10000000000000000000000000000000000000000000000000000000"
    KNOWN_VOTER_CBOR_2 = "8203581c20000000000000000000000000000000000000000000000000000000"
    GOV_ACTION_IDS = [
        "825820100000000000000000000000000000000000000000000000000000000000000003",
        "825820200000000000000000000000000000000000000000000000000000000000000003",
        "825820300000000000000000000000000000000000000000000000000000000000000003",
    ]
    GOV_ACTION_IDS_2 = [
        "825820100000000000000000000000000000000000000000000000000000000000000003",
        "825820300000000000000000000000000000000000000000000000000000000000000003",
    ]

    @pytest.fixture
    def default_procedures(self):
        """Create a default voting procedures instance from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        return VotingProcedures.from_cbor(reader)

    def test_get_governance_ids_by_voter(self, default_procedures):
        """Test getting governance action IDs for a voter."""
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR)
        voter = Voter.from_cbor(reader)

        ids = default_procedures.get_governance_action_ids_by_voter(voter)
        assert len(ids) == 3

        for i, action_id in enumerate(ids):
            writer = CborWriter()
            action_id.to_cbor(writer)
            encoded = writer.to_hex()
            assert encoded == self.GOV_ACTION_IDS[i]

    def test_get_governance_ids_by_voter_2(self, default_procedures):
        """Test getting governance action IDs for second voter."""
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR_2)
        voter = Voter.from_cbor(reader)

        ids = default_procedures.get_governance_action_ids_by_voter(voter)
        assert len(ids) == 2

        for i, action_id in enumerate(ids):
            writer = CborWriter()
            action_id.to_cbor(writer)
            encoded = writer.to_hex()
            assert encoded == self.GOV_ACTION_IDS_2[i]

    def test_get_governance_ids_by_voter_invalid_procedures_null(self):
        """Test that get_governance_action_ids_by_voter raises error with None procedures."""
        reader = CborReader.from_hex(self.KNOWN_VOTER_CBOR)
        voter = Voter.from_cbor(reader)

        with pytest.raises(AttributeError):
            None.get_governance_action_ids_by_voter(voter)

    def test_get_governance_ids_by_voter_invalid_voter_null(self, default_procedures):
        """Test that get_governance_action_ids_by_voter raises error with None voter."""
        with pytest.raises((CardanoError, AttributeError)):
            default_procedures.get_governance_action_ids_by_voter(None)


class TestVotingProceduresGetVoters:
    """Tests for VotingProcedures.get_voters method."""

    CBOR = "a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
    VOTERS = [
        "8202581c10000000000000000000000000000000000000000000000000000000",
        "8203581c20000000000000000000000000000000000000000000000000000000",
    ]

    @pytest.fixture
    def default_procedures(self):
        """Create a default voting procedures instance from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        return VotingProcedures.from_cbor(reader)

    def test_get_voters(self, default_procedures):
        """Test getting list of voters."""
        voters = default_procedures.get_voters()
        assert len(voters) == 2

        for i, voter in enumerate(voters):
            writer = CborWriter()
            voter.to_cbor(writer)
            encoded = writer.to_hex()
            assert encoded == self.VOTERS[i]

    def test_get_voters_invalid_procedures_null(self):
        """Test that get_voters raises error with None procedures."""
        with pytest.raises(AttributeError):
            None.get_voters()


class TestVotingProceduresJSON:
    """Tests for VotingProcedures JSON serialization."""

    def test_to_cip116_json(self):
        """Test conversion to CIP-116 JSON format."""
        procedures = VotingProcedures.new()

        drep_hash = Blake2bHash.from_hex("0" * 56)
        drep_cred = Credential.from_key_hash(drep_hash)
        voter1 = Voter.new(VoterType.DREP_KEY_HASH, drep_cred)

        hash1 = Blake2bHash.from_hex("0" * 64)
        action_id1 = GovernanceActionId.new(hash1, 0)
        vote1 = VotingProcedure.new(Vote.YES)

        procedures.insert(voter1, action_id1, vote1)

        hash2 = Blake2bHash.from_hex("1" * 64)
        action_id2 = GovernanceActionId.new(hash2, 1)
        vote2 = VotingProcedure.new(Vote.NO)

        procedures.insert(voter1, action_id2, vote2)

        writer = JsonWriter(JsonFormat.COMPACT)
        procedures.to_cip116_json(writer)
        json_str = writer.encode()

        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["key"]["tag"] == "drep_credential"
        assert len(parsed[0]["value"]) == 2

    def test_to_cip116_json_empty(self):
        """Test conversion of empty procedures to CIP-116 JSON format."""
        procedures = VotingProcedures.new()

        writer = JsonWriter(JsonFormat.COMPACT)
        procedures.to_cip116_json(writer)
        json_str = writer.encode()

        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
        assert len(parsed) == 0

    def test_to_cip116_json_invalid_procedures_null(self):
        """Test that to_cip116_json raises error with None procedures."""
        writer = JsonWriter(JsonFormat.COMPACT)
        with pytest.raises(AttributeError):
            None.to_cip116_json(writer)

    def test_to_cip116_json_invalid_writer_null(self):
        """Test that to_cip116_json raises error with None writer."""
        procedures = VotingProcedures.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            procedures.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        """Test that to_cip116_json raises error with invalid writer type."""
        procedures = VotingProcedures.new()
        with pytest.raises(TypeError):
            procedures.to_cip116_json("not a writer")
