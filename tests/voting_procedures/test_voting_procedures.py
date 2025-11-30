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
    Vote,
    VoterType,
    Voter,
    VotingProcedure,
    VotingProcedures,
    Credential,
    Blake2bHash,
    GovernanceActionId,
    Anchor,
    CborWriter,
    CborReader,
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
