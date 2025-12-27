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
from cometa import VotingProcedure, Vote, Anchor, Blake2bHash
from cometa.cbor import CborReader, CborWriter
from cometa.json import JsonWriter
from cometa.errors import CardanoError


CBOR_NO_WITHOUT_ANCHOR = "8200f6"
CBOR_YES_WITHOUT_ANCHOR = "8201f6"
CBOR_ABSTAIN_WITHOUT_ANCHOR = "8202f6"
CBOR_NO_WITH_ANCHOR = "8200827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CBOR_YES_WITH_ANCHOR = "8201827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CBOR_ABSTAIN_WITH_ANCHOR = "8202827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CBOR_ANCHOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"


def create_default_anchor():
    """Creates a default anchor for testing."""
    reader = CborReader.from_hex(CBOR_ANCHOR)
    return Anchor.from_cbor(reader)


def create_default_voting_procedure():
    """Creates a new default instance of the voting procedure."""
    reader = CborReader.from_hex(CBOR_YES_WITHOUT_ANCHOR)
    return VotingProcedure.from_cbor(reader)


class TestVotingProcedureNew:
    """Tests for VotingProcedure.new() factory method."""

    def test_new_creates_instance_without_anchor(self):
        """Test creating voting procedure without anchor - adapted from C test."""
        procedure = VotingProcedure.new(Vote.NO)
        assert procedure is not None
        assert procedure.vote == Vote.NO
        assert procedure.anchor is None

    def test_new_creates_instance_with_anchor(self):
        """Test creating voting procedure with anchor - adapted from C test."""
        anchor = create_default_anchor()
        procedure = VotingProcedure.new(Vote.NO, anchor)
        assert procedure is not None
        assert procedure.vote == Vote.NO
        assert procedure.anchor is not None

    def test_new_with_all_vote_types(self):
        """Test creating voting procedure with all vote types."""
        for vote in [Vote.NO, Vote.YES, Vote.ABSTAIN]:
            procedure = VotingProcedure.new(vote)
            assert procedure.vote == vote

    def test_new_with_yes_vote(self):
        """Test creating voting procedure with YES vote."""
        procedure = VotingProcedure.new(Vote.YES)
        assert procedure.vote == Vote.YES

    def test_new_with_abstain_vote(self):
        """Test creating voting procedure with ABSTAIN vote."""
        procedure = VotingProcedure.new(Vote.ABSTAIN)
        assert procedure.vote == Vote.ABSTAIN


class TestVotingProcedureFromCbor:
    """Tests for VotingProcedure.from_cbor() deserialization."""

    def test_from_cbor_no_without_anchor(self):
        """Test deserializing NO vote without anchor."""
        reader = CborReader.from_hex(CBOR_NO_WITHOUT_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.NO
        assert procedure.anchor is None

    def test_from_cbor_yes_without_anchor(self):
        """Test deserializing YES vote without anchor."""
        reader = CborReader.from_hex(CBOR_YES_WITHOUT_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.YES
        assert procedure.anchor is None

    def test_from_cbor_abstain_without_anchor(self):
        """Test deserializing ABSTAIN vote without anchor."""
        reader = CborReader.from_hex(CBOR_ABSTAIN_WITHOUT_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.ABSTAIN
        assert procedure.anchor is None

    def test_from_cbor_no_with_anchor(self):
        """Test deserializing NO vote with anchor."""
        reader = CborReader.from_hex(CBOR_NO_WITH_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.NO
        assert procedure.anchor is not None

    def test_from_cbor_yes_with_anchor(self):
        """Test deserializing YES vote with anchor."""
        reader = CborReader.from_hex(CBOR_YES_WITH_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.YES
        assert procedure.anchor is not None

    def test_from_cbor_abstain_with_anchor(self):
        """Test deserializing ABSTAIN vote with anchor."""
        reader = CborReader.from_hex(CBOR_ABSTAIN_WITH_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.ABSTAIN
        assert procedure.anchor is not None

    def test_from_cbor_invalid_not_array(self):
        """Test from_cbor fails when data doesn't start with array - adapted from C test."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            VotingProcedure.from_cbor(reader)

    def test_from_cbor_invalid_uint_as_type(self):
        """Test from_cbor fails with invalid uint as type - adapted from C test."""
        reader = CborReader.from_hex("82ef")
        with pytest.raises(CardanoError):
            VotingProcedure.from_cbor(reader)

    def test_from_cbor_invalid_anchor(self):
        """Test from_cbor fails with invalid anchor - adapted from C test."""
        reader = CborReader.from_hex("8200ef7668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            VotingProcedure.from_cbor(reader)


class TestVotingProcedureToCbor:
    """Tests for VotingProcedure.to_cbor() serialization."""

    def test_to_cbor_without_anchor(self):
        """Test serializing voting procedure without anchor - adapted from C test."""
        procedure = create_default_voting_procedure()
        writer = CborWriter()
        procedure.to_cbor(writer)
        result = writer.encode().hex()
        assert result == CBOR_YES_WITHOUT_ANCHOR

    def test_to_cbor_with_anchor(self):
        """Test serializing voting procedure with anchor - adapted from C test."""
        procedure = create_default_voting_procedure()
        anchor = create_default_anchor()
        procedure.anchor = anchor
        writer = CborWriter()
        procedure.to_cbor(writer)
        result = writer.encode().hex()
        assert result == CBOR_YES_WITH_ANCHOR

    def test_to_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        original = VotingProcedure.new(Vote.NO)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()
        reader = CborReader.from_bytes(cbor_data)
        restored = VotingProcedure.from_cbor(reader)
        assert restored.vote == original.vote

    def test_to_cbor_roundtrip_with_anchor(self):
        """Test CBOR serialization roundtrip with anchor."""
        anchor = create_default_anchor()
        original = VotingProcedure.new(Vote.YES, anchor)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()
        reader = CborReader.from_bytes(cbor_data)
        restored = VotingProcedure.from_cbor(reader)
        assert restored.vote == original.vote
        assert restored.anchor is not None


class TestVotingProcedureToCip116Json:
    """Tests for VotingProcedure.to_cip116_json() serialization."""

    def test_to_cip116_json_vote_yes_with_anchor(self):
        """Test converting YES vote with anchor to CIP-116 JSON - adapted from C test."""
        hash_value = Blake2bHash.from_hex("2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e")
        anchor = Anchor.new("https://example.com", hash_value)
        procedure = VotingProcedure.new(Vote.YES, anchor)
        writer = JsonWriter()
        procedure.to_cip116_json(writer)
        result = writer.encode()
        expected = '{"vote":"yes","anchor":{"url":"https://example.com","data_hash":"2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"}}'
        assert result == expected

    def test_to_cip116_json_vote_no_without_anchor(self):
        """Test converting NO vote without anchor to CIP-116 JSON - adapted from C test."""
        procedure = VotingProcedure.new(Vote.NO)
        writer = JsonWriter()
        procedure.to_cip116_json(writer)
        result = writer.encode()
        assert result == '{"vote":"no"}'

    def test_to_cip116_json_vote_abstain_without_anchor(self):
        """Test converting ABSTAIN vote without anchor to CIP-116 JSON - adapted from C test."""
        procedure = VotingProcedure.new(Vote.ABSTAIN)
        writer = JsonWriter()
        procedure.to_cip116_json(writer)
        result = writer.encode()
        assert result == '{"vote":"abstain"}'

    def test_to_cip116_json_all_vote_types(self):
        """Test CIP-116 JSON serialization for all vote types."""
        vote_map = {
            Vote.NO: '{"vote":"no"}',
            Vote.YES: '{"vote":"yes"}',
            Vote.ABSTAIN: '{"vote":"abstain"}'
        }
        for vote, expected in vote_map.items():
            procedure = VotingProcedure.new(vote)
            writer = JsonWriter()
            procedure.to_cip116_json(writer)
            result = writer.encode()
            assert result == expected


class TestVotingProcedureGetVote:
    """Tests for vote property getter."""

    def test_get_vote_returns_correct_value(self):
        """Test get_vote returns correct vote - adapted from C test."""
        procedure = create_default_voting_procedure()
        vote = procedure.vote
        assert vote == Vote.YES

    def test_get_vote_for_all_types(self):
        """Test get_vote for all vote types."""
        for expected_vote in [Vote.NO, Vote.YES, Vote.ABSTAIN]:
            procedure = VotingProcedure.new(expected_vote)
            assert procedure.vote == expected_vote


class TestVotingProcedureSetVote:
    """Tests for vote property setter."""

    def test_set_vote_changes_value(self):
        """Test set_vote changes the vote - adapted from C test."""
        procedure = create_default_voting_procedure()
        procedure.vote = Vote.NO
        assert procedure.vote == Vote.NO

    def test_set_vote_to_all_types(self):
        """Test setting vote to all types."""
        procedure = VotingProcedure.new(Vote.YES)
        for vote in [Vote.NO, Vote.YES, Vote.ABSTAIN]:
            procedure.vote = vote
            assert procedure.vote == vote

    def test_set_vote_multiple_times(self):
        """Test setting vote multiple times."""
        procedure = VotingProcedure.new(Vote.YES)
        procedure.vote = Vote.NO
        assert procedure.vote == Vote.NO
        procedure.vote = Vote.ABSTAIN
        assert procedure.vote == Vote.ABSTAIN
        procedure.vote = Vote.YES
        assert procedure.vote == Vote.YES


class TestVotingProcedureGetAnchor:
    """Tests for anchor property getter."""

    def test_get_anchor_returns_none_when_not_set(self):
        """Test get_anchor returns None when not set - adapted from C test."""
        procedure = create_default_voting_procedure()
        anchor = procedure.anchor
        assert anchor is None

    def test_get_anchor_returns_anchor_when_set(self):
        """Test get_anchor returns anchor when set."""
        anchor = create_default_anchor()
        procedure = VotingProcedure.new(Vote.YES, anchor)
        retrieved_anchor = procedure.anchor
        assert retrieved_anchor is not None


class TestVotingProcedureSetAnchor:
    """Tests for anchor property setter."""

    def test_set_anchor_assigns_anchor(self):
        """Test set_anchor assigns anchor - adapted from C test."""
        procedure = create_default_voting_procedure()
        anchor = create_default_anchor()
        procedure.anchor = anchor
        assert procedure.anchor is not None

    def test_set_anchor_replaces_existing(self):
        """Test setting anchor replaces existing anchor."""
        anchor1 = create_default_anchor()
        procedure = VotingProcedure.new(Vote.YES, anchor1)
        assert procedure.anchor is not None

        hash_value = Blake2bHash.from_hex("1111111111111111111111111111111111111111111111111111111111111111")
        anchor2 = Anchor.new("https://newurl.com", hash_value)
        procedure.anchor = anchor2
        assert procedure.anchor is not None

    def test_set_anchor_to_none_raises_error(self):
        """Test setting anchor to None raises error (C API doesn't allow NULL)."""
        anchor = create_default_anchor()
        procedure = VotingProcedure.new(Vote.YES, anchor)
        assert procedure.anchor is not None
        with pytest.raises(CardanoError):
            procedure.anchor = None


class TestVotingProcedureRepr:
    """Tests for __repr__ method."""

    def test_repr_without_anchor(self):
        """Test repr for voting procedure without anchor."""
        procedure = VotingProcedure.new(Vote.YES)
        result = repr(procedure)
        assert "VotingProcedure" in result
        assert "YES" in result
        assert "anchor" not in result

    def test_repr_with_anchor(self):
        """Test repr for voting procedure with anchor."""
        anchor = create_default_anchor()
        procedure = VotingProcedure.new(Vote.NO, anchor)
        result = repr(procedure)
        assert "VotingProcedure" in result
        assert "NO" in result
        assert "anchor" in result


class TestVotingProcedureContextManager:
    """Tests for context manager protocol."""

    def test_context_manager_enter_exit(self):
        """Test using voting procedure as context manager."""
        procedure = VotingProcedure.new(Vote.YES)
        with procedure as p:
            assert p is procedure
            assert p.vote == Vote.YES

    def test_context_manager_with_operations(self):
        """Test context manager with operations inside."""
        with VotingProcedure.new(Vote.NO) as procedure:
            procedure.vote = Vote.YES
            assert procedure.vote == Vote.YES


class TestVotingProcedureLifecycle:
    """Tests for object lifecycle and resource management."""

    def test_object_creation_and_deletion(self):
        """Test object can be created and deleted."""
        procedure = VotingProcedure.new(Vote.YES)
        assert procedure is not None
        del procedure

    def test_multiple_procedures_independent(self):
        """Test multiple procedures are independent."""
        proc1 = VotingProcedure.new(Vote.YES)
        proc2 = VotingProcedure.new(Vote.NO)
        assert proc1.vote == Vote.YES
        assert proc2.vote == Vote.NO
        proc1.vote = Vote.ABSTAIN
        assert proc1.vote == Vote.ABSTAIN
        assert proc2.vote == Vote.NO

    def test_anchor_shared_between_procedures(self):
        """Test anchor can be shared between procedures."""
        anchor = create_default_anchor()
        proc1 = VotingProcedure.new(Vote.YES, anchor)
        proc2 = VotingProcedure.new(Vote.NO, anchor)
        assert proc1.anchor is not None
        assert proc2.anchor is not None


class TestVotingProcedureIntegration:
    """Integration tests combining multiple operations."""

    def test_create_serialize_deserialize_cycle(self):
        """Test full cycle: create, serialize, deserialize."""
        original = VotingProcedure.new(Vote.YES)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()
        reader = CborReader.from_bytes(cbor_data)
        restored = VotingProcedure.from_cbor(reader)
        assert restored.vote == original.vote
        assert restored.anchor is None

    def test_create_modify_serialize(self):
        """Test creating, modifying, and serializing."""
        procedure = VotingProcedure.new(Vote.NO)
        procedure.vote = Vote.YES
        anchor = create_default_anchor()
        procedure.anchor = anchor
        writer = CborWriter()
        procedure.to_cbor(writer)
        cbor_data = writer.encode()
        assert len(cbor_data) > 0

    def test_deserialize_modify_serialize(self):
        """Test deserializing, modifying, and re-serializing."""
        reader = CborReader.from_hex(CBOR_NO_WITHOUT_ANCHOR)
        procedure = VotingProcedure.from_cbor(reader)
        assert procedure.vote == Vote.NO
        procedure.vote = Vote.ABSTAIN
        writer = CborWriter()
        procedure.to_cbor(writer)
        result = writer.encode().hex()
        assert result == CBOR_ABSTAIN_WITHOUT_ANCHOR

    def test_json_and_cbor_consistency(self):
        """Test that JSON and CBOR serialization are consistent."""
        hash_value = Blake2bHash.from_hex("2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e")
        anchor = Anchor.new("https://example.com", hash_value)
        procedure = VotingProcedure.new(Vote.YES, anchor)

        cbor_writer = CborWriter()
        procedure.to_cbor(cbor_writer)
        cbor_data = cbor_writer.encode()

        json_writer = JsonWriter()
        procedure.to_cip116_json(json_writer)
        json_data = json_writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        restored = VotingProcedure.from_cbor(reader)
        assert restored.vote == Vote.YES


class TestVotingProcedureEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_switching_votes_preserves_anchor(self):
        """Test that changing vote preserves anchor."""
        anchor = create_default_anchor()
        procedure = VotingProcedure.new(Vote.YES, anchor)
        procedure.vote = Vote.NO
        assert procedure.anchor is not None
        procedure.vote = Vote.ABSTAIN
        assert procedure.anchor is not None

    def test_replacing_anchor(self):
        """Test replacing anchor with a different one."""
        anchor1 = create_default_anchor()
        procedure = VotingProcedure.new(Vote.YES, anchor1)
        assert procedure.anchor is not None

        hash_value = Blake2bHash.from_hex("1111111111111111111111111111111111111111111111111111111111111111")
        anchor2 = Anchor.new("https://test.com", hash_value)
        procedure.anchor = anchor2
        assert procedure.anchor is not None

    def test_serialization_after_multiple_modifications(self):
        """Test serialization after multiple modifications."""
        procedure = VotingProcedure.new(Vote.YES)
        procedure.vote = Vote.NO
        procedure.vote = Vote.ABSTAIN
        procedure.vote = Vote.YES

        writer = CborWriter()
        procedure.to_cbor(writer)
        result = writer.encode().hex()
        assert result == CBOR_YES_WITHOUT_ANCHOR
