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

from cometa import (
    CborReader,
    CborWriter,
    Credential,
    CredentialType,
    InfoAction,
    NoConfidenceAction,
    GovernanceActionId,
    GovernanceActionType,
    Constitution,
    Anchor,
    HardForkInitiationAction,
    ProtocolVersion,
    ProposalProcedureSet,
    Blake2bHash,
    UnitInterval,
    UpdateCommitteeAction,
    CredentialSet,
    CommitteeMembersMap,
)


# Test vectors from vendor/cardano-c/lib/tests/proposal_procedures
INFO_ACTION_CBOR = "8106"
NO_CONFIDENCE_ACTION_CBOR = "8203f6"
NO_CONFIDENCE_ACTION_WITH_GOV_ID_CBOR = "8203825820000000000000000000000000000000000000000000000000000000000000000003"
HARD_FORK_INITIATION_ACTION_CBOR = "8301f6820103"
CONSTITUTION_CBOR = "82827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"


class TestInfoAction:
    def test_new(self):
        action = InfoAction.new()
        assert action is not None

    def test_from_cbor(self):
        reader = CborReader.from_hex(INFO_ACTION_CBOR)
        action = InfoAction.from_cbor(reader)
        assert action is not None

    def test_to_cbor(self):
        action = InfoAction.new()
        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == INFO_ACTION_CBOR


class TestNoConfidenceAction:
    def test_new_without_gov_action(self):
        action = NoConfidenceAction.new(None)
        assert action is not None

    def test_new_with_gov_action(self):
        tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        gov_action_id = GovernanceActionId.new(tx_hash, 3)
        action = NoConfidenceAction.new(gov_action_id)
        assert action is not None

    def test_from_cbor_without_gov_action(self):
        reader = CborReader.from_hex(NO_CONFIDENCE_ACTION_CBOR)
        action = NoConfidenceAction.from_cbor(reader)
        assert action is not None
        assert action.governance_action_id is None

    def test_from_cbor_with_gov_action(self):
        reader = CborReader.from_hex(NO_CONFIDENCE_ACTION_WITH_GOV_ID_CBOR)
        action = NoConfidenceAction.from_cbor(reader)
        assert action is not None
        assert action.governance_action_id is not None

    def test_to_cbor(self):
        action = NoConfidenceAction.new(None)
        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == NO_CONFIDENCE_ACTION_CBOR


class TestHardForkInitiationAction:
    def test_new(self):
        protocol_version = ProtocolVersion.new(1, 3)
        action = HardForkInitiationAction.new(protocol_version, None)
        assert action is not None
        assert action.governance_action_id is None

    def test_from_cbor(self):
        reader = CborReader.from_hex(HARD_FORK_INITIATION_ACTION_CBOR)
        action = HardForkInitiationAction.from_cbor(reader)
        assert action is not None

    def test_to_cbor(self):
        protocol_version = ProtocolVersion.new(1, 3)
        action = HardForkInitiationAction.new(protocol_version, None)
        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == HARD_FORK_INITIATION_ACTION_CBOR


class TestConstitution:
    def test_new(self):
        hash_val = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        anchor = Anchor.new("https://www.someurl.io", hash_val)
        constitution = Constitution.new(anchor, None)
        assert constitution is not None

    def test_from_cbor(self):
        reader = CborReader.from_hex(CONSTITUTION_CBOR)
        constitution = Constitution.from_cbor(reader)
        assert constitution is not None
        assert constitution.script_hash is None

    def test_to_cbor(self):
        hash_val = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        anchor = Anchor.new("https://www.someurl.io", hash_val)
        constitution = Constitution.new(anchor, None)
        writer = CborWriter()
        constitution.to_cbor(writer)
        assert writer.to_hex() == CONSTITUTION_CBOR


class TestProposalProcedureSet:
    def test_create_empty(self):
        procedure_set = ProposalProcedureSet()
        assert len(procedure_set) == 0


class TestUpdateCommitteeAction:
    def test_new_accepts_python_list_for_members_to_be_removed(self):
        """Test that UpdateCommitteeAction.new() accepts a Python list for members_to_be_removed."""
        # Create credentials
        cred1 = Credential.from_key_hash(bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"))
        cred2 = Credential.from_key_hash(bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538"))

        # Create members to be added (empty)
        members_to_add = CommitteeMembersMap()

        # Create quorum
        quorum = UnitInterval.new(1, 2)

        # Pass Python list directly
        action = UpdateCommitteeAction.new([cred1, cred2], members_to_add, quorum, None)
        assert action is not None
        assert len(action.members_to_be_removed) == 2

    def test_members_to_be_removed_setter_accepts_python_list(self):
        """Test that members_to_be_removed setter accepts a Python list."""
        # Create initial action with CredentialSet
        cred1 = Credential.from_key_hash(bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"))
        members_to_remove = CredentialSet.from_list([cred1])
        members_to_add = CommitteeMembersMap()
        quorum = UnitInterval.new(1, 2)

        action = UpdateCommitteeAction.new(members_to_remove, members_to_add, quorum, None)

        # Update using Python list
        cred2 = Credential.from_key_hash(bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538"))
        action.members_to_be_removed = [cred1, cred2]
        assert len(action.members_to_be_removed) == 2
