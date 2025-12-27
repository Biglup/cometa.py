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
    UpdateCommitteeAction,
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError,
    CredentialSet,
    Credential,
    CredentialType,
    CommitteeMembersMap,
    UnitInterval
)


CBOR = "8504825820000000000000000000000000000000000000000000000000000000000000000003d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105"
CBOR_WITHOUT_GOV_ACTION = "8504f6d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105"
GOV_ACTION_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
MEMBERS_TO_BE_REMOVED_CBOR = "d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000"
MEMBERS_TO_BE_ADDED_CBOR = "a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002"
QUORUM_CBOR = "d81e820105"
DATA_HASH = "00000000000000000000000000000000000000000000000000000000"
HASH_1 = "30000000000000000000000000000000000000000000000000000000"
HASH_2 = "40000000000000000000000000000000000000000000000000000000"
TX_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def create_default_governance_action_id() -> GovernanceActionId:
    """Helper function to create a default governance action ID from CBOR."""
    reader = CborReader.from_hex(GOV_ACTION_CBOR)
    return GovernanceActionId.from_cbor(reader)


def create_default_credential_set() -> CredentialSet:
    """Helper function to create a default credential set from CBOR."""
    reader = CborReader.from_hex(MEMBERS_TO_BE_REMOVED_CBOR)
    return CredentialSet.from_cbor(reader)


def create_default_committee_members_map() -> CommitteeMembersMap:
    """Helper function to create a default committee members map from CBOR."""
    reader = CborReader.from_hex(MEMBERS_TO_BE_ADDED_CBOR)
    return CommitteeMembersMap.from_cbor(reader)


def create_default_unit_interval() -> UnitInterval:
    """Helper function to create a default unit interval from CBOR."""
    reader = CborReader.from_hex(QUORUM_CBOR)
    return UnitInterval.from_cbor(reader)


def create_default_update_committee_action() -> UpdateCommitteeAction:
    """Helper function to create a default update committee action from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return UpdateCommitteeAction.from_cbor(reader)


def create_update_committee_action_without_gov_id() -> UpdateCommitteeAction:
    """Helper function to create an update committee action without governance action ID."""
    reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
    return UpdateCommitteeAction.from_cbor(reader)


class TestUpdateCommitteeAction:
    """Tests for the UpdateCommitteeAction class."""

    def test_new_creates_action_without_governance_action_id(self):
        """Test creating a new update committee action without governance action ID."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR_WITHOUT_GOV_ACTION

    def test_new_creates_action_with_governance_action_id(self):
        """Test creating a new update committee action with governance action ID."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()
        gov_action_id = create_default_governance_action_id()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            gov_action_id
        )

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_new_creates_action_with_none_governance_action_id(self):
        """Test creating a new update committee action with explicit None governance action ID."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            None
        )

        assert action is not None
        assert action.governance_action_id is None

    def test_new_with_list_of_credentials_for_members_to_be_removed(self):
        """Test creating a new action with a Python list of credentials instead of CredentialSet."""
        cred1 = Credential.from_key_hash(DATA_HASH)
        cred2 = Credential.from_key_hash("20000000000000000000000000000000000000000000000000000000")

        members_to_be_removed = [cred1, cred2]
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )

        assert action is not None
        assert action.members_to_be_removed is not None

    def test_new_raises_error_with_invalid_arguments(self):
        """Test that creating action with invalid arguments raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            UpdateCommitteeAction.new(None, None, None)

    def test_from_cbor_deserializes_action_with_governance_action_id(self):
        """Test deserializing an update committee action with governance action ID from CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = UpdateCommitteeAction.from_cbor(reader)

        assert action is not None
        assert action.governance_action_id is not None
        assert action.members_to_be_removed is not None
        assert action.members_to_be_added is not None
        assert action.quorum is not None

    def test_from_cbor_deserializes_action_without_governance_action_id(self):
        """Test deserializing an update committee action without governance action ID from CBOR."""
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = UpdateCommitteeAction.from_cbor(reader)

        assert action is not None
        assert action.governance_action_id is None

    def test_from_cbor_raises_error_with_null_reader(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            UpdateCommitteeAction.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_not_array(self):
        """Test that deserializing invalid CBOR (not an array) raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_array_size(self):
        """Test that deserializing invalid CBOR (wrong array size) raises error."""
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_action_id(self):
        """Test that deserializing invalid action ID raises error."""
        reader = CborReader.from_hex("85effe820103")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_governance_action(self):
        """Test that deserializing invalid governance action raises error."""
        reader = CborReader.from_hex("8504efb81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_members_to_be_added(self):
        """Test that deserializing invalid members to be added raises error."""
        reader = CborReader.from_hex("8504825820000000000000000000000000000000000000000000000000000000000000000003d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000ef8200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_members_to_be_removed(self):
        """Test that deserializing invalid members to be removed raises error."""
        reader = CborReader.from_hex("8504825820000000000000000000000000000000000000000000000000000000000000000003d9010282ef00581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_quorum(self):
        """Test that deserializing invalid quorum raises error."""
        reader = CborReader.from_hex("8504825820000000000000000000000000000000000000000000000000000000000000000003d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002efef820105")

        with pytest.raises(CardanoError):
            UpdateCommitteeAction.from_cbor(reader)

    def test_to_cbor_serializes_action_with_governance_action_id(self):
        """Test serializing an update committee action with governance action ID to CBOR."""
        action = create_default_update_committee_action()
        writer = CborWriter()
        action.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_serializes_action_without_governance_action_id(self):
        """Test serializing an update committee action without governance action ID to CBOR."""
        action = create_update_committee_action_without_gov_id()
        writer = CborWriter()
        action.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_WITHOUT_GOV_ACTION

    def test_to_cbor_raises_error_with_null_writer(self):
        """Test that serializing with null writer raises error."""
        action = create_default_update_committee_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.to_cbor(None)

    def test_get_governance_action_id_returns_id_when_set(self):
        """Test getting governance action ID returns ID when set."""
        action = create_default_update_committee_action()
        gov_action_id = action.governance_action_id

        assert gov_action_id is not None

    def test_get_governance_action_id_returns_none_when_not_set(self):
        """Test getting governance action ID returns None when not set."""
        action = create_update_committee_action_without_gov_id()
        gov_action_id = action.governance_action_id

        assert gov_action_id is None

    def test_set_governance_action_id_updates_id(self):
        """Test setting the governance action ID on an update committee action."""
        action = create_update_committee_action_without_gov_id()
        gov_action_id = create_default_governance_action_id()

        action.governance_action_id = gov_action_id

        retrieved_id = action.governance_action_id
        assert retrieved_id is not None

    def test_set_governance_action_id_can_be_set_to_none(self):
        """Test that governance action ID can be set to None."""
        action = create_default_update_committee_action()

        action.governance_action_id = None

        gov_action_id = action.governance_action_id
        assert gov_action_id is None

    def test_set_governance_action_id_with_new_id(self):
        """Test setting a new governance action ID."""
        action = create_default_update_committee_action()
        new_hash = Blake2bHash.from_hex(TX_HASH)
        new_gov_action_id = GovernanceActionId.new(new_hash, 5)

        action.governance_action_id = new_gov_action_id

        retrieved_id = action.governance_action_id
        assert retrieved_id is not None

    def test_get_members_to_be_removed_returns_credential_set(self):
        """Test getting members to be removed returns CredentialSet."""
        action = create_default_update_committee_action()
        members = action.members_to_be_removed

        assert members is not None
        assert isinstance(members, CredentialSet)

    def test_set_members_to_be_removed_with_credential_set(self):
        """Test setting members to be removed with CredentialSet."""
        action = create_default_update_committee_action()
        new_members = create_default_credential_set()

        action.members_to_be_removed = new_members

        retrieved_members = action.members_to_be_removed
        assert retrieved_members is not None

    def test_set_members_to_be_removed_with_list_of_credentials(self):
        """Test setting members to be removed with a Python list of credentials."""
        action = create_default_update_committee_action()
        cred1 = Credential.from_key_hash(DATA_HASH)

        action.members_to_be_removed = [cred1]

        retrieved_members = action.members_to_be_removed
        assert retrieved_members is not None

    def test_set_members_to_be_removed_raises_error_with_none(self):
        """Test that setting members to be removed to None raises error."""
        action = create_default_update_committee_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.members_to_be_removed = None

    def test_get_members_to_be_added_returns_committee_members_map(self):
        """Test getting members to be added returns CommitteeMembersMap."""
        action = create_default_update_committee_action()
        members = action.members_to_be_added

        assert members is not None
        assert isinstance(members, CommitteeMembersMap)

    def test_set_members_to_be_added_with_committee_members_map(self):
        """Test setting members to be added with CommitteeMembersMap."""
        action = create_default_update_committee_action()
        new_members = create_default_committee_members_map()

        action.members_to_be_added = new_members

        retrieved_members = action.members_to_be_added
        assert retrieved_members is not None

    def test_set_members_to_be_added_raises_error_with_none(self):
        """Test that setting members to be added to None raises error."""
        action = create_default_update_committee_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.members_to_be_added = None

    def test_get_quorum_returns_unit_interval(self):
        """Test getting quorum returns UnitInterval."""
        action = create_default_update_committee_action()
        quorum = action.quorum

        assert quorum is not None
        assert isinstance(quorum, UnitInterval)

    def test_set_quorum_with_unit_interval(self):
        """Test setting quorum with UnitInterval."""
        action = create_default_update_committee_action()
        new_quorum = UnitInterval.new(2, 3)

        action.quorum = new_quorum

        retrieved_quorum = action.quorum
        assert retrieved_quorum is not None

    def test_set_quorum_raises_error_with_none(self):
        """Test that setting quorum to None raises error."""
        action = create_default_update_committee_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.quorum = None

    def test_to_cip116_json_with_governance_action_id(self):
        """Test serializing update committee action with governance action ID to CIP-116 JSON."""
        hash1 = Blake2bHash.from_hex(TX_HASH)
        gov_action_id = GovernanceActionId.new(hash1, 5)

        cred_set = CredentialSet()
        cred_rem = Credential.from_key_hash(DATA_HASH)
        cred_set.add(cred_rem)

        members_map = create_default_committee_members_map()
        threshold = UnitInterval.new(2, 3)

        action = UpdateCommitteeAction.new(cred_set, members_map, threshold, gov_action_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "tag" in json_str
        assert "update_committee" in json_str
        assert "gov_action_id" in json_str
        assert "transaction_id" in json_str
        assert TX_HASH in json_str
        assert "gov_action_index" in json_str
        assert "5" in json_str
        assert "members_to_remove" in json_str
        assert "committee" in json_str
        assert "signature_threshold" in json_str

    def test_to_cip116_json_without_governance_action_id(self):
        """Test serializing update committee action without governance action ID to CIP-116 JSON."""
        cred_set = CredentialSet()
        members_map = create_default_committee_members_map()
        threshold = UnitInterval.new(1, 1)

        action = UpdateCommitteeAction.new(cred_set, members_map, threshold, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "tag" in json_str
        assert "update_committee" in json_str
        assert "gov_action_id" not in json_str
        assert "members_to_remove" in json_str
        assert "committee" in json_str
        assert "signature_threshold" in json_str

    def test_to_cip116_json_raises_error_with_null_writer(self):
        """Test that serializing to JSON with null writer raises error."""
        action = create_default_update_committee_action()

        with pytest.raises((CardanoError, TypeError)):
            action.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_invalid_writer_type(self):
        """Test that serializing to JSON with invalid writer type raises error."""
        action = create_default_update_committee_action()

        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")

    def test_repr_returns_string_representation(self):
        """Test that __repr__ returns a string representation."""
        action = create_default_update_committee_action()
        repr_str = repr(action)

        assert "UpdateCommitteeAction" in repr_str

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self for context manager."""
        action = create_default_update_committee_action()

        with action as ctx:
            assert ctx is action

    def test_context_manager_exit_completes(self):
        """Test that __exit__ completes without error."""
        action = create_default_update_committee_action()

        with action:
            pass

    def test_cbor_roundtrip_without_governance_action_id(self):
        """Test CBOR serialization roundtrip without governance action ID."""
        original = create_update_committee_action_without_gov_id()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = UpdateCommitteeAction.from_cbor(reader)

        assert restored is not None
        assert restored.governance_action_id is None

    def test_cbor_roundtrip_with_governance_action_id(self):
        """Test CBOR serialization roundtrip with governance action ID."""
        original = create_default_update_committee_action()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = UpdateCommitteeAction.from_cbor(reader)

        assert restored is not None
        assert restored.governance_action_id is not None

    def test_governance_action_id_property_update(self):
        """Test updating governance action ID property multiple times."""
        action = create_update_committee_action_without_gov_id()

        gov_id_1 = create_default_governance_action_id()
        action.governance_action_id = gov_id_1
        assert action.governance_action_id is not None

        action.governance_action_id = None
        assert action.governance_action_id is None

        tx_hash = Blake2bHash.from_hex(TX_HASH)
        gov_id_2 = GovernanceActionId.new(tx_hash, 10)
        action.governance_action_id = gov_id_2
        assert action.governance_action_id is not None

    def test_new_action_has_correct_initial_state_without_gov_id(self):
        """Test that a newly created action without gov ID has correct initial state."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )

        assert action.governance_action_id is None
        assert action.members_to_be_removed is not None
        assert action.members_to_be_added is not None
        assert action.quorum is not None

    def test_new_action_has_correct_initial_state_with_gov_id(self):
        """Test that a newly created action with gov ID has correct initial state."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()
        gov_action_id = create_default_governance_action_id()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            gov_action_id
        )

        assert action.governance_action_id is not None
        assert action.members_to_be_removed is not None
        assert action.members_to_be_added is not None
        assert action.quorum is not None

    def test_multiple_actions_are_independent(self):
        """Test that multiple action instances are independent."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action1 = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )
        action2 = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )

        gov_id = create_default_governance_action_id()
        action1.governance_action_id = gov_id

        assert action1.governance_action_id is not None
        assert action2.governance_action_id is None

    def test_from_cbor_with_valid_governance_action_structure(self):
        """Test deserializing from CBOR with valid governance action structure."""
        reader = CborReader.from_hex(CBOR)
        action = UpdateCommitteeAction.from_cbor(reader)

        writer = CborWriter()
        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_serialization_produces_deterministic_output(self):
        """Test that serialization produces deterministic output."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()
        gov_id = create_default_governance_action_id()

        action1 = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            gov_id
        )
        action2 = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            gov_id
        )

        writer1 = CborWriter()
        action1.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        action2.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_json_serialization_produces_valid_structure(self):
        """Test that JSON serialization produces valid structure."""
        action = create_default_update_committee_action()

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.startswith("{")
        assert json_str.endswith("}")
        assert json_str.count("{") >= json_str.count("}")

    def test_action_lifecycle_with_context_manager(self):
        """Test complete action lifecycle using context manager."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()
        gov_id = create_default_governance_action_id()

        with UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum,
            gov_id
        ) as action:
            assert action is not None
            assert action.governance_action_id is not None

            writer = CborWriter()
            action.to_cbor(writer)
            cbor_hex = writer.to_hex()

            assert len(cbor_hex) > 0

    def test_members_to_be_removed_property_updates(self):
        """Test updating members_to_be_removed property multiple times."""
        action = create_default_update_committee_action()

        members1 = create_default_credential_set()
        action.members_to_be_removed = members1
        assert action.members_to_be_removed is not None

        cred = Credential.from_key_hash(DATA_HASH)
        action.members_to_be_removed = [cred]
        assert action.members_to_be_removed is not None

    def test_members_to_be_added_property_updates(self):
        """Test updating members_to_be_added property multiple times."""
        action = create_default_update_committee_action()

        members1 = create_default_committee_members_map()
        action.members_to_be_added = members1
        assert action.members_to_be_added is not None

        members2 = create_default_committee_members_map()
        action.members_to_be_added = members2
        assert action.members_to_be_added is not None

    def test_quorum_property_updates(self):
        """Test updating quorum property multiple times."""
        action = create_default_update_committee_action()

        quorum1 = UnitInterval.new(1, 2)
        action.quorum = quorum1
        assert action.quorum is not None

        quorum2 = UnitInterval.new(2, 3)
        action.quorum = quorum2
        assert action.quorum is not None

    def test_all_properties_can_be_retrieved(self):
        """Test that all properties can be retrieved without errors."""
        action = create_default_update_committee_action()

        gov_id = action.governance_action_id
        members_removed = action.members_to_be_removed
        members_added = action.members_to_be_added
        quorum = action.quorum

        assert gov_id is not None
        assert members_removed is not None
        assert members_added is not None
        assert quorum is not None

    def test_action_with_empty_credential_set_for_removal(self):
        """Test creating action with empty credential set for members to be removed."""
        empty_set = CredentialSet()
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(empty_set, members_to_be_added, quorum)

        assert action is not None
        assert action.members_to_be_removed is not None

    def test_action_with_various_quorum_values(self):
        """Test creating actions with various quorum threshold values."""
        members_to_be_removed = create_default_credential_set()
        members_to_be_added = create_default_committee_members_map()

        test_values = [(1, 2), (2, 3), (3, 5), (1, 1)]

        for numerator, denominator in test_values:
            quorum = UnitInterval.new(numerator, denominator)
            action = UpdateCommitteeAction.new(
                members_to_be_removed,
                members_to_be_added,
                quorum
            )
            assert action is not None
            assert action.quorum is not None

    def test_cbor_deserialization_matches_original(self):
        """Test that deserializing and reserializing produces identical CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = UpdateCommitteeAction.from_cbor(reader)

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_action_properties_are_mutable(self):
        """Test that action properties can be changed after creation."""
        action = create_default_update_committee_action()

        original_members_removed = action.members_to_be_removed
        original_members_added = action.members_to_be_added
        original_quorum = action.quorum

        new_members_removed = create_default_credential_set()
        new_members_added = create_default_committee_members_map()
        new_quorum = UnitInterval.new(3, 4)

        action.members_to_be_removed = new_members_removed
        action.members_to_be_added = new_members_added
        action.quorum = new_quorum

        assert action.members_to_be_removed is not None
        assert action.members_to_be_added is not None
        assert action.quorum is not None

    def test_action_with_multiple_credentials_in_removal_list(self):
        """Test creating action with multiple credentials in removal list."""
        cred1 = Credential.from_key_hash(DATA_HASH)
        cred2 = Credential.from_key_hash(HASH_1)
        cred3 = Credential.from_key_hash(HASH_2)

        members_to_be_removed = [cred1, cred2, cred3]
        members_to_be_added = create_default_committee_members_map()
        quorum = create_default_unit_interval()

        action = UpdateCommitteeAction.new(
            members_to_be_removed,
            members_to_be_added,
            quorum
        )

        assert action is not None
        assert action.members_to_be_removed is not None
