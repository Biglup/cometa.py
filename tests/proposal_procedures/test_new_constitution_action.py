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
    NewConstitutionAction,
    Constitution,
    GovernanceActionId,
    Anchor,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "830582582000000000000000000000000000000000000000000000000000000000000000000382827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"
CBOR_WITHOUT_GOV_ACTION = "8305f682827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"
GOV_ACTION_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
CONSTITUTION_CBOR = "82827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"
DATA_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
ANCHOR_URL = "https://www.someurl.io"
ANCHOR_HASH = "2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"
SCRIPT_HASH = "1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"


def create_default_constitution() -> Constitution:
    """Helper function to create a default constitution from CBOR."""
    reader = CborReader.from_hex(CONSTITUTION_CBOR)
    return Constitution.from_cbor(reader)


def create_default_governance_action_id() -> GovernanceActionId:
    """Helper function to create a default governance action id from CBOR."""
    reader = CborReader.from_hex(GOV_ACTION_CBOR)
    return GovernanceActionId.from_cbor(reader)


def create_default_new_constitution_action() -> NewConstitutionAction:
    """Helper function to create a default new constitution action from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return NewConstitutionAction.from_cbor(reader)


class TestNewConstitutionAction:
    """Tests for the NewConstitutionAction class."""

    def test_new_creates_action_without_governance_action_id(self):
        """Test creating a new constitution action without governance action id."""
        constitution = create_default_constitution()
        action = NewConstitutionAction.new(constitution)

        assert action is not None
        assert action.constitution is not None
        assert action.governance_action_id is None

    def test_new_creates_action_with_governance_action_id(self):
        """Test creating a new constitution action with governance action id."""
        constitution = create_default_constitution()
        governance_action_id = create_default_governance_action_id()
        action = NewConstitutionAction.new(constitution, governance_action_id)

        assert action is not None
        assert action.constitution is not None
        assert action.governance_action_id is not None

    def test_new_raises_error_with_null_constitution(self):
        """Test that creating action with null constitution raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            NewConstitutionAction.new(None)

    def test_from_cbor_deserializes_action_with_governance_action_id(self):
        """Test deserializing an action with governance action id from CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = NewConstitutionAction.from_cbor(reader)

        assert action is not None
        assert action.constitution is not None
        assert action.governance_action_id is not None

    def test_from_cbor_deserializes_action_without_governance_action_id(self):
        """Test deserializing an action without governance action id from CBOR."""
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = NewConstitutionAction.from_cbor(reader)

        assert action is not None
        assert action.constitution is not None
        assert action.governance_action_id is None

    def test_from_cbor_raises_error_with_null_reader(self):
        """Test that from_cbor raises error with null reader."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            NewConstitutionAction.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_not_array(self):
        """Test that from_cbor raises error when CBOR is not an array."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            NewConstitutionAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_cbor_wrong_array_size(self):
        """Test that from_cbor raises error with wrong array size."""
        reader = CborReader.from_hex("8100")
        with pytest.raises(CardanoError):
            NewConstitutionAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_id(self):
        """Test that from_cbor raises error with invalid action type id."""
        reader = CborReader.from_hex("83effe820103")
        with pytest.raises(CardanoError):
            NewConstitutionAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_governance_action(self):
        """Test that from_cbor raises error with invalid governance action."""
        reader = CborReader.from_hex("8305ef820103")
        with pytest.raises(CardanoError):
            NewConstitutionAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_constitution(self):
        """Test that from_cbor raises error with invalid constitution."""
        reader = CborReader.from_hex("8305f6ef0103")
        with pytest.raises(CardanoError):
            NewConstitutionAction.from_cbor(reader)

    def test_to_cbor_serializes_action_with_governance_action_id(self):
        """Test serializing an action with governance action id to CBOR."""
        action = create_default_new_constitution_action()
        writer = CborWriter()
        action.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR

    def test_to_cbor_serializes_action_without_governance_action_id(self):
        """Test serializing an action without governance action id to CBOR."""
        constitution = create_default_constitution()
        action = NewConstitutionAction.new(constitution)
        writer = CborWriter()
        action.to_cbor(writer)

        hex_output = writer.to_hex()
        assert hex_output == CBOR_WITHOUT_GOV_ACTION

    def test_to_cbor_raises_error_with_null_writer(self):
        """Test that to_cbor raises error with null writer."""
        action = create_default_new_constitution_action()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.to_cbor(None)

    def test_constitution_property_returns_constitution(self):
        """Test that constitution property returns the constitution."""
        action = create_default_new_constitution_action()
        constitution = action.constitution

        assert constitution is not None

    def test_constitution_setter_sets_constitution(self):
        """Test that constitution setter sets the constitution."""
        action = create_default_new_constitution_action()
        new_constitution = create_default_constitution()

        action.constitution = new_constitution
        assert action.constitution is not None

    def test_constitution_setter_raises_error_with_null_constitution(self):
        """Test that constitution setter raises error with null constitution."""
        action = create_default_new_constitution_action()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.constitution = None

    def test_governance_action_id_property_returns_governance_action_id(self):
        """Test that governance_action_id property returns the governance action id."""
        action = create_default_new_constitution_action()
        gov_action_id = action.governance_action_id

        assert gov_action_id is not None

    def test_governance_action_id_property_returns_none_when_not_set(self):
        """Test that governance_action_id property returns None when not set."""
        constitution = create_default_constitution()
        action = NewConstitutionAction.new(constitution)

        assert action.governance_action_id is None

    def test_governance_action_id_setter_sets_governance_action_id(self):
        """Test that governance_action_id setter sets the governance action id."""
        action = create_default_new_constitution_action()
        new_gov_action_id = create_default_governance_action_id()

        action.governance_action_id = new_gov_action_id
        assert action.governance_action_id is not None

    def test_governance_action_id_setter_accepts_none(self):
        """Test that governance_action_id setter accepts None."""
        action = create_default_new_constitution_action()
        action.governance_action_id = None

        assert action.governance_action_id is None

    def test_to_cip116_json_serializes_action_with_governance_action_id(self):
        """Test serializing action with governance action id to CIP-116 JSON."""
        hash_hex = "0000000000000000000000000000000000000000000000000000000000000000"
        tx_hash = Blake2bHash.from_hex(hash_hex)
        action_id = GovernanceActionId.new(tx_hash, 6)

        anchor_hash = Blake2bHash.from_hex(ANCHOR_HASH)
        anchor = Anchor.new("https://example.com", anchor_hash)

        script_hash = Blake2bHash.from_hex(SCRIPT_HASH)
        constitution = Constitution.new(anchor, script_hash)

        action = NewConstitutionAction.new(constitution, action_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"tag":"new_constitution","gov_action_id":{"transaction_id":"0000000000000000000000000000000000000000000000000000000000000000","gov_action_index":"6"},"constitution":{"anchor":{"url":"https://example.com","data_hash":"2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"},"script_hash":"1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"}}'
        assert json_str == expected

    def test_to_cip116_json_serializes_action_without_governance_action_id(self):
        """Test serializing action without governance action id to CIP-116 JSON."""
        anchor_hash = Blake2bHash.from_hex(ANCHOR_HASH)
        anchor = Anchor.new("https://example.com", anchor_hash)
        constitution = Constitution.new(anchor, None)

        action = NewConstitutionAction.new(constitution, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"tag":"new_constitution","constitution":{"anchor":{"url":"https://example.com","data_hash":"2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"}}}'
        assert json_str == expected

    def test_to_cip116_json_raises_error_with_null_writer(self):
        """Test that to_cip116_json raises error with null writer."""
        action = create_default_new_constitution_action()
        with pytest.raises((CardanoError, TypeError)):
            action.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_invalid_writer_type(self):
        """Test that to_cip116_json raises error with invalid writer type."""
        action = create_default_new_constitution_action()
        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")

    def test_context_manager_enter_returns_self(self):
        """Test that context manager __enter__ returns self."""
        action = create_default_new_constitution_action()
        with action as ctx_action:
            assert ctx_action is action

    def test_context_manager_exit_does_not_raise(self):
        """Test that context manager __exit__ does not raise."""
        action = create_default_new_constitution_action()
        with action:
            pass

    def test_repr_returns_string(self):
        """Test that __repr__ returns a string representation."""
        action = create_default_new_constitution_action()
        repr_str = repr(action)

        assert isinstance(repr_str, str)
        assert "NewConstitutionAction" in repr_str

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization roundtrip preserves data."""
        original_action = create_default_new_constitution_action()

        writer = CborWriter()
        original_action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        restored_action = NewConstitutionAction.from_cbor(reader)

        assert restored_action is not None
        assert restored_action.constitution is not None
        assert restored_action.governance_action_id is not None

    def test_multiple_actions_can_share_constitution(self):
        """Test that multiple actions can share the same constitution."""
        constitution = create_default_constitution()
        action1 = NewConstitutionAction.new(constitution)
        action2 = NewConstitutionAction.new(constitution)

        assert action1 is not None
        assert action2 is not None
        assert action1.constitution is not None
        assert action2.constitution is not None

    def test_action_with_different_governance_action_ids_serializes_differently(self):
        """Test that actions with different gov action ids serialize differently."""
        constitution = create_default_constitution()

        hash1 = Blake2bHash.from_hex(DATA_HASH)
        action_id1 = GovernanceActionId.new(hash1, 1)
        action1 = NewConstitutionAction.new(constitution, action_id1)

        hash2 = Blake2bHash.from_hex(DATA_HASH)
        action_id2 = GovernanceActionId.new(hash2, 2)
        action2 = NewConstitutionAction.new(constitution, action_id2)

        writer1 = CborWriter()
        action1.to_cbor(writer1)
        hex1 = writer1.to_hex()

        writer2 = CborWriter()
        action2.to_cbor(writer2)
        hex2 = writer2.to_hex()

        assert hex1 != hex2
