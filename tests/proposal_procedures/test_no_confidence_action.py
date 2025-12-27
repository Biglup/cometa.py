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
    NoConfidenceAction,
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "8203825820000000000000000000000000000000000000000000000000000000000000000003"
CBOR_WITHOUT_GOV_ACTION = "8203f6"
GOV_ACTION_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
DATA_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def create_default_governance_action_id() -> GovernanceActionId:
    """Helper function to create a default governance action ID from CBOR."""
    reader = CborReader.from_hex(GOV_ACTION_CBOR)
    return GovernanceActionId.from_cbor(reader)


def create_governance_action_id_with_hash_and_index(hash_hex: str, index: int) -> GovernanceActionId:
    """Helper function to create a governance action ID with specific hash and index."""
    tx_hash = Blake2bHash.from_hex(hash_hex)
    return GovernanceActionId.new(tx_hash, index)


def create_default_no_confidence_action() -> NoConfidenceAction:
    """Helper function to create a default no confidence action from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return NoConfidenceAction.from_cbor(reader)


def create_no_confidence_action_without_gov_id() -> NoConfidenceAction:
    """Helper function to create a no confidence action without governance action ID."""
    reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
    return NoConfidenceAction.from_cbor(reader)


class TestNoConfidenceAction:
    """Tests for the NoConfidenceAction class."""

    def test_new_creates_action_without_governance_action_id(self):
        """Test creating a new no confidence action without governance action ID."""
        action = NoConfidenceAction.new()

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR_WITHOUT_GOV_ACTION

    def test_new_creates_action_with_governance_action_id(self):
        """Test creating a new no confidence action with governance action ID."""
        gov_action_id = create_default_governance_action_id()
        action = NoConfidenceAction.new(gov_action_id)

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_new_with_none_governance_action_id(self):
        """Test creating a new no confidence action with explicit None governance action ID."""
        action = NoConfidenceAction.new(None)

        assert action is not None
        assert action.governance_action_id is None

    def test_from_cbor_deserializes_action_with_governance_action_id(self):
        """Test deserializing a no confidence action with governance action ID from CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = NoConfidenceAction.from_cbor(reader)

        assert action is not None
        assert action.governance_action_id is not None

    def test_from_cbor_deserializes_action_without_governance_action_id(self):
        """Test deserializing a no confidence action without governance action ID from CBOR."""
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = NoConfidenceAction.from_cbor(reader)

        assert action is not None
        assert action.governance_action_id is None

    def test_from_cbor_raises_error_with_null_reader(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            NoConfidenceAction.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_not_array(self):
        """Test that deserializing invalid CBOR (not an array) raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            NoConfidenceAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_array_size(self):
        """Test that deserializing invalid CBOR (wrong array size) raises error."""
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            NoConfidenceAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_action_id(self):
        """Test that deserializing invalid action ID raises error."""
        reader = CborReader.from_hex("82effe820103")

        with pytest.raises(CardanoError):
            NoConfidenceAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_governance_action(self):
        """Test that deserializing invalid governance action raises error."""
        reader = CborReader.from_hex("8203ef820103")

        with pytest.raises(CardanoError):
            NoConfidenceAction.from_cbor(reader)

    def test_to_cbor_serializes_action_with_governance_action_id(self):
        """Test serializing a no confidence action with governance action ID to CBOR."""
        action = create_default_no_confidence_action()
        writer = CborWriter()
        action.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_serializes_action_without_governance_action_id(self):
        """Test serializing a no confidence action without governance action ID to CBOR."""
        action = create_no_confidence_action_without_gov_id()
        writer = CborWriter()
        action.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_WITHOUT_GOV_ACTION

    def test_to_cbor_raises_error_with_null_writer(self):
        """Test that serializing with null writer raises error."""
        action = create_default_no_confidence_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.to_cbor(None)

    def test_get_governance_action_id_returns_id_when_set(self):
        """Test getting governance action ID returns ID when set."""
        action = create_default_no_confidence_action()
        gov_action_id = action.governance_action_id

        assert gov_action_id is not None

    def test_get_governance_action_id_returns_none_when_not_set(self):
        """Test getting governance action ID returns None when not set."""
        action = create_no_confidence_action_without_gov_id()
        gov_action_id = action.governance_action_id

        assert gov_action_id is None

    def test_set_governance_action_id_updates_id(self):
        """Test setting the governance action ID on a no confidence action."""
        action = create_no_confidence_action_without_gov_id()
        gov_action_id = create_default_governance_action_id()

        action.governance_action_id = gov_action_id

        retrieved_id = action.governance_action_id
        assert retrieved_id is not None

    def test_set_governance_action_id_can_be_set_to_none(self):
        """Test that governance action ID can be set to None."""
        action = create_default_no_confidence_action()

        action.governance_action_id = None

        gov_action_id = action.governance_action_id
        assert gov_action_id is None

    def test_set_governance_action_id_with_new_id(self):
        """Test setting a new governance action ID."""
        action = create_default_no_confidence_action()
        new_hash = Blake2bHash.from_hex(DATA_HASH)
        new_gov_action_id = GovernanceActionId.new(new_hash, 5)

        action.governance_action_id = new_gov_action_id

        retrieved_id = action.governance_action_id
        assert retrieved_id is not None

    def test_to_cip116_json_with_governance_action_id(self):
        """Test serializing no confidence action with governance action ID to CIP-116 JSON."""
        tx_hash = Blake2bHash.from_hex(DATA_HASH)
        gov_action_id = GovernanceActionId.new(tx_hash, 4)
        action = NoConfidenceAction.new(gov_action_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "tag" in json_str
        assert "no_confidence" in json_str
        assert "gov_action_id" in json_str
        assert "transaction_id" in json_str
        assert DATA_HASH in json_str
        assert "gov_action_index" in json_str
        assert "4" in json_str

    def test_to_cip116_json_without_governance_action_id(self):
        """Test serializing no confidence action without governance action ID to CIP-116 JSON."""
        action = NoConfidenceAction.new(None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "tag" in json_str
        assert "no_confidence" in json_str
        assert "gov_action_id" not in json_str

    def test_to_cip116_json_raises_error_with_null_writer(self):
        """Test that serializing to JSON with null writer raises error."""
        action = create_default_no_confidence_action()

        with pytest.raises((CardanoError, TypeError)):
            action.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_invalid_writer_type(self):
        """Test that serializing to JSON with invalid writer type raises error."""
        action = create_default_no_confidence_action()

        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")

    def test_repr_returns_string_representation(self):
        """Test that __repr__ returns a string representation."""
        action = create_default_no_confidence_action()
        repr_str = repr(action)

        assert "NoConfidenceAction" in repr_str

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self for context manager."""
        action = create_default_no_confidence_action()

        with action as ctx:
            assert ctx is action

    def test_context_manager_exit_completes(self):
        """Test that __exit__ completes without error."""
        action = create_default_no_confidence_action()

        with action:
            pass

    def test_cbor_roundtrip_without_governance_action_id(self):
        """Test CBOR serialization roundtrip without governance action ID."""
        original = create_no_confidence_action_without_gov_id()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = NoConfidenceAction.from_cbor(reader)

        assert restored is not None
        assert restored.governance_action_id is None

    def test_cbor_roundtrip_with_governance_action_id(self):
        """Test CBOR serialization roundtrip with governance action ID."""
        original = create_default_no_confidence_action()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = NoConfidenceAction.from_cbor(reader)

        assert restored is not None
        assert restored.governance_action_id is not None

    def test_governance_action_id_property_update(self):
        """Test updating governance action ID property multiple times."""
        action = create_no_confidence_action_without_gov_id()

        gov_id_1 = create_default_governance_action_id()
        action.governance_action_id = gov_id_1
        assert action.governance_action_id is not None

        action.governance_action_id = None
        assert action.governance_action_id is None

        tx_hash = Blake2bHash.from_hex(DATA_HASH)
        gov_id_2 = GovernanceActionId.new(tx_hash, 10)
        action.governance_action_id = gov_id_2
        assert action.governance_action_id is not None

    def test_new_action_has_correct_initial_state_without_gov_id(self):
        """Test that a newly created action without gov ID has correct initial state."""
        action = NoConfidenceAction.new()

        assert action.governance_action_id is None

    def test_new_action_has_correct_initial_state_with_gov_id(self):
        """Test that a newly created action with gov ID has correct initial state."""
        gov_action_id = create_default_governance_action_id()
        action = NoConfidenceAction.new(gov_action_id)

        assert action.governance_action_id is not None

    def test_multiple_actions_are_independent(self):
        """Test that multiple action instances are independent."""
        action1 = NoConfidenceAction.new()
        action2 = NoConfidenceAction.new()

        gov_id = create_default_governance_action_id()
        action1.governance_action_id = gov_id

        assert action1.governance_action_id is not None
        assert action2.governance_action_id is None

    def test_from_cbor_with_valid_governance_action_structure(self):
        """Test deserializing from CBOR with valid governance action structure."""
        reader = CborReader.from_hex(CBOR)
        action = NoConfidenceAction.from_cbor(reader)

        writer = CborWriter()
        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_governance_action_id_property_getter_with_different_indices(self):
        """Test governance action ID property getter with different indices."""
        tx_hash = Blake2bHash.from_hex(DATA_HASH)

        for index in [0, 1, 3, 10, 100]:
            gov_id = GovernanceActionId.new(tx_hash, index)
            action = NoConfidenceAction.new(gov_id)

            retrieved_id = action.governance_action_id
            assert retrieved_id is not None

    def test_serialization_produces_deterministic_output(self):
        """Test that serialization produces deterministic output."""
        gov_id = create_default_governance_action_id()
        action1 = NoConfidenceAction.new(gov_id)
        action2 = NoConfidenceAction.new(gov_id)

        writer1 = CborWriter()
        action1.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        action2.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_json_serialization_produces_valid_structure(self):
        """Test that JSON serialization produces valid structure."""
        tx_hash = Blake2bHash.from_hex(DATA_HASH)
        gov_id = GovernanceActionId.new(tx_hash, 3)
        action = NoConfidenceAction.new(gov_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.startswith("{")
        assert json_str.endswith("}")
        assert json_str.count("{") == json_str.count("}")

    def test_action_lifecycle_with_context_manager(self):
        """Test complete action lifecycle using context manager."""
        gov_id = create_default_governance_action_id()

        with NoConfidenceAction.new(gov_id) as action:
            assert action is not None
            assert action.governance_action_id is not None

            writer = CborWriter()
            action.to_cbor(writer)
            cbor_hex = writer.to_hex()

            assert len(cbor_hex) > 0
