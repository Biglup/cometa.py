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

# pylint: disable=no-self-use

import pytest
from cometa import (
    InfoAction,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "8106"


def create_default_info_action() -> InfoAction:
    """Helper function to create a default info action from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return InfoAction.from_cbor(reader)


class TestInfoAction:
    """Tests for the InfoAction class."""

    def test_new_creates_action(self):
        """Test creating a new info action."""
        action = InfoAction.new()

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_from_cbor_deserializes_action(self):
        """Test deserializing an info action from CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = InfoAction.from_cbor(reader)

        assert action is not None

    def test_from_cbor_raises_error_with_null_reader(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            InfoAction.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_not_array(self):
        """Test that deserializing invalid CBOR (not an array) raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            InfoAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_array_size(self):
        """Test that deserializing invalid CBOR (wrong array size) raises error."""
        reader = CborReader.from_hex("8300")

        with pytest.raises(CardanoError):
            InfoAction.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_action_id(self):
        """Test that deserializing invalid action ID raises error."""
        reader = CborReader.from_hex("81ef")

        with pytest.raises(CardanoError):
            InfoAction.from_cbor(reader)

    def test_to_cbor_serializes_action(self):
        """Test serializing an info action to CBOR."""
        action = create_default_info_action()
        writer = CborWriter()
        action.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_raises_error_with_null_writer(self):
        """Test that serializing with null writer raises error."""
        action = create_default_info_action()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            action.to_cbor(None)

    def test_to_cip116_json_converts_info_action(self):
        """Test serializing info action to CIP-116 JSON."""
        action = InfoAction.new()

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == '{"tag":"info_action"}'

    def test_to_cip116_json_raises_error_with_null_writer(self):
        """Test that serializing to JSON with null writer raises error."""
        action = create_default_info_action()

        with pytest.raises((CardanoError, TypeError)):
            action.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_invalid_writer_type(self):
        """Test that serializing to JSON with invalid writer type raises error."""
        action = create_default_info_action()

        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")

    def test_repr_returns_string_representation(self):
        """Test that __repr__ returns a string representation."""
        action = create_default_info_action()
        repr_str = repr(action)

        assert "InfoAction" in repr_str

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self for context manager."""
        action = create_default_info_action()

        with action as ctx:
            assert ctx is action

    def test_context_manager_exit_completes(self):
        """Test that __exit__ completes without error."""
        action = create_default_info_action()

        with action:
            pass

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        original = create_default_info_action()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = InfoAction.from_cbor(reader)

        assert restored is not None

    def test_new_action_can_be_serialized(self):
        """Test that a newly created action can be serialized."""
        action = InfoAction.new()

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert len(cbor_hex) > 0

    def test_multiple_actions_are_independent(self):
        """Test that multiple action instances are independent."""
        action1 = InfoAction.new()
        action2 = InfoAction.new()

        assert action1 is not action2

        writer1 = CborWriter()
        action1.to_cbor(writer1)

        writer2 = CborWriter()
        action2.to_cbor(writer2)

        assert writer1.to_hex() == writer2.to_hex()

    def test_from_cbor_produces_consistent_result(self):
        """Test that deserializing from CBOR produces consistent result."""
        reader = CborReader.from_hex(CBOR)
        action = InfoAction.from_cbor(reader)

        writer = CborWriter()
        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_serialization_produces_deterministic_output(self):
        """Test that serialization produces deterministic output."""
        action1 = InfoAction.new()
        action2 = InfoAction.new()

        writer1 = CborWriter()
        action1.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        action2.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_json_serialization_produces_valid_structure(self):
        """Test that JSON serialization produces valid structure."""
        action = InfoAction.new()

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.startswith("{")
        assert json_str.endswith("}")
        assert json_str.count("{") == json_str.count("}")
        assert "tag" in json_str
        assert "info_action" in json_str

    def test_action_lifecycle_with_context_manager(self):
        """Test complete action lifecycle using context manager."""
        with InfoAction.new() as action:
            assert action is not None

            writer = CborWriter()
            action.to_cbor(writer)
            cbor_hex = writer.to_hex()

            assert len(cbor_hex) > 0
            assert cbor_hex == CBOR

    def test_multiple_cbor_serializations_are_consistent(self):
        """Test that multiple CBOR serializations of the same action are consistent."""
        action = create_default_info_action()

        writer1 = CborWriter()
        action.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        action.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        writer3 = CborWriter()
        action.to_cbor(writer3)
        cbor3 = writer3.to_hex()

        assert cbor1 == cbor2 == cbor3

    def test_multiple_json_serializations_are_consistent(self):
        """Test that multiple JSON serializations of the same action are consistent."""
        action = create_default_info_action()

        writer1 = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer1)
        json1 = writer1.encode()

        writer2 = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer2)
        json2 = writer2.encode()

        writer3 = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer3)
        json3 = writer3.encode()

        assert json1 == json2 == json3

    def test_cbor_deserialization_and_reserialization_maintains_data(self):
        """Test that CBOR deserialization and reserialization maintains data."""
        original_hex = CBOR

        reader = CborReader.from_hex(original_hex)
        action = InfoAction.from_cbor(reader)

        writer = CborWriter()
        action.to_cbor(writer)
        reserialized_hex = writer.to_hex()

        assert original_hex == reserialized_hex

    def test_new_action_is_valid(self):
        """Test that a newly created action is valid and can be used."""
        action = InfoAction.new()

        writer_cbor = CborWriter()
        action.to_cbor(writer_cbor)

        writer_json = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer_json)

        assert len(writer_cbor.to_hex()) > 0
        assert len(writer_json.encode()) > 0

    def test_action_can_be_used_after_context_manager(self):
        """Test that action can be used after exiting context manager."""
        action = InfoAction.new()

        with action:
            writer1 = CborWriter()
            action.to_cbor(writer1)
            cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        action.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_json_format_compact_produces_compact_output(self):
        """Test that JSON format compact produces compact output."""
        action = InfoAction.new()

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "\n" not in json_str
        assert "  " not in json_str

    def test_from_cbor_with_reader_at_correct_position(self):
        """Test deserializing from CBOR with reader at correct position."""
        reader = CborReader.from_hex(CBOR)
        action = InfoAction.from_cbor(reader)

        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_action_memory_cleanup(self):
        """Test that action memory is properly cleaned up."""
        for _ in range(100):
            action = InfoAction.new()
            writer = CborWriter()
            action.to_cbor(writer)
            del action
            del writer

    def test_cbor_hex_has_expected_structure(self):
        """Test that CBOR hex has expected structure."""
        action = InfoAction.new()
        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex.startswith("81")
        assert "06" in cbor_hex

    def test_new_creates_valid_cbor_immediately(self):
        """Test that new() creates valid CBOR immediately."""
        action = InfoAction.new()
        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        restored = InfoAction.from_cbor(reader)

        assert restored is not None
