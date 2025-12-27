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
from cometa import ScriptInvalidAfter, CborReader, CborWriter, JsonWriter


class TestScriptInvalidAfterCreation:
    """Tests for ScriptInvalidAfter initialization."""

    def test_can_create_with_valid_slot(self):
        """Test that ScriptInvalidAfter can be created with a valid slot number."""
        script = ScriptInvalidAfter.new(3000)
        assert script is not None
        assert script.slot == 3000

    def test_can_create_with_zero_slot(self):
        """Test that ScriptInvalidAfter can be created with slot 0."""
        script = ScriptInvalidAfter.new(0)
        assert script is not None
        assert script.slot == 0

    def test_can_create_with_large_slot(self):
        """Test that ScriptInvalidAfter can be created with a large slot value."""
        script = ScriptInvalidAfter.new(1000000)
        assert script is not None
        assert script.slot == 1000000

    def test_can_create_with_max_uint64_slot(self):
        """Test that ScriptInvalidAfter can be created with maximum uint64 value."""
        max_uint64 = 18446744073709551615
        script = ScriptInvalidAfter.new(max_uint64)
        assert script is not None
        assert script.slot == max_uint64


class TestScriptInvalidAfterCborSerialization:
    """Tests for ScriptInvalidAfter CBOR serialization."""

    def test_can_serialize_to_cbor(self):
        """Test that ScriptInvalidAfter can be serialized to CBOR."""
        script = ScriptInvalidAfter.new(3000)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert cbor_bytes is not None
        assert len(cbor_bytes) > 0

    def test_can_deserialize_from_cbor(self):
        """Test that ScriptInvalidAfter can be deserialized from CBOR."""
        script = ScriptInvalidAfter.new(3000)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        deserialized = ScriptInvalidAfter.from_cbor(reader)
        assert deserialized is not None
        assert deserialized.slot == 3000

    def test_cbor_round_trip_preserves_slot(self):
        """Test that CBOR serialization round-trip preserves slot value."""
        original_slot = 4000
        script = ScriptInvalidAfter.new(original_slot)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        deserialized = ScriptInvalidAfter.from_cbor(reader)
        assert deserialized.slot == original_slot

    def test_cbor_round_trip_with_zero_slot(self):
        """Test CBOR round-trip with slot value of 0."""
        script = ScriptInvalidAfter.new(0)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        deserialized = ScriptInvalidAfter.from_cbor(reader)
        assert deserialized.slot == 0

    def test_cbor_round_trip_with_large_slot(self):
        """Test CBOR round-trip with a large slot value."""
        large_slot = 999999999
        script = ScriptInvalidAfter.new(large_slot)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        deserialized = ScriptInvalidAfter.from_cbor(reader)
        assert deserialized.slot == large_slot

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that from_cbor raises error with invalid CBOR data."""
        invalid_cbor = bytes.fromhex("fe01")
        reader = CborReader.from_bytes(invalid_cbor)
        with pytest.raises(Exception):
            ScriptInvalidAfter.from_cbor(reader)

    def test_from_cbor_with_wrong_type_raises_error(self):
        """Test that from_cbor raises error when CBOR doesn't contain array."""
        invalid_cbor = bytes.fromhex("82fe")
        reader = CborReader.from_bytes(invalid_cbor)
        with pytest.raises(Exception):
            ScriptInvalidAfter.from_cbor(reader)


class TestScriptInvalidAfterCip116Json:
    """Tests for ScriptInvalidAfter CIP-116 JSON serialization."""

    def test_can_serialize_to_cip116_json(self):
        """Test that ScriptInvalidAfter can be serialized to CIP-116 JSON."""
        script = ScriptInvalidAfter.new(3000)
        writer = JsonWriter()
        script.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str is not None
        assert "timelock_expiry" in json_str
        assert "3000" in json_str

    def test_cip116_json_has_correct_structure(self):
        """Test that CIP-116 JSON has the correct structure."""
        script = ScriptInvalidAfter.new(3000)
        writer = JsonWriter()
        script.to_cip116_json(writer)
        json_str = writer.encode()
        assert "tag" in json_str
        assert "slot" in json_str

    def test_cip116_json_with_different_slots(self):
        """Test CIP-116 JSON serialization with different slot values."""
        test_slots = [0, 100, 3000, 4000, 999999]
        for slot_value in test_slots:
            script = ScriptInvalidAfter.new(slot_value)
            writer = JsonWriter()
            script.to_cip116_json(writer)
            json_str = writer.encode()
            assert str(slot_value) in json_str

    def test_cip116_json_with_invalid_writer_raises_error(self):
        """Test that to_cip116_json raises error with invalid writer."""
        script = ScriptInvalidAfter.new(3000)
        with pytest.raises(TypeError, match="writer must be a JsonWriter instance"):
            script.to_cip116_json("not a writer")

    def test_cip116_json_with_none_writer_raises_error(self):
        """Test that to_cip116_json raises error with None writer."""
        script = ScriptInvalidAfter.new(3000)
        with pytest.raises(TypeError):
            script.to_cip116_json(None)


class TestScriptInvalidAfterSlotProperty:
    """Tests for ScriptInvalidAfter slot property."""

    def test_can_get_slot(self):
        """Test that slot property can be retrieved."""
        script = ScriptInvalidAfter.new(3000)
        assert script.slot == 3000

    def test_can_set_slot(self):
        """Test that slot property can be modified."""
        script = ScriptInvalidAfter.new(3000)
        script.slot = 4000
        assert script.slot == 4000

    def test_can_set_slot_to_zero(self):
        """Test that slot can be set to zero."""
        script = ScriptInvalidAfter.new(3000)
        script.slot = 0
        assert script.slot == 0

    def test_can_set_slot_multiple_times(self):
        """Test that slot can be modified multiple times."""
        script = ScriptInvalidAfter.new(1000)
        script.slot = 2000
        assert script.slot == 2000
        script.slot = 3000
        assert script.slot == 3000
        script.slot = 4000
        assert script.slot == 4000

    def test_slot_setter_with_large_value(self):
        """Test setting slot to a large value."""
        script = ScriptInvalidAfter.new(0)
        large_slot = 999999999
        script.slot = large_slot
        assert script.slot == large_slot

    def test_slot_setter_with_max_uint64(self):
        """Test setting slot to maximum uint64 value."""
        script = ScriptInvalidAfter.new(0)
        max_uint64 = 18446744073709551615
        script.slot = max_uint64
        assert script.slot == max_uint64


class TestScriptInvalidAfterHash:
    """Tests for ScriptInvalidAfter hash property."""

    def test_can_get_hash(self):
        """Test that hash property can be retrieved."""
        script = ScriptInvalidAfter.new(3000)
        script_hash = script.hash
        assert script_hash is not None
        assert isinstance(script_hash, bytes)

    def test_hash_has_correct_length(self):
        """Test that hash has the correct length (28 bytes)."""
        script = ScriptInvalidAfter.new(3000)
        script_hash = script.hash
        assert len(script_hash) == 28

    def test_hash_is_consistent(self):
        """Test that hash is consistent for the same slot value."""
        script = ScriptInvalidAfter.new(3000)
        hash1 = script.hash
        hash2 = script.hash
        assert hash1 == hash2

    def test_hash_changes_when_slot_changes(self):
        """Test that hash changes when slot is modified."""
        script = ScriptInvalidAfter.new(3000)
        hash1 = script.hash
        script.slot = 4000
        hash2 = script.hash
        assert hash1 != hash2

    def test_different_slots_produce_different_hashes(self):
        """Test that different slots produce different hashes."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(4000)
        assert script1.hash != script2.hash


class TestScriptInvalidAfterEquality:
    """Tests for ScriptInvalidAfter equality comparison."""

    def test_equality_for_same_slot(self):
        """Test that two scripts with same slot are equal."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(3000)
        assert script1 == script2

    def test_equality_for_zero_slot(self):
        """Test that two scripts with slot 0 are equal."""
        script1 = ScriptInvalidAfter.new(0)
        script2 = ScriptInvalidAfter.new(0)
        assert script1 == script2

    def test_inequality_for_different_slots(self):
        """Test that scripts with different slots are not equal."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(4000)
        assert script1 != script2

    def test_inequality_with_non_script_invalid_after(self):
        """Test that ScriptInvalidAfter is not equal to other types."""
        script = ScriptInvalidAfter.new(3000)
        assert script != "not a script"
        assert script != 3000
        assert script is not None
        assert script != [3000]

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(3000)
        assert script1 == script2
        assert script2 == script1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(3000)
        script3 = ScriptInvalidAfter.new(3000)
        assert script1 == script2
        assert script2 == script3
        assert script1 == script3

    def test_equality_after_slot_modification(self):
        """Test equality after modifying slot values."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(4000)
        assert script1 != script2
        script2.slot = 3000
        assert script1 == script2


class TestScriptInvalidAfterRepr:
    """Tests for ScriptInvalidAfter string representation."""

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains the class name."""
        script = ScriptInvalidAfter.new(3000)
        repr_str = repr(script)
        assert "ScriptInvalidAfter" in repr_str

    def test_repr_contains_slot(self):
        """Test that __repr__ contains the slot value."""
        script = ScriptInvalidAfter.new(3000)
        repr_str = repr(script)
        assert "3000" in repr_str

    def test_repr_with_zero_slot(self):
        """Test __repr__ with slot value of 0."""
        script = ScriptInvalidAfter.new(0)
        repr_str = repr(script)
        assert "0" in repr_str

    def test_repr_with_large_slot(self):
        """Test __repr__ with a large slot value."""
        script = ScriptInvalidAfter.new(999999)
        repr_str = repr(script)
        assert "999999" in repr_str

    def test_repr_format(self):
        """Test that __repr__ has expected format."""
        script = ScriptInvalidAfter.new(3000)
        repr_str = repr(script)
        assert repr_str == "ScriptInvalidAfter(slot=3000)"


class TestScriptInvalidAfterContextManager:
    """Tests for ScriptInvalidAfter context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that ScriptInvalidAfter can be used as context manager."""
        with ScriptInvalidAfter.new(3000) as script:
            assert script is not None
            assert script.slot == 3000

    def test_context_manager_returns_self(self):
        """Test that __enter__ returns the script instance."""
        script = ScriptInvalidAfter.new(3000)
        with script as ctx_script:
            assert ctx_script is script

    def test_context_manager_allows_operations(self):
        """Test that operations can be performed within context manager."""
        with ScriptInvalidAfter.new(3000) as script:
            script.slot = 4000
            assert script.slot == 4000
            script_hash = script.hash
            assert len(script_hash) == 28

    def test_context_manager_with_cbor_operations(self):
        """Test CBOR operations within context manager."""
        with ScriptInvalidAfter.new(3000) as script:
            writer = CborWriter()
            script.to_cbor(writer)
            cbor_bytes = writer.encode()
            assert len(cbor_bytes) > 0

    def test_context_manager_with_json_operations(self):
        """Test JSON operations within context manager."""
        with ScriptInvalidAfter.new(3000) as script:
            writer = JsonWriter()
            script.to_cip116_json(writer)
            json_str = writer.encode()
            assert "timelock_expiry" in json_str


class TestScriptInvalidAfterEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_can_create_multiple_instances(self):
        """Test that multiple independent instances can be created."""
        script1 = ScriptInvalidAfter.new(1000)
        script2 = ScriptInvalidAfter.new(2000)
        script3 = ScriptInvalidAfter.new(3000)

        assert script1.slot == 1000
        assert script2.slot == 2000
        assert script3.slot == 3000

    def test_instances_are_independent(self):
        """Test that modifying one instance doesn't affect others."""
        script1 = ScriptInvalidAfter.new(1000)
        script2 = ScriptInvalidAfter.new(2000)

        script1.slot = 5000
        assert script1.slot == 5000
        assert script2.slot == 2000

    def test_cbor_serialization_of_multiple_scripts(self):
        """Test CBOR serialization of multiple different scripts."""
        scripts = [
            ScriptInvalidAfter.new(0),
            ScriptInvalidAfter.new(1000),
            ScriptInvalidAfter.new(3000),
            ScriptInvalidAfter.new(999999),
        ]

        for script in scripts:
            writer = CborWriter()
            script.to_cbor(writer)
            cbor_bytes = writer.encode()

            reader = CborReader.from_bytes(cbor_bytes)
            deserialized = ScriptInvalidAfter.from_cbor(reader)
            assert deserialized.slot == script.slot

    def test_json_serialization_of_multiple_scripts(self):
        """Test JSON serialization of multiple different scripts."""
        slots = [0, 1000, 3000, 4000, 999999]
        for slot_value in slots:
            script = ScriptInvalidAfter.new(slot_value)
            writer = JsonWriter()
            script.to_cip116_json(writer)
            json_str = writer.encode()
            assert "timelock_expiry" in json_str
            assert str(slot_value) in json_str

    def test_hash_consistency_across_equal_scripts(self):
        """Test that equal scripts have the same hash."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(3000)
        assert script1.hash == script2.hash

    def test_typical_mainnet_slot_values(self):
        """Test with typical mainnet slot values."""
        mainnet_slots = [5756214, 10000000, 50000000]
        for slot_value in mainnet_slots:
            script = ScriptInvalidAfter.new(slot_value)
            assert script.slot == slot_value
            assert len(script.hash) == 28

    def test_early_blockchain_slot_values(self):
        """Test with early blockchain slot values."""
        early_slots = [1, 10, 100, 1000]
        for slot_value in early_slots:
            script = ScriptInvalidAfter.new(slot_value)
            assert script.slot == slot_value

    def test_boundary_slot_values(self):
        """Test with boundary slot values."""
        max_uint64 = 18446744073709551615
        boundary_values = [0, 1, max_uint64 - 1, max_uint64]
        for slot_value in boundary_values:
            script = ScriptInvalidAfter.new(slot_value)
            assert script.slot == slot_value

    def test_slot_modification_sequence(self):
        """Test a sequence of slot modifications."""
        script = ScriptInvalidAfter.new(1000)
        modifications = [2000, 0, 3000, 100, 999999, 5000]
        for new_slot in modifications:
            script.slot = new_slot
            assert script.slot == new_slot

    def test_cbor_round_trip_multiple_times(self):
        """Test that multiple CBOR round-trips preserve data."""
        script = ScriptInvalidAfter.new(3000)
        for _ in range(5):
            writer = CborWriter()
            script.to_cbor(writer)
            cbor_bytes = writer.encode()

            reader = CborReader.from_bytes(cbor_bytes)
            script = ScriptInvalidAfter.from_cbor(reader)
            assert script.slot == 3000

    def test_comparison_chain(self):
        """Test chained equality comparisons."""
        script1 = ScriptInvalidAfter.new(3000)
        script2 = ScriptInvalidAfter.new(3000)
        script3 = ScriptInvalidAfter.new(4000)

        assert (script1 == script2) and (script2 != script3)
        assert (script1 == script2) or (script1 == script3)
        assert not (script1 != script2)
