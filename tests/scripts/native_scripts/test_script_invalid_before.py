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
from cometa.scripts.native_scripts import ScriptInvalidBefore
from cometa.cbor import CborReader, CborWriter
from cometa.json import JsonWriter, JsonFormat
from cometa.errors import CardanoError


SLOT_3000 = 3000
SLOT_4000 = 4000


class TestScriptInvalidBefore:
    """Tests for the ScriptInvalidBefore class."""

    def test_new_with_valid_slot(self):
        """Test creating a ScriptInvalidBefore with a valid slot number."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script is not None
        assert script.slot == SLOT_3000

    def test_new_with_zero_slot(self):
        """Test creating a ScriptInvalidBefore with slot 0."""
        script = ScriptInvalidBefore.new(0)
        assert script is not None
        assert script.slot == 0

    def test_new_with_large_slot(self):
        """Test creating a ScriptInvalidBefore with a large slot number."""
        large_slot = 2**63 - 1
        script = ScriptInvalidBefore.new(large_slot)
        assert script is not None
        assert script.slot == large_slot

    def test_slot_getter(self):
        """Test getting the slot from a ScriptInvalidBefore."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script.slot == SLOT_3000

    def test_slot_setter(self):
        """Test setting a new slot on a ScriptInvalidBefore."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script.slot == SLOT_3000
        script.slot = SLOT_4000
        assert script.slot == SLOT_4000

    def test_slot_setter_with_zero(self):
        """Test setting slot to zero."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        script.slot = 0
        assert script.slot == 0

    def test_slot_setter_with_large_value(self):
        """Test setting slot to a large value."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        large_slot = 2**63 - 1
        script.slot = large_slot
        assert script.slot == large_slot

    def test_to_cbor(self):
        """Test serializing a ScriptInvalidBefore to CBOR."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_from_cbor(self):
        """Test deserializing a ScriptInvalidBefore from CBOR."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptInvalidBefore.from_cbor(reader)
        assert script2.slot == SLOT_3000

    def test_from_cbor_with_invalid_data_no_array(self):
        """Test deserializing a ScriptInvalidBefore from invalid CBOR data (not an array)."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptInvalidBefore.from_cbor(reader)

    def test_from_cbor_with_invalid_data_no_int(self):
        """Test deserializing a ScriptInvalidBefore from CBOR with invalid array (no int)."""
        reader = CborReader.from_hex("82fe")
        with pytest.raises(CardanoError):
            ScriptInvalidBefore.from_cbor(reader)

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptInvalidBefore.from_cbor(reader)
        assert script1 == script2

    def test_hash_property(self):
        """Test getting the hash of the native script."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        script_hash = script.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_hash_property_consistency(self):
        """Test that hash property returns consistent results."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        hash1 = script.hash
        hash2 = script.hash
        assert hash1 == hash2

    def test_to_cip116_json(self):
        """Test serializing a ScriptInvalidBefore to CIP-116 JSON."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        writer = JsonWriter(JsonFormat.PRETTY)
        script.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag"' in json_str
        assert '"timelock_start"' in json_str
        assert '"slot"' in json_str
        assert '"3000"' in json_str

    def test_to_cip116_json_with_invalid_writer(self):
        """Test serializing to CIP-116 JSON with invalid writer."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        with pytest.raises(TypeError):
            script.to_cip116_json("not a writer")

    def test_equals_same_script(self):
        """Test equality of two ScriptInvalidBefore instances with the same slot."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_3000)
        assert script1 == script2

    def test_equals_different_script(self):
        """Test inequality of two ScriptInvalidBefore instances with different slots."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)
        assert script1 != script2

    def test_equals_with_non_script_invalid_before(self):
        """Test inequality with a non-ScriptInvalidBefore object."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script != "not a script"
        assert script != 42
        assert script != None

    def test_repr(self):
        """Test string representation of ScriptInvalidBefore."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        repr_str = repr(script)
        assert "ScriptInvalidBefore" in repr_str
        assert "3000" in repr_str

    def test_context_manager(self):
        """Test using ScriptInvalidBefore as a context manager."""
        with ScriptInvalidBefore.new(SLOT_3000) as script:
            assert script is not None
            assert script.slot == SLOT_3000

    def test_lifecycle(self):
        """Test object lifecycle and cleanup."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script.slot == SLOT_3000
        del script

    def test_multiple_slot_changes(self):
        """Test changing slot multiple times."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script.slot == SLOT_3000
        script.slot = SLOT_4000
        assert script.slot == SLOT_4000
        script.slot = SLOT_3000
        assert script.slot == SLOT_3000

    def test_cbor_serialization_deterministic(self):
        """Test that CBOR serialization is deterministic."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        writer1 = CborWriter()
        script.to_cbor(writer1)
        cbor_bytes1 = writer1.encode()
        writer2 = CborWriter()
        script.to_cbor(writer2)
        cbor_bytes2 = writer2.encode()
        assert cbor_bytes1 == cbor_bytes2

    def test_different_slots_produce_different_hashes(self):
        """Test that different slots produce different script hashes."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)
        assert script1.hash != script2.hash

    def test_equality_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script == script

    def test_equality_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_3000)
        assert script1 == script2
        assert script2 == script1

    def test_equality_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_3000)
        script3 = ScriptInvalidBefore.new(SLOT_3000)
        assert script1 == script2
        assert script2 == script3
        assert script1 == script3

    def test_inequality_reflexive(self):
        """Test that inequality works correctly."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)
        assert script1 != script2
        assert not (script1 == script2)

    def test_slot_immutability_after_cbor(self):
        """Test that slot remains unchanged after CBOR serialization."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        original_slot = script.slot
        writer = CborWriter()
        script.to_cbor(writer)
        assert script.slot == original_slot

    def test_cbor_writer_after_serialization(self):
        """Test that CBOR writer state is consistent after serialization."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_cbor_deserialization_creates_independent_object(self):
        """Test that CBOR deserialization creates independent objects."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptInvalidBefore.from_cbor(reader)
        script1.slot = SLOT_4000
        assert script2.slot == SLOT_3000

    def test_multiple_cbor_roundtrips(self):
        """Test multiple CBOR serialization and deserialization cycles."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        for _ in range(3):
            writer = CborWriter()
            script.to_cbor(writer)
            cbor_bytes = writer.encode()
            reader = CborReader.from_hex(cbor_bytes.hex())
            script = ScriptInvalidBefore.from_cbor(reader)
        assert script.slot == SLOT_3000

    def test_hash_property_after_slot_change(self):
        """Test that hash property updates after changing slot."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        hash1 = script.hash
        script.slot = SLOT_4000
        hash2 = script.hash
        assert hash1 != hash2

    def test_repr_with_different_slots(self):
        """Test that repr differs for different slots."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)
        repr1 = repr(script1)
        repr2 = repr(script2)
        assert repr1 != repr2
        assert "3000" in repr1
        assert "4000" in repr2

    def test_script_invalid_before_with_max_slot(self):
        """Test creating a ScriptInvalidBefore with maximum slot value."""
        max_slot = 2**64 - 1
        script = ScriptInvalidBefore.new(max_slot)
        assert script.slot == max_slot

    def test_equality_after_slot_change(self):
        """Test equality after slot changes."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)
        assert script1 != script2
        script2.slot = SLOT_3000
        assert script1 == script2

    def test_hash_property_with_zero_slot(self):
        """Test that hash property works with zero slot."""
        script = ScriptInvalidBefore.new(0)
        script_hash = script.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_cbor_roundtrip_with_zero_slot(self):
        """Test CBOR roundtrip with zero slot."""
        script1 = ScriptInvalidBefore.new(0)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptInvalidBefore.from_cbor(reader)
        assert script2.slot == 0
        assert script1 == script2

    def test_cbor_roundtrip_with_large_slot(self):
        """Test CBOR roundtrip with large slot value."""
        large_slot = 2**63 - 1
        script1 = ScriptInvalidBefore.new(large_slot)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptInvalidBefore.from_cbor(reader)
        assert script2.slot == large_slot
        assert script1 == script2

    def test_to_cip116_json_format(self):
        """Test that CIP-116 JSON has correct format."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        writer = JsonWriter(JsonFormat.PRETTY)
        script.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str.count('"tag"') == 1
        assert json_str.count('"slot"') == 1
        assert '"timelock_start"' in json_str

    def test_slot_property_returns_int(self):
        """Test that slot property returns an integer."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        slot = script.slot
        assert isinstance(slot, int)
        assert slot == SLOT_3000

    def test_context_manager_with_exception(self):
        """Test using ScriptInvalidBefore as a context manager with exception."""
        try:
            with ScriptInvalidBefore.new(SLOT_3000) as script:
                assert script.slot == SLOT_3000
                raise ValueError("Test exception")
        except ValueError:
            pass

    def test_script_with_slot_boundary_values(self):
        """Test script creation with boundary slot values."""
        script_zero = ScriptInvalidBefore.new(0)
        assert script_zero.slot == 0

        script_max = ScriptInvalidBefore.new(2**64 - 1)
        assert script_max.slot == 2**64 - 1

    def test_equality_with_same_object_reference(self):
        """Test equality when comparing the same object reference."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        assert script == script
        assert not (script != script)

    def test_hash_consistency_across_instances(self):
        """Test that hash is consistent across different instances with same slot."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_3000)
        assert script1.hash == script2.hash

    def test_slot_setter_multiple_consecutive_sets(self):
        """Test setting slot multiple consecutive times."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        for slot in [SLOT_4000, 5000, 6000, SLOT_3000]:
            script.slot = slot
            assert script.slot == slot

    def test_cbor_serialization_with_different_slots(self):
        """Test that CBOR serialization differs for different slots."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_4000)

        writer1 = CborWriter()
        script1.to_cbor(writer1)
        cbor1 = writer1.encode()

        writer2 = CborWriter()
        script2.to_cbor(writer2)
        cbor2 = writer2.encode()

        assert cbor1 != cbor2

    def test_repr_includes_class_name_and_slot(self):
        """Test that repr includes both class name and slot value."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        repr_str = repr(script)
        assert "ScriptInvalidBefore" in repr_str
        assert "slot" in repr_str
        assert str(SLOT_3000) in repr_str

    def test_slot_setter_preserves_object_identity(self):
        """Test that setting slot doesn't change object identity."""
        script = ScriptInvalidBefore.new(SLOT_3000)
        obj_id = id(script)
        script.slot = SLOT_4000
        assert id(script) == obj_id

    def test_equality_is_value_based_not_reference_based(self):
        """Test that equality is based on values, not object references."""
        script1 = ScriptInvalidBefore.new(SLOT_3000)
        script2 = ScriptInvalidBefore.new(SLOT_3000)
        assert script1 == script2
        assert script1 is not script2
        assert id(script1) != id(script2)
