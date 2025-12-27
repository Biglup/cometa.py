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
from cometa.scripts.native_scripts import ScriptAll, NativeScript
from cometa.cbor import CborReader, CborWriter
from cometa.json import JsonWriter, JsonFormat
from cometa.errors import CardanoError


ALL_SCRIPT_JSON = '''
{
  "type": "all",
  "scripts":
  [
    {
      "type": "after",
      "slot": 3000
    },
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    },
    {
      "type": "before",
      "slot": 4000
    }
  ]
}
'''

ALL_SCRIPT2_JSON = '''
{
  "type": "all",
  "scripts":
  [
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    },
    {
      "type": "before",
      "slot": 4000
    }
  ]
}
'''

SINGLE_SCRIPT_JSON = '''
{
  "type": "all",
  "scripts":
  [
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    }
  ]
}
'''

EMPTY_SCRIPT_JSON = '''
{
  "type": "all",
  "scripts": []
}
'''


class TestScriptAll:
    """Tests for the ScriptAll class."""

    def _get_script_all_from_json(self, json_str: str) -> ScriptAll:
        """Helper to get ScriptAll from a NativeScript created from JSON."""
        native_script = NativeScript.from_json(json_str)
        return native_script.to_all()

    def test_new_with_valid_script_list(self):
        """Test creating a ScriptAll with a valid NativeScriptList."""
        script_all = self._get_script_all_from_json(SINGLE_SCRIPT_JSON)
        scripts = script_all.scripts
        new_script_all = ScriptAll.new(scripts)
        assert new_script_all is not None
        assert len(new_script_all) == 1

    def test_new_with_python_list(self):
        """Test creating a ScriptAll with a Python list of scripts."""
        script_all = self._get_script_all_from_json(SINGLE_SCRIPT_JSON)
        scripts = script_all.scripts
        script_list = []
        for script in scripts:
            script_list.append(script)
        new_script_all = ScriptAll.new(script_list)
        assert new_script_all is not None
        assert len(new_script_all) == 1

    def test_new_with_empty_list(self):
        """Test creating a ScriptAll with an empty script list."""
        script_all = self._get_script_all_from_json(EMPTY_SCRIPT_JSON)
        scripts = script_all.scripts
        new_script_all = ScriptAll.new(scripts)
        assert new_script_all is not None
        assert len(new_script_all) == 0

    def test_from_cbor_with_valid_data(self):
        """Test deserializing a ScriptAll from valid CBOR data."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer = CborWriter()
        script_all1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_all2 = ScriptAll.from_cbor(reader)
        assert script_all2 is not None
        assert len(script_all2) == 3

    @staticmethod
    def test_from_cbor_with_invalid_data_no_array():
        """Test deserializing a ScriptAll from invalid CBOR data (no array)."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptAll.from_cbor(reader)

    @staticmethod
    def test_from_cbor_with_invalid_data_no_int():
        """Test deserializing a ScriptAll from invalid CBOR data (no int)."""
        reader = CborReader.from_hex("82fe")
        with pytest.raises(CardanoError):
            ScriptAll.from_cbor(reader)

    def test_to_cbor(self):
        """Test serializing a ScriptAll to CBOR."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer = CborWriter()
        script_all.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer = CborWriter()
        script_all1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_all2 = ScriptAll.from_cbor(reader)
        assert script_all1 == script_all2

    def test_to_cip116_json(self):
        """Test serializing a ScriptAll to CIP-116 JSON."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer = JsonWriter(JsonFormat.PRETTY)
        script_all.to_cip116_json(writer)
        json_str = writer.encode()
        assert "tag" in json_str
        assert "all" in json_str
        assert "scripts" in json_str

    def test_to_cip116_json_with_invalid_writer(self):
        """Test serializing to CIP-116 JSON with invalid writer."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        with pytest.raises(TypeError):
            script_all.to_cip116_json("not a writer")

    def test_get_scripts(self):
        """Test getting the scripts from a ScriptAll."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        scripts = script_all.scripts
        assert scripts is not None
        assert len(scripts) == 3

    def test_set_scripts(self):
        """Test setting new scripts on a ScriptAll."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert len(script_all) == 3
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        new_scripts = script_all2.scripts
        script_all.scripts = new_scripts
        assert len(script_all) == 2

    def test_set_scripts_with_python_list(self):
        """Test setting scripts using a Python list."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        new_scripts = script_all2.scripts
        script_list = []
        for script in new_scripts:
            script_list.append(script)
        script_all.scripts = script_list
        assert len(script_all) == 2

    def test_hash_property(self):
        """Test getting the hash of the ScriptAll."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_hash = script_all.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_hash_property_consistency(self):
        """Test that hash property returns consistent results."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        hash1 = script_all.hash
        hash2 = script_all.hash
        assert hash1 == hash2

    def test_len(self):
        """Test getting the length of the script list."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert len(script_all) == 3

    def test_len_with_empty_list(self):
        """Test length with empty script list."""
        script_all = self._get_script_all_from_json(EMPTY_SCRIPT_JSON)
        assert len(script_all) == 0

    def test_equals_same_script(self):
        """Test equality of two ScriptAll instances with the same content."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert script_all1 == script_all2

    def test_equals_different_script(self):
        """Test inequality of two ScriptAll instances with different content."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        assert script_all1 != script_all2

    def test_equals_with_non_script_all(self):
        """Test inequality with a non-ScriptAll object."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert script_all != "not a script"
        assert script_all != 42
        assert script_all is not None

    def test_repr(self):
        """Test string representation of ScriptAll."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        repr_str = repr(script_all)
        assert "ScriptAll" in repr_str
        assert "len=3" in repr_str

    def test_context_manager(self):
        """Test using ScriptAll as a context manager."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        with script_all:
            assert script_all is not None
            assert len(script_all) == 3

    def test_lifecycle(self):
        """Test object lifecycle and cleanup."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert len(script_all) == 3
        del script_all

    def test_cbor_serialization_deterministic(self):
        """Test that CBOR serialization is deterministic."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer1 = CborWriter()
        script_all.to_cbor(writer1)
        cbor_bytes1 = writer1.encode()
        writer2 = CborWriter()
        script_all.to_cbor(writer2)
        cbor_bytes2 = writer2.encode()
        assert cbor_bytes1 == cbor_bytes2

    def test_different_scripts_produce_different_hashes(self):
        """Test that different scripts produce different hashes."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        assert script_all1.hash != script_all2.hash

    def test_equality_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = script_all
        assert script_all == script_all2

    def test_equality_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert script_all1 == script_all2
        assert script_all2 == script_all1

    def test_equality_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all3 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert script_all1 == script_all2
        assert script_all2 == script_all3
        assert script_all1 == script_all3

    def test_inequality_reflexive(self):
        """Test that inequality works correctly."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        assert script_all1 != script_all2
        assert script_all1 != script_all2

    def test_multiple_cbor_roundtrips(self):
        """Test multiple CBOR serialization and deserialization cycles."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        for _ in range(3):
            writer = CborWriter()
            script_all.to_cbor(writer)
            cbor_bytes = writer.encode()
            reader = CborReader.from_hex(cbor_bytes.hex())
            script_all = ScriptAll.from_cbor(reader)
        assert len(script_all) == 3

    def test_scripts_property_returns_independent_object(self):
        """Test that scripts property returns independent objects."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        scripts1 = script_all.scripts
        scripts2 = script_all.scripts
        assert len(scripts1) == len(scripts2)

    def test_empty_script_list_evaluates_to_true(self):
        """Test that empty script list creates valid ScriptAll (evaluates to true)."""
        script_all = self._get_script_all_from_json(EMPTY_SCRIPT_JSON)
        assert script_all is not None
        assert len(script_all) == 0
        script_hash = script_all.hash
        assert len(script_hash) == 28

    def test_set_scripts_updates_hash(self):
        """Test that setting scripts updates the hash."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        hash1 = script_all.hash
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        new_scripts = script_all2.scripts
        script_all.scripts = new_scripts
        hash2 = script_all.hash
        assert hash1 != hash2

    def test_repr_with_different_lengths(self):
        """Test that repr differs for different script list lengths."""
        script_all1 = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        repr1 = repr(script_all1)
        repr2 = repr(script_all2)
        assert repr1 != repr2
        assert "len=3" in repr1
        assert "len=2" in repr2

    def test_new_with_single_script(self):
        """Test creating a ScriptAll with a single script."""
        script_all = self._get_script_all_from_json(SINGLE_SCRIPT_JSON)
        assert len(script_all) == 1

    def test_new_with_multiple_scripts(self):
        """Test creating a ScriptAll with multiple scripts."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        assert len(script_all) == 3

    def test_hash_with_empty_script_list(self):
        """Test getting hash with empty script list."""
        script_all = self._get_script_all_from_json(EMPTY_SCRIPT_JSON)
        script_hash = script_all.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_cbor_roundtrip_with_empty_list(self):
        """Test CBOR roundtrip with empty script list."""
        script_all1 = self._get_script_all_from_json(EMPTY_SCRIPT_JSON)
        writer = CborWriter()
        script_all1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_all2 = ScriptAll.from_cbor(reader)
        assert script_all1 == script_all2
        assert len(script_all2) == 0

    def test_scripts_getter_after_setter(self):
        """Test that scripts getter returns updated value after setter."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        original_scripts = script_all.scripts
        assert len(original_scripts) == 3
        script_all2 = self._get_script_all_from_json(ALL_SCRIPT2_JSON)
        new_scripts = script_all2.scripts
        script_all.scripts = new_scripts
        updated_scripts = script_all.scripts
        assert len(updated_scripts) == 2

    def test_cip116_json_format(self):
        """Test that CIP-116 JSON output has correct format."""
        script_all = self._get_script_all_from_json(ALL_SCRIPT_JSON)
        writer = JsonWriter(JsonFormat.PRETTY)
        script_all.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag": "all"' in json_str
        assert '"scripts":' in json_str
        assert '"tag": "timelock_start"' in json_str
        assert '"slot": "3000"' in json_str
        assert '"tag": "pubkey"' in json_str
        assert '"pubkey": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"' in json_str
        assert '"tag": "timelock_expiry"' in json_str
        assert '"slot": "4000"' in json_str
