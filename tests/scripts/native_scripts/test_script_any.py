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
from cometa.scripts.native_scripts import ScriptAny, NativeScript
from cometa.cbor import CborReader, CborWriter
from cometa.json import JsonWriter, JsonFormat
from cometa.errors import CardanoError


ANY_SCRIPT_JSON = '''
{
  "type": "any",
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

ANY_SCRIPT2_JSON = '''
{
  "type": "any",
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
  "type": "any",
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
  "type": "any",
  "scripts": []
}
'''


class TestScriptAny:
    """Tests for the ScriptAny class."""

    def _get_script_any_from_json(self, json_str: str) -> ScriptAny:
        """Helper to get ScriptAny from a NativeScript created from JSON."""
        native_script = NativeScript.from_json(json_str)
        return native_script.to_any()

    def test_new_with_valid_script_list(self):
        """Test creating a ScriptAny with a valid NativeScriptList."""
        script_any = self._get_script_any_from_json(SINGLE_SCRIPT_JSON)
        scripts = script_any.scripts
        new_script_any = ScriptAny.new(scripts)
        assert new_script_any is not None
        assert len(new_script_any) == 1

    def test_new_with_python_list(self):
        """Test creating a ScriptAny with a Python list of scripts."""
        script_any = self._get_script_any_from_json(SINGLE_SCRIPT_JSON)
        scripts = script_any.scripts
        script_list = []
        for script in scripts:
            script_list.append(script)
        new_script_any = ScriptAny.new(script_list)
        assert new_script_any is not None
        assert len(new_script_any) == 1

    def test_new_with_empty_list(self):
        """Test creating a ScriptAny with an empty script list."""
        script_any = self._get_script_any_from_json(EMPTY_SCRIPT_JSON)
        scripts = script_any.scripts
        new_script_any = ScriptAny.new(scripts)
        assert new_script_any is not None
        assert len(new_script_any) == 0

    def test_from_cbor_with_valid_data(self):
        """Test deserializing a ScriptAny from valid CBOR data."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer = CborWriter()
        script_any1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_any2 = ScriptAny.from_cbor(reader)
        assert script_any2 is not None
        assert len(script_any2) == 3

    @staticmethod
    def test_from_cbor_with_invalid_data_no_array():
        """Test deserializing a ScriptAny from invalid CBOR data (no array)."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptAny.from_cbor(reader)

    @staticmethod
    def test_from_cbor_with_invalid_data_no_int():
        """Test deserializing a ScriptAny from invalid CBOR data (no int)."""
        reader = CborReader.from_hex("82fe")
        with pytest.raises(CardanoError):
            ScriptAny.from_cbor(reader)

    def test_to_cbor(self):
        """Test serializing a ScriptAny to CBOR."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer = CborWriter()
        script_any.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer = CborWriter()
        script_any1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_any2 = ScriptAny.from_cbor(reader)
        assert script_any1 == script_any2

    def test_to_cip116_json(self):
        """Test serializing a ScriptAny to CIP-116 JSON."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer = JsonWriter(JsonFormat.PRETTY)
        script_any.to_cip116_json(writer)
        json_str = writer.encode()
        assert "tag" in json_str
        assert "any" in json_str
        assert "scripts" in json_str

    def test_to_cip116_json_with_invalid_writer(self):
        """Test serializing to CIP-116 JSON with invalid writer."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        with pytest.raises(TypeError):
            script_any.to_cip116_json("not a writer")

    def test_get_scripts(self):
        """Test getting the scripts from a ScriptAny."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        scripts = script_any.scripts
        assert scripts is not None
        assert len(scripts) == 3

    def test_set_scripts(self):
        """Test setting new scripts on a ScriptAny."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert len(script_any) == 3
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        new_scripts = script_any2.scripts
        script_any.scripts = new_scripts
        assert len(script_any) == 2

    def test_set_scripts_with_python_list(self):
        """Test setting scripts using a Python list."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        new_scripts = script_any2.scripts
        script_list = []
        for script in new_scripts:
            script_list.append(script)
        script_any.scripts = script_list
        assert len(script_any) == 2

    def test_hash_property(self):
        """Test getting the hash of the ScriptAny."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_hash = script_any.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_hash_property_consistency(self):
        """Test that hash property returns consistent results."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        hash1 = script_any.hash
        hash2 = script_any.hash
        assert hash1 == hash2

    def test_len(self):
        """Test getting the length of the script list."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert len(script_any) == 3

    def test_len_with_empty_list(self):
        """Test length with empty script list."""
        script_any = self._get_script_any_from_json(EMPTY_SCRIPT_JSON)
        assert len(script_any) == 0

    def test_equals_same_script(self):
        """Test equality of two ScriptAny instances with the same content."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert script_any1 == script_any2

    def test_equals_different_script(self):
        """Test inequality of two ScriptAny instances with different content."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        assert script_any1 != script_any2

    def test_equals_with_non_script_any(self):
        """Test inequality with a non-ScriptAny object."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert script_any != "not a script"
        assert script_any != 42
        assert script_any is not None

    def test_repr(self):
        """Test string representation of ScriptAny."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        repr_str = repr(script_any)
        assert "ScriptAny" in repr_str
        assert "len=3" in repr_str

    def test_context_manager(self):
        """Test using ScriptAny as a context manager."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        with script_any:
            assert script_any is not None
            assert len(script_any) == 3

    def test_lifecycle(self):
        """Test object lifecycle and cleanup."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert len(script_any) == 3
        del script_any

    def test_cbor_serialization_deterministic(self):
        """Test that CBOR serialization is deterministic."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer1 = CborWriter()
        script_any.to_cbor(writer1)
        cbor_bytes1 = writer1.encode()
        writer2 = CborWriter()
        script_any.to_cbor(writer2)
        cbor_bytes2 = writer2.encode()
        assert cbor_bytes1 == cbor_bytes2

    def test_different_scripts_produce_different_hashes(self):
        """Test that different scripts produce different hashes."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        assert script_any1.hash != script_any2.hash

    def test_equality_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = script_any
        assert script_any == script_any2

    def test_equality_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert script_any1 == script_any2
        assert script_any2 == script_any1

    def test_equality_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any3 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert script_any1 == script_any2
        assert script_any2 == script_any3
        assert script_any1 == script_any3

    def test_inequality_reflexive(self):
        """Test that inequality works correctly."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        assert script_any1 != script_any2
        assert script_any1 != script_any2

    def test_multiple_cbor_roundtrips(self):
        """Test multiple CBOR serialization and deserialization cycles."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        for _ in range(3):
            writer = CborWriter()
            script_any.to_cbor(writer)
            cbor_bytes = writer.encode()
            reader = CborReader.from_hex(cbor_bytes.hex())
            script_any = ScriptAny.from_cbor(reader)
        assert len(script_any) == 3

    def test_scripts_property_returns_independent_object(self):
        """Test that scripts property returns independent objects."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        scripts1 = script_any.scripts
        scripts2 = script_any.scripts
        assert len(scripts1) == len(scripts2)

    def test_empty_script_list_evaluates_to_false(self):
        """Test that empty script list creates valid ScriptAny (evaluates to false)."""
        script_any = self._get_script_any_from_json(EMPTY_SCRIPT_JSON)
        assert script_any is not None
        assert len(script_any) == 0
        script_hash = script_any.hash
        assert len(script_hash) == 28

    def test_set_scripts_updates_hash(self):
        """Test that setting scripts updates the hash."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        hash1 = script_any.hash
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        new_scripts = script_any2.scripts
        script_any.scripts = new_scripts
        hash2 = script_any.hash
        assert hash1 != hash2

    def test_repr_with_different_lengths(self):
        """Test that repr differs for different script list lengths."""
        script_any1 = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        repr1 = repr(script_any1)
        repr2 = repr(script_any2)
        assert repr1 != repr2
        assert "len=3" in repr1
        assert "len=2" in repr2

    def test_new_with_single_script(self):
        """Test creating a ScriptAny with a single script."""
        script_any = self._get_script_any_from_json(SINGLE_SCRIPT_JSON)
        assert len(script_any) == 1

    def test_new_with_multiple_scripts(self):
        """Test creating a ScriptAny with multiple scripts."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        assert len(script_any) == 3

    def test_hash_with_empty_script_list(self):
        """Test getting hash with empty script list."""
        script_any = self._get_script_any_from_json(EMPTY_SCRIPT_JSON)
        script_hash = script_any.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_cbor_roundtrip_with_empty_list(self):
        """Test CBOR roundtrip with empty script list."""
        script_any1 = self._get_script_any_from_json(EMPTY_SCRIPT_JSON)
        writer = CborWriter()
        script_any1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script_any2 = ScriptAny.from_cbor(reader)
        assert script_any1 == script_any2
        assert len(script_any2) == 0

    def test_scripts_getter_after_setter(self):
        """Test that scripts getter returns updated value after setter."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        original_scripts = script_any.scripts
        assert len(original_scripts) == 3
        script_any2 = self._get_script_any_from_json(ANY_SCRIPT2_JSON)
        new_scripts = script_any2.scripts
        script_any.scripts = new_scripts
        updated_scripts = script_any.scripts
        assert len(updated_scripts) == 2

    def test_cip116_json_format(self):
        """Test that CIP-116 JSON output has correct format."""
        script_any = self._get_script_any_from_json(ANY_SCRIPT_JSON)
        writer = JsonWriter(JsonFormat.PRETTY)
        script_any.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag": "any"' in json_str
        assert '"scripts":' in json_str
        assert '"tag": "timelock_start"' in json_str
        assert '"slot": "3000"' in json_str
        assert '"tag": "pubkey"' in json_str
        assert '"pubkey": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"' in json_str
        assert '"tag": "timelock_expiry"' in json_str
        assert '"slot": "4000"' in json_str
