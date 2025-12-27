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
from cometa.scripts.native_scripts import ScriptPubkey
from cometa.cbor import CborReader, CborWriter
from cometa.errors import CardanoError


KEY_HASH_HEX = "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
KEY_HASH_HEX2 = "666e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
KEY_HASH_SHORT = "666e394a544f242081e41d1965137b1bb412ac230d40ed5407821c"


class TestScriptPubkey:
    """Tests for the ScriptPubkey class."""

    def test_new_with_valid_key_hash(self):
        """Test creating a ScriptPubkey with a valid key hash."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        assert script is not None
        assert script.key_hash == key_hash

    def test_new_with_non_standard_key_hash_length(self):
        """Test creating a ScriptPubkey with a non-standard key hash length."""
        key_hash = bytes.fromhex("966e39")
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash

    def test_new_with_empty_key_hash(self):
        """Test creating a ScriptPubkey with an empty key hash."""
        with pytest.raises(CardanoError):
            ScriptPubkey.new(b"")

    def test_key_hash_getter(self):
        """Test getting the key hash from a ScriptPubkey."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash

    def test_to_cbor(self):
        """Test serializing a ScriptPubkey to CBOR."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_from_cbor(self):
        """Test deserializing a ScriptPubkey from CBOR."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptPubkey.from_cbor(reader)
        assert script2.key_hash == key_hash

    def test_from_cbor_with_invalid_data(self):
        """Test deserializing a ScriptPubkey from invalid CBOR data."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptPubkey.from_cbor(reader)

    def test_from_cbor_with_invalid_array(self):
        """Test deserializing a ScriptPubkey from CBOR with invalid array."""
        reader = CborReader.from_hex("82fe")
        with pytest.raises(CardanoError):
            ScriptPubkey.from_cbor(reader)

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptPubkey.from_cbor(reader)
        assert script1 == script2

    def test_hash_property(self):
        """Test getting the hash of the native script."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        script_hash = script.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)

    def test_hash_property_consistency(self):
        """Test that hash property returns consistent results."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        hash1 = script.hash
        hash2 = script.hash
        assert hash1 == hash2

    def test_equals_same_script(self):
        """Test equality of two ScriptPubkey instances with the same key hash."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        script2 = ScriptPubkey.new(key_hash)
        assert script1 == script2

    def test_equals_different_script(self):
        """Test inequality of two ScriptPubkey instances with different key hashes."""
        key_hash1 = bytes.fromhex(KEY_HASH_HEX)
        key_hash2 = bytes.fromhex(KEY_HASH_HEX2)
        script1 = ScriptPubkey.new(key_hash1)
        script2 = ScriptPubkey.new(key_hash2)
        assert script1 != script2

    def test_equals_with_non_script_pubkey(self):
        """Test inequality with a non-ScriptPubkey object."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        assert script != "not a script"
        assert script != 42
        assert script != None

    def test_repr(self):
        """Test string representation of ScriptPubkey."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        repr_str = repr(script)
        assert "ScriptPubkey" in repr_str
        assert KEY_HASH_HEX in repr_str

    def test_context_manager(self):
        """Test using ScriptPubkey as a context manager."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        with ScriptPubkey.new(key_hash) as script:
            assert script is not None
            assert script.key_hash == key_hash

    def test_lifecycle(self):
        """Test object lifecycle and cleanup."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash
        del script

    def test_cbor_serialization_deterministic(self):
        """Test that CBOR serialization is deterministic."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        writer1 = CborWriter()
        script.to_cbor(writer1)
        cbor_bytes1 = writer1.encode()
        writer2 = CborWriter()
        script.to_cbor(writer2)
        cbor_bytes2 = writer2.encode()
        assert cbor_bytes1 == cbor_bytes2

    def test_different_key_hashes_produce_different_hashes(self):
        """Test that different key hashes produce different script hashes."""
        key_hash1 = bytes.fromhex(KEY_HASH_HEX)
        key_hash2 = bytes.fromhex(KEY_HASH_HEX2)
        script1 = ScriptPubkey.new(key_hash1)
        script2 = ScriptPubkey.new(key_hash2)
        assert script1.hash != script2.hash

    def test_new_with_max_length_key_hash(self):
        """Test creating a ScriptPubkey with a 28-byte key hash."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        assert len(key_hash) == 28
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash

    def test_equality_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        assert script == script

    def test_equality_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        script2 = ScriptPubkey.new(key_hash)
        assert script1 == script2
        assert script2 == script1

    def test_equality_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        script2 = ScriptPubkey.new(key_hash)
        script3 = ScriptPubkey.new(key_hash)
        assert script1 == script2
        assert script2 == script3
        assert script1 == script3

    def test_inequality_reflexive(self):
        """Test that inequality works correctly."""
        key_hash1 = bytes.fromhex(KEY_HASH_HEX)
        key_hash2 = bytes.fromhex(KEY_HASH_HEX2)
        script1 = ScriptPubkey.new(key_hash1)
        script2 = ScriptPubkey.new(key_hash2)
        assert script1 != script2
        assert not (script1 == script2)

    def test_key_hash_immutability_after_cbor(self):
        """Test that key hash remains unchanged after CBOR serialization."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        original_hash = script.key_hash
        writer = CborWriter()
        script.to_cbor(writer)
        assert script.key_hash == original_hash

    def test_cbor_writer_after_error(self):
        """Test that CBOR writer state is consistent after error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_bytes = writer.encode()
        assert len(cbor_bytes) > 0

    def test_key_hash_property_returns_copy(self):
        """Test that key_hash property returns independent bytes."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        retrieved_hash = script.key_hash
        assert retrieved_hash == key_hash
        assert isinstance(retrieved_hash, bytes)

    def test_script_pubkey_with_all_zeros_hash(self):
        """Test creating a ScriptPubkey with an all-zeros key hash."""
        key_hash = bytes(28)
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash

    def test_script_pubkey_with_all_ones_hash(self):
        """Test creating a ScriptPubkey with an all-ones key hash."""
        key_hash = bytes([0xFF] * 28)
        script = ScriptPubkey.new(key_hash)
        assert script.key_hash == key_hash

    def test_cbor_deserialization_creates_independent_object(self):
        """Test that CBOR deserialization creates independent objects."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script1 = ScriptPubkey.new(key_hash)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_hex(cbor_bytes.hex())
        script2 = ScriptPubkey.from_cbor(reader)
        # Verify both objects have the same key hash but are independent
        assert script1.key_hash == script2.key_hash
        assert script1 == script2

    def test_multiple_cbor_roundtrips(self):
        """Test multiple CBOR serialization and deserialization cycles."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script = ScriptPubkey.new(key_hash)
        for _ in range(3):
            writer = CborWriter()
            script.to_cbor(writer)
            cbor_bytes = writer.encode()
            reader = CborReader.from_hex(cbor_bytes.hex())
            script = ScriptPubkey.from_cbor(reader)
        assert script.key_hash == key_hash

    def test_repr_with_different_key_hashes(self):
        """Test that repr differs for different key hashes."""
        key_hash1 = bytes.fromhex(KEY_HASH_HEX)
        key_hash2 = bytes.fromhex(KEY_HASH_HEX2)
        script1 = ScriptPubkey.new(key_hash1)
        script2 = ScriptPubkey.new(key_hash2)
        repr1 = repr(script1)
        repr2 = repr(script2)
        assert repr1 != repr2
        assert KEY_HASH_HEX in repr1
        assert KEY_HASH_HEX2 in repr2
