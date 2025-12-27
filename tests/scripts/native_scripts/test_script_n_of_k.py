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
    ScriptNOfK,
    NativeScript,
    NativeScriptList,
    ScriptPubkey,
    ScriptInvalidBefore,
    ScriptInvalidAfter,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError,
)


PUBKEY_SCRIPT_JSON = """{
  "type": "sig",
  "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
}"""

AT_LEAST_SCRIPT_JSON = """{
  "type": "atLeast",
  "required": 2,
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
}"""

AT_LEAST_SCRIPT2_JSON = """{
  "type": "atLeast",
  "required": 2,
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
}"""


class TestScriptNOfKNew:
    def test_new_with_native_script_list(self):
        """Test creating ScriptNOfK with NativeScriptList."""
        scripts = NativeScriptList()
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        scripts.add(pubkey)

        n_of_k = ScriptNOfK.new(scripts, 1)
        assert n_of_k is not None
        assert n_of_k.required == 1
        assert len(n_of_k) == 1

    def test_new_with_python_list(self):
        """Test creating ScriptNOfK with Python list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        n_of_k = ScriptNOfK.new([pubkey1, pubkey2], 2)
        assert n_of_k is not None
        assert n_of_k.required == 2
        assert len(n_of_k) == 2

    def test_new_with_required_zero(self):
        """Test creating ScriptNOfK with required=0."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 0)
        assert n_of_k is not None
        assert n_of_k.required == 0

    def test_new_with_required_greater_than_scripts(self):
        """Test creating ScriptNOfK with required > number of scripts."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 5)
        assert n_of_k is not None
        assert n_of_k.required == 5

    def test_new_with_multiple_script_types(self):
        """Test creating ScriptNOfK with different script types."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        n_of_k = ScriptNOfK.new([pubkey, invalid_before, invalid_after], 2)
        assert n_of_k is not None
        assert n_of_k.required == 2
        assert len(n_of_k) == 3


class TestScriptNOfKFromCbor:
    def test_from_cbor_valid(self):
        """Test deserializing ScriptNOfK from valid CBOR via NativeScript roundtrip."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_after = ScriptInvalidAfter.new(4000)
        n_of_k_original = ScriptNOfK.new([pubkey, invalid_after], 2)

        native = NativeScript.from_n_of_k(n_of_k_original)
        writer = CborWriter()
        native.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        native_restored = NativeScript.from_cbor(reader)
        n_of_k = native_restored.to_n_of_k()

        assert n_of_k is not None
        assert n_of_k.required == 2
        assert len(n_of_k) == 2

    def test_from_cbor_invalid_type(self):
        """Test from_cbor with invalid CBOR type."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptNOfK.from_cbor(reader)

    def test_from_cbor_invalid_structure_no_array(self):
        """Test from_cbor with invalid CBOR structure (no array)."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            ScriptNOfK.from_cbor(reader)

    def test_from_cbor_invalid_structure_no_int(self):
        """Test from_cbor with invalid CBOR structure (no int)."""
        reader = CborReader.from_hex("83fe")
        with pytest.raises(CardanoError):
            ScriptNOfK.from_cbor(reader)


class TestScriptNOfKToCbor:
    def test_to_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        n_of_k = ScriptNOfK.new([pubkey1, pubkey2], 2)
        native = NativeScript.from_n_of_k(n_of_k)

        writer = CborWriter()
        native.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        native2 = NativeScript.from_cbor(reader)
        n_of_k2 = native2.to_n_of_k()

        assert n_of_k2.required == n_of_k.required
        assert len(n_of_k2) == len(n_of_k)


class TestScriptNOfKToCip116Json:
    def test_to_cip116_json(self):
        """Test serialization to CIP-116 JSON format."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_after = ScriptInvalidAfter.new(4000)

        n_of_k = ScriptNOfK.new([pubkey, invalid_after], 2)

        writer = JsonWriter(JsonFormat.PRETTY)
        n_of_k.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag": "n_of_k"' in json_str
        assert '"n": 2' in json_str
        assert '"scripts"' in json_str

    def test_to_cip116_json_invalid_writer(self):
        """Test to_cip116_json with invalid writer."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 1)

        with pytest.raises(TypeError):
            n_of_k.to_cip116_json("not a writer")


class TestScriptNOfKRequired:
    def test_get_required(self):
        """Test getting the required property."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 2)
        assert n_of_k.required == 2

    def test_set_required(self):
        """Test setting the required property."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 1)
        assert n_of_k.required == 1

        n_of_k.required = 3
        assert n_of_k.required == 3

    def test_set_required_to_zero(self):
        """Test setting required to zero."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 1)
        n_of_k.required = 0
        assert n_of_k.required == 0


class TestScriptNOfKScripts:
    def test_get_scripts(self):
        """Test getting the scripts property."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        n_of_k = ScriptNOfK.new([pubkey1, pubkey2], 2)

        scripts = n_of_k.scripts
        assert scripts is not None
        assert len(scripts) == 2

    def test_set_scripts_with_native_script_list(self):
        """Test setting scripts with NativeScriptList."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey1], 1)

        new_scripts = NativeScriptList()
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        new_scripts.add(pubkey2)

        n_of_k.scripts = new_scripts
        assert len(n_of_k) == 1

    def test_set_scripts_with_python_list(self):
        """Test setting scripts with Python list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey1], 1)

        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        pubkey3 = ScriptPubkey.new(
            bytes.fromhex("c275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        n_of_k.scripts = [pubkey2, pubkey3]
        assert len(n_of_k) == 2


class TestScriptNOfKHash:
    def test_hash(self):
        """Test computing the hash of the script."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_after = ScriptInvalidAfter.new(4000)
        n_of_k = ScriptNOfK.new([pubkey, invalid_after], 2)

        hash_val = n_of_k.hash
        assert hash_val is not None
        assert len(hash_val) == 28
        assert isinstance(hash_val, bytes)

    def test_hash_consistency(self):
        """Test that hash is consistent for the same script."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 1)

        hash1 = n_of_k.hash
        hash2 = n_of_k.hash
        assert hash1 == hash2


class TestScriptNOfKLen:
    def test_len(self):
        """Test getting the length of the script list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        n_of_k = ScriptNOfK.new([pubkey1, pubkey2], 2)
        assert len(n_of_k) == 2

    def test_len_empty(self):
        """Test len with empty script list."""
        n_of_k = ScriptNOfK.new([], 0)
        assert len(n_of_k) == 0


class TestScriptNOfKEquals:
    def test_equals_same(self):
        """Test equality with the same scripts."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k1 = ScriptNOfK.new([pubkey], 1)
        n_of_k2 = ScriptNOfK.new([pubkey], 1)
        assert n_of_k1 == n_of_k2

    def test_equals_different_required(self):
        """Test equality with different required values.

        Note: The C implementation only compares the scripts list, not the required field.
        This is the expected behavior from the underlying C library.
        """
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k1 = ScriptNOfK.new([pubkey], 1)
        n_of_k2 = ScriptNOfK.new([pubkey], 2)
        assert n_of_k1 == n_of_k2

    def test_equals_different_scripts(self):
        """Test equality with different scripts."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        n_of_k1 = ScriptNOfK.new([pubkey1], 1)
        n_of_k2 = ScriptNOfK.new([pubkey2], 1)
        assert n_of_k1 != n_of_k2

    def test_equals_different_length(self):
        """Test equality with different script list lengths."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        n_of_k1 = ScriptNOfK.new([pubkey1], 1)
        n_of_k2 = ScriptNOfK.new([pubkey1, pubkey2], 1)
        assert n_of_k1 != n_of_k2

    def test_equals_not_implemented(self):
        """Test equality with non-ScriptNOfK object."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k = ScriptNOfK.new([pubkey], 1)
        assert n_of_k != "not a script"


class TestScriptNOfKRepr:
    def test_repr(self):
        """Test string representation."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        n_of_k = ScriptNOfK.new([pubkey1, pubkey2], 2)
        repr_str = repr(n_of_k)
        assert "ScriptNOfK" in repr_str
        assert "required=2" in repr_str
        assert "len=2" in repr_str


class TestScriptNOfKContextManager:
    def test_context_manager(self):
        """Test using ScriptNOfK as a context manager."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        with ScriptNOfK.new([pubkey], 1) as n_of_k:
            assert n_of_k is not None
            assert n_of_k.required == 1


class TestScriptNOfKInvalidInput:
    def test_init_with_null_ptr(self):
        """Test that __init__ raises error with NULL pointer."""
        from cometa._ffi import ffi

        with pytest.raises(CardanoError):
            ScriptNOfK(ffi.NULL)


class TestScriptNOfKIntegration:
    def test_integration_with_native_script(self):
        """Test integration with NativeScript."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        n_of_k = ScriptNOfK.new([pubkey, invalid_before, invalid_after], 2)
        native_script = NativeScript.from_n_of_k(n_of_k)

        assert native_script is not None

        n_of_k2 = native_script.to_n_of_k()
        assert n_of_k2.required == 2
        assert len(n_of_k2) == 3

    def test_complex_nested_script(self):
        """Test with complex nested script structure."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        n_of_k = ScriptNOfK.new([pubkey1, pubkey2, invalid_before, invalid_after], 3)

        assert n_of_k.required == 3
        assert len(n_of_k) == 4

        hash_val = n_of_k.hash
        assert len(hash_val) == 28

        writer = CborWriter()
        native = NativeScript.from_n_of_k(n_of_k)
        native.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        native2 = NativeScript.from_cbor(reader)
        n_of_k2 = native2.to_n_of_k()

        assert n_of_k2.required == n_of_k.required
        assert len(n_of_k2) == len(n_of_k)
        assert n_of_k2.hash == n_of_k.hash
