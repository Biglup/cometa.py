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
from cometa.scripts.native_scripts import (
    NativeScript,
    NativeScriptType,
    ScriptPubkey,
    ScriptAll,
    ScriptAny,
    ScriptNOfK,
    ScriptInvalidBefore,
    ScriptInvalidAfter,
)
from cometa.cbor import CborReader, CborWriter
from cometa.errors import CardanoError


KEY_HASH_HEX = "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
KEY_HASH_HEX2 = "b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538"

PUBKEY_SCRIPT_CBOR = "8200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
PUBKEY_SCRIPT_HASH = "44e8537337e941f125478607b7ab91515b5eca4ef647b10c16c63ed2"

BEFORE_SCRIPT_CBOR = "82041a02625a0a"
BEFORE_SCRIPT_HASH = "bdda6da5dcca0c3dcb5a1000b23febf79e5741f3f1872b8aadaf92f6"

AFTER_SCRIPT_CBOR = "8205190bb8"
AFTER_SCRIPT_HASH = "e638e31a6c57bde95c0b644ec0c584a239fab33ba99f41c91b410d1d"

ALL_SCRIPT_CBOR = "8201838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
ALL_SCRIPT_HASH = "5ea7df92c0b5c88f60061d04140aee2b69414bafe04fbe19144bb693"

ANY_SCRIPT_CBOR = "8202838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
ANY_SCRIPT_HASH = "70e5950987ed08bf51fa0138fbda822f216b0aa9dca48ae947c1e511"

N_OF_K_SCRIPT_CBOR = "830302838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
N_OF_K_SCRIPT_HASH = "a1fe3a12ce7c1d7e8c0621d97970cf3092f5c1f7677adc954a96c09b"

NESTED_SCRIPT_CBOR = "8202828200581cb275b08c999097247f7c17e77007c7010cd19f20cc086ad99d3985388201838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
NESTED_SCRIPT_HASH = "8b8370c97ae17eb69a8c97f733888f7485b60fd820c69211c8bbeb56"

PUBKEY_JSON = '{"type":"sig","keyHash":"966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"}'
AFTER_JSON = '{"type":"after","slot":40000010}'
BEFORE_JSON = '{"type":"before","slot":3000}'
ALL_JSON = '{"type":"all","scripts":[{"type":"before","slot":3000},{"type":"sig","keyHash":"966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"},{"type":"after","slot":4000}]}'
ANY_JSON = '{"type":"any","scripts":[{"type":"before","slot":3000},{"type":"sig","keyHash":"966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"},{"type":"after","slot":4000}]}'
N_OF_K_JSON = '{"type":"atLeast","required":2,"scripts":[{"type":"before","slot":3000},{"type":"sig","keyHash":"966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"},{"type":"after","slot":4000}]}'


class TestNativeScriptFromPubkey:
    """Tests for NativeScript.from_pubkey factory method."""

    def test_from_pubkey_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptPubkey."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_PUBKEY

    def test_from_pubkey_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_pubkey(None)

    def test_from_pubkey_preserves_data(self):
        """Test that from_pubkey preserves the original script data."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        recovered = native_script.to_pubkey()
        assert recovered.key_hash == key_hash


class TestNativeScriptFromAll:
    """Tests for NativeScript.from_all factory method."""

    def test_from_all_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptAll."""
        script_all = ScriptAll.new([])
        native_script = NativeScript.from_all(script_all)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ALL_OF

    def test_from_all_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_all(None)

    def test_from_all_with_subscripts(self):
        """Test creating a NativeScript from ScriptAll with subscripts."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        native_pubkey = NativeScript.from_pubkey(pubkey)
        script_all = ScriptAll.new([native_pubkey])
        native_script = NativeScript.from_all(script_all)
        recovered = native_script.to_all()
        assert len(recovered) == 1


class TestNativeScriptFromAny:
    """Tests for NativeScript.from_any factory method."""

    def test_from_any_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptAny."""
        script_any = ScriptAny.new([])
        native_script = NativeScript.from_any(script_any)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ANY_OF

    def test_from_any_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_any(None)

    def test_from_any_with_subscripts(self):
        """Test creating a NativeScript from ScriptAny with subscripts."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        pubkey = ScriptPubkey.new(key_hash)
        native_pubkey = NativeScript.from_pubkey(pubkey)
        script_any = ScriptAny.new([native_pubkey])
        native_script = NativeScript.from_any(script_any)
        recovered = native_script.to_any()
        assert len(recovered) == 1


class TestNativeScriptFromNOfK:
    """Tests for NativeScript.from_n_of_k factory method."""

    def test_from_n_of_k_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptNOfK."""
        script_n_of_k = ScriptNOfK.new([], 2)
        native_script = NativeScript.from_n_of_k(script_n_of_k)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_N_OF_K

    def test_from_n_of_k_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_n_of_k(None)

    def test_from_n_of_k_preserves_threshold(self):
        """Test that from_n_of_k preserves the threshold value."""
        script_n_of_k = ScriptNOfK.new([], 3)
        native_script = NativeScript.from_n_of_k(script_n_of_k)
        recovered = native_script.to_n_of_k()
        assert recovered.required == 3


class TestNativeScriptFromInvalidBefore:
    """Tests for NativeScript.from_invalid_before factory method."""

    def test_from_invalid_before_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptInvalidBefore."""
        script = ScriptInvalidBefore.new(1000)
        native_script = NativeScript.from_invalid_before(script)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_BEFORE

    def test_from_invalid_before_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_invalid_before(None)

    def test_from_invalid_before_preserves_slot(self):
        """Test that from_invalid_before preserves the slot value."""
        script = ScriptInvalidBefore.new(5000)
        native_script = NativeScript.from_invalid_before(script)
        recovered = native_script.to_invalid_before()
        assert recovered.slot ==5000


class TestNativeScriptFromInvalidAfter:
    """Tests for NativeScript.from_invalid_after factory method."""

    def test_from_invalid_after_with_valid_script(self):
        """Test creating a NativeScript from a valid ScriptInvalidAfter."""
        script = ScriptInvalidAfter.new(1000)
        native_script = NativeScript.from_invalid_after(script)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_AFTER

    def test_from_invalid_after_with_none(self):
        """Test creating a NativeScript from None raises an error."""
        with pytest.raises((CardanoError, AttributeError)):
            NativeScript.from_invalid_after(None)

    def test_from_invalid_after_preserves_slot(self):
        """Test that from_invalid_after preserves the slot value."""
        script = ScriptInvalidAfter.new(8000)
        native_script = NativeScript.from_invalid_after(script)
        recovered = native_script.to_invalid_after()
        assert recovered.slot ==8000


class TestNativeScriptFromCbor:
    """Tests for NativeScript.from_cbor method."""

    def test_from_cbor_pubkey_script(self):
        """Test deserializing a pubkey script from CBOR."""
        reader = CborReader.from_hex(PUBKEY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_PUBKEY
        assert native_script.hash.hex() == PUBKEY_SCRIPT_HASH

    def test_from_cbor_invalid_before_script(self):
        """Test deserializing an invalid_before script from CBOR."""
        reader = CborReader.from_hex(BEFORE_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_BEFORE
        assert native_script.hash.hex() == BEFORE_SCRIPT_HASH

    def test_from_cbor_invalid_after_script(self):
        """Test deserializing an invalid_after script from CBOR."""
        reader = CborReader.from_hex(AFTER_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_AFTER
        assert native_script.hash.hex() == AFTER_SCRIPT_HASH

    def test_from_cbor_all_script(self):
        """Test deserializing an all script from CBOR."""
        reader = CborReader.from_hex(ALL_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ALL_OF
        assert native_script.hash.hex() == ALL_SCRIPT_HASH

    def test_from_cbor_any_script(self):
        """Test deserializing an any script from CBOR."""
        reader = CborReader.from_hex(ANY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ANY_OF
        assert native_script.hash.hex() == ANY_SCRIPT_HASH

    def test_from_cbor_n_of_k_script(self):
        """Test deserializing an n-of-k script from CBOR."""
        reader = CborReader.from_hex(N_OF_K_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_N_OF_K
        assert native_script.hash.hex() == N_OF_K_SCRIPT_HASH

    def test_from_cbor_nested_script(self):
        """Test deserializing a nested script from CBOR."""
        reader = CborReader.from_hex(NESTED_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script is not None
        assert native_script.hash.hex() == NESTED_SCRIPT_HASH

    def test_from_cbor_with_invalid_data(self):
        """Test deserializing from invalid CBOR data."""
        reader = CborReader.from_hex("fe01")
        with pytest.raises(CardanoError):
            NativeScript.from_cbor(reader)

    def test_from_cbor_with_incomplete_data(self):
        """Test deserializing from incomplete CBOR data."""
        reader = CborReader.from_hex("82")
        with pytest.raises(CardanoError):
            NativeScript.from_cbor(reader)


class TestNativeScriptFromJson:
    """Tests for NativeScript.from_json method."""

    def test_from_json_pubkey_script(self):
        """Test deserializing a pubkey script from JSON."""
        native_script = NativeScript.from_json(PUBKEY_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_PUBKEY
        assert native_script.hash.hex() == PUBKEY_SCRIPT_HASH

    def test_from_json_invalid_after_script(self):
        """Test deserializing an invalid_after script from JSON."""
        native_script = NativeScript.from_json(BEFORE_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_AFTER

    def test_from_json_invalid_before_script(self):
        """Test deserializing an invalid_before script from JSON."""
        native_script = NativeScript.from_json(AFTER_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.INVALID_BEFORE

    def test_from_json_all_script(self):
        """Test deserializing an all script from JSON."""
        native_script = NativeScript.from_json(ALL_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ALL_OF
        assert native_script.hash.hex() == ALL_SCRIPT_HASH

    def test_from_json_any_script(self):
        """Test deserializing an any script from JSON."""
        native_script = NativeScript.from_json(ANY_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_ANY_OF
        assert native_script.hash.hex() == ANY_SCRIPT_HASH

    def test_from_json_n_of_k_script(self):
        """Test deserializing an n-of-k script from JSON."""
        native_script = NativeScript.from_json(N_OF_K_JSON)
        assert native_script is not None
        assert native_script.script_type == NativeScriptType.REQUIRE_N_OF_K
        assert native_script.hash.hex() == N_OF_K_SCRIPT_HASH

    def test_from_json_with_invalid_json(self):
        """Test deserializing from invalid JSON."""
        with pytest.raises(CardanoError):
            NativeScript.from_json("{invalid json")

    def test_from_json_with_empty_string(self):
        """Test deserializing from empty string."""
        with pytest.raises(CardanoError):
            NativeScript.from_json("")

    def test_from_json_with_malformed_script(self):
        """Test deserializing from malformed script JSON."""
        with pytest.raises(CardanoError):
            NativeScript.from_json('{"type":"unknown"}')


class TestNativeScriptToCbor:
    """Tests for NativeScript.to_cbor method."""

    def test_to_cbor_pubkey_script(self):
        """Test serializing a pubkey script to CBOR."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        writer = CborWriter()
        native_script.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == PUBKEY_SCRIPT_CBOR

    def test_to_cbor_all_script(self):
        """Test serializing an all script to CBOR."""
        reader = CborReader.from_hex(ALL_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        writer = CborWriter()
        native_script.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == ALL_SCRIPT_CBOR

    def test_to_cbor_any_script(self):
        """Test serializing an any script to CBOR."""
        reader = CborReader.from_hex(ANY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        writer = CborWriter()
        native_script.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == ANY_SCRIPT_CBOR

    def test_to_cbor_n_of_k_script(self):
        """Test serializing an n-of-k script to CBOR."""
        reader = CborReader.from_hex(N_OF_K_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        writer = CborWriter()
        native_script.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == N_OF_K_SCRIPT_CBOR

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        reader = CborReader.from_hex(NESTED_SCRIPT_CBOR)
        script1 = NativeScript.from_cbor(reader)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader2 = CborReader.from_hex(cbor_bytes.hex())
        script2 = NativeScript.from_cbor(reader2)
        assert script1 == script2


class TestNativeScriptScriptType:
    """Tests for NativeScript.script_type property."""

    def test_script_type_pubkey(self):
        """Test script_type property for pubkey script."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        assert native_script.script_type == NativeScriptType.REQUIRE_PUBKEY

    def test_script_type_all(self):
        """Test script_type property for all script."""
        script_all = ScriptAll.new([])
        native_script = NativeScript.from_all(script_all)
        assert native_script.script_type == NativeScriptType.REQUIRE_ALL_OF

    def test_script_type_any(self):
        """Test script_type property for any script."""
        script_any = ScriptAny.new([])
        native_script = NativeScript.from_any(script_any)
        assert native_script.script_type == NativeScriptType.REQUIRE_ANY_OF

    def test_script_type_n_of_k(self):
        """Test script_type property for n-of-k script."""
        script_n_of_k = ScriptNOfK.new([], 2)
        native_script = NativeScript.from_n_of_k(script_n_of_k)
        assert native_script.script_type == NativeScriptType.REQUIRE_N_OF_K

    def test_script_type_invalid_before(self):
        """Test script_type property for invalid_before script."""
        script = ScriptInvalidBefore.new(1000)
        native_script = NativeScript.from_invalid_before(script)
        assert native_script.script_type == NativeScriptType.INVALID_BEFORE

    def test_script_type_invalid_after(self):
        """Test script_type property for invalid_after script."""
        script = ScriptInvalidAfter.new(1000)
        native_script = NativeScript.from_invalid_after(script)
        assert native_script.script_type == NativeScriptType.INVALID_AFTER


class TestNativeScriptHash:
    """Tests for NativeScript.hash property."""

    def test_hash_pubkey_script(self):
        """Test hash property for pubkey script."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        script_hash = native_script.hash
        assert len(script_hash) == 28
        assert isinstance(script_hash, bytes)
        assert script_hash.hex() == PUBKEY_SCRIPT_HASH

    def test_hash_all_script(self):
        """Test hash property for all script."""
        reader = CborReader.from_hex(ALL_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script.hash.hex() == ALL_SCRIPT_HASH

    def test_hash_any_script(self):
        """Test hash property for any script."""
        reader = CborReader.from_hex(ANY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script.hash.hex() == ANY_SCRIPT_HASH

    def test_hash_n_of_k_script(self):
        """Test hash property for n-of-k script."""
        reader = CborReader.from_hex(N_OF_K_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script.hash.hex() == N_OF_K_SCRIPT_HASH

    def test_hash_consistency(self):
        """Test that hash property returns consistent results."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        hash1 = native_script.hash
        hash2 = native_script.hash
        assert hash1 == hash2


class TestNativeScriptToPubkey:
    """Tests for NativeScript.to_pubkey method."""

    def test_to_pubkey_with_pubkey_script(self):
        """Test converting a pubkey script to ScriptPubkey."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        recovered = native_script.to_pubkey()
        assert recovered.key_hash == key_hash

    def test_to_pubkey_with_wrong_type(self):
        """Test converting a non-pubkey script to ScriptPubkey raises error."""
        script_all = ScriptAll.new([])
        native_script = NativeScript.from_all(script_all)
        with pytest.raises(CardanoError):
            native_script.to_pubkey()

    def test_to_pubkey_preserves_data(self):
        """Test that to_pubkey preserves all script data."""
        reader = CborReader.from_hex(PUBKEY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script_pubkey = native_script.to_pubkey()
        assert script_pubkey.key_hash.hex() == KEY_HASH_HEX


class TestNativeScriptToAll:
    """Tests for NativeScript.to_all method."""

    def test_to_all_with_all_script(self):
        """Test converting an all script to ScriptAll."""
        script_all = ScriptAll.new([])
        native_script = NativeScript.from_all(script_all)
        recovered = native_script.to_all()
        assert recovered is not None
        assert len(recovered) == 0

    def test_to_all_with_wrong_type(self):
        """Test converting a non-all script to ScriptAll raises error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with pytest.raises(CardanoError):
            native_script.to_all()

    def test_to_all_preserves_subscripts(self):
        """Test that to_all preserves all subscripts."""
        reader = CborReader.from_hex(ALL_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script_all = native_script.to_all()
        assert len(script_all) ==3


class TestNativeScriptToAny:
    """Tests for NativeScript.to_any method."""

    def test_to_any_with_any_script(self):
        """Test converting an any script to ScriptAny."""
        script_any = ScriptAny.new([])
        native_script = NativeScript.from_any(script_any)
        recovered = native_script.to_any()
        assert recovered is not None
        assert len(recovered) == 0

    def test_to_any_with_wrong_type(self):
        """Test converting a non-any script to ScriptAny raises error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with pytest.raises(CardanoError):
            native_script.to_any()

    def test_to_any_preserves_subscripts(self):
        """Test that to_any preserves all subscripts."""
        reader = CborReader.from_hex(ANY_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script_any = native_script.to_any()
        assert len(script_any) ==3


class TestNativeScriptToNOfK:
    """Tests for NativeScript.to_n_of_k method."""

    def test_to_n_of_k_with_n_of_k_script(self):
        """Test converting an n-of-k script to ScriptNOfK."""
        script_n_of_k = ScriptNOfK.new([], 2)
        native_script = NativeScript.from_n_of_k(script_n_of_k)
        recovered = native_script.to_n_of_k()
        assert recovered.required == 2

    def test_to_n_of_k_with_wrong_type(self):
        """Test converting a non-n-of-k script to ScriptNOfK raises error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with pytest.raises(CardanoError):
            native_script.to_n_of_k()

    def test_to_n_of_k_preserves_data(self):
        """Test that to_n_of_k preserves threshold and subscripts."""
        reader = CborReader.from_hex(N_OF_K_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script_n_of_k = native_script.to_n_of_k()
        assert script_n_of_k.required == 2
        assert len(script_n_of_k) ==3


class TestNativeScriptToInvalidBefore:
    """Tests for NativeScript.to_invalid_before method."""

    def test_to_invalid_before_with_invalid_before_script(self):
        """Test converting an invalid_before script to ScriptInvalidBefore."""
        script = ScriptInvalidBefore.new(5000)
        native_script = NativeScript.from_invalid_before(script)
        recovered = native_script.to_invalid_before()
        assert recovered.slot ==5000

    def test_to_invalid_before_with_wrong_type(self):
        """Test converting a non-invalid_before script raises error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with pytest.raises(CardanoError):
            native_script.to_invalid_before()

    def test_to_invalid_before_preserves_slot(self):
        """Test that to_invalid_before preserves the slot value."""
        reader = CborReader.from_hex(BEFORE_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script = native_script.to_invalid_before()
        assert script.slot == 40000010


class TestNativeScriptToInvalidAfter:
    """Tests for NativeScript.to_invalid_after method."""

    def test_to_invalid_after_with_invalid_after_script(self):
        """Test converting an invalid_after script to ScriptInvalidAfter."""
        script = ScriptInvalidAfter.new(8000)
        native_script = NativeScript.from_invalid_after(script)
        recovered = native_script.to_invalid_after()
        assert recovered.slot ==8000

    def test_to_invalid_after_with_wrong_type(self):
        """Test converting a non-invalid_after script raises error."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with pytest.raises(CardanoError):
            native_script.to_invalid_after()

    def test_to_invalid_after_preserves_slot(self):
        """Test that to_invalid_after preserves the slot value."""
        reader = CborReader.from_hex(AFTER_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        script = native_script.to_invalid_after()
        assert script.slot == 3000


class TestNativeScriptEquality:
    """Tests for NativeScript equality comparison."""

    def test_equals_same_pubkey_script(self):
        """Test equality of two identical pubkey scripts."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey1 = ScriptPubkey.new(key_hash)
        script_pubkey2 = ScriptPubkey.new(key_hash)
        native_script1 = NativeScript.from_pubkey(script_pubkey1)
        native_script2 = NativeScript.from_pubkey(script_pubkey2)
        assert native_script1 == native_script2

    def test_equals_different_pubkey_scripts(self):
        """Test inequality of two different pubkey scripts."""
        key_hash1 = bytes.fromhex(KEY_HASH_HEX)
        key_hash2 = bytes.fromhex(KEY_HASH_HEX2)
        script_pubkey1 = ScriptPubkey.new(key_hash1)
        script_pubkey2 = ScriptPubkey.new(key_hash2)
        native_script1 = NativeScript.from_pubkey(script_pubkey1)
        native_script2 = NativeScript.from_pubkey(script_pubkey2)
        assert native_script1 != native_script2

    def test_equals_different_script_types(self):
        """Test inequality of scripts with different types."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        script_all = ScriptAll.new([])
        native_script1 = NativeScript.from_pubkey(script_pubkey)
        native_script2 = NativeScript.from_all(script_all)
        assert native_script1 != native_script2

    def test_equals_with_non_native_script(self):
        """Test inequality with a non-NativeScript object."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        assert native_script != "not a script"
        assert native_script != 42
        assert native_script != None

    def test_equals_from_cbor(self):
        """Test equality of scripts deserialized from CBOR."""
        reader1 = CborReader.from_hex(NESTED_SCRIPT_CBOR)
        reader2 = CborReader.from_hex(NESTED_SCRIPT_CBOR)
        script1 = NativeScript.from_cbor(reader1)
        script2 = NativeScript.from_cbor(reader2)
        assert script1 == script2


class TestNativeScriptRepr:
    """Tests for NativeScript.__repr__ method."""

    def test_repr_pubkey_script(self):
        """Test string representation of pubkey script."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        repr_str = repr(native_script)
        assert "NativeScript" in repr_str
        assert "PUBKEY" in repr_str or "REQUIRE_PUBKEY" in repr_str

    def test_repr_all_script(self):
        """Test string representation of all script."""
        script_all = ScriptAll.new([])
        native_script = NativeScript.from_all(script_all)
        repr_str = repr(native_script)
        assert "NativeScript" in repr_str
        assert "ALL" in repr_str

    def test_repr_any_script(self):
        """Test string representation of any script."""
        script_any = ScriptAny.new([])
        native_script = NativeScript.from_any(script_any)
        repr_str = repr(native_script)
        assert "NativeScript" in repr_str
        assert "ANY" in repr_str


class TestNativeScriptContextManager:
    """Tests for NativeScript context manager support."""

    def test_context_manager_enter_exit(self):
        """Test using NativeScript as a context manager."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with native_script as script:
            assert script is not None
            assert script.script_type == NativeScriptType.REQUIRE_PUBKEY

    def test_context_manager_allows_operations(self):
        """Test that operations work inside context manager."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey)
        with native_script as script:
            script_hash = script.hash
            assert len(script_hash) == 28


class TestNativeScriptEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_init_with_null_pointer(self):
        """Test that initializing with NULL pointer raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            NativeScript(ffi.NULL)

    def test_multiple_conversions(self):
        """Test multiple back-and-forth conversions."""
        key_hash = bytes.fromhex(KEY_HASH_HEX)
        script_pubkey1 = ScriptPubkey.new(key_hash)
        native_script = NativeScript.from_pubkey(script_pubkey1)
        script_pubkey2 = native_script.to_pubkey()
        native_script2 = NativeScript.from_pubkey(script_pubkey2)
        assert native_script == native_script2

    def test_complex_nested_script(self):
        """Test working with complex nested scripts."""
        reader = CborReader.from_hex(NESTED_SCRIPT_CBOR)
        native_script = NativeScript.from_cbor(reader)
        assert native_script.script_type == NativeScriptType.REQUIRE_ANY_OF
        script_any = native_script.to_any()
        assert len(script_any) ==2
