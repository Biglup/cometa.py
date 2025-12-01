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
    CborReader,
    CborWriter,
    Script,
    ScriptLanguage,
    NativeScript,
    NativeScriptType,
    NativeScriptList,
    ScriptPubkey,
    ScriptAll,
    ScriptAny,
    ScriptNOfK,
    ScriptInvalidBefore,
    ScriptInvalidAfter,
    PlutusV1Script,
    PlutusV2Script,
    PlutusV3Script,
)


# Test vectors from vendor/cardano-c/lib/tests/scripts
PUBKEY_SCRIPT_JSON = """{
  "type": "sig",
  "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
}"""

BEFORE_SCRIPT_JSON = """{
  "type": "after",
  "slot": 4000
}"""

AFTER_SCRIPT_JSON = """{
  "type": "before",
  "slot": 3000
}"""

ALL_SCRIPT_JSON = """{
  "type": "all",
  "scripts":
  [
    {
      "type": "before",
      "slot": 3000
    },
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    },
    {
      "type": "after",
      "slot": 4000
    }
  ]
}"""

ANY_SCRIPT_JSON = """{
  "type": "any",
  "scripts":
  [
    {
      "type": "before",
      "slot": 3000
    },
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    },
    {
      "type": "after",
      "slot": 4000
    }
  ]
}"""

AT_LEAST_SCRIPT_JSON = """{
  "type": "atLeast",
  "required": 2,
  "scripts":
  [
    {
      "type": "before",
      "slot": 3000
    },
    {
      "type": "sig",
      "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
    },
    {
      "type": "after",
      "slot": 4000
    }
  ]
}"""

NESTED_NATIVE_SCRIPT_JSON = """{
  "type": "any",
  "scripts":
  [
    {
      "type": "sig",
      "keyHash": "b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538"
    },
    {
      "type": "all",
      "scripts":
      [
        {
          "type": "before",
          "slot": 3000
        },
        {
          "type": "sig",
          "keyHash": "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
        },
        {
          "type": "after",
          "slot": 4000
        }
      ]
    }
  ]
}"""

NESTED_NATIVE_SCRIPT_CBOR = "8202828200581cb275b08c999097247f7c17e77007c7010cd19f20cc086ad99d3985388201838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
NESTED_NATIVE_SCRIPT_HASH = "8b8370c97ae17eb69a8c97f733888f7485b60fd820c69211c8bbeb56"

# Plutus script test vectors
PLUTUS_V1_SCRIPT_HEX = "4d01000033222220051200120011"
PLUTUS_V1_HASH = "67f33146617a5e61936081db3b2117cbf59bd2123748f58ac9678656"
PLUTUS_V1_CBOR = "4e4d01000033222220051200120011"


class TestNativeScript:
    def test_from_json_pubkey(self):
        script = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.REQUIRE_PUBKEY

    def test_from_json_invalid_before(self):
        # BEFORE_SCRIPT_JSON has "type": "before" which corresponds to INVALID_BEFORE
        script = NativeScript.from_json(BEFORE_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.INVALID_BEFORE

    def test_from_json_invalid_after(self):
        # AFTER_SCRIPT_JSON has "type": "after" which corresponds to INVALID_AFTER
        script = NativeScript.from_json(AFTER_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.INVALID_AFTER

    def test_from_json_all(self):
        script = NativeScript.from_json(ALL_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.REQUIRE_ALL_OF

    def test_from_json_any(self):
        script = NativeScript.from_json(ANY_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.REQUIRE_ANY_OF

    def test_from_json_n_of_k(self):
        script = NativeScript.from_json(AT_LEAST_SCRIPT_JSON)
        assert script is not None
        assert script.script_type == NativeScriptType.REQUIRE_N_OF_K

    def test_nested_script_hash(self):
        script = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        assert script is not None
        hash_val = script.hash
        assert hash_val.hex() == NESTED_NATIVE_SCRIPT_HASH

    def test_nested_script_cbor_roundtrip(self):
        script = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == NESTED_NATIVE_SCRIPT_CBOR

        reader = CborReader.from_hex(cbor_hex)
        script2 = NativeScript.from_cbor(reader)
        assert script2.hash.hex() == NESTED_NATIVE_SCRIPT_HASH

    def test_from_pubkey(self):
        key_hash = bytes.fromhex(
            "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
        )
        pubkey = ScriptPubkey.new(key_hash)
        script = NativeScript.from_pubkey(pubkey)
        assert script is not None
        assert script.script_type == NativeScriptType.REQUIRE_PUBKEY


class TestScriptPubkey:
    def test_new(self):
        key_hash = bytes.fromhex(
            "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
        )
        script = ScriptPubkey.new(key_hash)
        assert script is not None
        assert script.key_hash == key_hash

    def test_from_native_script(self):
        native_script = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        pubkey_script = native_script.to_pubkey()
        assert pubkey_script is not None
        expected_hash = bytes.fromhex(
            "966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
        )
        assert pubkey_script.key_hash == expected_hash


class TestScriptInvalidBefore:
    def test_new(self):
        script = ScriptInvalidBefore.new(3000)
        assert script is not None
        assert script.slot == 3000


class TestScriptInvalidAfter:
    def test_new(self):
        script = ScriptInvalidAfter.new(4000)
        assert script is not None
        assert script.slot == 4000


class TestScriptAll:
    def test_new(self):
        scripts = NativeScriptList()
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        scripts.add(pubkey)

        script_all = ScriptAll.new(scripts)
        assert script_all is not None
        assert len(script_all) == 1


class TestScriptAny:
    def test_new(self):
        scripts = NativeScriptList()
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        scripts.add(pubkey)

        script_any = ScriptAny.new(scripts)
        assert script_any is not None
        assert len(script_any) == 1


class TestScriptNOfK:
    def test_new(self):
        scripts = NativeScriptList()
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        native_script = NativeScript.from_pubkey(pubkey)
        scripts.add(native_script)

        script_nofk = ScriptNOfK.new(scripts, 1)
        assert script_nofk is not None
        assert script_nofk.required == 1
        assert len(script_nofk.scripts) == 1


class TestNativeScriptList:
    def test_create_empty(self):
        scripts = NativeScriptList()
        assert len(scripts) == 0

    def test_add_and_get(self):
        scripts = NativeScriptList()
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        scripts.add(pubkey)
        assert len(scripts) == 1

        retrieved = scripts.get(0)
        assert retrieved is not None

    def test_iteration(self):
        scripts = NativeScriptList()
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        scripts.add(pubkey1)
        scripts.add(pubkey2)

        count = 0
        for script in scripts:
            count += 1
        assert count == 2


class TestPlutusV1Script:
    def test_new(self):
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV1Script.new(script_bytes)
        assert script is not None
        assert script.hash.hex() == PLUTUS_V1_HASH

    def test_raw_bytes(self):
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV1Script.new(script_bytes)
        assert script.raw_bytes == script_bytes

    def test_cbor_roundtrip(self):
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV1Script.new(script_bytes)

        writer = CborWriter()
        script.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == PLUTUS_V1_CBOR

        reader = CborReader.from_hex(cbor_hex)
        script2 = PlutusV1Script.from_cbor(reader)
        assert script2.hash.hex() == PLUTUS_V1_HASH


class TestPlutusV2Script:
    def test_new(self):
        # Use the same script bytes - different Plutus version produces different hash
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV2Script.new(script_bytes)
        assert script is not None
        # V2 produces a different hash than V1 for the same bytes
        assert script.hash.hex() != PLUTUS_V1_HASH
        assert len(script.hash) == 28

    def test_raw_bytes(self):
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV2Script.new(script_bytes)
        assert script.raw_bytes == script_bytes


class TestPlutusV3Script:
    def test_new(self):
        # Use the same script bytes - different Plutus version produces different hash
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV3Script.new(script_bytes)
        assert script is not None
        # V3 produces a different hash than V1 and V2 for the same bytes
        assert script.hash.hex() != PLUTUS_V1_HASH
        assert len(script.hash) == 28

    def test_raw_bytes(self):
        script_bytes = bytes.fromhex(PLUTUS_V1_SCRIPT_HEX)
        script = PlutusV3Script.new(script_bytes)
        assert script.raw_bytes == script_bytes


class TestScript:
    def test_from_native_script(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_plutus_v1(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v1(plutus)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V1

    def test_from_plutus_v2(self):
        plutus = PlutusV2Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v2(plutus)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V2

    def test_from_plutus_v3(self):
        plutus = PlutusV3Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v3(plutus)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V3

    def test_hash(self):
        native = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        script = Script.from_native(native)
        assert script.hash.hex() == NESTED_NATIVE_SCRIPT_HASH
