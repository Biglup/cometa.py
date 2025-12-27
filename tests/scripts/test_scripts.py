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

    def test_new_accepts_python_list(self):
        """Test that ScriptAll.new() accepts a Python list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        # Pass Python list directly
        script_all = ScriptAll.new([pubkey1, pubkey2])
        assert script_all is not None
        assert len(script_all) == 2

    def test_scripts_setter_accepts_python_list(self):
        """Test that scripts setter accepts a Python list."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        script_all = ScriptAll.new([pubkey])

        # Update with Python list
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        script_all.scripts = [pubkey, pubkey2]
        assert len(script_all) == 2


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

    def test_new_accepts_python_list(self):
        """Test that ScriptAny.new() accepts a Python list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        # Pass Python list directly
        script_any = ScriptAny.new([pubkey1, pubkey2])
        assert script_any is not None
        assert len(script_any) == 2

    def test_scripts_setter_accepts_python_list(self):
        """Test that scripts setter accepts a Python list."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        script_any = ScriptAny.new([pubkey])

        # Update with Python list
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        script_any.scripts = [pubkey, pubkey2]
        assert len(script_any) == 2


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

    def test_new_accepts_python_list(self):
        """Test that ScriptNOfK.new() accepts a Python list."""
        pubkey1 = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )

        # Pass Python list directly
        script_nofk = ScriptNOfK.new([pubkey1, pubkey2], 1)
        assert script_nofk is not None
        assert script_nofk.required == 1
        assert len(script_nofk.scripts) == 2

    def test_scripts_setter_accepts_python_list(self):
        """Test that scripts setter accepts a Python list."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        script_nofk = ScriptNOfK.new([pubkey], 1)

        # Update with Python list
        pubkey2 = ScriptPubkey.new(
            bytes.fromhex("b275b08c999097247f7c17e77007c7010cd19f20cc086ad99d398538")
        )
        script_nofk.scripts = [pubkey, pubkey2]
        assert len(script_nofk.scripts) == 2


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

    def test_from_list(self):
        """Test NativeScriptList.from_list() with various script types."""
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        invalid_before = ScriptInvalidBefore.new(3000)
        invalid_after = ScriptInvalidAfter.new(4000)

        scripts = NativeScriptList.from_list([pubkey, invalid_before, invalid_after])
        assert len(scripts) == 3

    def test_from_list_with_native_scripts(self):
        """Test NativeScriptList.from_list() with NativeScript objects."""
        native1 = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        native2 = NativeScript.from_json(BEFORE_SCRIPT_JSON)

        scripts = NativeScriptList.from_list([native1, native2])
        assert len(scripts) == 2


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

    def test_from_native_with_pubkey(self):
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        script = Script.from_native(pubkey)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_all(self):
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        all_script = ScriptAll.new([pubkey])
        script = Script.from_native(all_script)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_any(self):
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        any_script = ScriptAny.new([pubkey])
        script = Script.from_native(any_script)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_n_of_k(self):
        pubkey = ScriptPubkey.new(
            bytes.fromhex("966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37")
        )
        n_of_k_script = ScriptNOfK.new([pubkey], 1)
        script = Script.from_native(n_of_k_script)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_invalid_before(self):
        invalid_before = ScriptInvalidBefore.new(3000)
        script = Script.from_native(invalid_before)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_invalid_after(self):
        invalid_after = ScriptInvalidAfter.new(4000)
        script = Script.from_native(invalid_after)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE

    def test_from_native_with_invalid_type(self):
        with pytest.raises(TypeError):
            Script.from_native("invalid")

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

    def test_from_cbor_native(self):
        cbor_hex = "82008202828200581cb275b08c999097247f7c17e77007c7010cd19f20cc086ad99d3985388201838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
        reader = CborReader.from_hex(cbor_hex)
        script = Script.from_cbor(reader)
        assert script is not None
        assert script.language == ScriptLanguage.NATIVE
        assert script.hash.hex() == "8b8370c97ae17eb69a8c97f733888f7485b60fd820c69211c8bbeb56"

    def test_from_cbor_plutus_v1(self):
        cbor_hex = "82014e4d01000033222220051200120011"
        reader = CborReader.from_hex(cbor_hex)
        script = Script.from_cbor(reader)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V1
        assert script.hash.hex() == PLUTUS_V1_HASH

    def test_from_cbor_plutus_v2(self):
        cbor_hex = "82025908955908920100003233223232323232332232323232323232323232332232323232322223232533532323232325335001101d13357389211e77726f6e67207573616765206f66207265666572656e636520696e7075740001c3232533500221533500221333573466e1c00800408007c407854cd4004840784078d40900114cd4c8d400488888888888802d40044c08526221533500115333533550222350012222002350022200115024213355023320015021001232153353235001222222222222300e00250052133550253200150233355025200100115026320013550272253350011502722135002225335333573466e3c00801c0940904d40b00044c01800c884c09526135001220023333573466e1cd55cea80224000466442466002006004646464646464646464646464646666ae68cdc39aab9d500c480008cccccccccccc88888888888848cccccccccccc00403403002c02802402001c01801401000c008cd405c060d5d0a80619a80b80c1aba1500b33501701935742a014666aa036eb94068d5d0a804999aa80dbae501a35742a01066a02e0446ae85401cccd5406c08dd69aba150063232323333573466e1cd55cea801240004664424660020060046464646666ae68cdc39aab9d5002480008cc8848cc00400c008cd40b5d69aba15002302e357426ae8940088c98c80c0cd5ce01901a01709aab9e5001137540026ae854008c8c8c8cccd5cd19b8735573aa004900011991091980080180119a816bad35742a004605c6ae84d5d1280111931901819ab9c03203402e135573ca00226ea8004d5d09aba2500223263202c33573805c06005426aae7940044dd50009aba1500533501775c6ae854010ccd5406c07c8004d5d0a801999aa80dbae200135742a00460426ae84d5d1280111931901419ab9c02a02c026135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d55cf280089baa00135742a00860226ae84d5d1280211931900d19ab9c01c01e018375a00a6666ae68cdc39aab9d375400a9000100e11931900c19ab9c01a01c016101b132632017335738921035054350001b135573ca00226ea800448c88c008dd6000990009aa80d911999aab9f0012500a233500930043574200460066ae880080608c8c8cccd5cd19b8735573aa004900011991091980080180118061aba150023005357426ae8940088c98c8050cd5ce00b00c00909aab9e5001137540024646464646666ae68cdc39aab9d5004480008cccc888848cccc00401401000c008c8c8c8cccd5cd19b8735573aa0049000119910919800801801180a9aba1500233500f014357426ae8940088c98c8064cd5ce00d80e80b89aab9e5001137540026ae854010ccd54021d728039aba150033232323333573466e1d4005200423212223002004357426aae79400c8cccd5cd19b875002480088c84888c004010dd71aba135573ca00846666ae68cdc3a801a400042444006464c6403666ae7007407c06406005c4d55cea80089baa00135742a00466a016eb8d5d09aba2500223263201533573802e03202626ae8940044d5d1280089aab9e500113754002266aa002eb9d6889119118011bab00132001355018223233335573e0044a010466a00e66442466002006004600c6aae754008c014d55cf280118021aba200301613574200222440042442446600200800624464646666ae68cdc3a800a400046a02e600a6ae84d55cf280191999ab9a3370ea00490011280b91931900819ab9c01201400e00d135573aa00226ea80048c8c8cccd5cd19b875001480188c848888c010014c01cd5d09aab9e500323333573466e1d400920042321222230020053009357426aae7940108cccd5cd19b875003480088c848888c004014c01cd5d09aab9e500523333573466e1d40112000232122223003005375c6ae84d55cf280311931900819ab9c01201400e00d00c00b135573aa00226ea80048c8c8cccd5cd19b8735573aa004900011991091980080180118029aba15002375a6ae84d5d1280111931900619ab9c00e01000a135573ca00226ea80048c8cccd5cd19b8735573aa002900011bae357426aae7940088c98c8028cd5ce00600700409baa001232323232323333573466e1d4005200c21222222200323333573466e1d4009200a21222222200423333573466e1d400d2008233221222222233001009008375c6ae854014dd69aba135744a00a46666ae68cdc3a8022400c4664424444444660040120106eb8d5d0a8039bae357426ae89401c8cccd5cd19b875005480108cc8848888888cc018024020c030d5d0a8049bae357426ae8940248cccd5cd19b875006480088c848888888c01c020c034d5d09aab9e500b23333573466e1d401d2000232122222223005008300e357426aae7940308c98c804ccd5ce00a80b80880800780700680600589aab9d5004135573ca00626aae7940084d55cf280089baa0012323232323333573466e1d400520022333222122333001005004003375a6ae854010dd69aba15003375a6ae84d5d1280191999ab9a3370ea0049000119091180100198041aba135573ca00c464c6401866ae700380400280244d55cea80189aba25001135573ca00226ea80048c8c8cccd5cd19b875001480088c8488c00400cdd71aba135573ca00646666ae68cdc3a8012400046424460040066eb8d5d09aab9e500423263200933573801601a00e00c26aae7540044dd500089119191999ab9a3370ea00290021091100091999ab9a3370ea00490011190911180180218031aba135573ca00846666ae68cdc3a801a400042444004464c6401466ae7003003802001c0184d55cea80089baa0012323333573466e1d40052002200623333573466e1d40092000200623263200633573801001400800626aae74dd5000a4c244004244002921035054310012333333357480024a00c4a00c4a00c46a00e6eb400894018008480044488c0080049400848488c00800c4488004448c8c00400488cc00cc0080080041"
        reader = CborReader.from_hex(cbor_hex)
        script = Script.from_cbor(reader)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V2

    def test_from_cbor_plutus_v3(self):
        cbor_hex = "82035908955908920100003233223232323232332232323232323232323232332232323232322223232533532323232325335001101d13357389211e77726f6e67207573616765206f66207265666572656e636520696e7075740001c3232533500221533500221333573466e1c00800408007c407854cd4004840784078d40900114cd4c8d400488888888888802d40044c08526221533500115333533550222350012222002350022200115024213355023320015021001232153353235001222222222222300e00250052133550253200150233355025200100115026320013550272253350011502722135002225335333573466e3c00801c0940904d40b00044c01800c884c09526135001220023333573466e1cd55cea80224000466442466002006004646464646464646464646464646666ae68cdc39aab9d500c480008cccccccccccc88888888888848cccccccccccc00403403002c02802402001c01801401000c008cd405c060d5d0a80619a80b80c1aba1500b33501701935742a014666aa036eb94068d5d0a804999aa80dbae501a35742a01066a02e0446ae85401cccd5406c08dd69aba150063232323333573466e1cd55cea801240004664424660020060046464646666ae68cdc39aab9d5002480008cc8848cc00400c008cd40b5d69aba15002302e357426ae8940088c98c80c0cd5ce01901a01709aab9e5001137540026ae854008c8c8c8cccd5cd19b8735573aa004900011991091980080180119a816bad35742a004605c6ae84d5d1280111931901819ab9c03203402e135573ca00226ea8004d5d09aba2500223263202c33573805c06005426aae7940044dd50009aba1500533501775c6ae854010ccd5406c07c8004d5d0a801999aa80dbae200135742a00460426ae84d5d1280111931901419ab9c02a02c026135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d55cf280089baa00135742a00860226ae84d5d1280211931900d19ab9c01c01e018375a00a6666ae68cdc39aab9d375400a9000100e11931900c19ab9c01a01c016101b132632017335738921035054350001b135573ca00226ea800448c88c008dd6000990009aa80d911999aab9f0012500a233500930043574200460066ae880080608c8c8cccd5cd19b8735573aa004900011991091980080180118061aba150023005357426ae8940088c98c8050cd5ce00b00c00909aab9e5001137540024646464646666ae68cdc39aab9d5004480008cccc888848cccc00401401000c008c8c8c8cccd5cd19b8735573aa0049000119910919800801801180a9aba1500233500f014357426ae8940088c98c8064cd5ce00d80e80b89aab9e5001137540026ae854010ccd54021d728039aba150033232323333573466e1d4005200423212223002004357426aae79400c8cccd5cd19b875002480088c84888c004010dd71aba135573ca00846666ae68cdc3a801a400042444006464c6403666ae7007407c06406005c4d55cea80089baa00135742a00466a016eb8d5d09aba2500223263201533573802e03202626ae8940044d5d1280089aab9e500113754002266aa002eb9d6889119118011bab00132001355018223233335573e0044a010466a00e66442466002006004600c6aae754008c014d55cf280118021aba200301613574200222440042442446600200800624464646666ae68cdc3a800a400046a02e600a6ae84d55cf280191999ab9a3370ea00490011280b91931900819ab9c01201400e00d135573aa00226ea80048c8c8cccd5cd19b875001480188c848888c010014c01cd5d09aab9e500323333573466e1d400920042321222230020053009357426aae7940108cccd5cd19b875003480088c848888c004014c01cd5d09aab9e500523333573466e1d40112000232122223003005375c6ae84d55cf280311931900819ab9c01201400e00d00c00b135573aa00226ea80048c8c8cccd5cd19b8735573aa004900011991091980080180118029aba15002375a6ae84d5d1280111931900619ab9c00e01000a135573ca00226ea80048c8cccd5cd19b8735573aa002900011bae357426aae7940088c98c8028cd5ce00600700409baa001232323232323333573466e1d4005200c21222222200323333573466e1d4009200a21222222200423333573466e1d400d2008233221222222233001009008375c6ae854014dd69aba135744a00a46666ae68cdc3a8022400c4664424444444660040120106eb8d5d0a8039bae357426ae89401c8cccd5cd19b875005480108cc8848888888cc018024020c030d5d0a8049bae357426ae8940248cccd5cd19b875006480088c848888888c01c020c034d5d09aab9e500b23333573466e1d401d2000232122222223005008300e357426aae7940308c98c804ccd5ce00a80b80880800780700680600589aab9d5004135573ca00626aae7940084d55cf280089baa0012323232323333573466e1d400520022333222122333001005004003375a6ae854010dd69aba15003375a6ae84d5d1280191999ab9a3370ea0049000119091180100198041aba135573ca00c464c6401866ae700380400280244d55cea80189aba25001135573ca00226ea80048c8c8cccd5cd19b875001480088c8488c00400cdd71aba135573ca00646666ae68cdc3a8012400046424460040066eb8d5d09aab9e500423263200933573801601a00e00c26aae7540044dd500089119191999ab9a3370ea00290021091100091999ab9a3370ea00490011190911180180218031aba135573ca00846666ae68cdc3a801a400042444004464c6401466ae7003003802001c0184d55cea80089baa0012323333573466e1d40052002200623333573466e1d40092000200623263200633573801001400800626aae74dd5000a4c244004244002921035054310012333333357480024a00c4a00c4a00c46a00e6eb400894018008480044488c0080049400848488c00800c4488004448c8c00400488cc00cc0080080041"
        reader = CborReader.from_hex(cbor_hex)
        script = Script.from_cbor(reader)
        assert script is not None
        assert script.language == ScriptLanguage.PLUTUS_V3

    def test_to_cbor_native(self):
        native = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        script = Script.from_native(native)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_hex = writer.to_hex()
        expected = "82008202828200581cb275b08c999097247f7c17e77007c7010cd19f20cc086ad99d3985388201838205190bb88200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378204190fa0"
        assert cbor_hex == expected

    def test_to_cbor_plutus_v1(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v1(plutus)
        writer = CborWriter()
        script.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == "82014e4d01000033222220051200120011"

    def test_to_native(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        converted = script.to_native()
        assert converted is not None
        assert converted.script_type == NativeScriptType.REQUIRE_PUBKEY

    def test_to_native_from_non_native_fails(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v1(plutus)
        with pytest.raises(Exception):
            script.to_native()

    def test_to_plutus_v1(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v1(plutus)
        converted = script.to_plutus_v1()
        assert converted is not None
        assert converted.hash.hex() == PLUTUS_V1_HASH

    def test_to_plutus_v1_from_non_v1_fails(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        with pytest.raises(Exception):
            script.to_plutus_v1()

    def test_to_plutus_v2(self):
        plutus = PlutusV2Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v2(plutus)
        converted = script.to_plutus_v2()
        assert converted is not None
        assert len(converted.hash) == 28

    def test_to_plutus_v2_from_non_v2_fails(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        with pytest.raises(Exception):
            script.to_plutus_v2()

    def test_to_plutus_v3(self):
        plutus = PlutusV3Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v3(plutus)
        converted = script.to_plutus_v3()
        assert converted is not None
        assert len(converted.hash) == 28

    def test_to_plutus_v3_from_non_v3_fails(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        with pytest.raises(Exception):
            script.to_plutus_v3()

    def test_hash(self):
        native = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        script = Script.from_native(native)
        assert script.hash.hex() == NESTED_NATIVE_SCRIPT_HASH

    def test_hash_plutus_v1(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script = Script.from_plutus_v1(plutus)
        assert script.hash.hex() == PLUTUS_V1_HASH

    def test_equality_same_native_scripts(self):
        native1 = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script1 = Script.from_native(native1)
        native2 = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script2 = Script.from_native(native2)
        assert script1 == script2

    def test_equality_different_native_scripts(self):
        native1 = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script1 = Script.from_native(native1)
        native2 = NativeScript.from_json(BEFORE_SCRIPT_JSON)
        script2 = Script.from_native(native2)
        assert script1 != script2

    def test_equality_same_plutus_v1_scripts(self):
        plutus1 = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script1 = Script.from_plutus_v1(plutus1)
        plutus2 = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script2 = Script.from_plutus_v1(plutus2)
        assert script1 == script2

    def test_equality_different_types(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script1 = Script.from_native(native)
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script2 = Script.from_plutus_v1(plutus)
        assert script1 != script2

    def test_equality_with_non_script(self):
        native = NativeScript.from_json(PUBKEY_SCRIPT_JSON)
        script = Script.from_native(native)
        assert script != "not a script"
        assert script != 42
        assert script != None

    def test_repr(self):
        native = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        script = Script.from_native(native)
        repr_str = repr(script)
        assert "Script" in repr_str
        assert "NATIVE" in repr_str
        assert NESTED_NATIVE_SCRIPT_HASH in repr_str

    def test_cbor_roundtrip_native(self):
        native = NativeScript.from_json(NESTED_NATIVE_SCRIPT_JSON)
        script1 = Script.from_native(native)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        script2 = Script.from_cbor(reader)
        assert script1 == script2

    def test_cbor_roundtrip_plutus_v1(self):
        plutus = PlutusV1Script.new(bytes.fromhex(PLUTUS_V1_SCRIPT_HEX))
        script1 = Script.from_plutus_v1(plutus)
        writer = CborWriter()
        script1.to_cbor(writer)
        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        script2 = Script.from_cbor(reader)
        assert script1 == script2
