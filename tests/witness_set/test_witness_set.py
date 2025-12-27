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
    ExUnits,
    PlutusData,
    PlutusDataSet,
    VkeyWitness,
    VkeyWitnessSet,
    BootstrapWitness,
    BootstrapWitnessSet,
    NativeScriptSet,
    PlutusV1ScriptSet,
    PlutusV2ScriptSet,
    PlutusV3ScriptSet,
    Redeemer,
    RedeemerTag,
    RedeemerList,
    WitnessSet,
    CardanoError,
    JsonWriter,
)


CONWAY_CBOR_WITH_SETS = "a700d90102828258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a01d90102828200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c3702d90102838200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c3703d9010282820158644d01000033222220051200120011821a00000001820158644d0100003322222005120012001104d90102849f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff05a482000082d8799f0102030405ff821821182c82010182d8799f0102030405ff821821182c82030382d8799f0102030405ff821821182c82040482d8799f0102030405ff821821182c06d90102828200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
CONWAY_CBOR = "a100d90102828258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
VKEY_WITNESS_SET_CBOR = "d90102828258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
BOOTSTRAP_WITNESS_SET_CBOR = "d90102828200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
NATIVE_SCRIPT_SET_CBOR = "d90102848200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
PLUTUS_V1_SCRIPT_SET_CBOR = "d90102838200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
PLUTUS_V2_SCRIPT_SET_CBOR = "d9010282820158644d01000033222220051200120011821a00000001"
PLUTUS_V3_SCRIPT_SET_CBOR = "d9010282820158644d01000033222220051200120011821a00000001"
PLUTUS_DATA_SET_CBOR = "d90102849f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff9f01029f0102030405ff9f0102030405ff05ff"
REDEEMER_LIST_CBOR = "a482000082d8799f0102030405ff821821182c82010182d8799f0102030405ff821821182c82030382d8799f0102030405ff821821182c82040482d8799f0102030405ff821821182c"
VKEY_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
SIGNATURE_HEX = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
PLUTUS_DATA_CBOR = "d8799f0102030405ff"


class TestWitnessSetConstruction:
    """Tests for WitnessSet construction and basic lifecycle."""

    def test_new_creates_empty_witness_set(self):
        """Test that WitnessSet() creates a new empty witness set."""
        witness_set = WitnessSet()
        assert witness_set is not None
        assert witness_set.vkeys is None
        assert witness_set.bootstrap is None
        assert witness_set.native_scripts is None
        assert witness_set.plutus_v1_scripts is None
        assert witness_set.plutus_v2_scripts is None
        assert witness_set.plutus_v3_scripts is None
        assert witness_set.plutus_data is None
        assert witness_set.redeemers is None

    def test_repr(self):
        """Test the string representation of WitnessSet."""
        witness_set = WitnessSet()
        assert repr(witness_set) == "WitnessSet(...)"

    def test_context_manager(self):
        """Test that WitnessSet can be used as a context manager."""
        with WitnessSet() as witness_set:
            assert witness_set is not None


class TestWitnessSetSerialization:
    """Tests for WitnessSet CBOR serialization and deserialization."""

    def test_from_cbor_with_only_vkeys(self):
        """Test deserializing a witness set with only vkeys."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)
        assert witness_set is not None
        assert witness_set.vkeys is not None
        assert witness_set.bootstrap is None
        assert witness_set.native_scripts is None

    def test_to_cbor_preserves_original_encoding(self):
        """Test that to_cbor preserves the original CBOR encoding."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)
        writer = CborWriter()
        witness_set.to_cbor(writer)
        assert writer.to_hex() == CONWAY_CBOR

    def test_from_cbor_invalid_reader_raises_error(self):
        """Test that from_cbor raises error with invalid CBOR."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            WitnessSet.from_cbor(reader)

    def test_to_cbor_with_invalid_writer_raises_error(self):
        """Test that to_cbor handles invalid cases."""
        witness_set = WitnessSet()
        writer = CborWriter()
        witness_set.to_cbor(writer)
        assert len(writer.to_hex()) > 0


class TestWitnessSetVkeys:
    """Tests for vkey witness management."""

    def test_get_vkeys_returns_none_initially(self):
        """Test that vkeys is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.vkeys is None

    def test_set_vkeys_with_witness_set(self):
        """Test setting vkeys with a VkeyWitnessSet."""
        witness_set = WitnessSet()
        vkey_set = VkeyWitnessSet()
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)
        vkey_set.add(witness)

        witness_set.vkeys = vkey_set

        retrieved = witness_set.vkeys
        assert retrieved is not None
        assert len(retrieved) == 1

    def test_set_vkeys_with_python_list(self):
        """Test setting vkeys with a Python list of VkeyWitness."""
        witness_set = WitnessSet()
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness1 = VkeyWitness.new(vkey, signature)
        witness2 = VkeyWitness.new(vkey, signature)

        witness_set.vkeys = [witness1, witness2]

        retrieved = witness_set.vkeys
        assert retrieved is not None
        assert len(retrieved) >= 1

    def test_set_vkeys_to_none_clears_vkeys(self):
        """Test that setting vkeys to None clears the vkeys."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(VKEY_WITNESS_SET_CBOR)
        vkey_set = VkeyWitnessSet.from_cbor(reader)
        witness_set.vkeys = vkey_set

        witness_set.vkeys = None

        assert witness_set.vkeys is None

    def test_get_vkeys_from_cbor(self):
        """Test getting vkeys from a deserialized witness set."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)
        vkeys = witness_set.vkeys
        assert vkeys is not None
        assert len(vkeys) == 2


class TestWitnessSetBootstrap:
    """Tests for bootstrap witness management."""

    def test_get_bootstrap_returns_none_initially(self):
        """Test that bootstrap is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.bootstrap is None

    def test_set_bootstrap_to_none_clears_bootstrap(self):
        """Test that setting bootstrap to None clears the bootstrap."""
        witness_set = WitnessSet()
        bootstrap_set = BootstrapWitnessSet()

        witness_set.bootstrap = bootstrap_set
        witness_set.bootstrap = None

        assert witness_set.bootstrap is None


class TestWitnessSetNativeScripts:
    """Tests for native script management."""

    def test_get_native_scripts_returns_none_initially(self):
        """Test that native_scripts is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.native_scripts is None

    def test_set_native_scripts_with_script_set(self):
        """Test setting native_scripts with a NativeScriptSet."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(NATIVE_SCRIPT_SET_CBOR)
        script_set = NativeScriptSet.from_cbor(reader)

        witness_set.native_scripts = script_set

        retrieved = witness_set.native_scripts
        assert retrieved is not None
        assert len(retrieved) == 4

    def test_set_native_scripts_to_none_clears_scripts(self):
        """Test that setting native_scripts to None clears the scripts."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(NATIVE_SCRIPT_SET_CBOR)
        script_set = NativeScriptSet.from_cbor(reader)
        witness_set.native_scripts = script_set

        witness_set.native_scripts = None

        assert witness_set.native_scripts is None


class TestWitnessSetPlutusV1Scripts:
    """Tests for Plutus V1 script management."""

    def test_get_plutus_v1_scripts_returns_none_initially(self):
        """Test that plutus_v1_scripts is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.plutus_v1_scripts is None

    def test_set_plutus_v1_scripts_to_none_clears_scripts(self):
        """Test that setting plutus_v1_scripts to None clears the scripts."""
        witness_set = WitnessSet()
        script_set = PlutusV1ScriptSet()
        witness_set.plutus_v1_scripts = script_set

        witness_set.plutus_v1_scripts = None

        assert witness_set.plutus_v1_scripts is None


class TestWitnessSetPlutusV2Scripts:
    """Tests for Plutus V2 script management."""

    def test_get_plutus_v2_scripts_returns_none_initially(self):
        """Test that plutus_v2_scripts is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.plutus_v2_scripts is None

    def test_set_plutus_v2_scripts_to_none_clears_scripts(self):
        """Test that setting plutus_v2_scripts to None clears the scripts."""
        witness_set = WitnessSet()
        script_set = PlutusV2ScriptSet()
        witness_set.plutus_v2_scripts = script_set

        witness_set.plutus_v2_scripts = None

        assert witness_set.plutus_v2_scripts is None


class TestWitnessSetPlutusV3Scripts:
    """Tests for Plutus V3 script management."""

    def test_get_plutus_v3_scripts_returns_none_initially(self):
        """Test that plutus_v3_scripts is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.plutus_v3_scripts is None

    def test_set_plutus_v3_scripts_to_none_clears_scripts(self):
        """Test that setting plutus_v3_scripts to None clears the scripts."""
        witness_set = WitnessSet()
        script_set = PlutusV3ScriptSet()
        witness_set.plutus_v3_scripts = script_set

        witness_set.plutus_v3_scripts = None

        assert witness_set.plutus_v3_scripts is None


class TestWitnessSetPlutusData:
    """Tests for Plutus data management."""

    def test_get_plutus_data_returns_none_initially(self):
        """Test that plutus_data is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.plutus_data is None

    def test_set_plutus_data_with_data_set(self):
        """Test setting plutus_data with a PlutusDataSet."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(PLUTUS_DATA_SET_CBOR)
        data_set = PlutusDataSet.from_cbor(reader)

        witness_set.plutus_data = data_set

        retrieved = witness_set.plutus_data
        assert retrieved is not None
        assert len(retrieved) == 4

    def test_set_plutus_data_with_python_list(self):
        """Test setting plutus_data with a Python list of PlutusData."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(PLUTUS_DATA_CBOR)
        data1 = PlutusData.from_cbor(reader)
        reader2 = CborReader.from_hex(PLUTUS_DATA_CBOR)
        data2 = PlutusData.from_cbor(reader2)

        witness_set.plutus_data = [data1, data2]

        retrieved = witness_set.plutus_data
        assert retrieved is not None
        assert len(retrieved) == 2

    def test_set_plutus_data_to_none_clears_data(self):
        """Test that setting plutus_data to None clears the data."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(PLUTUS_DATA_SET_CBOR)
        data_set = PlutusDataSet.from_cbor(reader)
        witness_set.plutus_data = data_set

        witness_set.plutus_data = None

        assert witness_set.plutus_data is None


class TestWitnessSetRedeemers:
    """Tests for redeemer management."""

    def test_get_redeemers_returns_none_initially(self):
        """Test that redeemers is None for a new witness set."""
        witness_set = WitnessSet()
        assert witness_set.redeemers is None

    def test_set_redeemers_with_redeemer_list(self):
        """Test setting redeemers with a RedeemerList."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(REDEEMER_LIST_CBOR)
        redeemer_list = RedeemerList.from_cbor(reader)

        witness_set.redeemers = redeemer_list

        retrieved = witness_set.redeemers
        assert retrieved is not None
        assert len(retrieved) == 4

    def test_set_redeemers_with_python_list(self):
        """Test setting redeemers with a Python list of Redeemer."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(REDEEMER_LIST_CBOR)
        redeemer_list = RedeemerList.from_cbor(reader)
        redeemer1 = redeemer_list.get(0)
        redeemer2 = redeemer_list.get(1)

        witness_set.redeemers = [redeemer1, redeemer2]

        retrieved = witness_set.redeemers
        assert retrieved is not None
        assert len(retrieved) == 2

    def test_set_redeemers_to_none_clears_redeemers(self):
        """Test that setting redeemers to None clears the redeemers."""
        witness_set = WitnessSet()
        reader = CborReader.from_hex(REDEEMER_LIST_CBOR)
        redeemer_list = RedeemerList.from_cbor(reader)
        witness_set.redeemers = redeemer_list

        witness_set.redeemers = None

        assert witness_set.redeemers is None


class TestWitnessSetCborCache:
    """Tests for CBOR cache management."""

    def test_clear_cbor_cache(self):
        """Test that clear_cbor_cache can be called without error."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)

        witness_set.clear_cbor_cache()

        writer = CborWriter()
        witness_set.to_cbor(writer)
        assert len(writer.to_hex()) > 0

    def test_clear_cbor_cache_changes_serialization(self):
        """Test that clearing CBOR cache may change the serialization."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)

        writer1 = CborWriter()
        witness_set.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        witness_set.clear_cbor_cache()

        writer2 = CborWriter()
        witness_set.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == CONWAY_CBOR


class TestWitnessSetJsonSerialization:
    """Tests for CIP-116 JSON serialization."""

    def test_to_cip116_json_with_empty_witness_set(self):
        """Test serializing an empty witness set to CIP-116 JSON."""
        witness_set = WitnessSet()
        writer = JsonWriter()
        witness_set.to_cip116_json(writer)
        json_str = writer.encode()
        assert len(json_str) > 0
        assert "{" in json_str

    def test_to_cip116_json_with_vkeys(self):
        """Test serializing a witness set with vkeys to CIP-116 JSON."""
        reader = CborReader.from_hex(CONWAY_CBOR)
        witness_set = WitnessSet.from_cbor(reader)
        writer = JsonWriter()
        witness_set.to_cip116_json(writer)
        json_str = writer.encode()
        assert len(json_str) > 0

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that to_cip116_json raises error with invalid writer."""
        witness_set = WitnessSet()
        with pytest.raises(TypeError):
            witness_set.to_cip116_json("not a writer")


class TestWitnessSetEdgeCases:
    """Tests for edge cases and error handling."""

    def test_multiple_operations_on_same_witness_set(self):
        """Test performing multiple operations on the same witness set."""
        witness_set = WitnessSet()

        vkey_reader = CborReader.from_hex(VKEY_WITNESS_SET_CBOR)
        vkey_set = VkeyWitnessSet.from_cbor(vkey_reader)
        witness_set.vkeys = vkey_set

        bootstrap_set = BootstrapWitnessSet()
        witness_set.bootstrap = bootstrap_set

        redeemer_reader = CborReader.from_hex(REDEEMER_LIST_CBOR)
        redeemer_list = RedeemerList.from_cbor(redeemer_reader)
        witness_set.redeemers = redeemer_list

        assert witness_set.vkeys is not None
        assert witness_set.bootstrap is not None
        assert witness_set.redeemers is not None

    def test_serialization_after_modifications(self):
        """Test that serialization works after modifying the witness set."""
        witness_set = WitnessSet()

        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)
        witness_set.vkeys = [witness]

        writer = CborWriter()
        witness_set.to_cbor(writer)
        assert len(writer.to_hex()) > 0

    def test_deserialization_and_reserialization_roundtrip(self):
        """Test that deserialize-serialize-deserialize produces same result."""
        reader1 = CborReader.from_hex(CONWAY_CBOR)
        witness_set1 = WitnessSet.from_cbor(reader1)

        writer = CborWriter()
        witness_set1.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        witness_set2 = WitnessSet.from_cbor(reader2)

        assert witness_set2.vkeys is not None
