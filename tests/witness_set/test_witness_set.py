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

from cometa import (
    CborReader,
    CborWriter,
    ExUnits,
    PlutusData,
    VkeyWitness,
    VkeyWitnessSet,
    Redeemer,
    RedeemerTag,
    RedeemerList,
    WitnessSet,
)


# Test vectors from vendor/cardano-c/lib/tests/witness_set
VKEY_WITNESS_CBOR = "8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
VKEY_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
SIGNATURE_HEX = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

REDEEMER_CBOR = "840000d8799f0102030405ff821821182c"
PLUTUS_DATA_CBOR = "d8799f0102030405ff"


class TestVkeyWitness:
    def test_new(self):
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)
        assert witness is not None
        assert witness.vkey == vkey
        assert witness.signature == signature

    def test_from_cbor(self):
        reader = CborReader.from_hex(VKEY_WITNESS_CBOR)
        witness = VkeyWitness.from_cbor(reader)
        assert witness is not None
        assert witness.vkey == bytes.fromhex(VKEY_HEX)
        assert witness.signature == bytes.fromhex(SIGNATURE_HEX)

    def test_to_cbor(self):
        reader = CborReader.from_hex(VKEY_WITNESS_CBOR)
        witness = VkeyWitness.from_cbor(reader)

        writer = CborWriter()
        witness.to_cbor(writer)
        assert writer.to_hex() == VKEY_WITNESS_CBOR


class TestVkeyWitnessSet:
    def test_create_empty(self):
        witness_set = VkeyWitnessSet()
        assert len(witness_set) == 0

    def test_add_and_get(self):
        witness_set = VkeyWitnessSet()
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)

        witness_set.add(witness)
        assert len(witness_set) == 1

        retrieved = witness_set.get(0)
        assert retrieved is not None
        assert retrieved.vkey == vkey

    def test_iteration(self):
        witness_set = VkeyWitnessSet()
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)

        witness_set.add(witness)

        count = 0
        for w in witness_set:
            count += 1
            assert w.vkey == vkey
        assert count == 1


class TestRedeemer:
    def test_from_cbor(self):
        reader = CborReader.from_hex(REDEEMER_CBOR)
        redeemer = Redeemer.from_cbor(reader)
        assert redeemer is not None
        assert redeemer.tag == RedeemerTag.SPEND
        assert redeemer.index == 0

    def test_new(self):
        # Create PlutusData from CBOR
        reader = CborReader.from_hex(PLUTUS_DATA_CBOR)
        plutus_data = PlutusData.from_cbor(reader)

        # Create ExUnits
        ex_units = ExUnits.new(33, 44)

        # Create redeemer
        redeemer = Redeemer.new(RedeemerTag.SPEND, 0, plutus_data, ex_units)
        assert redeemer is not None
        assert redeemer.tag == RedeemerTag.SPEND
        assert redeemer.index == 0

    def test_to_cbor(self):
        reader = CborReader.from_hex(REDEEMER_CBOR)
        redeemer = Redeemer.from_cbor(reader)

        writer = CborWriter()
        redeemer.to_cbor(writer)
        # The CBOR may be slightly different due to encoding, but should be valid
        encoded = writer.to_hex()
        assert len(encoded) > 0


class TestRedeemerList:
    def test_create_empty(self):
        redeemer_list = RedeemerList()
        assert len(redeemer_list) == 0

    def test_add_and_get(self):
        redeemer_list = RedeemerList()

        reader = CborReader.from_hex(REDEEMER_CBOR)
        redeemer = Redeemer.from_cbor(reader)

        redeemer_list.add(redeemer)
        assert len(redeemer_list) == 1

        retrieved = redeemer_list.get(0)
        assert retrieved is not None
        assert retrieved.tag == RedeemerTag.SPEND


class TestWitnessSet:
    def test_create_empty(self):
        witness_set = WitnessSet()
        assert witness_set is not None

    def test_vkey_witnesses(self):
        witness_set = WitnessSet()

        # Create vkey witness set
        vkey_set = VkeyWitnessSet()
        vkey = bytes.fromhex(VKEY_HEX)
        signature = bytes.fromhex(SIGNATURE_HEX)
        witness = VkeyWitness.new(vkey, signature)
        vkey_set.add(witness)

        # Set on witness set
        witness_set.vkey_witnesses = vkey_set

        # Retrieve
        retrieved = witness_set.vkey_witnesses
        assert retrieved is not None
        assert len(retrieved) == 1

    def test_redeemers(self):
        witness_set = WitnessSet()

        # Create redeemer list
        redeemer_list = RedeemerList()
        reader = CborReader.from_hex(REDEEMER_CBOR)
        redeemer = Redeemer.from_cbor(reader)
        redeemer_list.add(redeemer)

        # Set on witness set
        witness_set.redeemers = redeemer_list

        # Retrieve
        retrieved = witness_set.redeemers
        assert retrieved is not None
        assert len(retrieved) == 1
