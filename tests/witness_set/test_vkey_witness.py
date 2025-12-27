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
from cometa.witness_set.vkey_witness import VkeyWitness
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter
from cometa.json.json_format import JsonFormat
from cometa.errors import CardanoError


CBOR = "8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
VKEY_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
SIGNATURE_HEX = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"


def test_vkey_witness_new_creates_instance():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    assert witness is not None


def test_vkey_witness_new_with_invalid_vkey_raises_error():
    invalid_vkey = bytes.fromhex("ff")
    signature = bytes.fromhex(SIGNATURE_HEX)
    with pytest.raises(CardanoError):
        VkeyWitness.new(invalid_vkey, signature)


def test_vkey_witness_new_with_invalid_signature_raises_error():
    vkey = bytes.fromhex(VKEY_HEX)
    invalid_signature = bytes.fromhex("ff")
    with pytest.raises(CardanoError):
        VkeyWitness.new(vkey, invalid_signature)


def test_vkey_witness_from_cbor_creates_instance():
    reader = CborReader.from_hex(CBOR)
    witness = VkeyWitness.from_cbor(reader)
    assert witness is not None


def test_vkey_witness_from_cbor_with_invalid_cbor_raises_error():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        VkeyWitness.from_cbor(reader)


def test_vkey_witness_from_cbor_with_invalid_key_raises_error():
    invalid_cbor = "82ef203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
    reader = CborReader.from_hex(invalid_cbor)
    with pytest.raises(CardanoError):
        VkeyWitness.from_cbor(reader)


def test_vkey_witness_from_cbor_with_invalid_signature_raises_error():
    invalid_cbor = "8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660cef406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
    reader = CborReader.from_hex(invalid_cbor)
    with pytest.raises(CardanoError):
        VkeyWitness.from_cbor(reader)


def test_vkey_witness_to_cbor_serializes_correctly():
    reader = CborReader.from_hex(CBOR)
    witness = VkeyWitness.from_cbor(reader)
    writer = CborWriter()
    witness.to_cbor(writer)
    encoded = writer.encode()
    assert encoded.hex() == CBOR


def test_vkey_witness_vkey_property_returns_correct_value():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    assert witness.vkey == vkey


def test_vkey_witness_signature_property_returns_correct_value():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    assert witness.signature == signature


def test_vkey_witness_vkey_setter_sets_value():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    new_vkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    witness.vkey = new_vkey
    assert witness.vkey == new_vkey


def test_vkey_witness_vkey_setter_with_invalid_vkey_raises_error():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    invalid_vkey = bytes.fromhex("ff")
    with pytest.raises(CardanoError):
        witness.vkey = invalid_vkey


def test_vkey_witness_signature_setter_sets_value():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    new_signature = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    witness.signature = new_signature
    assert witness.signature == new_signature


def test_vkey_witness_signature_setter_with_invalid_signature_raises_error():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    invalid_signature = bytes.fromhex("ff")
    with pytest.raises(CardanoError):
        witness.signature = invalid_signature


def test_vkey_witness_has_public_key_returns_true_for_matching_key():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    assert witness.has_public_key(vkey) is True


def test_vkey_witness_has_public_key_returns_false_for_non_matching_key():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    other_vkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    assert witness.has_public_key(other_vkey) is False


def test_vkey_witness_has_public_key_with_invalid_vkey_raises_error():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    invalid_vkey = bytes.fromhex("ff")
    with pytest.raises(CardanoError):
        witness.has_public_key(invalid_vkey)


def test_vkey_witness_to_cip116_json_serializes_correctly():
    vkey = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    signature = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    witness = VkeyWitness.new(vkey, signature)
    writer = JsonWriter(JsonFormat.COMPACT)
    witness.to_cip116_json(writer)
    json_str = writer.encode()
    expected = '{"vkey":"0000000000000000000000000000000000000000000000000000000000000000","signature":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}'
    assert json_str == expected


def test_vkey_witness_to_cip116_json_with_invalid_writer_raises_error():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    with pytest.raises(TypeError):
        witness.to_cip116_json("not a writer")


def test_vkey_witness_context_manager_works():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    with VkeyWitness.new(vkey, signature) as witness:
        assert witness is not None


def test_vkey_witness_repr_returns_string():
    vkey = bytes.fromhex(VKEY_HEX)
    signature = bytes.fromhex(SIGNATURE_HEX)
    witness = VkeyWitness.new(vkey, signature)
    assert repr(witness) == "VkeyWitness(...)"


def test_vkey_witness_init_with_null_ptr_raises_error():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError, match="VkeyWitness: invalid handle"):
        VkeyWitness(ffi.NULL)
