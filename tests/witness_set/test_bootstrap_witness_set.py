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
from cometa.witness_set.bootstrap_witness_set import BootstrapWitnessSet
from cometa.witness_set.bootstrap_witness import BootstrapWitness
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter
from cometa.json.json_format import JsonFormat
from cometa.errors import CardanoError


CBOR = "d90102848458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
CBOR_WITHOUT_TAG = "848458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a08458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
BOOTSTRAP_WITNESS1_CBOR = "8458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
BOOTSTRAP_WITNESS2_CBOR = "8458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
BOOTSTRAP_WITNESS3_CBOR = "8458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"
BOOTSTRAP_WITNESS4_CBOR = "8458203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a5820000000000000000000000000000000000000000000000000000000000000000041a0"


def create_default_bootstrap_witness(cbor: str) -> BootstrapWitness:
    reader = CborReader.from_hex(cbor)
    return BootstrapWitness.from_cbor(reader)


def test_bootstrap_witness_set_new_creates_instance():
    witness_set = BootstrapWitnessSet()
    assert witness_set is not None
    assert len(witness_set) == 0


def test_bootstrap_witness_set_new_with_null_ptr_raises_error():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError, match="BootstrapWitnessSet: invalid handle"):
        BootstrapWitnessSet(ffi.NULL)


def test_bootstrap_witness_set_from_cbor_creates_instance():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    assert witness_set is not None
    assert len(witness_set) == 4


def test_bootstrap_witness_set_from_cbor_without_tag():
    reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    assert witness_set is not None
    assert len(witness_set) == 4


def test_bootstrap_witness_set_from_cbor_with_invalid_cbor_raises_error():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        BootstrapWitnessSet.from_cbor(reader)


def test_bootstrap_witness_set_from_cbor_with_invalid_array_raises_error():
    reader = CborReader.from_hex("ff")
    with pytest.raises(CardanoError):
        BootstrapWitnessSet.from_cbor(reader)


def test_bootstrap_witness_set_from_cbor_with_invalid_elements_raises_error():
    reader = CborReader.from_hex("9ffeff")
    with pytest.raises(CardanoError):
        BootstrapWitnessSet.from_cbor(reader)


def test_bootstrap_witness_set_from_cbor_with_missing_end_array_raises_error():
    reader = CborReader.from_hex("9f01")
    with pytest.raises(CardanoError):
        BootstrapWitnessSet.from_cbor(reader)


def test_bootstrap_witness_set_from_list_creates_instance():
    witnesses = [
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS2_CBOR),
    ]
    witness_set = BootstrapWitnessSet.from_list(witnesses)
    assert witness_set is not None
    assert len(witness_set) == 2


def test_bootstrap_witness_set_from_list_with_empty_list():
    witness_set = BootstrapWitnessSet.from_list([])
    assert witness_set is not None
    assert len(witness_set) == 0


def test_bootstrap_witness_set_to_cbor_serializes_correctly():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded = writer.encode()
    assert encoded.hex() == CBOR


def test_bootstrap_witness_set_to_cbor_without_tag_serializes_correctly():
    reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded = writer.encode()
    assert encoded.hex() == CBOR_WITHOUT_TAG


def test_bootstrap_witness_set_to_cbor_empty_set():
    witness_set = BootstrapWitnessSet()
    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded = writer.encode()
    assert encoded.hex() == "d9010280"


def test_bootstrap_witness_set_to_cbor_roundtrip():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded = writer.encode()

    reader2 = CborReader.from_hex(encoded.hex())
    witness_set2 = BootstrapWitnessSet.from_cbor(reader2)
    assert len(witness_set2) == len(witness_set)


def test_bootstrap_witness_set_add_adds_witness():
    witness_set = BootstrapWitnessSet()
    witness = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness_set.add(witness)
    assert len(witness_set) == 1


def test_bootstrap_witness_set_add_multiple_witnesses():
    witness_set = BootstrapWitnessSet()
    witnesses = [
        BOOTSTRAP_WITNESS1_CBOR,
        BOOTSTRAP_WITNESS2_CBOR,
        BOOTSTRAP_WITNESS3_CBOR,
        BOOTSTRAP_WITNESS4_CBOR,
    ]
    for cbor in witnesses:
        witness = create_default_bootstrap_witness(cbor)
        witness_set.add(witness)
    assert len(witness_set) == 4


def test_bootstrap_witness_set_get_retrieves_witness():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    witness = witness_set.get(0)
    assert witness is not None


def test_bootstrap_witness_set_get_retrieves_all_witnesses():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    for i in range(4):
        witness = witness_set.get(i)
        assert witness is not None


def test_bootstrap_witness_set_get_with_invalid_index_raises_error():
    witness_set = BootstrapWitnessSet()
    with pytest.raises(IndexError):
        witness_set.get(0)


def test_bootstrap_witness_set_get_with_negative_index_raises_error():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    with pytest.raises(IndexError):
        witness_set.get(-1)


def test_bootstrap_witness_set_get_with_out_of_bounds_index_raises_error():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    with pytest.raises(IndexError):
        witness_set.get(10)


def test_bootstrap_witness_set_use_tag_property_get():
    witness_set = BootstrapWitnessSet()
    assert isinstance(witness_set.use_tag, bool)


def test_bootstrap_witness_set_use_tag_property_set():
    witness_set = BootstrapWitnessSet()
    witness_set.use_tag = True
    assert witness_set.use_tag is True
    witness_set.use_tag = False
    assert witness_set.use_tag is False


def test_bootstrap_witness_set_use_tag_affects_serialization():
    witness_set = BootstrapWitnessSet()
    witness = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness_set.add(witness)

    witness_set.use_tag = True
    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded_with_tag = writer.encode().hex()
    assert encoded_with_tag.startswith("d90102")

    witness_set.use_tag = False
    writer2 = CborWriter()
    witness_set.to_cbor(writer2)
    encoded_without_tag = writer2.encode().hex()
    assert not encoded_without_tag.startswith("d90102")


def test_bootstrap_witness_set_len_returns_correct_count():
    witness_set = BootstrapWitnessSet()
    assert len(witness_set) == 0

    witness = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness_set.add(witness)
    assert len(witness_set) == 1


def test_bootstrap_witness_set_len_with_multiple_witnesses():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    assert len(witness_set) == 4


def test_bootstrap_witness_set_iter_iterates_over_witnesses():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    count = 0
    for witness in witness_set:
        assert witness is not None
        count += 1
    assert count == 4


def test_bootstrap_witness_set_iter_empty_set():
    witness_set = BootstrapWitnessSet()
    count = 0
    for _ in witness_set:
        count += 1
    assert count == 0


def test_bootstrap_witness_set_getitem_retrieves_witness():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    witness = witness_set[0]
    assert witness is not None


def test_bootstrap_witness_set_getitem_with_invalid_index_raises_error():
    witness_set = BootstrapWitnessSet()
    with pytest.raises(IndexError):
        _ = witness_set[0]


def test_bootstrap_witness_set_bool_returns_true_for_non_empty():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    assert bool(witness_set) is True


def test_bootstrap_witness_set_bool_returns_false_for_empty():
    witness_set = BootstrapWitnessSet()
    assert bool(witness_set) is False


def test_bootstrap_witness_set_repr():
    witness_set = BootstrapWitnessSet()
    repr_str = repr(witness_set)
    assert "BootstrapWitnessSet" in repr_str
    assert "len=0" in repr_str


def test_bootstrap_witness_set_repr_with_witnesses():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)
    repr_str = repr(witness_set)
    assert "BootstrapWitnessSet" in repr_str
    assert "len=4" in repr_str


def test_bootstrap_witness_set_to_cip116_json_serializes_correctly():
    witness_set = BootstrapWitnessSet()
    witnesses = [
        BOOTSTRAP_WITNESS1_CBOR,
        BOOTSTRAP_WITNESS2_CBOR,
        BOOTSTRAP_WITNESS3_CBOR,
        BOOTSTRAP_WITNESS4_CBOR,
    ]
    for cbor in witnesses:
        witness = create_default_bootstrap_witness(cbor)
        witness_set.add(witness)

    writer = JsonWriter(JsonFormat.COMPACT)
    witness_set.to_cip116_json(writer)
    json_str = writer.encode()

    expected = '[{"attributes":"a0","chain_code":"0000000000000000000000000000000000000000000000000000000000000000","signature":"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a","vkey":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"},{"attributes":"a0","chain_code":"0000000000000000000000000000000000000000000000000000000000000000","signature":"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a","vkey":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"},{"attributes":"a0","chain_code":"0000000000000000000000000000000000000000000000000000000000000000","signature":"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a","vkey":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"},{"attributes":"a0","chain_code":"0000000000000000000000000000000000000000000000000000000000000000","signature":"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a","vkey":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"}]'
    assert json_str == expected


def test_bootstrap_witness_set_to_cip116_json_empty_set():
    witness_set = BootstrapWitnessSet()
    writer = JsonWriter(JsonFormat.COMPACT)
    witness_set.to_cip116_json(writer)
    json_str = writer.encode()
    assert json_str == "[]"


def test_bootstrap_witness_set_to_cip116_json_with_invalid_writer_raises_error():
    witness_set = BootstrapWitnessSet()
    with pytest.raises(TypeError):
        witness_set.to_cip116_json("not a writer")


def test_bootstrap_witness_set_contains_returns_true_for_existing_witness():
    witness_set = BootstrapWitnessSet()
    witness = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness_set.add(witness)

    found = False
    for w in witness_set:
        if w.vkey == witness.vkey and w.signature == witness.signature:
            found = True
            break
    assert found


def test_bootstrap_witness_set_contains_returns_false_for_non_existing_witness():
    witness_set = BootstrapWitnessSet()
    witness = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)

    assert witness not in witness_set


def test_bootstrap_witness_set_isdisjoint_returns_true_for_disjoint_sets():
    witness_set1 = BootstrapWitnessSet()
    witness_set2 = BootstrapWitnessSet()

    assert witness_set1.isdisjoint(witness_set2)


def test_bootstrap_witness_set_isdisjoint_returns_true_for_different_witnesses():
    witness1 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness2 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS2_CBOR)

    witness_set1 = BootstrapWitnessSet()
    witness_set1.add(witness1)

    witness_set2 = BootstrapWitnessSet()
    witness_set2.add(witness2)

    assert witness_set1.isdisjoint(witness_set2) is True


def test_bootstrap_witness_set_context_manager():
    with BootstrapWitnessSet() as witness_set:
        assert witness_set is not None
        assert len(witness_set) == 0


def test_bootstrap_witness_set_serialization_roundtrip():
    witness_set = BootstrapWitnessSet()
    witnesses = [
        BOOTSTRAP_WITNESS1_CBOR,
        BOOTSTRAP_WITNESS2_CBOR,
        BOOTSTRAP_WITNESS3_CBOR,
        BOOTSTRAP_WITNESS4_CBOR,
    ]
    for cbor in witnesses:
        witness = create_default_bootstrap_witness(cbor)
        witness_set.add(witness)

    writer = CborWriter()
    witness_set.to_cbor(writer)
    encoded = writer.encode()

    reader = CborReader.from_hex(encoded.hex())
    witness_set2 = BootstrapWitnessSet.from_cbor(reader)

    assert len(witness_set2) == len(witness_set)


def test_bootstrap_witness_set_add_witnesses_in_sequence():
    witness_set = BootstrapWitnessSet()
    assert len(witness_set) == 0

    witness1 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR)
    witness_set.add(witness1)
    assert len(witness_set) == 1

    witness2 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS2_CBOR)
    witness_set.add(witness2)
    assert len(witness_set) == 2

    witness3 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS3_CBOR)
    witness_set.add(witness3)
    assert len(witness_set) == 3

    witness4 = create_default_bootstrap_witness(BOOTSTRAP_WITNESS4_CBOR)
    witness_set.add(witness4)
    assert len(witness_set) == 4


def test_bootstrap_witness_set_get_each_witness():
    reader = CborReader.from_hex(CBOR)
    witness_set = BootstrapWitnessSet.from_cbor(reader)

    witnesses = [
        BOOTSTRAP_WITNESS1_CBOR,
        BOOTSTRAP_WITNESS2_CBOR,
        BOOTSTRAP_WITNESS3_CBOR,
        BOOTSTRAP_WITNESS4_CBOR,
    ]

    for i in range(4):
        witness = witness_set.get(i)
        writer = CborWriter()
        witness.to_cbor(writer)
        encoded = writer.encode().hex()
        assert encoded == witnesses[i]


def test_bootstrap_witness_set_iteration_order():
    witness_set = BootstrapWitnessSet()
    witnesses = [
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS2_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS3_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS4_CBOR),
    ]

    for witness in witnesses:
        witness_set.add(witness)

    iterated_witnesses = list(witness_set)
    assert len(iterated_witnesses) == 4


def test_bootstrap_witness_set_from_list_maintains_count():
    witnesses = [
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS1_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS2_CBOR),
        create_default_bootstrap_witness(BOOTSTRAP_WITNESS3_CBOR),
    ]
    witness_set = BootstrapWitnessSet.from_list(witnesses)
    assert len(witness_set) == 3


def test_bootstrap_witness_set_empty_iteration():
    witness_set = BootstrapWitnessSet()
    witnesses = list(witness_set)
    assert len(witnesses) == 0
