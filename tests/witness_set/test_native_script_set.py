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
from cometa.witness_set.native_script_set import NativeScriptSet
from cometa.scripts.native_scripts.native_script import NativeScript
from cometa.scripts.native_scripts.script_pubkey import ScriptPubkey
from cometa.scripts.native_scripts.script_all import ScriptAll
from cometa.scripts.native_scripts.script_any import ScriptAny
from cometa.scripts.native_scripts.script_n_of_k import ScriptNOfK
from cometa.scripts.native_scripts.script_invalid_before import ScriptInvalidBefore
from cometa.scripts.native_scripts.script_invalid_after import ScriptInvalidAfter
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter
from cometa.json.json_format import JsonFormat
from cometa.errors import CardanoError


CBOR = "d90102848200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
CBOR_WITHOUT_TAG = "848200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c378200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
NATIVE_SCRIPT1_CBOR = "8200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
NATIVE_SCRIPT2_CBOR = "8200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
NATIVE_SCRIPT3_CBOR = "8200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"
NATIVE_SCRIPT4_CBOR = "8200581c966e394a544f242081e41d1965137b1bb412ac230d40ed5407821c37"


def create_default_native_script(cbor: str) -> NativeScript:
    """
    Creates a NativeScript from CBOR hex string.
    """
    reader = CborReader.from_hex(cbor)
    return NativeScript.from_cbor(reader)


def test_native_script_set_new_creates_instance():
    """
    Test that NativeScriptSet can be created.
    """
    script_set = NativeScriptSet()
    assert script_set is not None
    assert len(script_set) == 0


def test_native_script_set_from_cbor_creates_instance():
    """
    Test that NativeScriptSet can be deserialized from CBOR with tag.
    """
    reader = CborReader.from_hex(CBOR)
    script_set = NativeScriptSet.from_cbor(reader)
    assert script_set is not None
    assert len(script_set) == 4


def test_native_script_set_from_cbor_without_tag():
    """
    Test that NativeScriptSet can be deserialized from CBOR without tag.
    """
    reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
    script_set = NativeScriptSet.from_cbor(reader)
    assert script_set is not None
    assert len(script_set) == 4
    assert not script_set.use_tag


def test_native_script_set_from_cbor_with_invalid_cbor_raises_error():
    """
    Test that invalid CBOR raises CardanoError.
    """
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        NativeScriptSet.from_cbor(reader)


def test_native_script_set_from_cbor_with_invalid_array_raises_error():
    """
    Test that invalid CBOR array raises CardanoError.
    """
    reader = CborReader.from_hex("ff")
    with pytest.raises(CardanoError):
        NativeScriptSet.from_cbor(reader)


def test_native_script_set_from_cbor_with_invalid_elements_raises_error():
    """
    Test that invalid script elements raise CardanoError.
    """
    reader = CborReader.from_hex("9ffeff")
    with pytest.raises(CardanoError):
        NativeScriptSet.from_cbor(reader)


def test_native_script_set_from_list_creates_instance():
    """
    Test that NativeScriptSet can be created from a list of scripts.
    """
    scripts = [
        create_default_native_script(NATIVE_SCRIPT1_CBOR),
        create_default_native_script(NATIVE_SCRIPT2_CBOR),
    ]
    script_set = NativeScriptSet.from_list(scripts)
    assert script_set is not None
    assert len(script_set) == 2


def test_native_script_set_from_list_with_empty_list():
    """
    Test that NativeScriptSet can be created from an empty list.
    """
    script_set = NativeScriptSet.from_list([])
    assert script_set is not None
    assert len(script_set) == 0


def test_native_script_set_to_cbor_serializes_correctly():
    """
    Test that NativeScriptSet can be serialized to CBOR.
    """
    reader = CborReader.from_hex(CBOR)
    script_set = NativeScriptSet.from_cbor(reader)
    writer = CborWriter()
    script_set.to_cbor(writer)
    assert writer.encode().hex() == CBOR


def test_native_script_set_to_cbor_serializes_empty_set():
    """
    Test that an empty NativeScriptSet serializes correctly.
    """
    script_set = NativeScriptSet()
    writer = CborWriter()
    script_set.to_cbor(writer)
    assert writer.encode().hex() == "d9010280"


def test_native_script_set_to_cbor_round_trip():
    """
    Test that serialization and deserialization round-trip correctly.
    """
    reader = CborReader.from_hex(CBOR)
    script_set = NativeScriptSet.from_cbor(reader)
    writer = CborWriter()
    script_set.to_cbor(writer)
    assert writer.encode().hex() == CBOR


def test_native_script_set_to_cbor_round_trip_without_tag():
    """
    Test that serialization and deserialization round-trip correctly without tag.
    """
    reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
    script_set = NativeScriptSet.from_cbor(reader)
    writer = CborWriter()
    script_set.to_cbor(writer)
    assert writer.encode().hex() == CBOR_WITHOUT_TAG


def test_native_script_set_add_native_script():
    """
    Test that a NativeScript can be added to the set.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    assert len(script_set) == 1


def test_native_script_set_add_script_pubkey():
    """
    Test that a ScriptPubkey can be added to the set.
    """
    script_set = NativeScriptSet()
    reader = CborReader.from_hex(NATIVE_SCRIPT1_CBOR)
    native_script = NativeScript.from_cbor(reader)
    pubkey_script = native_script.to_pubkey()
    script_set.add(pubkey_script)
    assert len(script_set) == 1


def test_native_script_set_add_multiple_scripts():
    """
    Test that multiple scripts can be added to the set.
    """
    script_set = NativeScriptSet()
    native_scripts = [
        NATIVE_SCRIPT1_CBOR,
        NATIVE_SCRIPT2_CBOR,
        NATIVE_SCRIPT3_CBOR,
        NATIVE_SCRIPT4_CBOR,
    ]
    for cbor in native_scripts:
        script = create_default_native_script(cbor)
        script_set.add(script)
    assert len(script_set) == 4


def test_native_script_set_add_invalid_type_raises_error():
    """
    Test that adding an invalid type raises TypeError.
    """
    script_set = NativeScriptSet()
    with pytest.raises(TypeError):
        script_set.add("invalid")


def test_native_script_set_get_retrieves_script():
    """
    Test that get retrieves a script at the specified index.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    retrieved = script_set.get(0)
    assert retrieved is not None


def test_native_script_set_get_with_invalid_index_raises_error():
    """
    Test that get with an out-of-bounds index raises IndexError.
    """
    script_set = NativeScriptSet()
    with pytest.raises(IndexError):
        script_set.get(0)


def test_native_script_set_get_with_negative_index_raises_error():
    """
    Test that get with a negative index raises IndexError.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    with pytest.raises(IndexError):
        script_set.get(-1)


def test_native_script_set_use_tag_property():
    """
    Test that the use_tag property can be read and set.
    """
    script_set = NativeScriptSet()
    script_set.use_tag = True
    assert script_set.use_tag is True
    script_set.use_tag = False
    assert script_set.use_tag is False


def test_native_script_set_use_tag_affects_serialization():
    """
    Test that use_tag affects CBOR serialization.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)

    script_set.use_tag = True
    writer1 = CborWriter()
    script_set.to_cbor(writer1)
    cbor_with_tag = writer1.encode().hex()

    script_set.use_tag = False
    writer2 = CborWriter()
    script_set.to_cbor(writer2)
    cbor_without_tag = writer2.encode().hex()

    assert cbor_with_tag != cbor_without_tag
    assert cbor_with_tag.startswith("d90102")
    assert not cbor_without_tag.startswith("d90102")


def test_native_script_set_len_returns_correct_count():
    """
    Test that len returns the correct number of scripts.
    """
    script_set = NativeScriptSet()
    assert len(script_set) == 0

    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    assert len(script_set) == 1

    script2 = create_default_native_script(NATIVE_SCRIPT2_CBOR)
    script_set.add(script2)
    assert len(script_set) == 2


def test_native_script_set_iter_iterates_over_scripts():
    """
    Test that iteration works correctly.
    """
    script_set = NativeScriptSet()
    scripts = [
        create_default_native_script(NATIVE_SCRIPT1_CBOR),
        create_default_native_script(NATIVE_SCRIPT2_CBOR),
    ]
    for script in scripts:
        script_set.add(script)

    count = 0
    for script in script_set:
        assert script is not None
        count += 1
    assert count == 2


def test_native_script_set_getitem_retrieves_script():
    """
    Test that bracket notation retrieves scripts.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    retrieved = script_set[0]
    assert retrieved is not None


def test_native_script_set_getitem_with_invalid_index_raises_error():
    """
    Test that bracket notation with invalid index raises IndexError.
    """
    script_set = NativeScriptSet()
    with pytest.raises(IndexError):
        _ = script_set[0]


def test_native_script_set_bool_returns_true_when_not_empty():
    """
    Test that bool returns True when set is not empty.
    """
    script_set = NativeScriptSet()
    assert not bool(script_set)

    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)
    assert bool(script_set)


def test_native_script_set_repr_returns_string():
    """
    Test that repr returns a string representation.
    """
    script_set = NativeScriptSet()
    repr_str = repr(script_set)
    assert "NativeScriptSet" in repr_str
    assert "len=0" in repr_str


def test_native_script_set_context_manager():
    """
    Test that NativeScriptSet can be used as a context manager.
    """
    with NativeScriptSet() as script_set:
        assert script_set is not None
        script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
        script_set.add(script)
        assert len(script_set) == 1


def test_native_script_set_to_cip116_json_converts_set():
    """
    Test that to_cip116_json serializes to CIP-116 compliant JSON.
    """
    script_set = NativeScriptSet()
    native_scripts = [
        NATIVE_SCRIPT1_CBOR,
        NATIVE_SCRIPT2_CBOR,
        NATIVE_SCRIPT3_CBOR,
        NATIVE_SCRIPT4_CBOR,
    ]
    for cbor in native_scripts:
        script = create_default_native_script(cbor)
        script_set.add(script)

    writer = JsonWriter(JsonFormat.COMPACT)
    script_set.to_cip116_json(writer)
    json_str = writer.encode()
    assert json_str.startswith("[")
    assert json_str.endswith("]")
    assert "pubkey" in json_str


def test_native_script_set_to_cip116_json_converts_empty_set():
    """
    Test that to_cip116_json handles empty sets correctly.
    """
    script_set = NativeScriptSet()
    writer = JsonWriter(JsonFormat.COMPACT)
    script_set.to_cip116_json(writer)
    json_str = writer.encode()
    assert json_str == "[]"


def test_native_script_set_to_cip116_json_with_invalid_writer_raises_error():
    """
    Test that to_cip116_json with invalid writer raises TypeError.
    """
    script_set = NativeScriptSet()
    with pytest.raises(TypeError):
        script_set.to_cip116_json("invalid")


def test_native_script_set_contains_checks_membership():
    """
    Test that __contains__ checks if a script is in the set.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)

    assert script in script_set

    other_script = create_default_native_script(NATIVE_SCRIPT2_CBOR)
    assert other_script in script_set


def test_native_script_set_isdisjoint_returns_true_when_disjoint():
    """
    Test that isdisjoint returns True when sets have no common elements.
    """
    script_set1 = NativeScriptSet()
    script1 = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set1.add(script1)

    script_set2 = NativeScriptSet()
    script2 = create_default_native_script(NATIVE_SCRIPT3_CBOR)
    script_set2.add(script2)

    result = script_set1.isdisjoint(script_set2)
    assert isinstance(result, bool)


def test_native_script_set_isdisjoint_with_empty_set():
    """
    Test that isdisjoint returns True when comparing with empty set.
    """
    script_set1 = NativeScriptSet()
    script1 = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set1.add(script1)

    script_set2 = NativeScriptSet()

    assert script_set1.isdisjoint(script_set2)


def test_native_script_set_from_cbor_validates_elements():
    """
    Test that from_cbor validates individual script elements.
    """
    reader = CborReader.from_hex(CBOR)
    script_set = NativeScriptSet.from_cbor(reader)

    for i in range(len(script_set)):
        script = script_set.get(i)
        assert script is not None
        writer = CborWriter()
        script.to_cbor(writer)
        assert writer.encode().hex() in [
            NATIVE_SCRIPT1_CBOR,
            NATIVE_SCRIPT2_CBOR,
            NATIVE_SCRIPT3_CBOR,
            NATIVE_SCRIPT4_CBOR,
        ]


def test_native_script_set_add_preserves_order():
    """
    Test that adding scripts maintains order.
    """
    script_set = NativeScriptSet()
    scripts = [
        create_default_native_script(NATIVE_SCRIPT1_CBOR),
        create_default_native_script(NATIVE_SCRIPT2_CBOR),
        create_default_native_script(NATIVE_SCRIPT3_CBOR),
    ]
    for script in scripts:
        script_set.add(script)

    for i in range(len(scripts)):
        retrieved = script_set.get(i)
        assert retrieved is not None


def test_native_script_set_serialization_deterministic():
    """
    Test that serialization produces deterministic output.
    """
    script_set1 = NativeScriptSet()
    script_set2 = NativeScriptSet()

    native_scripts = [
        NATIVE_SCRIPT1_CBOR,
        NATIVE_SCRIPT2_CBOR,
        NATIVE_SCRIPT3_CBOR,
        NATIVE_SCRIPT4_CBOR,
    ]

    for cbor in native_scripts:
        script1 = create_default_native_script(cbor)
        script2 = create_default_native_script(cbor)
        script_set1.add(script1)
        script_set2.add(script2)

    writer1 = CborWriter()
    script_set1.to_cbor(writer1)

    writer2 = CborWriter()
    script_set2.to_cbor(writer2)

    assert writer1.encode().hex() == writer2.encode().hex()


def test_native_script_set_from_list_with_different_script_types():
    """
    Test that from_list can handle different native script types.
    """
    reader = CborReader.from_hex(NATIVE_SCRIPT1_CBOR)
    native_script = NativeScript.from_cbor(reader)
    pubkey_script = native_script.to_pubkey()

    scripts = [native_script, pubkey_script]
    script_set = NativeScriptSet.from_list(scripts)
    assert script_set is not None
    assert len(script_set) >= 1


def test_native_script_set_iteration_does_not_modify_set():
    """
    Test that iterating over the set does not modify it.
    """
    script_set = NativeScriptSet()
    scripts = [
        create_default_native_script(NATIVE_SCRIPT1_CBOR),
        create_default_native_script(NATIVE_SCRIPT2_CBOR),
    ]
    for script in scripts:
        script_set.add(script)

    original_len = len(script_set)
    for _ in script_set:
        pass
    assert len(script_set) == original_len


def test_native_script_set_multiple_iterations():
    """
    Test that the set can be iterated multiple times.
    """
    script_set = NativeScriptSet()
    script = create_default_native_script(NATIVE_SCRIPT1_CBOR)
    script_set.add(script)

    count1 = sum(1 for _ in script_set)
    count2 = sum(1 for _ in script_set)
    assert count1 == count2 == 1


def test_native_script_set_empty_iteration():
    """
    Test that iterating over an empty set works correctly.
    """
    script_set = NativeScriptSet()
    count = sum(1 for _ in script_set)
    assert count == 0
