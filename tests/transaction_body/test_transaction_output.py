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
    TransactionOutput,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
    Address,
    Value,
    Datum,
    Script,
)


CBOR = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
CBOR_DIFFERENT_ADDRESS = "a400583900537ba48a023f0a3c66e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
CBOR_DIFFERENT_VALUE = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4340a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
CBOR_DIFFERENT_SCRIPT = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200122211"
LEGACY_OUTPUT_CBOR = "83583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a58200000000000000000000000000000000000000000000000000000000000000000"
LEGACY_OUTPUT_NO_DATUM_CBOR = "82583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
BABBAGE_INLINE_DATUM_CBOR = "a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff"
BABBAGE_DATUM_HASH_CBOR = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a0282005820000000000000000000000000000000000000000000000000000000000000000003d8185182014e4d01000033222220051200120011"
BABBAGE_REF_SCRIPT_CBOR = "a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a03d8185182014e4d01000033222220051200120011"
BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR = "82583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
MARY_OUTPUT_POINTER_CBOR = "825826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51bbcd9819561bddc66141a02faf080"
ADDRESS_IN_OUTPUTS = "addr_test1qpfhhfy2qgls50r9u4yh0l7z67xpg0a5rrhkmvzcuqrd0znuzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q9gw0lz"
VALUE_CBOR = "821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"
DATUM_CBOR = "8201d81849d8799f0102030405ff"
DATUM_HASH_CBOR = "820058200000000000000000000000000000000000000000000000000000000000000000"
SCRIPT_REF_CBOR = "82014E4D01000033222220051200120011"


def new_default_address():
    return Address.from_string(ADDRESS_IN_OUTPUTS)


def new_default_value():
    reader = CborReader.from_hex(VALUE_CBOR)
    return Value.from_cbor(reader)


def new_default_datum():
    reader = CborReader.from_hex(DATUM_CBOR)
    return Datum.from_cbor(reader)


def new_default_datum_hash():
    reader = CborReader.from_hex(DATUM_HASH_CBOR)
    return Datum.from_cbor(reader)


def new_default_script_ref():
    reader = CborReader.from_hex(SCRIPT_REF_CBOR)
    return Script.from_cbor(reader)


def new_default_output(cbor):
    reader = CborReader.from_hex(cbor)
    return TransactionOutput.from_cbor(reader)


class TestTransactionOutputNew:
    def test_new_valid(self):
        address = new_default_address()
        output = TransactionOutput.new(address, 1000000)
        assert output is not None
        assert str(output.address) == ADDRESS_IN_OUTPUTS

    def test_new_with_zero_amount(self):
        address = new_default_address()
        output = TransactionOutput.new(address, 0)
        assert output is not None

    def test_new_with_large_amount(self):
        address = new_default_address()
        large_amount = 45000000000000000
        output = TransactionOutput.new(address, large_amount)
        assert output is not None

    def test_new_none_address(self):
        with pytest.raises((CardanoError, AttributeError)):
            TransactionOutput.new(None, 1000000)


class TestTransactionOutputFromCbor:
    def test_from_cbor_valid(self):
        reader = CborReader.from_hex(CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_legacy_output(self):
        reader = CborReader.from_hex(LEGACY_OUTPUT_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_legacy_no_datum(self):
        reader = CborReader.from_hex(LEGACY_OUTPUT_NO_DATUM_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_babbage_inline_datum(self):
        reader = CborReader.from_hex(BABBAGE_INLINE_DATUM_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_babbage_datum_hash(self):
        reader = CborReader.from_hex(BABBAGE_DATUM_HASH_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_babbage_ref_script(self):
        reader = CborReader.from_hex(BABBAGE_REF_SCRIPT_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_babbage_no_optional_fields(self):
        reader = CborReader.from_hex(BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_mary_pointer_address(self):
        reader = CborReader.from_hex(MARY_OUTPUT_POINTER_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_from_cbor_invalid_not_array(self):
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_map(self):
        reader = CborReader.from_hex(
            "ef00583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_key_format(self):
        reader = CborReader.from_hex(
            "a4ef583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_address(self):
        reader = CborReader.from_hex(
            "a400ef3900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_value(self):
        reader = CborReader.from_hex(
            "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801ef1a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_datum(self):
        reader = CborReader.from_hex(
            "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a02ef01d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_invalid_key(self):
        reader = CborReader.from_hex(
            "a409583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d818ef82014e4d01000033222220051200120011"
        )
        with pytest.raises(CardanoError):
            TransactionOutput.from_cbor(reader)

    def test_from_cbor_none_reader(self):
        with pytest.raises((CardanoError, AttributeError)):
            TransactionOutput.from_cbor(None)


class TestTransactionOutputToCbor:
    def test_to_cbor_valid(self):
        output = new_default_output(CBOR)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output == CBOR.lower()

    def test_to_cbor_roundtrip(self):
        reader = CborReader.from_hex(CBOR)
        output = TransactionOutput.from_cbor(reader)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output == CBOR.lower()

    def test_to_cbor_legacy_output(self):
        output = new_default_output(LEGACY_OUTPUT_CBOR)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output is not None

    def test_to_cbor_legacy_no_datum(self):
        output = new_default_output(LEGACY_OUTPUT_NO_DATUM_CBOR)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output is not None

    def test_to_cbor_babbage_no_optional_fields(self):
        output = new_default_output(BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output is not None

    def test_to_cbor_mary_pointer_address(self):
        output = new_default_output(MARY_OUTPUT_POINTER_CBOR)
        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output is not None

    def test_to_cbor_none_writer(self):
        output = new_default_output(CBOR)
        with pytest.raises((CardanoError, AttributeError)):
            output.to_cbor(None)


class TestTransactionOutputToCip116Json:
    def test_to_cip116_json_valid(self):
        output = new_default_output(CBOR)
        writer = JsonWriter()
        output.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"address"' in json_str
        assert '"amount"' in json_str
        assert '"coin"' in json_str
        assert '"plutus_data"' in json_str
        assert '"script_ref"' in json_str

    def test_to_cip116_json_legacy_output(self):
        output = new_default_output(LEGACY_OUTPUT_CBOR)
        writer = JsonWriter()
        output.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"address"' in json_str
        assert '"amount"' in json_str
        assert '"plutus_data"' in json_str
        assert '"datum_hash"' in json_str

    def test_to_cip116_json_mary_pointer_output(self):
        output = new_default_output(MARY_OUTPUT_POINTER_CBOR)
        writer = JsonWriter()
        output.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"address"' in json_str
        assert '"amount"' in json_str
        assert '"coin":"50000000"' in json_str

    def test_to_cip116_json_none_writer(self):
        output = new_default_output(CBOR)
        with pytest.raises((CardanoError, TypeError)):
            output.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        output = new_default_output(CBOR)
        with pytest.raises(TypeError):
            output.to_cip116_json("not a writer")


class TestTransactionOutputAddressProperty:
    def test_get_address(self):
        output = new_default_output(CBOR)
        address = output.address
        assert address is not None
        assert str(address) == ADDRESS_IN_OUTPUTS

    def test_set_address(self):
        output = new_default_output(CBOR)
        new_address = new_default_address()
        output.address = new_address
        assert str(output.address) == ADDRESS_IN_OUTPUTS

    def test_set_address_none(self):
        output = new_default_output(CBOR)
        with pytest.raises((CardanoError, AttributeError)):
            output.address = None


class TestTransactionOutputValueProperty:
    def test_get_value(self):
        output = new_default_output(CBOR)
        value = output.value
        assert value is not None

    def test_set_value(self):
        output = new_default_output(CBOR)
        new_value = new_default_value()
        output.value = new_value
        assert output.value is not None

    def test_set_value_none(self):
        output = new_default_output(CBOR)
        with pytest.raises((CardanoError, AttributeError)):
            output.value = None


class TestTransactionOutputDatumProperty:
    def test_get_datum(self):
        output = new_default_output(BABBAGE_INLINE_DATUM_CBOR)
        datum = output.datum
        assert datum is not None

    def test_get_datum_none(self):
        output = new_default_output(BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR)
        datum = output.datum
        assert datum is None

    def test_set_datum(self):
        output = new_default_output(BABBAGE_INLINE_DATUM_CBOR)
        new_datum = new_default_datum()
        output.datum = new_datum
        assert output.datum is not None

    def test_set_datum_hash(self):
        output = new_default_output(BABBAGE_DATUM_HASH_CBOR)
        new_datum = new_default_datum_hash()
        output.datum = new_datum
        assert output.datum is not None

    def test_set_datum_none(self):
        output = new_default_output(BABBAGE_INLINE_DATUM_CBOR)
        output.datum = None
        assert output.datum is None


class TestTransactionOutputScriptRefProperty:
    def test_get_script_ref(self):
        output = new_default_output(BABBAGE_REF_SCRIPT_CBOR)
        script_ref = output.script_ref
        assert script_ref is not None

    def test_get_script_ref_none(self):
        output = new_default_output(BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR)
        script_ref = output.script_ref
        assert script_ref is None

    def test_set_script_ref(self):
        output = new_default_output(BABBAGE_REF_SCRIPT_CBOR)
        new_script = new_default_script_ref()
        output.script_ref = new_script
        assert output.script_ref is not None

    def test_set_script_ref_none(self):
        output = new_default_output(BABBAGE_REF_SCRIPT_CBOR)
        output.script_ref = None
        assert output.script_ref is None


class TestTransactionOutputEquality:
    def test_equals_same_values(self):
        output1 = new_default_output(CBOR)
        output2 = new_default_output(CBOR)
        assert output1 == output2

    def test_equals_different_address(self):
        output1 = new_default_output(CBOR)
        output2 = new_default_output(CBOR_DIFFERENT_ADDRESS)
        assert output1 != output2

    def test_equals_different_value(self):
        output1 = new_default_output(CBOR)
        output2 = new_default_output(CBOR_DIFFERENT_VALUE)
        assert output1 != output2

    def test_equals_different_script(self):
        output1 = new_default_output(CBOR)
        output2 = new_default_output(CBOR_DIFFERENT_SCRIPT)
        assert output1 != output2

    def test_equals_different_formats(self):
        output1 = new_default_output(CBOR)
        output2 = new_default_output(LEGACY_OUTPUT_NO_DATUM_CBOR)
        assert output1 != output2

    def test_equals_same_object(self):
        output = new_default_output(CBOR)
        assert output == output

    def test_equals_different_type(self):
        output = new_default_output(CBOR)
        assert output != "not a transaction output"
        assert output != 42
        assert output != None


class TestTransactionOutputRepr:
    def test_repr_valid(self):
        output = new_default_output(CBOR)
        repr_str = repr(output)
        assert "TransactionOutput" in repr_str
        assert "address=" in repr_str
        assert "value=" in repr_str


class TestTransactionOutputContextManager:
    def test_context_manager(self):
        address = new_default_address()
        with TransactionOutput.new(address, 1000000) as output:
            assert output is not None

    def test_context_manager_usage(self):
        address = new_default_address()
        with TransactionOutput.new(address, 1000000) as output:
            writer = CborWriter()
            output.to_cbor(writer)
            assert writer.to_hex() is not None


class TestTransactionOutputEdgeCases:
    def test_multiple_property_modifications(self):
        output = new_default_output(CBOR)
        new_address = new_default_address()
        new_value = new_default_value()
        new_datum = new_default_datum()
        new_script = new_default_script_ref()

        output.address = new_address
        output.value = new_value
        output.datum = new_datum
        output.script_ref = new_script

        assert output.address is not None
        assert output.value is not None
        assert output.datum is not None
        assert output.script_ref is not None

    def test_serialization_after_modification(self):
        reader = CborReader.from_hex(CBOR)
        output = TransactionOutput.from_cbor(reader)

        new_value = new_default_value()
        output.value = new_value

        writer = CborWriter()
        output.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output is not None

        reader2 = CborReader.from_hex(hex_output)
        output2 = TransactionOutput.from_cbor(reader2)
        assert output2.value is not None

    def test_clear_optional_fields(self):
        output = new_default_output(CBOR)
        output.datum = None
        output.script_ref = None
        assert output.datum is None
        assert output.script_ref is None

    def test_set_all_optional_fields(self):
        output = new_default_output(BABBAGE_NO_OPTIONAL_FIELD_SCRIPT_CBOR)
        assert output.datum is None
        assert output.script_ref is None

        new_datum = new_default_datum()
        new_script = new_default_script_ref()
        output.datum = new_datum
        output.script_ref = new_script

        assert output.datum is not None
        assert output.script_ref is not None
