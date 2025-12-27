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
    Utxo,
    UtxoList,
    TransactionInput,
    TransactionOutput,
    Address,
    CborReader,
    CborWriter,
)


TX_ID_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def create_test_input(index: int = 0) -> TransactionInput:
    """Helper to create a test TransactionInput."""
    return TransactionInput.from_hex(TX_ID_HASH, index)


def create_test_output(lovelace: int = 1000000) -> TransactionOutput:
    """Helper to create a test TransactionOutput."""
    address = Address.from_string(
        "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
    )
    return TransactionOutput.new(address, lovelace)


class TestUtxo:
    """Tests for the Utxo class."""

    def test_utxo_new(self):
        """Test creating a new UTXO."""
        tx_input = create_test_input(0)
        tx_output = create_test_output(2000000)

        utxo = Utxo.new(tx_input, tx_output)

        assert utxo is not None
        assert utxo.input.index == 0
        assert utxo.output.value.coin == 2000000

    def test_utxo_input_property(self):
        """Test getting the input property."""
        tx_input = create_test_input(5)
        tx_output = create_test_output()

        utxo = Utxo.new(tx_input, tx_output)

        retrieved_input = utxo.input
        assert retrieved_input.index == 5

    def test_utxo_output_property(self):
        """Test getting the output property."""
        tx_input = create_test_input()
        tx_output = create_test_output(5000000)

        utxo = Utxo.new(tx_input, tx_output)

        retrieved_output = utxo.output
        assert retrieved_output.value.coin == 5000000

    def test_utxo_set_input(self):
        """Test setting a new input."""
        tx_input = create_test_input(0)
        tx_output = create_test_output()

        utxo = Utxo.new(tx_input, tx_output)
        assert utxo.input.index == 0

        new_input = create_test_input(10)
        utxo.input = new_input
        assert utxo.input.index == 10

    def test_utxo_set_output(self):
        """Test setting a new output."""
        tx_input = create_test_input()
        tx_output = create_test_output(1000000)

        utxo = Utxo.new(tx_input, tx_output)
        assert utxo.output.value.coin == 1000000

        new_output = create_test_output(9000000)
        utxo.output = new_output
        assert utxo.output.value.coin == 9000000

    def test_utxo_equality(self):
        """Test UTXO equality comparison."""
        tx_input1 = create_test_input(0)
        tx_output1 = create_test_output(1000000)
        utxo1 = Utxo.new(tx_input1, tx_output1)

        tx_input2 = create_test_input(0)
        tx_output2 = create_test_output(1000000)
        utxo2 = Utxo.new(tx_input2, tx_output2)

        assert utxo1 == utxo2

    def test_utxo_inequality(self):
        """Test UTXO inequality comparison."""
        tx_input1 = create_test_input(0)
        tx_output1 = create_test_output(1000000)
        utxo1 = Utxo.new(tx_input1, tx_output1)

        tx_input2 = create_test_input(1)  # Different index
        tx_output2 = create_test_output(1000000)
        utxo2 = Utxo.new(tx_input2, tx_output2)

        assert utxo1 != utxo2

    def test_utxo_repr(self):
        """Test UTXO string representation."""
        tx_input = create_test_input(3)
        tx_output = create_test_output()

        utxo = Utxo.new(tx_input, tx_output)

        repr_str = repr(utxo)
        assert "Utxo" in repr_str
        assert "input" in repr_str

    def test_utxo_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip."""
        tx_input = create_test_input(7)
        tx_output = create_test_output(3000000)

        utxo = Utxo.new(tx_input, tx_output)

        # Serialize to CBOR
        writer = CborWriter()
        utxo.to_cbor(writer)
        cbor_bytes = writer.encode()

        # Deserialize from CBOR
        reader = CborReader.from_bytes(cbor_bytes)
        recovered_utxo = Utxo.from_cbor(reader)

        assert recovered_utxo.input.index == 7
        assert recovered_utxo.output.value.coin == 3000000

    def test_utxo_context_manager(self):
        """Test UTXO as context manager."""
        tx_input = create_test_input()
        tx_output = create_test_output()

        with Utxo.new(tx_input, tx_output) as utxo:
            assert utxo is not None
            assert utxo.input.index == 0

    def test_utxo_direct_init_raises(self):
        """Test that direct __init__ without ptr raises error."""
        with pytest.raises(Exception):
            Utxo()


class TestUtxoList:
    """Tests for the UtxoList class."""

    def test_utxo_list_new(self):
        """Test creating a new empty UtxoList."""
        utxo_list = UtxoList()

        assert utxo_list is not None
        assert len(utxo_list) == 0

    def test_utxo_list_add(self):
        """Test adding UTxOs to the list."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        assert len(utxo_list) == 1

        utxo_list.add(utxo2)
        assert len(utxo_list) == 2

    def test_utxo_list_get(self):
        """Test getting UTxOs by index."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        utxo_list.add(utxo2)

        retrieved1 = utxo_list.get(0)
        retrieved2 = utxo_list.get(1)

        assert retrieved1.input.index == 0
        assert retrieved2.input.index == 1

    def test_utxo_list_getitem(self):
        """Test bracket notation for getting UTxOs."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        utxo_list.add(utxo2)

        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 1

    def test_utxo_list_negative_index(self):
        """Test negative indexing."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        utxo_list.add(utxo2)

        assert utxo_list[-1].input.index == 1
        assert utxo_list[-2].input.index == 0

    def test_utxo_list_index_out_of_range(self):
        """Test that out of range index raises IndexError."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(0), create_test_output()))

        with pytest.raises(IndexError):
            utxo_list.get(5)

    def test_utxo_list_iteration(self):
        """Test iterating over UtxoList."""
        utxo_list = UtxoList()

        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output(1000000 * (i + 1)))
            utxo_list.add(utxo)

        indices = [utxo.input.index for utxo in utxo_list]
        assert indices == [0, 1, 2, 3, 4]

    def test_utxo_list_remove(self):
        """Test removing a UTxO from the list."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        utxo_list.add(utxo2)
        assert len(utxo_list) == 2

        utxo_list.remove(utxo1)
        assert len(utxo_list) == 1
        assert utxo_list[0].input.index == 1

    def test_utxo_list_clear(self):
        """Test clearing the list."""
        utxo_list = UtxoList()

        for i in range(3):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        assert len(utxo_list) == 3

        utxo_list.clear()
        assert len(utxo_list) == 0

    def test_utxo_list_clone(self):
        """Test cloning a UtxoList."""
        utxo_list = UtxoList()

        utxo1 = Utxo.new(create_test_input(0), create_test_output(1000000))
        utxo2 = Utxo.new(create_test_input(1), create_test_output(2000000))

        utxo_list.add(utxo1)
        utxo_list.add(utxo2)

        cloned = utxo_list.clone()

        assert len(cloned) == 2
        assert cloned[0].input.index == 0
        assert cloned[1].input.index == 1

    def test_utxo_list_concat(self):
        """Test concatenating two UtxoLists."""
        list1 = UtxoList()
        list1.add(Utxo.new(create_test_input(0), create_test_output()))
        list1.add(Utxo.new(create_test_input(1), create_test_output()))

        list2 = UtxoList()
        list2.add(Utxo.new(create_test_input(2), create_test_output()))
        list2.add(Utxo.new(create_test_input(3), create_test_output()))

        result = list1.concat(list2)

        assert len(result) == 4
        assert result[0].input.index == 0
        assert result[3].input.index == 3

    def test_utxo_list_add_operator(self):
        """Test + operator for concatenation."""
        list1 = UtxoList()
        list1.add(Utxo.new(create_test_input(0), create_test_output()))

        list2 = UtxoList()
        list2.add(Utxo.new(create_test_input(1), create_test_output()))

        result = list1 + list2

        assert len(result) == 2

    def test_utxo_list_add_operator_with_python_list(self):
        """Test + operator with Python list."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(0), create_test_output()))

        python_list = [
            Utxo.new(create_test_input(1), create_test_output()),
            Utxo.new(create_test_input(2), create_test_output()),
        ]

        result = utxo_list + python_list

        assert len(result) == 3

    def test_utxo_list_slice(self):
        """Test slicing a UtxoList."""
        utxo_list = UtxoList()

        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        sliced = utxo_list.slice(1, 4)

        assert len(sliced) == 3
        assert sliced[0].input.index == 1
        assert sliced[2].input.index == 3

    def test_utxo_list_from_list(self):
        """Test creating UtxoList from Python list."""
        utxos = [
            Utxo.new(create_test_input(0), create_test_output(1000000)),
            Utxo.new(create_test_input(1), create_test_output(2000000)),
            Utxo.new(create_test_input(2), create_test_output(3000000)),
        ]

        utxo_list = UtxoList.from_list(utxos)

        assert len(utxo_list) == 3
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 1
        assert utxo_list[2].input.index == 2

    def test_utxo_list_bool_empty(self):
        """Test bool conversion for empty list."""
        utxo_list = UtxoList()
        assert not utxo_list
        assert bool(utxo_list) is False

    def test_utxo_list_bool_non_empty(self):
        """Test bool conversion for non-empty list."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(), create_test_output()))

        assert utxo_list
        assert bool(utxo_list) is True

    def test_utxo_list_repr(self):
        """Test string representation."""
        utxo_list = UtxoList()
        utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
        utxo_list.add(Utxo.new(create_test_input(1), create_test_output()))

        repr_str = repr(utxo_list)
        assert "UtxoList" in repr_str
        assert "2" in repr_str

    def test_utxo_list_context_manager(self):
        """Test UtxoList as context manager."""
        with UtxoList() as utxo_list:
            utxo_list.add(Utxo.new(create_test_input(), create_test_output()))
            assert len(utxo_list) == 1

    def test_utxo_list_erase_single(self):
        """Test erasing a single element from the list."""
        utxo_list = UtxoList()

        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        assert len(utxo_list) == 5

        # Erase element at index 2 (third element)
        removed = utxo_list.erase(2, 1)

        # Original list should now have 4 elements
        assert len(utxo_list) == 4
        # Removed list should have 1 element
        assert len(removed) == 1
        assert removed[0].input.index == 2

        # Check remaining elements
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 1
        assert utxo_list[2].input.index == 3  # Was at index 3, now at 2
        assert utxo_list[3].input.index == 4  # Was at index 4, now at 3

    def test_utxo_list_erase_multiple(self):
        """Test erasing multiple elements from the list."""
        utxo_list = UtxoList()

        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        # Erase 2 elements starting at index 1
        removed = utxo_list.erase(1, 2)

        assert len(utxo_list) == 3
        assert len(removed) == 2
        assert removed[0].input.index == 1
        assert removed[1].input.index == 2

        # Check remaining elements
        assert utxo_list[0].input.index == 0
        assert utxo_list[1].input.index == 3
        assert utxo_list[2].input.index == 4

    def test_utxo_list_erase_negative_index(self):
        """Test erasing with negative index."""
        utxo_list = UtxoList()

        for i in range(5):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        # Erase last element using negative index
        removed = utxo_list.erase(-1, 1)

        assert len(utxo_list) == 4
        assert len(removed) == 1
        assert removed[0].input.index == 4

    def test_utxo_list_erase_default_count(self):
        """Test erasing with default delete_count (should erase 1 element)."""
        utxo_list = UtxoList()

        for i in range(3):
            utxo = Utxo.new(create_test_input(i), create_test_output())
            utxo_list.add(utxo)

        removed = utxo_list.erase(1)  # Using default delete_count=1

        assert len(utxo_list) == 2
        assert len(removed) == 1
        assert removed[0].input.index == 1


class TestUtxoEdgeCases:
    """Tests for edge cases and error handling in Utxo."""

    def test_utxo_from_cbor_with_test_vector(self):
        """Test deserializing from CBOR using test vector from C tests."""
        cbor_hex = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"

        reader = CborReader.from_hex(cbor_hex)
        utxo = Utxo.from_cbor(reader)

        assert utxo is not None
        assert utxo.input is not None
        assert utxo.output is not None

    def test_utxo_to_cbor_with_test_vector(self):
        """Test serializing to CBOR matches test vector from C tests."""
        cbor_hex = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"

        reader = CborReader.from_hex(cbor_hex)
        utxo = Utxo.from_cbor(reader)

        writer = CborWriter()
        utxo.to_cbor(writer)
        encoded_hex = writer.to_hex()

        assert encoded_hex == cbor_hex

    def test_utxo_from_cbor_invalid_cbor(self):
        """Test that from_cbor fails with invalid CBOR data."""
        reader = CborReader.from_hex("01")

        with pytest.raises(Exception):
            Utxo.from_cbor(reader)

    def test_utxo_from_cbor_invalid_array(self):
        """Test that from_cbor fails when CBOR doesn't start with array."""
        reader = CborReader.from_hex("ef")

        with pytest.raises(Exception):
            Utxo.from_cbor(reader)

    def test_utxo_from_cbor_invalid_input(self):
        """Test that from_cbor fails with invalid input in CBOR."""
        with pytest.raises(Exception):
            reader = CborReader.from_hex("822ef")
            Utxo.from_cbor(reader)

    def test_utxo_from_cbor_invalid_output(self):
        """Test that from_cbor fails with invalid output in CBOR."""
        invalid_cbor = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001ef583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(Exception):
            Utxo.from_cbor(reader)

    def test_utxo_equality_with_same_object(self):
        """Test that a UTXO equals itself."""
        tx_input = create_test_input(0)
        tx_output = create_test_output(1000000)
        utxo = Utxo.new(tx_input, tx_output)

        assert utxo == utxo

    def test_utxo_equality_with_none(self):
        """Test that UTXO comparison with None returns False."""
        tx_input = create_test_input(0)
        tx_output = create_test_output(1000000)
        utxo = Utxo.new(tx_input, tx_output)

        assert utxo != None
        assert not (utxo == None)

    def test_utxo_equality_with_different_type(self):
        """Test that UTXO comparison with different type returns False."""
        tx_input = create_test_input(0)
        tx_output = create_test_output(1000000)
        utxo = Utxo.new(tx_input, tx_output)

        assert utxo != "not a utxo"
        assert utxo != 42
        assert utxo != []

    def test_utxo_equality_different_outputs(self):
        """Test UTXOs with different outputs are not equal."""
        tx_input = create_test_input(0)
        tx_output1 = create_test_output(1000000)
        tx_output2 = create_test_output(2000000)

        utxo1 = Utxo.new(tx_input, tx_output1)
        utxo2 = Utxo.new(tx_input, tx_output2)

        assert utxo1 != utxo2

    def test_utxo_set_input_invalid(self):
        """Test setting input with invalid value."""
        tx_input = create_test_input(0)
        tx_output = create_test_output()
        utxo = Utxo.new(tx_input, tx_output)

        with pytest.raises((TypeError, AttributeError)):
            utxo.input = None

    def test_utxo_set_output_invalid(self):
        """Test setting output with invalid value."""
        tx_input = create_test_input(0)
        tx_output = create_test_output()
        utxo = Utxo.new(tx_input, tx_output)

        with pytest.raises((TypeError, AttributeError)):
            utxo.output = None


class TestUtxoJsonSerialization:
    """Tests for CIP-116 JSON serialization of Utxo."""

    def test_utxo_to_cip116_json(self):
        """Test serializing UTXO to CIP-116 JSON format."""
        from cometa import JsonWriter, JsonFormat

        cbor_hex = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"

        reader = CborReader.from_hex(cbor_hex)
        utxo = Utxo.from_cbor(reader)

        writer = JsonWriter(JsonFormat.COMPACT)
        utxo.to_cip116_json(writer)
        json_str = writer.encode()

        assert "input" in json_str
        assert "output" in json_str
        assert "transaction_id" in json_str
        assert "bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e0" in json_str

    def test_utxo_to_cip116_json_with_expected_format(self):
        """Test that CIP-116 JSON output matches expected format."""
        from cometa import JsonWriter, JsonFormat

        cbor_hex = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821af0078c21a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c410a"

        reader = CborReader.from_hex(cbor_hex)
        utxo = Utxo.from_cbor(reader)

        writer = JsonWriter(JsonFormat.COMPACT)
        utxo.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"input":{"transaction_id":"bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e0","index":1},"output":{"address":"addr_test1qq585l3hyxgj3nas2v3xymd23vvartfhceme6gv98aaeg9muzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q2g7k3g","amount":{"coin":"4027026465","assets":{"1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601":{"50584c":"5"},"659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82":{"54534c41":"10"}}}}}'

        assert json_str == expected

    def test_utxo_to_cip116_json_invalid_writer(self):
        """Test that to_cip116_json fails with invalid writer."""
        tx_input = create_test_input(0)
        tx_output = create_test_output()
        utxo = Utxo.new(tx_input, tx_output)

        with pytest.raises((TypeError, AttributeError)):
            utxo.to_cip116_json(None)

    def test_utxo_to_cip116_json_wrong_writer_type(self):
        """Test that to_cip116_json fails with wrong writer type."""
        tx_input = create_test_input(0)
        tx_output = create_test_output()
        utxo = Utxo.new(tx_input, tx_output)

        with pytest.raises((TypeError, AttributeError)):
            utxo.to_cip116_json("not a writer")
