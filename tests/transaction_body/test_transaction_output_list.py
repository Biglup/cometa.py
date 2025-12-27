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
    TransactionOutputList,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "84a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a02820058200000000000000000000000000000000000000000000000000000000000000000a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ffa2005826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51b8cd9819561bddc6614011a02faf080"
CBOR_EMPTY = "80"
TRANSACTION_OUTPUT1_CBOR = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"
TRANSACTION_OUTPUT2_CBOR = "83583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a58200000000000000000000000000000000000000000000000000000000000000000"
TRANSACTION_OUTPUT3_CBOR = "a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff"
TRANSACTION_OUTPUT4_CBOR = "825826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51bbcd9819561bddc66141a02faf080"

TRANSACTION_OUTPUT_CBORS = [
    TRANSACTION_OUTPUT1_CBOR,
    TRANSACTION_OUTPUT2_CBOR,
    TRANSACTION_OUTPUT3_CBOR,
    TRANSACTION_OUTPUT4_CBOR,
]


def create_transaction_output_from_cbor(cbor_hex: str) -> TransactionOutput:
    """Helper function to create TransactionOutput from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return TransactionOutput.from_cbor(reader)


class TestTransactionOutputListInit:
    """Tests for TransactionOutputList initialization."""

    def test_new_creates_empty_list(self):
        """Test creating an empty transaction output list."""
        output_list = TransactionOutputList()

        assert output_list is not None
        assert len(output_list) == 0
        assert not bool(output_list)

    def test_new_with_null_ptr_raises_error(self):
        """Test that creating list with NULL pointer raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            TransactionOutputList(ffi.NULL)


class TestTransactionOutputListFromCbor:
    """Tests for TransactionOutputList CBOR deserialization."""

    def test_from_cbor_deserializes_list(self):
        """Test deserializing a transaction output list from CBOR."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        assert output_list is not None
        assert len(output_list) == 4

    def test_from_cbor_deserializes_empty_list(self):
        """Test deserializing an empty transaction output list from CBOR."""
        reader = CborReader.from_hex(CBOR_EMPTY)
        output_list = TransactionOutputList.from_cbor(reader)

        assert output_list is not None
        assert len(output_list) == 0

    def test_from_cbor_preserves_output_order(self):
        """Test that CBOR deserialization preserves output order."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        assert len(output_list) == 4

        for i in range(4):
            output = output_list[i]
            assert output is not None

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that from_cbor with null reader raises error."""
        with pytest.raises(AttributeError):
            TransactionOutputList.from_cbor(None)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that from_cbor with invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            TransactionOutputList.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test that from_cbor with non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TransactionOutputList.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test that from_cbor with invalid elements raises error."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            TransactionOutputList.from_cbor(reader)


class TestTransactionOutputListToCbor:
    """Tests for TransactionOutputList CBOR serialization."""

    def test_to_cbor_serializes_empty_list(self):
        """Test serializing an empty transaction output list to CBOR."""
        output_list = TransactionOutputList()
        writer = CborWriter()

        output_list.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR_EMPTY

    def test_to_cbor_serializes_list(self):
        """Test serializing a transaction output list to CBOR."""
        output_list = TransactionOutputList()

        for cbor_hex in TRANSACTION_OUTPUT_CBORS:
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)

        writer = CborWriter()
        output_list.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_to_cbor_roundtrip(self):
        """Test that CBOR serialization roundtrips correctly."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        writer = CborWriter()
        output_list.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that to_cbor with null writer raises error."""
        output_list = TransactionOutputList()
        with pytest.raises(AttributeError):
            output_list.to_cbor(None)


class TestTransactionOutputListAdd:
    """Tests for TransactionOutputList add method."""

    def test_add_adds_output(self):
        """Test adding an output to the list."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)

        output_list.add(output)

        assert len(output_list) == 1

    def test_add_multiple_outputs(self):
        """Test adding multiple outputs to the list."""
        output_list = TransactionOutputList()

        for cbor_hex in TRANSACTION_OUTPUT_CBORS:
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)

        assert len(output_list) == 4

    def test_add_with_null_output_raises_error(self):
        """Test that add with null output raises error."""
        output_list = TransactionOutputList()
        with pytest.raises(AttributeError):
            output_list.add(None)


class TestTransactionOutputListGet:
    """Tests for TransactionOutputList get method."""

    def test_get_retrieves_output(self):
        """Test retrieving an output from the list."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        output = output_list.get(0)

        assert output is not None

    def test_get_retrieves_correct_output(self):
        """Test that get retrieves the correct output."""
        output_list = TransactionOutputList()

        for cbor_hex in TRANSACTION_OUTPUT_CBORS:
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)

        for i in range(4):
            output = output_list.get(i)
            assert output is not None

    def test_get_with_negative_index_raises_error(self):
        """Test that get with negative index raises error."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output_list.add(output)

        with pytest.raises(IndexError):
            output_list.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self):
        """Test that get with out of bounds index raises error."""
        output_list = TransactionOutputList()

        with pytest.raises(IndexError):
            output_list.get(0)


class TestTransactionOutputListLen:
    """Tests for TransactionOutputList length."""

    def test_len_returns_zero_for_empty_list(self):
        """Test that len returns 0 for empty list."""
        output_list = TransactionOutputList()

        assert len(output_list) == 0

    def test_len_returns_correct_length(self):
        """Test that len returns correct length."""
        output_list = TransactionOutputList()

        for i, cbor_hex in enumerate(TRANSACTION_OUTPUT_CBORS):
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)
            assert len(output_list) == i + 1


class TestTransactionOutputListFromList:
    """Tests for TransactionOutputList.from_list factory method."""

    def test_from_list_creates_list_from_iterable(self):
        """Test creating a list from an iterable of outputs."""
        outputs = [create_transaction_output_from_cbor(cbor) for cbor in TRANSACTION_OUTPUT_CBORS]
        output_list = TransactionOutputList.from_list(outputs)

        assert len(output_list) == 4

    def test_from_list_with_empty_iterable(self):
        """Test creating a list from an empty iterable."""
        output_list = TransactionOutputList.from_list([])

        assert len(output_list) == 0

    def test_from_list_preserves_order(self):
        """Test that from_list preserves output order."""
        outputs = [create_transaction_output_from_cbor(cbor) for cbor in TRANSACTION_OUTPUT_CBORS]
        output_list = TransactionOutputList.from_list(outputs)

        for i in range(4):
            output = output_list[i]
            assert output is not None


class TestTransactionOutputListIterator:
    """Tests for TransactionOutputList iteration."""

    def test_iter_iterates_over_all_outputs(self):
        """Test iterating over all outputs in the list."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        count = 0
        for output in output_list:
            assert output is not None
            count += 1

        assert count == 4

    def test_iter_on_empty_list(self):
        """Test iterating over an empty list."""
        output_list = TransactionOutputList()

        count = 0
        for _ in output_list:
            count += 1

        assert count == 0


class TestTransactionOutputListGetItem:
    """Tests for TransactionOutputList bracket notation access."""

    def test_getitem_retrieves_output(self):
        """Test retrieving an output using bracket notation."""
        reader = CborReader.from_hex(CBOR)
        output_list = TransactionOutputList.from_cbor(reader)

        output = output_list[0]

        assert output is not None

    def test_getitem_with_out_of_bounds_raises_error(self):
        """Test that bracket notation with out of bounds raises error."""
        output_list = TransactionOutputList()

        with pytest.raises(IndexError):
            _ = output_list[0]


class TestTransactionOutputListBool:
    """Tests for TransactionOutputList boolean conversion."""

    def test_bool_returns_false_for_empty_list(self):
        """Test that bool returns False for empty list."""
        output_list = TransactionOutputList()

        assert not bool(output_list)

    def test_bool_returns_true_for_non_empty_list(self):
        """Test that bool returns True for non-empty list."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output_list.add(output)

        assert bool(output_list)


class TestTransactionOutputListRepr:
    """Tests for TransactionOutputList string representation."""

    def test_repr_shows_length(self):
        """Test that repr shows the length of the list."""
        output_list = TransactionOutputList()

        assert "len=0" in repr(output_list)

    def test_repr_with_non_empty_list(self):
        """Test repr with non-empty list."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output_list.add(output)

        assert "len=1" in repr(output_list)


class TestTransactionOutputListContextManager:
    """Tests for TransactionOutputList context manager protocol."""

    def test_context_manager_enter_exit(self):
        """Test using TransactionOutputList as context manager."""
        with TransactionOutputList() as output_list:
            assert output_list is not None
            assert len(output_list) == 0


class TestTransactionOutputListSequenceMethods:
    """Tests for TransactionOutputList sequence methods."""

    def test_index_finds_output(self):
        """Test that index finds an output in the list."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output_list.add(output)

        index = output_list.index(output)

        assert index == 0

    def test_index_with_start_parameter(self):
        """Test index with start parameter."""
        output_list = TransactionOutputList()
        outputs = [create_transaction_output_from_cbor(cbor) for cbor in TRANSACTION_OUTPUT_CBORS]

        for output in outputs:
            output_list.add(output)

        with pytest.raises(ValueError):
            output_list.index(outputs[0], start=1)

    def test_index_with_stop_parameter(self):
        """Test index with stop parameter."""
        output_list = TransactionOutputList()
        outputs = [create_transaction_output_from_cbor(cbor) for cbor in TRANSACTION_OUTPUT_CBORS]

        for output in outputs:
            output_list.add(output)

        with pytest.raises(ValueError):
            output_list.index(outputs[2], stop=2)

    def test_index_raises_error_when_not_found(self):
        """Test that index raises ValueError when output not found."""
        output_list = TransactionOutputList()
        output1 = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output2 = create_transaction_output_from_cbor(TRANSACTION_OUTPUT2_CBOR)
        output_list.add(output1)

        with pytest.raises(ValueError):
            output_list.index(output2)

    def test_count_counts_occurrences(self):
        """Test that count returns the number of occurrences."""
        output_list = TransactionOutputList()
        output = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output_list.add(output)
        output_list.add(output)

        count = output_list.count(output)

        assert count == 2

    def test_count_returns_zero_when_not_found(self):
        """Test that count returns 0 when output not found."""
        output_list = TransactionOutputList()
        output1 = create_transaction_output_from_cbor(TRANSACTION_OUTPUT1_CBOR)
        output2 = create_transaction_output_from_cbor(TRANSACTION_OUTPUT2_CBOR)
        output_list.add(output1)

        count = output_list.count(output2)

        assert count == 0

    def test_reversed_iterates_in_reverse_order(self):
        """Test that reversed iterates in reverse order."""
        output_list = TransactionOutputList()

        for cbor_hex in TRANSACTION_OUTPUT_CBORS:
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)

        reverse_list = list(reversed(output_list))

        assert len(reverse_list) == 4


class TestTransactionOutputListToCip116Json:
    """Tests for TransactionOutputList CIP-116 JSON serialization."""

    def test_to_cip116_json_serializes_list(self):
        """Test serializing a transaction output list to CIP-116 JSON."""
        output_list = TransactionOutputList()

        for cbor_hex in TRANSACTION_OUTPUT_CBORS:
            output = create_transaction_output_from_cbor(cbor_hex)
            output_list.add(output)

        writer = JsonWriter(JsonFormat.COMPACT)
        output_list.to_cip116_json(writer)
        result = writer.encode()

        assert result.startswith("[")
        assert result.endswith("]")
        assert len(result) > 0

    def test_to_cip116_json_serializes_empty_list(self):
        """Test serializing an empty list to CIP-116 JSON."""
        output_list = TransactionOutputList()
        writer = JsonWriter(JsonFormat.COMPACT)

        output_list.to_cip116_json(writer)
        result = writer.encode()

        assert result == "[]"

    def test_to_cip116_json_with_null_writer_raises_error(self):
        """Test that to_cip116_json with null writer raises error."""
        output_list = TransactionOutputList()

        with pytest.raises(TypeError, match="JsonWriter"):
            output_list.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_type_raises_error(self):
        """Test that to_cip116_json with invalid writer type raises error."""
        output_list = TransactionOutputList()

        with pytest.raises(TypeError, match="JsonWriter"):
            output_list.to_cip116_json("not a writer")
