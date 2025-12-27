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
from cometa import TransactionInput, CborReader, CborWriter, JsonWriter, CardanoError


CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102005"
TX_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"
TX_ID_HASH_2 = "ff02030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"
TX_INVALID_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a0908070605040302010010"


class TestTransactionInputNew:
    def test_new_valid(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        assert tx_input is not None
        assert tx_input.transaction_id == tx_id
        assert tx_input.index == 0

    def test_new_with_non_zero_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        assert tx_input is not None
        assert tx_input.transaction_id == tx_id
        assert tx_input.index == 5

    def test_new_invalid_hash_size(self):
        invalid_hash = bytes.fromhex(TX_INVALID_ID_HASH)
        with pytest.raises(CardanoError):
            TransactionInput.new(invalid_hash, 0)

    def test_new_empty_hash(self):
        with pytest.raises(CardanoError):
            TransactionInput.new(b"", 0)

    def test_new_none_hash(self):
        with pytest.raises((CardanoError, TypeError)):
            TransactionInput.new(None, 0)


class TestTransactionInputFromHex:
    def test_from_hex_valid(self):
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        assert tx_input is not None
        assert tx_input.transaction_id.hex() == TX_ID_HASH.lower()
        assert tx_input.index == 0

    def test_from_hex_with_index(self):
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 5)
        assert tx_input is not None
        assert tx_input.index == 5

    def test_from_hex_invalid_hash(self):
        with pytest.raises(CardanoError):
            TransactionInput.from_hex(TX_INVALID_ID_HASH, 1)

    def test_from_hex_empty_string(self):
        with pytest.raises(CardanoError):
            TransactionInput.from_hex("", 0)

    def test_from_hex_invalid_hex(self):
        with pytest.raises(CardanoError):
            TransactionInput.from_hex("invalid_hex_string", 0)

    def test_from_hex_none(self):
        with pytest.raises((CardanoError, AttributeError)):
            TransactionInput.from_hex(None, 0)


class TestTransactionInputFromCbor:
    def test_from_cbor_valid(self):
        reader = CborReader.from_hex(CBOR)
        tx_input = TransactionInput.from_cbor(reader)
        assert tx_input is not None
        assert tx_input.transaction_id.hex() == TX_ID_HASH.lower()
        assert tx_input.index == 5

    def test_from_cbor_invalid_not_array(self):
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TransactionInput.from_cbor(reader)

    def test_from_cbor_invalid_array_size(self):
        reader = CborReader.from_hex("8100")
        with pytest.raises(CardanoError):
            TransactionInput.from_cbor(reader)

    def test_from_cbor_invalid_index_type(self):
        reader = CborReader.from_hex(
            "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020ef"
        )
        with pytest.raises(CardanoError):
            TransactionInput.from_cbor(reader)

    def test_from_cbor_invalid_hash(self):
        reader = CborReader.from_hex(
            "8200ef1c00000000000000000000000000000000000000000000000000000000"
        )
        with pytest.raises(CardanoError):
            TransactionInput.from_cbor(reader)

    def test_from_cbor_none_reader(self):
        with pytest.raises((CardanoError, AttributeError)):
            TransactionInput.from_cbor(None)


class TestTransactionInputToCbor:
    def test_to_cbor_valid(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        writer = CborWriter()
        tx_input.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output == CBOR.lower()

    def test_to_cbor_roundtrip(self):
        reader = CborReader.from_hex(CBOR)
        tx_input = TransactionInput.from_cbor(reader)
        writer = CborWriter()
        tx_input.to_cbor(writer)
        hex_output = writer.to_hex()
        assert hex_output == CBOR.lower()

    def test_to_cbor_none_writer(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        with pytest.raises((CardanoError, AttributeError)):
            tx_input.to_cbor(None)


class TestTransactionInputToCip116Json:
    def test_to_cip116_json_valid(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        writer = JsonWriter()
        tx_input.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"transaction_id"' in json_str
        assert TX_ID_HASH.lower() in json_str
        assert '"index"' in json_str
        assert '5' in json_str

    def test_to_cip116_json_from_cbor(self):
        reader = CborReader.from_hex(CBOR)
        tx_input = TransactionInput.from_cbor(reader)
        writer = JsonWriter()
        tx_input.to_cip116_json(writer)
        json_str = writer.encode()
        expected_json = f'{{"transaction_id":"{TX_ID_HASH.lower()}","index":5}}'
        assert json_str == expected_json

    def test_to_cip116_json_zero_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        writer = JsonWriter()
        tx_input.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"index":0' in json_str

    def test_to_cip116_json_none_writer(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        with pytest.raises((CardanoError, TypeError)):
            tx_input.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        with pytest.raises(TypeError):
            tx_input.to_cip116_json("not a writer")


class TestTransactionInputProperties:
    def test_get_transaction_id(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        assert tx_input.transaction_id == tx_id

    def test_set_transaction_id(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_id_2 = bytes.fromhex(TX_ID_HASH_2)
        tx_input = TransactionInput.new(tx_id, 0)
        tx_input.transaction_id = tx_id_2
        assert tx_input.transaction_id == tx_id_2

    def test_set_transaction_id_empty(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        with pytest.raises(CardanoError):
            tx_input.transaction_id = b""

    def test_get_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        assert tx_input.index == 5

    def test_set_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        tx_input.index = 10
        assert tx_input.index == 10

    def test_set_index_zero(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        tx_input.index = 0
        assert tx_input.index == 0

    def test_set_index_large_value(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        tx_input.index = 999999
        assert tx_input.index == 999999


class TestTransactionInputEquality:
    def test_equals_same_values(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 5)
        assert tx_input1 == tx_input2

    def test_equals_different_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 1)
        assert tx_input1 != tx_input2

    def test_equals_different_hash(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_id_2 = bytes.fromhex(TX_ID_HASH_2)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id_2, 5)
        assert tx_input1 != tx_input2

    def test_equals_same_object(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        assert tx_input == tx_input

    def test_equals_different_type(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        assert tx_input != "not a transaction input"
        assert tx_input != 42
        assert tx_input != None


class TestTransactionInputComparison:
    def test_compare_equal(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 5)
        assert not (tx_input1 < tx_input2)
        assert not (tx_input2 < tx_input1)

    def test_compare_different_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 1)
        assert tx_input2 < tx_input1
        assert not (tx_input1 < tx_input2)

    def test_compare_different_hash(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_id_2 = bytes.fromhex(TX_ID_HASH_2)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id_2, 5)
        assert tx_input1 < tx_input2

    def test_compare_invalid_type(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        with pytest.raises(TypeError):
            _ = tx_input < "not a transaction input"


class TestTransactionInputHash:
    def test_hash_same_values(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 5)
        assert hash(tx_input1) == hash(tx_input2)

    def test_hash_different_values(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 1)
        assert hash(tx_input1) != hash(tx_input2)

    def test_hash_in_set(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input1 = TransactionInput.new(tx_id, 5)
        tx_input2 = TransactionInput.new(tx_id, 5)
        tx_input3 = TransactionInput.new(tx_id, 1)
        input_set = {tx_input1, tx_input2, tx_input3}
        assert len(input_set) == 2

    def test_hash_in_dict(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        input_dict = {tx_input: "value"}
        assert input_dict[tx_input] == "value"


class TestTransactionInputRepr:
    def test_repr_valid(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        repr_str = repr(tx_input)
        assert "TransactionInput" in repr_str
        assert TX_ID_HASH.lower() in repr_str
        assert "5" in repr_str

    def test_repr_zero_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 0)
        repr_str = repr(tx_input)
        assert "index=0" in repr_str


class TestTransactionInputContextManager:
    def test_context_manager(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        with TransactionInput.new(tx_id, 5) as tx_input:
            assert tx_input is not None
            assert tx_input.index == 5

    def test_context_manager_usage(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        with TransactionInput.new(tx_id, 5) as tx_input:
            writer = CborWriter()
            tx_input.to_cbor(writer)
            assert writer.to_hex() is not None


class TestTransactionInputEdgeCases:
    def test_large_index(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        large_index = 2**32 - 1
        tx_input = TransactionInput.new(tx_id, large_index)
        assert tx_input.index == large_index

    def test_multiple_setters(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_id_2 = bytes.fromhex(TX_ID_HASH_2)
        tx_input = TransactionInput.new(tx_id, 5)
        tx_input.index = 10
        tx_input.transaction_id = tx_id_2
        tx_input.index = 15
        assert tx_input.transaction_id == tx_id_2
        assert tx_input.index == 15

    def test_serialization_after_modification(self):
        reader = CborReader.from_hex(CBOR)
        tx_input = TransactionInput.from_cbor(reader)
        original_index = tx_input.index
        tx_input.index = 10
        writer = CborWriter()
        tx_input.to_cbor(writer)
        reader2 = CborReader.from_hex(writer.to_hex())
        tx_input2 = TransactionInput.from_cbor(reader2)
        assert tx_input2.index == 10
        assert tx_input2.index != original_index
