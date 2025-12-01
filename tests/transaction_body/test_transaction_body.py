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
    Value,
    TransactionInput,
    TransactionInputSet,
    TransactionOutput,
    TransactionOutputList,
    TransactionBody,
    Address,
)


# Test vectors from vendor/cardano-c/lib/tests/transaction_body
TX_INPUT_CBOR = "8258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102005"
TX_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"

VALUE_CBOR = "821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a"

TX_OUTPUT_CBOR = "a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011"

ADDRESS_BECH32 = "addr_test1qpfhhfy2qgls50r9u4yh0l7z67xpg0a5rrhkmvzcuqrd0znuzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q9gw0lz"


class TestValue:
    def test_new(self):
        value = Value.new(1000000, None)
        assert value is not None
        assert value.coin == 1000000

    def test_from_coin(self):
        value = Value.from_coin(1000000)
        assert value is not None
        assert value.coin == 1000000

    def test_zero(self):
        value = Value.zero()
        assert value is not None
        assert value.coin == 0

    def test_from_cbor(self):
        reader = CborReader.from_hex(VALUE_CBOR)
        value = Value.from_cbor(reader)
        assert value is not None
        assert value.coin == 1000000

    def test_to_cbor(self):
        reader = CborReader.from_hex(VALUE_CBOR)
        value = Value.from_cbor(reader)

        writer = CborWriter()
        value.to_cbor(writer)
        assert len(writer.to_hex()) > 0

    def test_from_dict_int(self):
        value = Value.from_dict(1500000)
        assert value is not None
        assert value.coin == 1500000
        assert value.multi_asset is None or value.multi_asset.policy_count == 0

    def test_from_dict_with_assets(self):
        policy_id = bytes.fromhex("57fca08abbaddee36da742a839f7d83a7e1d2419f1507fcbf3916522")
        value = Value.from_dict([
            1500000,
            {
                policy_id: {
                    b"CHOC": 2000
                }
            }
        ])
        assert value is not None
        assert value.coin == 1500000
        assert value.asset_count == 2  # lovelace + CHOC

    def test_from_dict_multiple_assets(self):
        policy_id = bytes.fromhex("57fca08abbaddee36da742a839f7d83a7e1d2419f1507fcbf3916522")
        value = Value.from_dict([
            2000000,
            {
                policy_id: {
                    b"TOKEN1": 100,
                    b"TOKEN2": 200
                }
            }
        ])
        assert value is not None
        assert value.coin == 2000000
        assert value.asset_count == 3  # lovelace + TOKEN1 + TOKEN2

    def test_to_dict_coin_only(self):
        value = Value.from_coin(1500000)
        result = value.to_dict()
        assert result == 1500000

    def test_to_dict_with_assets(self):
        policy_id = bytes.fromhex("57fca08abbaddee36da742a839f7d83a7e1d2419f1507fcbf3916522")
        value = Value.from_dict([
            1500000,
            {
                policy_id: {
                    b"CHOC": 2000
                }
            }
        ])
        result = value.to_dict()
        assert isinstance(result, list)
        assert result[0] == 1500000
        assert policy_id in result[1]
        assert result[1][policy_id][b"CHOC"] == 2000


class TestTransactionInput:
    def test_new(self):
        tx_id = bytes.fromhex(TX_ID_HASH)
        tx_input = TransactionInput.new(tx_id, 5)
        assert tx_input is not None
        assert tx_input.index == 5

    def test_from_hex(self):
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 5)
        assert tx_input is not None
        assert tx_input.index == 5

    def test_from_cbor(self):
        reader = CborReader.from_hex(TX_INPUT_CBOR)
        tx_input = TransactionInput.from_cbor(reader)
        assert tx_input is not None
        assert tx_input.index == 5
        assert tx_input.transaction_id.hex() == TX_ID_HASH

    def test_to_cbor(self):
        reader = CborReader.from_hex(TX_INPUT_CBOR)
        tx_input = TransactionInput.from_cbor(reader)

        writer = CborWriter()
        tx_input.to_cbor(writer)
        assert writer.to_hex() == TX_INPUT_CBOR


class TestTransactionInputSet:
    def test_create_empty(self):
        input_set = TransactionInputSet()
        assert len(input_set) == 0

    def test_add_and_get(self):
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 5)

        input_set.add(tx_input)
        assert len(input_set) == 1

        retrieved = input_set.get(0)
        assert retrieved is not None
        assert retrieved.index == 5

    def test_iteration(self):
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 5)
        input_set.add(tx_input)

        count = 0
        for inp in input_set:
            count += 1
            assert inp.index == 5
        assert count == 1


class TestTransactionOutput:
    def test_from_cbor(self):
        reader = CborReader.from_hex(TX_OUTPUT_CBOR)
        output = TransactionOutput.from_cbor(reader)
        assert output is not None

    def test_new(self):
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        assert output is not None

    def test_to_cbor(self):
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)

        writer = CborWriter()
        output.to_cbor(writer)
        assert len(writer.to_hex()) > 0


class TestTransactionOutputList:
    def test_create_empty(self):
        output_list = TransactionOutputList()
        assert len(output_list) == 0

    def test_add_and_get(self):
        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)

        output_list.add(output)
        assert len(output_list) == 1

        retrieved = output_list.get(0)
        assert retrieved is not None

    def test_iteration(self):
        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        output_list.add(output)

        count = 0
        for out in output_list:
            count += 1
        assert count == 1


class TestTransactionBody:
    def test_new(self):
        # Set up inputs
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        input_set.add(tx_input)

        # Set up outputs
        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        output_list.add(output)

        # Create body
        body = TransactionBody.new(input_set, output_list, 200000)
        assert body is not None
        assert body.fee == 200000

    def test_inputs_and_outputs(self):
        # Set up inputs
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        input_set.add(tx_input)

        # Set up outputs
        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        output_list.add(output)

        # Create body
        body = TransactionBody.new(input_set, output_list, 200000)

        # Verify
        assert len(body.inputs) == 1
        assert len(body.outputs) == 1
        assert body.fee == 200000
