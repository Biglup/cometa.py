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
    Transaction,
    TransactionBody,
    TransactionInput,
    TransactionInputSet,
    TransactionOutput,
    TransactionOutputList,
    WitnessSet,
    Address,
)


# Test vectors from vendor/cardano-c/lib/tests/transaction
TX_CBOR = "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b000b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b582088e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a10481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c71213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799fd8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9fd8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980fffff5f6"

TX_CBOR2 = "84a600d9010281825820260aed6e7a24044b1254a87a509468a649f522a4e54e830ac10f27ea7b5ec61f010183a300581d70b429738bd6cc58b5c7932d001aa2bd05cfea47020a556c8c753d4436011a004c4b40028200582007845f8f3841996e3d8157954e2f5e2fb90465f27112fc5fe9056d916fae245ba200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba011a04636769a200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba01821a00177a6ea2581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff198a5447742544319271044774554481a0031f9194577444f47451a0056898d4577555344431a000fc589467753484942411a000103c2581c659ab0b5658687c2e74cd10dba8244015b713bf503b90557769d77a7a14a57696e675269646572731a02269552021a0002e665031a01353f84081a013531740b58204107eada931c72a600a6e3305bd22c7aeb9ada7c3f6823b155f4db85de36a69aa200d9010281825820e686ade5bc97372f271fd2abc06cfd96c24b3d9170f9459de1d8e3dd8fd385575840653324a9dddad004f05a8ac99fa2d1811af5f00543591407fb5206cfe9ac91bb1412404323fa517e0e189684cd3592e7f74862e3f16afbc262519abec958180c04d9010281d8799fd8799fd8799fd8799f581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68ffd8799fd8799fd8799f581c042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339baffffffff581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c681b000001863784a12ed8799fd8799f4040ffd8799f581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff1984577444f4745ffffffd8799fd87980190c8efffff5f6"

TX_CBOR3_TX_ID = "2d7f290c815e061fb7c27e91d2a898bd7b454a71c9b7a26660e2257ac31ebe32"

TX_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"
ADDRESS_BECH32 = "addr_test1qpfhhfy2qgls50r9u4yh0l7z67xpg0a5rrhkmvzcuqrd0znuzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q9gw0lz"


class TestTransaction:
    def test_from_cbor(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)
        assert tx is not None

    def test_to_cbor(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)

        writer = CborWriter()
        tx.to_cbor(writer)
        # CBOR output should be non-empty
        assert len(writer.to_hex()) > 0

    def test_id(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)
        tx_id = tx.id
        assert tx_id is not None
        # Transaction ID should be 32 bytes
        assert len(tx_id) == 32

    def test_body(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)
        body = tx.body
        assert body is not None

    def test_witness_set(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)
        witness_set = tx.witness_set
        assert witness_set is not None

    def test_is_valid(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)
        # is_valid should return a boolean
        assert isinstance(tx.is_valid, bool)

    def test_new(self):
        # Create inputs
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        input_set.add(tx_input)

        # Create outputs
        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        output_list.add(output)

        # Create body
        body = TransactionBody.new(input_set, output_list, 200000)

        # Create empty witness set
        witness_set = WitnessSet()

        # Create transaction
        tx = Transaction.new(body, witness_set)
        assert tx is not None
        assert tx.body is not None
        assert tx.witness_set is not None

    def test_cbor_roundtrip(self):
        reader = CborReader.from_hex(TX_CBOR)
        tx = Transaction.from_cbor(reader)

        writer = CborWriter()
        tx.to_cbor(writer)
        cbor_hex = writer.to_hex()

        # Roundtrip: parse the re-serialized CBOR
        reader2 = CborReader.from_hex(cbor_hex)
        tx2 = Transaction.from_cbor(reader2)
        assert tx2 is not None
        # IDs should match
        assert tx.id.to_hex() == tx2.id.to_hex()

    def test_multiple_transactions(self):
        # Parse two different transactions
        reader1 = CborReader.from_hex(TX_CBOR)
        tx1 = Transaction.from_cbor(reader1)

        reader2 = CborReader.from_hex(TX_CBOR2)
        tx2 = Transaction.from_cbor(reader2)

        assert tx1 is not None
        assert tx2 is not None
        # Transaction IDs should be different
        assert tx1.id.to_hex() != tx2.id.to_hex()
