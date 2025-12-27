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
    CborReader,
    CborWriter,
    JsonWriter,
    Blake2bHash,
    Blake2bHashSet,
    NetworkId,
    Address,
    TransactionInput,
    TransactionInputSet,
    TransactionOutput,
    TransactionOutputList,
    TransactionBody,
    CardanoError,
)


CONWAY_CBOR_WITH_SETS = "b500d90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5000181a2005839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc01820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e020a031903e804d90102828304581c26b17b78de4f035dc0bfce60d1d3c3a8085c38dcce5fb8767e518bed1901f48405581c0d94e174732ef9aae73f395ab44507bfa983d65023c11a951f0c32e4581ca646474b8f5431261506b6c273d307c7569a4eb6c96b42dd4a29520a582003170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c11131405a2581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d005581de0404b5a4088ae9abcf486a7e7b8f82069e6fcfe1bf226f1851ce72570030682a3581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000002b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000003b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba19020b0758202ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa08186409a3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c413831581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e0b58206199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de0dd90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5010ed9010281581c6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d390f0110a2005839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc01820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e11186412d90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d50013a28202581c10000000000000000000000000000000000000000000000000000000a38258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258202000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008203581c20000000000000000000000000000000000000000000000000000000a28258201000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f582000000000000000000000000000000000000000000000000000000000000000008258203000000000000000000000000000000000000000000000000000000000000000038200827668747470733a2f2f7777772e736f6d6575726c2e696f5820000000000000000000000000000000000000000000000000000000000000000014d9010281841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f830582582000000000000000000000000000000000000000000000000000000000000000000382827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000151907d0161903e8"

INPUT_SET_CBOR = "d90102848258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001021058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001022058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a09080706050403020100102305"

OUTPUT_LIST_CBOR = "84a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a02820058200000000000000000000000000000000000000000000000000000000000000000a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ffa2005826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51b8cd9819561bddc6614011a02faf080"

SMALL_BODY_CBOR = "a400d90102848258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001021058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001022058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001023050184a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a02820058200000000000000000000000000000000000000000000000000000000000000000a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ffa2005826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51b8cd9819561bddc6614011a02faf0800218640319fde8"

SMALL_BODY_NO_TTL_CBOR = "a300d90102848258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001021058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001022058258200102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001023050184a400583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ff03d8185182014e4d01000033222220051200120011a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a02820058200000000000000000000000000000000000000000000000000000000000000000a300583900537ba48a023f0a3c65e54977ffc2d78c143fb418ef6db058e006d78a7c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a000f4240a2581c00000000000000000000000000000000000000000000000000000000a3443031323218644433343536186344404142420a581c11111111111111111111111111111111111111111111111111111111a3443031323218644433343536186344404142420a028201d81849d8799f0102030405ffa2005826412813b99a80cfb4024374bd0f502959485aa56e0648564ff805f2e51b8cd9819561bddc6614011a02faf080021864"

TX_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"
ADDRESS_BECH32 = "addr_test1qpfhhfy2qgls50r9u4yh0l7z67xpg0a5rrhkmvzcuqrd0znuzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q9gw0lz"


def create_default_transaction_body():
    reader = CborReader.from_hex(CONWAY_CBOR_WITH_SETS)
    body = TransactionBody.from_cbor(reader)
    body.clear_cbor_cache()
    return body


class TestTransactionBodyNew:
    def test_new_with_ttl(self):
        inputs_reader = CborReader.from_hex(INPUT_SET_CBOR)
        inputs = TransactionInputSet.from_cbor(inputs_reader)

        outputs_reader = CborReader.from_hex(OUTPUT_LIST_CBOR)
        outputs = TransactionOutputList.from_cbor(outputs_reader)

        body = TransactionBody.new(inputs, outputs, 100, 65000)

        assert body is not None
        assert body.fee == 100
        assert body.invalid_after == 65000
        assert len(body.inputs) > 0
        assert len(body.outputs) > 0

    def test_new_without_ttl(self):
        inputs_reader = CborReader.from_hex(INPUT_SET_CBOR)
        inputs = TransactionInputSet.from_cbor(inputs_reader)

        outputs_reader = CborReader.from_hex(OUTPUT_LIST_CBOR)
        outputs = TransactionOutputList.from_cbor(outputs_reader)

        body = TransactionBody.new(inputs, outputs, 100)

        assert body is not None
        assert body.fee == 100
        assert body.invalid_after is None

    def test_new_with_python_lists(self):
        input1 = TransactionInput.from_hex(TX_ID_HASH, 0)
        output1 = TransactionOutput.new(Address.from_string(ADDRESS_BECH32), 1000000)

        body = TransactionBody.new([input1], [output1], 200000)

        assert body is not None
        assert body.fee == 200000
        assert len(body.inputs) == 1
        assert len(body.outputs) == 1


class TestTransactionBodyFromCbor:
    def test_from_cbor_success(self):
        reader = CborReader.from_hex(CONWAY_CBOR_WITH_SETS)
        body = TransactionBody.from_cbor(reader)

        assert body is not None
        assert body.fee > 0

    def test_from_cbor_invalid_data(self):
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            TransactionBody.from_cbor(reader)


class TestTransactionBodyToCbor:
    def test_to_cbor_preserves_original(self):
        reader = CborReader.from_hex(CONWAY_CBOR_WITH_SETS)
        body = TransactionBody.from_cbor(reader)

        writer = CborWriter()
        body.to_cbor(writer)

        assert writer.to_hex() == CONWAY_CBOR_WITH_SETS

    def test_to_cbor_after_clear_cache(self):
        reader = CborReader.from_hex(SMALL_BODY_CBOR)
        body = TransactionBody.from_cbor(reader)
        body.clear_cbor_cache()

        writer = CborWriter()
        body.to_cbor(writer)

        assert len(writer.to_hex()) > 0


class TestTransactionBodyClearCborCache:
    def test_clear_cbor_cache(self):
        body = create_default_transaction_body()
        body.clear_cbor_cache()

        writer = CborWriter()
        body.to_cbor(writer)
        assert len(writer.to_hex()) > 0


class TestTransactionBodyToCip116Json:
    def test_to_cip116_json(self):
        body = create_default_transaction_body()
        writer = JsonWriter()

        body.to_cip116_json(writer)
        json_str = writer.encode()

        assert len(json_str) > 0
        assert "inputs" in json_str or "fee" in json_str

    def test_to_cip116_json_invalid_writer(self):
        body = create_default_transaction_body()
        with pytest.raises(TypeError):
            body.to_cip116_json("not a writer")


class TestTransactionBodyHash:
    def test_hash_property(self):
        body = create_default_transaction_body()
        hash_obj = body.hash

        assert hash_obj is not None
        assert isinstance(hash_obj, Blake2bHash)
        assert len(hash_obj.to_bytes()) == 32


class TestTransactionBodyInputs:
    def test_get_inputs(self):
        body = create_default_transaction_body()
        inputs = body.inputs

        assert inputs is not None
        assert isinstance(inputs, TransactionInputSet)
        assert len(inputs) > 0

    def test_set_inputs_with_set(self):
        body = create_default_transaction_body()
        new_inputs = TransactionInputSet()
        new_inputs.add(TransactionInput.from_hex(TX_ID_HASH, 0))

        body.inputs = new_inputs

        assert len(body.inputs) == 1

    def test_set_inputs_with_list(self):
        body = create_default_transaction_body()
        input1 = TransactionInput.from_hex(TX_ID_HASH, 0)
        input2 = TransactionInput.from_hex(TX_ID_HASH, 1)

        body.inputs = [input1, input2]

        assert len(body.inputs) == 2


class TestTransactionBodyOutputs:
    def test_get_outputs(self):
        body = create_default_transaction_body()
        outputs = body.outputs

        assert outputs is not None
        assert isinstance(outputs, TransactionOutputList)
        assert len(outputs) > 0

    def test_set_outputs_with_list(self):
        body = create_default_transaction_body()
        output1 = TransactionOutput.new(Address.from_string(ADDRESS_BECH32), 1000000)
        output2 = TransactionOutput.new(Address.from_string(ADDRESS_BECH32), 2000000)

        body.outputs = [output1, output2]

        assert len(body.outputs) == 2

    def test_set_outputs_with_output_list(self):
        body = create_default_transaction_body()
        new_outputs = TransactionOutputList()
        new_outputs.add(TransactionOutput.new(Address.from_string(ADDRESS_BECH32), 1000000))

        body.outputs = new_outputs

        assert len(body.outputs) == 1


class TestTransactionBodyFee:
    def test_get_fee(self):
        body = create_default_transaction_body()
        fee = body.fee

        assert fee >= 0
        assert isinstance(fee, int)

    def test_set_fee(self):
        body = create_default_transaction_body()
        body.fee = 500000

        assert body.fee == 500000

    def test_set_fee_zero(self):
        body = create_default_transaction_body()
        body.fee = 0

        assert body.fee == 0


class TestTransactionBodyInvalidAfter:
    def test_get_invalid_after_when_set(self):
        inputs_reader = CborReader.from_hex(INPUT_SET_CBOR)
        inputs = TransactionInputSet.from_cbor(inputs_reader)
        outputs_reader = CborReader.from_hex(OUTPUT_LIST_CBOR)
        outputs = TransactionOutputList.from_cbor(outputs_reader)

        body = TransactionBody.new(inputs, outputs, 100, 65000)

        assert body.invalid_after == 65000

    def test_get_invalid_after_when_not_set(self):
        inputs_reader = CborReader.from_hex(INPUT_SET_CBOR)
        inputs = TransactionInputSet.from_cbor(inputs_reader)
        outputs_reader = CborReader.from_hex(OUTPUT_LIST_CBOR)
        outputs = TransactionOutputList.from_cbor(outputs_reader)

        body = TransactionBody.new(inputs, outputs, 100)

        assert body.invalid_after is None

    def test_set_invalid_after(self):
        body = create_default_transaction_body()
        body.invalid_after = 100000

        assert body.invalid_after == 100000

    def test_set_invalid_after_to_none(self):
        body = create_default_transaction_body()
        body.invalid_after = 100000
        body.invalid_after = None

        assert body.invalid_after is None


class TestTransactionBodyInvalidBefore:
    def test_get_invalid_before(self):
        body = create_default_transaction_body()
        invalid_before = body.invalid_before

        assert invalid_before is None or isinstance(invalid_before, int)

    def test_set_invalid_before(self):
        body = create_default_transaction_body()
        body.invalid_before = 50000

        assert body.invalid_before == 50000

    def test_set_invalid_before_to_none(self):
        body = create_default_transaction_body()
        body.invalid_before = 50000
        body.invalid_before = None

        assert body.invalid_before is None


class TestTransactionBodyCertificates:
    def test_get_certificates_when_none(self):
        inputs_reader = CborReader.from_hex(INPUT_SET_CBOR)
        inputs = TransactionInputSet.from_cbor(inputs_reader)
        outputs_reader = CborReader.from_hex(OUTPUT_LIST_CBOR)
        outputs = TransactionOutputList.from_cbor(outputs_reader)
        body = TransactionBody.new(inputs, outputs, 100)

        assert body.certificates is None

    def test_get_certificates_when_present(self):
        body = create_default_transaction_body()
        certs = body.certificates

        assert certs is not None or certs is None

    def test_set_certificates_to_none(self):
        body = create_default_transaction_body()
        body.certificates = None

        assert body.certificates is None


class TestTransactionBodyWithdrawals:
    def test_get_withdrawals(self):
        body = create_default_transaction_body()
        withdrawals = body.withdrawals

        assert withdrawals is not None or withdrawals is None

    def test_set_withdrawals_to_none(self):
        body = create_default_transaction_body()
        body.withdrawals = None

        assert body.withdrawals is None


class TestTransactionBodyUpdate:
    def test_get_update(self):
        body = create_default_transaction_body()
        update = body.update

        assert update is not None or update is None

    def test_set_update_to_none(self):
        body = create_default_transaction_body()
        body.update = None

        assert body.update is None


class TestTransactionBodyAuxDataHash:
    def test_get_aux_data_hash(self):
        body = create_default_transaction_body()
        aux_hash = body.aux_data_hash

        assert aux_hash is not None or aux_hash is None

    def test_set_aux_data_hash(self):
        body = create_default_transaction_body()
        hash_obj = Blake2bHash.from_hex("2ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa")

        body.aux_data_hash = hash_obj

        assert body.aux_data_hash is not None

    def test_set_aux_data_hash_to_none(self):
        body = create_default_transaction_body()
        body.aux_data_hash = None

        assert body.aux_data_hash is None


class TestTransactionBodyMint:
    def test_get_mint(self):
        body = create_default_transaction_body()
        mint = body.mint

        assert mint is not None or mint is None

    def test_set_mint_to_none(self):
        body = create_default_transaction_body()
        body.mint = None

        assert body.mint is None


class TestTransactionBodyScriptDataHash:
    def test_get_script_data_hash(self):
        body = create_default_transaction_body()
        script_hash = body.script_data_hash

        assert script_hash is not None or script_hash is None

    def test_set_script_data_hash(self):
        body = create_default_transaction_body()
        hash_obj = Blake2bHash.from_hex("6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de")

        body.script_data_hash = hash_obj

        assert body.script_data_hash is not None

    def test_set_script_data_hash_to_none(self):
        body = create_default_transaction_body()
        body.script_data_hash = None

        assert body.script_data_hash is None


class TestTransactionBodyCollateral:
    def test_get_collateral(self):
        body = create_default_transaction_body()
        collateral = body.collateral

        assert collateral is not None or collateral is None

    def test_set_collateral_with_set(self):
        body = create_default_transaction_body()
        coll_set = TransactionInputSet()
        coll_set.add(TransactionInput.from_hex(TX_ID_HASH, 0))

        body.collateral = coll_set

        assert body.collateral is not None
        assert len(body.collateral) == 1

    def test_set_collateral_with_list(self):
        body = create_default_transaction_body()
        input1 = TransactionInput.from_hex(TX_ID_HASH, 0)

        body.collateral = [input1]

        assert body.collateral is not None
        assert len(body.collateral) == 1

    def test_set_collateral_to_none(self):
        body = create_default_transaction_body()
        body.collateral = None

        assert body.collateral is None


class TestTransactionBodyRequiredSigners:
    def test_get_required_signers(self):
        body = create_default_transaction_body()
        signers = body.required_signers

        assert signers is not None or signers is None

    def test_set_required_signers_with_set(self):
        body = create_default_transaction_body()
        signer_set = Blake2bHashSet()
        hash_obj = Blake2bHash.from_hex("6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de")
        signer_set.add(hash_obj)

        body.required_signers = signer_set

        assert body.required_signers is not None

    def test_set_required_signers_with_list(self):
        body = create_default_transaction_body()
        hash_obj = Blake2bHash.from_hex("6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de")

        body.required_signers = [hash_obj]

        assert body.required_signers is not None

    def test_set_required_signers_to_none(self):
        body = create_default_transaction_body()
        body.required_signers = None

        assert body.required_signers is None


class TestTransactionBodyNetworkId:
    def test_get_network_id(self):
        body = create_default_transaction_body()
        network_id = body.network_id

        assert network_id is None or isinstance(network_id, NetworkId)

    def test_set_network_id(self):
        body = create_default_transaction_body()
        body.network_id = NetworkId.MAINNET

        assert body.network_id == NetworkId.MAINNET

    def test_set_network_id_to_testnet(self):
        body = create_default_transaction_body()
        body.network_id = NetworkId.TESTNET

        assert body.network_id == NetworkId.TESTNET

    def test_set_network_id_to_none(self):
        body = create_default_transaction_body()
        body.network_id = NetworkId.MAINNET
        body.network_id = None

        assert body.network_id is None


class TestTransactionBodyCollateralReturn:
    def test_get_collateral_return(self):
        body = create_default_transaction_body()
        coll_return = body.collateral_return

        assert coll_return is not None or coll_return is None

    def test_set_collateral_return(self):
        body = create_default_transaction_body()
        output = TransactionOutput.new(Address.from_string(ADDRESS_BECH32), 1000000)

        body.collateral_return = output

        assert body.collateral_return is not None

    def test_set_collateral_return_to_none(self):
        body = create_default_transaction_body()
        body.collateral_return = None

        assert body.collateral_return is None


class TestTransactionBodyTotalCollateral:
    def test_get_total_collateral(self):
        body = create_default_transaction_body()
        total_coll = body.total_collateral

        assert total_coll is None or isinstance(total_coll, int)

    def test_set_total_collateral(self):
        body = create_default_transaction_body()
        body.total_collateral = 5000000

        assert body.total_collateral == 5000000

    def test_set_total_collateral_to_none(self):
        body = create_default_transaction_body()
        body.total_collateral = 5000000
        body.total_collateral = None

        assert body.total_collateral is None


class TestTransactionBodyReferenceInputs:
    def test_get_reference_inputs(self):
        body = create_default_transaction_body()
        ref_inputs = body.reference_inputs

        assert ref_inputs is not None or ref_inputs is None

    def test_set_reference_inputs_with_set(self):
        body = create_default_transaction_body()
        ref_set = TransactionInputSet()
        ref_set.add(TransactionInput.from_hex(TX_ID_HASH, 0))

        body.reference_inputs = ref_set

        assert body.reference_inputs is not None

    def test_set_reference_inputs_with_list(self):
        body = create_default_transaction_body()
        input1 = TransactionInput.from_hex(TX_ID_HASH, 0)

        body.reference_inputs = [input1]

        assert body.reference_inputs is not None

    def test_set_reference_inputs_to_none(self):
        body = create_default_transaction_body()
        body.reference_inputs = None

        assert body.reference_inputs is None


class TestTransactionBodyVotingProcedures:
    def test_get_voting_procedures(self):
        body = create_default_transaction_body()
        voting = body.voting_procedures

        assert voting is not None or voting is None

    def test_set_voting_procedures_to_none(self):
        body = create_default_transaction_body()
        body.voting_procedures = None

        assert body.voting_procedures is None


class TestTransactionBodyProposalProcedures:
    def test_get_proposal_procedures(self):
        body = create_default_transaction_body()
        proposals = body.proposal_procedures

        assert proposals is not None or proposals is None

    def test_set_proposal_procedures_to_none(self):
        body = create_default_transaction_body()
        body.proposal_procedures = None

        assert body.proposal_procedures is None


class TestTransactionBodyTreasuryValue:
    def test_get_treasury_value(self):
        body = create_default_transaction_body()
        treasury = body.treasury_value

        assert treasury is None or isinstance(treasury, int)

    def test_set_treasury_value(self):
        body = create_default_transaction_body()
        body.treasury_value = 2000

        assert body.treasury_value == 2000

    def test_set_treasury_value_to_none(self):
        body = create_default_transaction_body()
        body.treasury_value = 2000
        body.treasury_value = None

        assert body.treasury_value is None


class TestTransactionBodyDonation:
    def test_get_donation(self):
        body = create_default_transaction_body()
        donation = body.donation

        assert donation is None or isinstance(donation, int)

    def test_set_donation(self):
        body = create_default_transaction_body()
        body.donation = 1000

        assert body.donation == 1000

    def test_set_donation_to_none(self):
        body = create_default_transaction_body()
        body.donation = 1000
        body.donation = None

        assert body.donation is None


class TestTransactionBodyMagicMethods:
    def test_repr(self):
        body = create_default_transaction_body()
        repr_str = repr(body)

        assert "TransactionBody" in repr_str
        assert "fee" in repr_str

    def test_context_manager(self):
        with create_default_transaction_body() as body:
            assert body is not None
            assert body.fee >= 0
