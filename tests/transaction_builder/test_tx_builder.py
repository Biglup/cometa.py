"""
Comprehensive tests for TxBuilder class.

These tests build actual transactions using mocked UTXOs and provider to verify
all TxBuilder methods work correctly with different argument formats.

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
    Address,
    AssetName,
    Blake2bHash,
    ConstrPlutusData,
    Credential,
    DRep,
    DRepType,
    NetworkId,
    ProtocolParameters,
    RewardAddress,
    Script,
    ScriptAll,
    ScriptInvalidAfter,
    SlotConfig,
    Transaction,
    TransactionInput,
    TransactionOutput,
    TxBuilder,
    Utxo,
    UtxoList,
    Value,
)
from cometa.transaction_builder import LargeFirstCoinSelector


TX_ID_HASH = "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7"
TX_ID_HASH_ALT = "1111111111111111111111111111111111111111111111111111111111111111"

TEST_ADDRESS = (
    "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer"
    "3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
)
TEST_ADDRESS_2 = (
    "addr_test1qpjhcqawjma79scw4d9fjudwcu0sww9kv9x8f30fer3rmpu"
    "2qn0kv3udaf5pmf94ts27ul2w7q3sepupwccez2u2lu5s7aa8rv"
)
STAKE_ADDRESS = "stake_test1uqfu74w3wh4gfzu8m6e7j987h4lq9r3t7ef5gaw497uu85qsqfy27"
POOL_ID = "pool1pu5jlj4q9w9jlxeu370a3c9myx47md5j5m2str0naunn2q3lkdy"

ALWAYS_SUCCEEDS_SCRIPT_V3 = (
    "590dff010000323232332232323232332232323232323232232498c8c8c94cd4ccd5cd19b874800000804c0484c8c8c8c8c8ccc88848ccc00401000c008c8c8c94cd4ccd5cd19b874800000806c0684c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8cccccccccccc8ccc8cc8cc888888888888888848cccccccccccccccc00404404003c03803403002c02802402001c01801401000c008c004d5d080a18009aba1013302123232325335333573466e1d2000002031030133221233001003002301d35742002600a6ae84d5d1000898192481035054310035573c0046aae74004dd5000998108009aba101123232325335333573466e1d200000203002f13232333322221233330010050040030023232325335333573466e1d2000002035034133221233001003002302a35742002660564646464a66a666ae68cdc3a40000040720702642446004006605c6ae8400454cd4ccd5cd19b87480080080e40e04c8ccc888488ccc00401401000cdd69aba1002375a6ae84004dd69aba1357440026ae880044c0e92401035054310035573c0046aae74004dd50009aba1357440022606c9201035054310035573c0046aae74004dd51aba1003300735742004646464a66a666ae68cdc3a400000406a068224440062a66a666ae68cdc3a400400406a068264244460020086eb8d5d08008a99a999ab9a3370e900200101a81a099091118010021aba1001130364901035054310035573c0046aae74004dd51aba10013302875c6ae84d5d10009aba200135744002260629201035054310035573c0046aae74004dd50009bad3574201e60026ae84038c008c009d69980f80a9aba100c33302202075a6ae8402cc8c8c94cd4ccd5cd19b87480000080b80b44cc8848cc00400c008c8c8c94cd4ccd5cd19b87480000080c40c04cc8848cc00400c008cc0b9d69aba1001302d357426ae880044c0c9241035054310035573c0046aae74004dd51aba10013232325335333573466e1d20000020310301332212330010030023302e75a6ae84004c0b4d5d09aba200113032491035054310035573c0046aae74004dd51aba1357440022605e921035054310035573c0046aae74004dd51aba100a3301f75c6ae84024ccc0888c8c8c94cd4ccd5cd19b87480000080bc0b84c84888888c01401cdd71aba100115335333573466e1d200200202f02e13212222223002007301b357420022a66a666ae68cdc3a400800405e05c2642444444600600e60486ae8400454cd4ccd5cd19b87480180080bc0b84cc884888888cc01802001cdd69aba10013019357426ae8800454cd4ccd5cd19b87480200080bc0b84c84888888c00401cc068d5d08008a99a999ab9a3370e9005001017817099910911111198020040039bad3574200260306ae84d5d1000898182481035054310035573c0046aae74004dd50008131aba1008330020263574200e6eb8d5d080319981100b198110149191919299a999ab9a3370e9000001017817089110010a99a999ab9a3370e9001001017817089110008a99a999ab9a3370e900200101781708911001898182481035054310035573c0046aae74004dd50009aba10053301f0143574200860026ae8400cc004d5d09aba2003302075a6040eb8d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba20011301c491035054310035573c0046aae74004dd51aba10063574200a646464a66a666ae68cdc3a40000040360342642444444600a00e6eb8d5d08008a99a999ab9a3370e900100100d80d0999109111111980100400398039aba100133011016357426ae8800454cd4ccd5cd19b874801000806c0684c84888888c00c01cc040d5d08008a99a999ab9a3370e900300100d80d099910911111198030040039bad35742002600a6ae84d5d10008a99a999ab9a3370e900400100d80d0990911111180080398031aba100115335333573466e1d200a00201b01a13322122222233004008007375a6ae84004c010d5d09aba20011301c4901035054310035573c0046aae74004dd51aba13574400a4646464a66a666ae68cdc3a4000004036034264666444246660020080060046eb4d5d080118089aba10013232325335333573466e1d200000201f01e1323332221222222233300300a0090083301601e357420046ae84004cc059d71aba1357440026ae8800454cd4ccd5cd19b874800800807c0784cc8848888888cc01c024020cc054074d5d0800991919299a999ab9a3370e90000010110108999109198008018011bad357420026eb4d5d09aba200113023491035054310035573c0046aae74004dd51aba1357440022a66a666ae68cdc3a400800403e03c26644244444446600401201066602c028eb4d5d08009980abae357426ae8800454cd4ccd5cd19b874801800807c0784c848888888c010020cc054074d5d08008a99a999ab9a3370e900400100f80f09919199991110911111119998008058050048041980b80f9aba1003330150163574200466603002ceb4d5d08009a991919299a999ab9a3370e900000101201189980e1bad357420026eb4d5d09aba2001130254901035054310035573c0046aae74004dd51aba135744002446602a0040026ae88004d5d10008a99a999ab9a3370e900500100f80f0999109111111198028048041980a80e9aba10013232325335333573466e1d200000202202113301875c6ae840044c08d241035054310035573c0046aae74004dd51aba1357440022a66a666ae68cdc3a401800403e03c22444444400c26040921035054310035573c0046aae74004dd51aba1357440026ae880044c071241035054310035573c0046aae74004dd50009191919299a999ab9a3370e900000100d00c899910911111111111980280680618079aba10013301075a6ae84d5d10008a99a999ab9a3370e900100100d00c899910911111111111980100680618079aba10013301075a6ae84d5d10008a9919a999ab9a3370e900200180d80d099910911111111111980500680618081aba10023001357426ae8800854cd4ccd5cd19b874801800c06c0684c8ccc888488888888888ccc018038034030c044d5d080198011aba1001375a6ae84d5d10009aba200215335333573466e1d200800301b01a133221222222222223300700d00c3010357420046eb4d5d09aba200215335333573466e1d200a00301b01a132122222222122300100c3010357420042a66a666ae68cdc3a4018006036034266442444444444446600601a01860206ae84008dd69aba1357440042a66a666ae68cdc3a401c006036034266442444444444446601201a0186eb8d5d08011bae357426ae8800854cd4ccd5cd19b874804000c06c0684cc88488888888888cc020034030dd71aba1002375a6ae84d5d10010a99a999ab9a3370e900900180d80d099910911111111111980580680618081aba10023010357426ae8800854cd4ccd5cd19b874805000c06c0684c8488888888888c010030c040d5d08010980e2481035054310023232325335333573466e1d200000201e01d13212223003004375c6ae8400454c8cd4ccd5cd19b874800800c07c0784c84888c004010c004d5d08010a99a999ab9a3370e900200180f80f099910911198010028021bae3574200460026ae84d5d1001098102481035054310023232325335333573466e1d2000002022021132122230030043017357420022a66a666ae68cdc3a4004004044042224440042a66a666ae68cdc3a40080040440422244400226046921035054310035573c0046aae74004dd50009aab9e00235573a0026ea8004d55cf0011aab9d00137540024646464a66a666ae68cdc3a400000403203026424446006008601c6ae8400454cd4ccd5cd19b87480080080640604c84888c008010c038d5d08008a99a999ab9a3370e900200100c80c099091118008021bae3574200226034921035054310035573c0046aae74004dd50009191919299a999ab9a3370e900000100c00b8999109198008018011bae357420026eb4d5d09aba200113019491035054310035573c0046aae74004dd50009aba200113014491035054310035573c0046aae74004dd50009808911299a999ab9a3370e900000080880809809249035054330015335333573466e20005200001101013300333702900000119b81480000044c8cc8848cc00400c008cdc200180099b840020013300400200130102225335333573466e1d200000101000f10021330030013370c004002464460046eb0004c04088cccd55cf8009005119a80498021aba10023003357440040224646464a66a666ae68cdc3a400000401e01c26424460040066eb8d5d08008a99a999ab9a3370e900100100780709909118008019bae3574200226020921035054310035573c0046aae74004dd500091191919299a999ab9a3370e900100100780708910008a99a999ab9a3370e9000001007807099091180100198029aba1001130104901035054310035573c0046aae74004dd50009119118011bab001300e2233335573e002401046466a0106600e600c6aae74004c014d55cf00098021aba20033574200401e4424660020060042440042442446600200800640024646464a66a666ae68cdc3a400000401000e200e2a66a666ae68cdc3a400400401000e201026012921035054310035573c0046aae74004dd500091191919299a999ab9a3370e9000001004003889110010a99a999ab9a3370e90010010040038990911180180218029aba100115335333573466e1d200400200800711222001130094901035054310035573c0046aae74004dd50009191919299a999ab9a3370e90000010030028999109198008018011bae357420026eb4d5d09aba200113007491035054310035573c0046aae74004dd5000891001091000919319ab9c0010021200123230010012300223300200200101"
)


def create_test_utxo(
    tx_hash: str = TX_ID_HASH,
    index: int = 0,
    address: str = TEST_ADDRESS,
    lovelace: int = 10_000_000,
) -> Utxo:
    """Helper to create a test UTXO."""
    tx_input = TransactionInput.from_hex(tx_hash, index)
    addr = Address.from_string(address)
    tx_output = TransactionOutput.new(addr, lovelace)
    return Utxo.new(tx_input, tx_output)


def create_test_utxo_with_value(
    tx_hash: str = TX_ID_HASH,
    index: int = 0,
    address: str = TEST_ADDRESS,
    value: Value = None,
) -> Utxo:
    """Helper to create a test UTXO with a Value."""
    tx_input = TransactionInput.from_hex(tx_hash, index)
    addr = Address.from_string(address)
    tx_output = TransactionOutput.new(addr, value.coin)
    tx_output.value = value
    return Utxo.new(tx_input, tx_output)


def create_protocol_params() -> ProtocolParameters:
    """Create test protocol parameters."""
    params = ProtocolParameters.new()
    params.min_fee_a = 44
    params.min_fee_b = 155381
    params.coins_per_utxo_byte = 4310
    params.max_tx_size = 16384
    params.max_value_size = 5000
    params.key_deposit = 2_000_000
    params.pool_deposit = 500_000_000
    params.drep_deposit = 2_000_000
    params.gov_action_deposit = 100_000_000_000
    params.collateral_percentage = 150
    params.max_collateral_inputs = 3
    return params


@pytest.fixture
def protocol_params():
    """Create test protocol parameters."""
    return create_protocol_params()


@pytest.fixture
def slot_config():
    """Create test slot configuration."""
    return SlotConfig.preprod()


@pytest.fixture
def builder(protocol_params, slot_config):
    """Create a TxBuilder instance for testing."""
    return TxBuilder(protocol_params, slot_config)


class TestBuildSimpleTransactions:
    """Tests that build actual simple transactions."""

    def test_build_send_lovelace_with_string_address(self, protocol_params, slot_config):
        """Build a transaction sending lovelace using string addresses."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body is not None
        assert tx.body.fee > 0

    def test_build_send_lovelace_with_address_object(self, protocol_params, slot_config):
        """Build a transaction sending lovelace using Address objects."""
        builder = TxBuilder(protocol_params, slot_config)
        recipient = Address.from_string(TEST_ADDRESS_2)
        change_addr = Address.from_string(TEST_ADDRESS)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(change_addr)
            .send_lovelace(recipient, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.fee > 0

    def test_build_multiple_outputs(self, protocol_params, slot_config):
        """Build a transaction with multiple outputs."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .send_lovelace(TEST_ADDRESS_2, 3_000_000)
            .send_lovelace(TEST_ADDRESS_2, 2_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        outputs = tx.body.outputs
        assert len(outputs) >= 3

    def test_build_with_utxo_list(self, protocol_params, slot_config):
        """Build a transaction using UtxoList instead of Python list."""
        builder = TxBuilder(protocol_params, slot_config)

        utxo_list = UtxoList()
        utxo_list.add(create_test_utxo(index=0, lovelace=100_000_000))
        utxo_list.add(create_test_utxo(index=1, lovelace=50_000_000))

        tx = (
            builder
            .set_utxos(utxo_list)
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 10_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_network_id(self, protocol_params, slot_config):
        """Build a transaction with explicit network ID."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .set_network_id(NetworkId.TESTNET)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithValue:
    """Tests that build transactions with multi-asset values."""

    def test_build_send_value_with_tokens(self, protocol_params, slot_config):
        """Build a transaction sending a Value with native tokens."""
        builder = TxBuilder(protocol_params, slot_config)

        policy_id = bytes.fromhex("aa" * 28)
        asset_name = b"TestToken"

        value = Value.from_dict([
            5_000_000,
            {policy_id: {asset_name: 100}}
        ])

        utxo_value = Value.from_dict([
            100_000_000,
            {policy_id: {asset_name: 500}}
        ])
        utxo = create_test_utxo_with_value(index=0, value=utxo_value)

        tx = (
            builder
            .set_utxos([utxo])
            .set_change_address(TEST_ADDRESS)
            .send_value(TEST_ADDRESS_2, value)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_send_value_string_address(self, protocol_params, slot_config):
        """Build send_value with string address."""
        builder = TxBuilder(protocol_params, slot_config)

        value = Value.from_coin(5_000_000)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_value(TEST_ADDRESS_2, value)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_send_value_address_object(self, protocol_params, slot_config):
        """Build send_value with Address object."""
        builder = TxBuilder(protocol_params, slot_config)

        value = Value.from_coin(5_000_000)
        recipient = Address.from_string(TEST_ADDRESS_2)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_value(recipient, value)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithMinting:
    """Tests that build transactions with token minting."""

    def test_build_mint_with_native_script(self, protocol_params, slot_config):
        """Build a minting transaction with native script."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"MyToken", 1000)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_with_hex_string_policy(self, protocol_params, slot_config):
        """Build minting with hex string policy ID."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id_hex = native_script.hash.hex()

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id_hex, b"MyToken", 500)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_with_blake2b_hash_policy(self, protocol_params, slot_config):
        """Build minting with Blake2bHash policy ID."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_hash = Blake2bHash.from_bytes(native_script.hash)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_hash, b"MyToken", 100)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_with_asset_name_object(self, protocol_params, slot_config):
        """Build minting with AssetName object."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash
        asset_name = AssetName.from_bytes(b"TokenName")

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, asset_name, 50)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_and_send_to_self(self, protocol_params, slot_config):
        """Build a mint transaction that sends tokens to the minter."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash

        value_with_tokens = Value.from_dict([
            2_000_000,
            {policy_id: {b"MyNFT": 1}}
        ])

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"MyNFT", 1)
            .add_script(native_script)
            .send_value(TEST_ADDRESS, value_with_tokens)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_burn_tokens(self, protocol_params, slot_config):
        """Build a transaction that burns tokens."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash

        utxo_value = Value.from_dict([
            100_000_000,
            {policy_id: {b"BurnMe": 100}}
        ])
        utxo = create_test_utxo_with_value(index=0, value=utxo_value)

        tx = (
            builder
            .set_utxos([utxo])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"BurnMe", -100)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_with_asset_id(self, protocol_params, slot_config):
        """Build minting using mint_token_with_id."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash
        asset_name = b"TestAsset"
        asset_id_bytes = policy_id + asset_name

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token_with_id(asset_id_bytes, 100)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_mint_with_asset_id_hex_string(self, protocol_params, slot_config):
        """Build minting using mint_token_with_id with hex string."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash
        asset_name = b"TestAsset"
        asset_id_hex = (policy_id + asset_name).hex()

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token_with_id(asset_id_hex, 100)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithMetadata:
    """Tests that build transactions with metadata."""

    def test_build_with_dict_metadata(self, protocol_params, slot_config):
        """Build a transaction with dictionary metadata."""
        builder = TxBuilder(protocol_params, slot_config)

        metadata = {
            "message": "Hello Cardano!",
            "version": 1
        }

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_metadata(674, metadata)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_json_string_metadata(self, protocol_params, slot_config):
        """Build a transaction with JSON string metadata."""
        builder = TxBuilder(protocol_params, slot_config)

        metadata_json = '{"msg": "Test message"}'

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_metadata(674, metadata_json)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_nft_metadata(self, protocol_params, slot_config):
        """Build a minting transaction with CIP-25 NFT metadata."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash
        policy_id_hex = policy_id.hex()

        nft_metadata = {
            policy_id_hex: {
                "MyNFT": {
                    "name": "My First NFT",
                    "image": "ipfs://QmTest123",
                    "description": "A test NFT"
                }
            }
        }

        value_with_nft = Value.from_dict([
            2_000_000,
            {policy_id: {b"MyNFT": 1}}
        ])

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"MyNFT", 1)
            .add_script(native_script)
            .send_value(TEST_ADDRESS, value_with_nft)
            .set_metadata(721, nft_metadata)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithValidityIntervals:
    """Tests that build transactions with various validity intervals."""

    def test_build_with_expires_in(self, protocol_params, slot_config):
        """Build with expires_in (seconds from now)."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(7200)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.invalid_after is not None

    def test_build_with_valid_until_slot(self, protocol_params, slot_config):
        """Build with set_valid_until using slot number."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_valid_until(slot=999999999)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_valid_from_slot(self, protocol_params, slot_config):
        """Build with set_valid_from using slot number."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_valid_from(slot=1)
            .set_valid_until(slot=999999999)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.invalid_before is not None

    def test_build_with_valid_after(self, protocol_params, slot_config):
        """Build with valid_after (seconds from now for start)."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .valid_after(60)
            .expires_in(7200)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.invalid_before is not None


class TestBuildWithSigners:
    """Tests that build transactions with required signers."""

    def test_build_with_signer_hex_string(self, protocol_params, slot_config):
        """Build with add_signer using hex string."""
        builder = TxBuilder(protocol_params, slot_config)

        pub_key_hash = "aa" * 28

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .add_signer(pub_key_hash)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert len(tx.body.required_signers) > 0

    def test_build_with_signer_blake2b_hash(self, protocol_params, slot_config):
        """Build with add_signer using Blake2bHash object."""
        builder = TxBuilder(protocol_params, slot_config)

        pub_key_hash = Blake2bHash.from_hex("bb" * 28)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .add_signer(pub_key_hash)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_pad_signer_count(self, protocol_params, slot_config):
        """Build with pad_signer_count for fee estimation."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .pad_signer_count(3)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithScripts:
    """Tests that build transactions with scripts."""

    def test_build_with_native_script_directly(self, protocol_params, slot_config):
        """Build with native script passed directly to add_script."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"Token", 1)
            .add_script(native_script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_script_wrapper(self, protocol_params, slot_config):
        """Build with Script wrapper object."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        script = Script.from_native(native_script)
        policy_id = script.hash

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .mint_token(policy_id, b"Token", 1)
            .add_script(script)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithDonation:
    """Tests that build transactions with treasury donations."""

    def test_build_with_donation(self, protocol_params, slot_config):
        """Build a transaction with treasury donation."""
        builder = TxBuilder(protocol_params, slot_config)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_donation(1_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithMinimumFee:
    """Tests that build transactions with minimum fee override."""

    def test_build_with_minimum_fee(self, protocol_params, slot_config):
        """Build a transaction with minimum fee set."""
        builder = TxBuilder(protocol_params, slot_config)

        min_fee = 500_000

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .set_minimum_fee(min_fee)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.fee >= min_fee


class TestBuildWithExplicitInputs:
    """Tests that build transactions with explicit input selection."""

    def test_build_with_add_input(self, protocol_params, slot_config):
        """Build with explicit input using add_input."""
        builder = TxBuilder(protocol_params, slot_config)

        specific_utxo = create_test_utxo(
            tx_hash=TX_ID_HASH_ALT,
            index=0,
            lovelace=100_000_000
        )

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=50_000_000)])
            .set_change_address(TEST_ADDRESS)
            .add_input(specific_utxo)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)

    def test_build_with_add_reference_input(self, protocol_params, slot_config):
        """Build with reference input."""
        builder = TxBuilder(protocol_params, slot_config)

        reference_utxo = create_test_utxo(
            tx_hash=TX_ID_HASH_ALT,
            index=5,
            lovelace=10_000_000
        )

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .add_reference_input(reference_utxo)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert len(tx.body.reference_inputs) > 0


class TestBuildWithCoinSelector:
    """Tests that build transactions with custom coin selectors."""

    def test_build_with_large_first_selector(self, protocol_params, slot_config):
        """Build with LargeFirstCoinSelector."""
        builder = TxBuilder(protocol_params, slot_config)

        selector = LargeFirstCoinSelector.new()

        tx = (
            builder
            .set_coin_selector(selector)
            .set_utxos([
                create_test_utxo(index=0, lovelace=10_000_000),
                create_test_utxo(index=1, lovelace=50_000_000),
                create_test_utxo(index=2, lovelace=30_000_000),
            ])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 5_000_000)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestBuildWithOutput:
    """Tests that build transactions with pre-built outputs."""

    def test_build_with_add_output(self, protocol_params, slot_config):
        """Build with pre-built TransactionOutput."""
        builder = TxBuilder(protocol_params, slot_config)

        address = Address.from_string(TEST_ADDRESS_2)
        output = TransactionOutput.new(address, 5_000_000)

        tx = (
            builder
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .add_output(output)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)


class TestMethodChaining:
    """Tests that verify proper method chaining works end-to-end."""

    def test_full_method_chain(self, protocol_params, slot_config):
        """Build a complex transaction using full method chain."""
        builder = TxBuilder(protocol_params, slot_config)

        native_script = ScriptAll.new([
            ScriptInvalidAfter.new(1001655683199)
        ])
        policy_id = native_script.hash

        value_with_token = Value.from_dict([
            2_000_000,
            {policy_id: {b"ChainToken": 1}}
        ])

        tx = (
            builder
            .set_network_id(NetworkId.TESTNET)
            .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
            .set_change_address(TEST_ADDRESS)
            .send_lovelace(TEST_ADDRESS_2, 3_000_000)
            .mint_token(policy_id, b"ChainToken", 1)
            .add_script(native_script)
            .send_value(TEST_ADDRESS, value_with_token)
            .set_metadata(674, {"msg": "Chain test"})
            .add_signer("cc" * 28)
            .expires_in(3600)
            .build()
        )

        assert isinstance(tx, Transaction)
        assert tx.body.fee > 0


class TestErrorCases:
    """Tests for error handling in transaction building."""

    def test_build_without_change_address_fails(self, protocol_params, slot_config):
        """Building without change address should fail."""
        builder = TxBuilder(protocol_params, slot_config)

        with pytest.raises(Exception):
            (
                builder
                .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
                .send_lovelace(TEST_ADDRESS_2, 5_000_000)
                .expires_in(3600)
                .build()
            )

    def test_build_with_insufficient_funds_fails(self, protocol_params, slot_config):
        """Building with insufficient funds should fail."""
        builder = TxBuilder(protocol_params, slot_config)

        with pytest.raises(Exception):
            (
                builder
                .set_utxos([create_test_utxo(index=0, lovelace=1_000_000)])
                .set_change_address(TEST_ADDRESS)
                .send_lovelace(TEST_ADDRESS_2, 500_000_000)
                .expires_in(3600)
                .build()
            )

    def test_validity_interval_both_params_raises(self, builder):
        """set_valid_until with both slot and unix_time should raise."""
        with pytest.raises(ValueError, match="Specify either"):
            builder.set_valid_until(slot=100, unix_time=12345)

    def test_validity_interval_no_params_raises(self, builder):
        """set_valid_until with no params should raise."""
        with pytest.raises(ValueError, match="Must specify either"):
            builder.set_valid_until()


class TestBuilderLifecycle:
    """Tests for TxBuilder initialization and lifecycle."""

    def test_create_builder(self, protocol_params, slot_config):
        """Test basic builder creation."""
        builder = TxBuilder(protocol_params, slot_config)
        assert builder is not None
        assert repr(builder) == "TxBuilder()"

    def test_builder_context_manager(self, protocol_params, slot_config):
        """Test builder as context manager."""
        with TxBuilder(protocol_params, slot_config) as builder:
            assert builder is not None

            tx = (
                builder
                .set_utxos([create_test_utxo(index=0, lovelace=100_000_000)])
                .set_change_address(TEST_ADDRESS)
                .send_lovelace(TEST_ADDRESS_2, 5_000_000)
                .expires_in(3600)
                .build()
            )
            assert isinstance(tx, Transaction)


class TestHelperFunctions:
    """Tests for module-level helper functions."""

    def test_to_reward_address_string(self):
        """Test _to_reward_address with string."""
        from cometa.transaction_builder.tx_builder import _to_reward_address

        result = _to_reward_address(STAKE_ADDRESS)
        assert isinstance(result, RewardAddress)

    def test_to_reward_address_object(self):
        """Test _to_reward_address with RewardAddress object."""
        from cometa.transaction_builder.tx_builder import _to_reward_address

        addr = RewardAddress.from_bech32(STAKE_ADDRESS)
        result = _to_reward_address(addr)
        assert result is addr

    def test_to_drep_object(self):
        """Test _to_drep with DRep object."""
        from cometa.transaction_builder.tx_builder import _to_drep

        cred = Credential.from_key_hash(Blake2bHash.from_hex("aa" * 28))
        drep = DRep.new(DRepType.KEY_HASH, cred)
        result = _to_drep(drep)
        assert result is drep

    def test_to_plutus_data_ptr_none(self):
        """Test _to_plutus_data_ptr with None."""
        from cometa.transaction_builder.tx_builder import _to_plutus_data_ptr

        result = _to_plutus_data_ptr(None)
        assert result is None

    def test_to_plutus_data_ptr_plutus_data(self):
        """Test _to_plutus_data_ptr with PlutusData."""
        from cometa.transaction_builder.tx_builder import _to_plutus_data_ptr

        data = ConstrPlutusData(0)
        result = _to_plutus_data_ptr(data)
        assert result is not None
