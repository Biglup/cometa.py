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

from cometa.transaction_builder.balancing import balance_transaction, is_transaction_balanced
from cometa.transaction_builder.coin_selection import LargeFirstCoinSelector
from cometa.transaction_builder.evaluation import TxEvaluatorHandle
from cometa.transaction import Transaction
from cometa.transaction_body import TransactionBody
from cometa.protocol_params import ProtocolParameters, ExUnitPrices
from cometa.common import UnitInterval, ExUnits
from cometa.common.utxo_list import UtxoList
from cometa.common.utxo import Utxo
from cometa.address import Address
from cometa.witness_set import WitnessSet, RedeemerList, Redeemer
from cometa.cbor import CborReader
from cometa.errors import CardanoError


BALANCED_TX_CBOR = "84a300d9010282825820027b68d4c11e97d7e065cc2702912cb1a21b6d0e56c6a74dd605889a5561138500825820d3c887d17486d483a2b46b58b01cb9344745f15fdd8f8e70a57f854cdd88a633010182a2005839005cf6c91279a859a072601779fb33bb07c34e1d641d45df51ff63b967f15db05f56035465bf8900a09bdaa16c3d8b8244fea686524408dd8001821a00e4e1c0a1581c0b0d621b5c26d0a1fd0893a4b04c19d860296a69ede1fbcfc5179882a1474e46542d30303101a200583900dc435fc2638f6684bd1f9f6f917d80c92ae642a4a33a412e516479e64245236ab8056760efceebbff57e8cab220182be3e36439e520a6454011a0d294e28021a00029eb9a0f5f6"
UNBALANCED_TX_CBOR = "84a300d9010282825820027b68d4c11e97d7e065cc2702912cb1a21b6d0e56c6a74dd605889a5561138500825820d3c887d17486d483a2b46b58b01cb9344745f15fdd8f8e70a57f854cdd88a633010182a2005839005cf6c91279a859a072601779fb33bb07c34e1d641d45df51ff63b967f15db05f56035465bf8900a09bdaa16c3d8b8244fea686524408dd8001821a00e4e1c0a1581c0b0d621b5c26d0a1fd0893a4b04c19d860296a69ede1fbcfc5179882a1474e46542d30303101a200583900dc435fc2638f6684bd1f9f6f917d80c92ae642a4a33a412e516479e64245236ab8056760efceebbff57e8cab220182be3e36439e520a6454011a0d294e28021a00000000a0f5f6"
COMPLEX_TX_CBOR = "84b000818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5000181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e020a031903e8049182008200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d083078200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d00a83088200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d01483088200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f186482018200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f82008200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f8a03581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef9258208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db01927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f81581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f000001f682026b6578616d706c652e636f6d827368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d58304581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d01901f483028200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db784108200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05f683118200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0584108200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05f683118200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05840b8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db70a840c8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d08200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0a850d8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db78200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0a82018200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d005a1581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d00a0758202ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa08186409a3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e0b58206199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de0d818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5010e81581c6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d3910825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e11186412818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5001481841864581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d08106827468747470733a2f2f74657374696e672e7468697358203e33018e8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80da700818258206199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c891875501868205186482041901f48200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548201818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548202818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f54830301818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f540281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f6376796669647171676775726a687268716169697370717275656c6876797071786565777072796676775820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a003815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b4500481187b0582840100d87a9f187bff82190bb8191b58840201d87a9f187bff821913881907d006815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b450f5a6011904d2026373747203821904d2637374720445627974657305a2667374726b6579187b81676c6973746b65796873747276616c75650626"

CBOR_DIFFERENT_VAL1 = "82825820027b68d4c11e97d7e065cc2702912cb1a21b6d0e56c6a74dd605889a5561138500a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a00118f32a1581c0b0d621b5c26d0a1fd0893a4b04c19d860296a69ede1fbcfc5179882a1474e46542d30303101"
CBOR_DIFFERENT_VAL2 = "82825820d3c887d17486d483a2b46b58b01cb9344745f15fdd8f8e70a57f854cdd88a63301a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa8011a0dff3f6f"
CBOR_DIFFERENT_VAL3 = "82825820bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e001a200583900287a7e37219128cfb05322626daa8b19d1ad37c6779d21853f7b94177c16240714ea0e12b41a914f2945784ac494bb19573f0ca61a08afa801821a026679b8a2581c1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601a14350584c05581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c420a"

TEST_ADDRESS = "addr_test1qqnqfr70emn3kyywffxja44znvdw0y4aeyh0vdc3s3rky48vlp50u6nrq5s7k6h89uqrjnmr538y6e50crvz6jdv3vqqxah5fk"


def create_transaction(cbor_hex: str) -> Transaction:
    """
    Create a transaction from CBOR hex string.
    """
    reader = CborReader.from_hex(cbor_hex)
    return Transaction.from_cbor(reader)


def create_utxo(cbor_hex: str) -> Utxo:
    """
    Create a UTXO from CBOR hex string.
    """
    reader = CborReader.from_hex(cbor_hex)
    return Utxo.from_cbor(reader)


def create_utxo_list() -> UtxoList:
    """
    Create a list of test UTXOs.
    """
    utxo_list = UtxoList()
    utxo1 = create_utxo(CBOR_DIFFERENT_VAL1)
    utxo2 = create_utxo(CBOR_DIFFERENT_VAL2)
    utxo3 = create_utxo(CBOR_DIFFERENT_VAL3)

    utxo_list.add(utxo2)
    utxo_list.add(utxo1)
    utxo_list.add(utxo3)

    return utxo_list


def create_protocol_parameters() -> ProtocolParameters:
    """
    Create protocol parameters for testing.
    """
    params = ProtocolParameters.new()

    memory_prices = UnitInterval.from_float(0.0577)
    steps_prices = UnitInterval.from_float(0.0000721)
    script_ref_cost = UnitInterval.from_float(15.0)

    ex_unit_prices = ExUnitPrices.new(memory_prices, steps_prices)

    params.min_fee_a = 44
    params.min_fee_b = 155381
    params.execution_costs = ex_unit_prices
    params.ref_script_cost_per_byte = script_ref_cost
    params.ada_per_utxo_byte = 4310
    params.key_deposit = 2000000
    params.pool_deposit = 2000000
    params.drep_deposit = 500000000

    return params


def create_transaction_without_inputs(cbor_hex: str, target_coin: int) -> Transaction:
    """
    Create a transaction with no inputs and modified output coin value.
    """
    tx = create_transaction(cbor_hex)
    body = tx.body

    from cometa.transaction_body import TransactionInputSet, TransactionOutputList
    inputs = TransactionInputSet()
    body.inputs = inputs

    outputs = body.outputs
    output = outputs.get(0)
    value = output.value
    value.coin = target_coin

    new_outputs = TransactionOutputList()
    new_outputs.add(output)
    body.outputs = new_outputs

    return tx


def create_transaction_without_inputs_no_assets(cbor_hex: str, target_coin: int) -> Transaction:
    """
    Create a transaction with no inputs, no assets, and modified output coin value.
    """
    from cometa.transaction_body import TransactionInputSet, TransactionOutputList, Value

    tx = create_transaction(cbor_hex)
    body = tx.body

    inputs = TransactionInputSet()
    body.inputs = inputs

    outputs = body.outputs
    output = outputs.get(0)

    value = Value.zero()
    value.coin = target_coin
    output.value = value

    new_outputs = TransactionOutputList()
    new_outputs.add(output)
    body.outputs = new_outputs

    body.fee = 0

    return tx


class MockTxEvaluator:
    """
    Mock transaction evaluator that sets fixed execution units for all redeemers.
    """

    def get_name(self) -> str:
        """
        Get the name of the evaluator.
        """
        return "MockEvaluator"

    def evaluate(self, tx: Transaction, utxos):
        """
        Evaluate transaction redeemers with fixed execution units.
        """
        witness = tx.witness_set
        redeemers = witness.redeemers

        if redeemers is None:
            return []

        result = []
        ex_units = ExUnits.new(1000000000, 5000000000)

        for i in range(len(redeemers)):
            redeemer = redeemers.get(i)
            redeemer.ex_units = ex_units
            result.append(redeemer)

        return result


@pytest.fixture(name="protocol_params")
def fixture_protocol_params():
    """
    Fixture for protocol parameters.
    """
    return create_protocol_parameters()


@pytest.fixture(name="utxo_list")
def fixture_utxo_list():
    """
    Fixture for UTXO list.
    """
    return create_utxo_list()


@pytest.fixture(name="change_address")
def fixture_change_address():
    """
    Fixture for change address.
    """
    return Address.from_string(TEST_ADDRESS)


@pytest.fixture(name="coin_selector")
def fixture_coin_selector():
    """
    Fixture for coin selector.
    """
    return LargeFirstCoinSelector.new()


@pytest.fixture(name="evaluator")
def fixture_evaluator():
    """
    Fixture for transaction evaluator.
    """
    mock_eval = MockTxEvaluator()
    return TxEvaluatorHandle(mock_eval)


class TestBalanceTransaction:
    """
    Tests for balance_transaction function.
    """

    def test_can_balance_transaction(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction can successfully balance a transaction.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        reference_inputs = UtxoList()

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxo_list,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=reference_inputs,
            available_collateral_utxo=reference_inputs,
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_can_balance_transaction_no_assets(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction can balance a transaction with no assets.
        """
        tx = create_transaction_without_inputs_no_assets(BALANCED_TX_CBOR, 234827000)
        reference_inputs = UtxoList()

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxo_list,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=reference_inputs,
            available_collateral_utxo=reference_inputs,
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_can_balance_transaction_with_donations(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction can balance a transaction with donations.
        """
        tx = create_transaction_without_inputs_no_assets(BALANCED_TX_CBOR, 234827000)
        body = tx.body

        donation = 123456
        body.donation = donation

        reference_inputs = UtxoList()

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxo_list,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=reference_inputs,
            available_collateral_utxo=reference_inputs,
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_use_suggested_fee_if_given_and_enough(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction uses the suggested fee if provided and sufficient.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        body = tx.body
        body.fee = 5000000

        reference_inputs = UtxoList()

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxo_list,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=reference_inputs,
            available_collateral_utxo=reference_inputs,
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_can_balance_tx_with_scripts(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction can balance a transaction with scripts.
        """
        tx = create_transaction_without_inputs(COMPLEX_TX_CBOR, 15000000)
        reference_inputs = UtxoList()

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxo_list,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=reference_inputs,
            available_collateral_utxo=utxo_list,
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_balance_transaction_with_list_utxos(
        self,
        protocol_params,
        change_address,
        coin_selector,
        evaluator
    ):
        """
        Test that balance_transaction accepts lists of UTXOs.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)

        utxo1 = create_utxo(CBOR_DIFFERENT_VAL1)
        utxo2 = create_utxo(CBOR_DIFFERENT_VAL2)
        utxo3 = create_utxo(CBOR_DIFFERENT_VAL3)
        utxos = [utxo2, utxo1, utxo3]

        balance_transaction(
            unbalanced_tx=tx,
            protocol_params=protocol_params,
            change_address=change_address,
            available_utxo=utxos,
            coin_selector=coin_selector,
            foreign_signature_count=1,
            reference_inputs=[],
            available_collateral_utxo=[],
            collateral_change_address=change_address,
            evaluator=evaluator,
        )

        utxo_list = create_utxo_list()
        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_balance_transaction_minimal_arguments_raises_without_evaluator(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector
    ):
        """
        Test that balance_transaction raises an error without evaluator for script txs.

        Note: In the C implementation, certain balancing operations require additional
        parameters like evaluator or collateral for proper operation.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)

        # Balance transaction with minimal arguments - raises error for script txs
        with pytest.raises(CardanoError):
            balance_transaction(
                unbalanced_tx=tx,
                protocol_params=protocol_params,
                change_address=change_address,
                available_utxo=utxo_list,
                coin_selector=coin_selector,
            )


class TestIsTransactionBalanced:
    """
    Tests for is_transaction_balanced function.
    """

    def test_returns_true_if_transaction_is_balanced(
        self,
        protocol_params,
        utxo_list
    ):
        """
        Test that is_transaction_balanced returns True for a balanced transaction.
        """
        tx = create_transaction(BALANCED_TX_CBOR)
        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_returns_true_if_transaction_is_balanced_with_deposit(
        self,
        protocol_params
    ):
        """
        Test that is_transaction_balanced returns True for a balanced transaction with deposit.
        """
        tx = create_transaction(BALANCED_TX_CBOR)
        body = tx.body

        donation = 2000000
        body.donation = donation

        utxo_list = UtxoList()
        utxo1 = create_utxo(CBOR_DIFFERENT_VAL1)
        utxo2 = create_utxo(CBOR_DIFFERENT_VAL2)
        utxo3 = create_utxo(CBOR_DIFFERENT_VAL3)

        output = utxo1.output
        value = output.value
        original_coin = value.coin
        value.coin = original_coin + donation

        utxo_list.add(utxo2)
        utxo_list.add(utxo1)
        utxo_list.add(utxo3)

        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert is_balanced

    def test_returns_false_if_transaction_is_not_balanced(
        self,
        protocol_params,
        utxo_list
    ):
        """
        Test that is_transaction_balanced returns False for an unbalanced transaction.
        """
        tx = create_transaction(UNBALANCED_TX_CBOR)
        is_balanced = is_transaction_balanced(tx, utxo_list, protocol_params)
        assert not is_balanced

    def test_is_transaction_balanced_with_list_utxos(
        self,
        protocol_params
    ):
        """
        Test that is_transaction_balanced accepts a list of UTXOs.
        """
        tx = create_transaction(BALANCED_TX_CBOR)

        utxo1 = create_utxo(CBOR_DIFFERENT_VAL1)
        utxo2 = create_utxo(CBOR_DIFFERENT_VAL2)
        utxo3 = create_utxo(CBOR_DIFFERENT_VAL3)
        utxos = [utxo2, utxo1, utxo3]

        is_balanced = is_transaction_balanced(tx, utxos, protocol_params)
        assert is_balanced


class TestTransactionBalancingErrors:
    """
    Tests for error handling in transaction balancing functions.
    """

    def test_is_transaction_balanced_raises_error_if_tx_is_none(
        self,
        protocol_params,
        utxo_list
    ):
        """
        Test that is_transaction_balanced raises error if transaction is None.
        """
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            is_transaction_balanced(None, utxo_list, protocol_params)

    def test_is_transaction_balanced_raises_error_if_protocol_params_is_none(
        self,
        utxo_list
    ):
        """
        Test that is_transaction_balanced raises CardanoError if protocol_params is None.
        """
        tx = create_transaction(BALANCED_TX_CBOR)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            is_transaction_balanced(tx, utxo_list, None)

    def test_is_transaction_balanced_raises_error_if_resolved_inputs_is_none(
        self,
        protocol_params
    ):
        """
        Test that is_transaction_balanced raises CardanoError if resolved_inputs is None.
        """
        tx = create_transaction(BALANCED_TX_CBOR)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            is_transaction_balanced(tx, None, protocol_params)

    def test_balance_transaction_raises_error_if_tx_is_none(
        self,
        protocol_params,
        utxo_list,
        change_address,
        coin_selector
    ):
        """
        Test that balance_transaction raises CardanoError if transaction is None.
        """
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            balance_transaction(
                unbalanced_tx=None,
                protocol_params=protocol_params,
                change_address=change_address,
                available_utxo=utxo_list,
                coin_selector=coin_selector,
            )

    def test_balance_transaction_raises_error_if_protocol_params_is_none(
        self,
        utxo_list,
        change_address,
        coin_selector
    ):
        """
        Test that balance_transaction raises CardanoError if protocol_params is None.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            balance_transaction(
                unbalanced_tx=tx,
                protocol_params=None,
                change_address=change_address,
                available_utxo=utxo_list,
                coin_selector=coin_selector,
            )

    def test_balance_transaction_raises_error_if_change_address_is_none(
        self,
        protocol_params,
        utxo_list,
        coin_selector
    ):
        """
        Test that balance_transaction raises CardanoError if change_address is None.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            balance_transaction(
                unbalanced_tx=tx,
                protocol_params=protocol_params,
                change_address=None,
                available_utxo=utxo_list,
                coin_selector=coin_selector,
            )

    def test_balance_transaction_raises_error_if_available_utxo_is_none(
        self,
        protocol_params,
        change_address,
        coin_selector
    ):
        """
        Test that balance_transaction raises CardanoError if available_utxo is None.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            balance_transaction(
                unbalanced_tx=tx,
                protocol_params=protocol_params,
                change_address=change_address,
                available_utxo=None,
                coin_selector=coin_selector,
            )

    def test_balance_transaction_raises_error_if_coin_selector_is_none(
        self,
        protocol_params,
        utxo_list,
        change_address
    ):
        """
        Test that balance_transaction raises CardanoError if coin_selector is None.
        """
        tx = create_transaction_without_inputs(BALANCED_TX_CBOR, 15000000)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            balance_transaction(
                unbalanced_tx=tx,
                protocol_params=protocol_params,
                change_address=change_address,
                available_utxo=utxo_list,
                coin_selector=None,
            )
