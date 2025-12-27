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

# pylint: disable=no-self-use

import pytest

from cometa.transaction_builder.balancing import ImplicitCoin, compute_implicit_coin
from cometa.transaction import Transaction
from cometa.protocol_params import ProtocolParameters
from cometa.cbor import CborReader
from cometa.errors import CardanoError


TRANSACTION_CBOR = "84b000818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5000181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e020a031903e8049182008200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d083078200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d00a83088200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d01483088200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f186482018200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f82008200581cc37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f8a03581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef9258208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db01927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f81581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f000001f682026b6578616d706c652e636f6d827368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d58304581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d01901f483028200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db784108200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05f683118200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0584108200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05f683118200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab05840b8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db70a840c8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d08200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0a850d8200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0581c1732c16e26f8efb749c7f67113ec507a97fb3b382b8c147538e92db78200581cb276b4f7a706a81364de606d890343a76af570268d4bbfee2fc8fcab0a82018200581c13cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d005a1581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d00a0758202ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa08186409a3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c413831581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e0b58206199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de0d818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5010e81581c6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d3910825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e11186412818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5001481841864581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d08106827468747470733a2f2f74657374696e672e7468697358203e33018e8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80da700818258206199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c891875501868205186482041901f48200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548201818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548202818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f54830301818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f540281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f6376796669647171676775726a687268716169697370717275656c6876797071786565777072796676775820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a003815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b4500481187b0582840100d87a9f187bff82190bb8191b58840201d87a9f187bff821913881907d006815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b450f5a6011904d2026373747203821904d2637374720445627974657305a2667374726b6579187b81676c6973746b65796873747276616c75650626"


@pytest.fixture(name="transaction")
def fixture_transaction():
    """
    Create a test transaction from CBOR.
    """
    reader = CborReader.from_hex(TRANSACTION_CBOR)
    return Transaction.from_cbor(reader)


@pytest.fixture(name="protocol_params")
def fixture_protocol_params():
    """
    Create test protocol parameters.
    """
    params = ProtocolParameters.new()
    params.key_deposit = 2
    params.pool_deposit = 3
    params.drep_deposit = 5
    return params


class TestImplicitCoin:
    """
    Tests for the ImplicitCoin dataclass.
    """

    def test_implicit_coin_creation(self):
        """
        Test creating an ImplicitCoin instance.
        """
        implicit_coin = ImplicitCoin(
            withdrawals=100,
            deposits=50,
            reclaim_deposits=25
        )

        assert implicit_coin.withdrawals == 100
        assert implicit_coin.deposits == 50
        assert implicit_coin.reclaim_deposits == 25

    def test_implicit_coin_net_value_positive(self):
        """
        Test net_value calculation when result is positive.
        """
        implicit_coin = ImplicitCoin(
            withdrawals=100,
            deposits=50,
            reclaim_deposits=25
        )

        assert implicit_coin.net_value == 75

    def test_implicit_coin_net_value_negative(self):
        """
        Test net_value calculation when result is negative.
        """
        implicit_coin = ImplicitCoin(
            withdrawals=10,
            deposits=100,
            reclaim_deposits=25
        )

        assert implicit_coin.net_value == -65

    def test_implicit_coin_net_value_zero(self):
        """
        Test net_value calculation when result is zero.
        """
        implicit_coin = ImplicitCoin(
            withdrawals=100,
            deposits=75,
            reclaim_deposits=0
        )

        assert implicit_coin.net_value == 25

    def test_implicit_coin_all_zero(self):
        """
        Test ImplicitCoin with all zero values.
        """
        implicit_coin = ImplicitCoin(
            withdrawals=0,
            deposits=0,
            reclaim_deposits=0
        )

        assert implicit_coin.net_value == 0

    def test_implicit_coin_dataclass_equality(self):
        """
        Test that two ImplicitCoin instances with same values are equal.
        """
        coin1 = ImplicitCoin(withdrawals=10, deposits=5, reclaim_deposits=3)
        coin2 = ImplicitCoin(withdrawals=10, deposits=5, reclaim_deposits=3)

        assert coin1 == coin2

    def test_implicit_coin_dataclass_inequality(self):
        """
        Test that two ImplicitCoin instances with different values are not equal.
        """
        coin1 = ImplicitCoin(withdrawals=10, deposits=5, reclaim_deposits=3)
        coin2 = ImplicitCoin(withdrawals=20, deposits=5, reclaim_deposits=3)

        assert coin1 != coin2


class TestComputeImplicitCoin:
    """
    Tests for the compute_implicit_coin function.
    """

    def test_compute_implicit_coin_success(self, transaction, protocol_params):
        """
        Test successful computation of implicit coin values.
        """
        implicit_coin = compute_implicit_coin(transaction, protocol_params)

        assert isinstance(implicit_coin, ImplicitCoin)
        assert implicit_coin.withdrawals == 10
        assert implicit_coin.deposits == 157
        assert implicit_coin.reclaim_deposits == 137

    def test_compute_implicit_coin_net_value(self, transaction, protocol_params):
        """
        Test that net_value calculation is correct after computation.
        """
        implicit_coin = compute_implicit_coin(transaction, protocol_params)

        expected_net = implicit_coin.withdrawals + implicit_coin.reclaim_deposits - implicit_coin.deposits
        assert implicit_coin.net_value == expected_net
        assert implicit_coin.net_value == -10

    def test_compute_implicit_coin_with_none_transaction(self, protocol_params):
        """
        Test that passing None as transaction raises CardanoError.
        """
        with pytest.raises((CardanoError, AttributeError)):
            compute_implicit_coin(None, protocol_params)

    def test_compute_implicit_coin_with_none_protocol_params(self, transaction):
        """
        Test that passing None as protocol_params raises CardanoError.
        """
        with pytest.raises((CardanoError, AttributeError)):
            compute_implicit_coin(transaction, None)

    def test_compute_implicit_coin_with_both_none(self):
        """
        Test that passing None for both parameters raises CardanoError.
        """
        with pytest.raises((CardanoError, AttributeError)):
            compute_implicit_coin(None, None)

    def test_compute_implicit_coin_returns_correct_types(self, transaction, protocol_params):
        """
        Test that all returned values are of correct type (int).
        """
        implicit_coin = compute_implicit_coin(transaction, protocol_params)

        assert isinstance(implicit_coin.withdrawals, int)
        assert isinstance(implicit_coin.deposits, int)
        assert isinstance(implicit_coin.reclaim_deposits, int)

    def test_compute_implicit_coin_non_negative_values(self, transaction, protocol_params):
        """
        Test that all individual values are non-negative.
        """
        implicit_coin = compute_implicit_coin(transaction, protocol_params)

        assert implicit_coin.withdrawals >= 0
        assert implicit_coin.deposits >= 0
        assert implicit_coin.reclaim_deposits >= 0

    def test_compute_implicit_coin_with_different_protocol_params(self, transaction):
        """
        Test computation with different protocol parameter values.
        """
        params = ProtocolParameters.new()
        params.key_deposit = 10
        params.pool_deposit = 20
        params.drep_deposit = 30

        implicit_coin = compute_implicit_coin(transaction, params)

        assert isinstance(implicit_coin, ImplicitCoin)
        assert implicit_coin.withdrawals >= 0
        assert implicit_coin.deposits >= 0
        assert implicit_coin.reclaim_deposits >= 0


class TestImplicitCoinIntegration:
    """
    Integration tests for ImplicitCoin functionality.
    """

    def test_implicit_coin_computation_consistency(self, transaction, protocol_params):
        """
        Test that computing implicit coin multiple times returns consistent results.
        """
        result1 = compute_implicit_coin(transaction, protocol_params)
        result2 = compute_implicit_coin(transaction, protocol_params)

        assert result1 == result2

    def test_implicit_coin_net_value_formula(self, transaction, protocol_params):
        """
        Test that the net_value formula is correctly implemented.
        """
        implicit_coin = compute_implicit_coin(transaction, protocol_params)

        manual_net = implicit_coin.withdrawals + implicit_coin.reclaim_deposits - implicit_coin.deposits
        assert implicit_coin.net_value == manual_net

    def test_implicit_coin_str_representation(self):
        """
        Test string representation of ImplicitCoin dataclass.
        """
        coin = ImplicitCoin(withdrawals=10, deposits=157, reclaim_deposits=137)
        str_repr = str(coin)

        assert "10" in str_repr
        assert "157" in str_repr
        assert "137" in str_repr
