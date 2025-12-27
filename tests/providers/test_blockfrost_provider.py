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

import json
import pytest
from unittest.mock import patch, Mock, MagicMock
from urllib.error import HTTPError, URLError

from cometa import NetworkMagic, Address, CardanoError
from cometa.providers import BlockfrostProvider


TEST_PROJECT_ID = "test_project_id_12345"
TEST_ADDRESS = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
TEST_ASSET_ID = "1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c96014350584c"
TEST_TX_HASH = "bb217abaca60fc0ca68c1555eca6a96d2478547818ae76ce6836133f3cc546e0"
TEST_DATUM_HASH = "923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec"


class TestBlockfrostProviderInit:
    """Tests for BlockfrostProvider initialization."""

    def test_init_with_mainnet(self):
        """Test initialization with mainnet network."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        assert provider._network == NetworkMagic.MAINNET
        assert provider._project_id == TEST_PROJECT_ID
        assert provider._base_url == "https://cardano-mainnet.blockfrost.io/api/v0/"

    def test_init_with_preprod(self):
        """Test initialization with preprod network."""
        provider = BlockfrostProvider(NetworkMagic.PREPROD, TEST_PROJECT_ID)

        assert provider._network == NetworkMagic.PREPROD
        assert provider._project_id == TEST_PROJECT_ID
        assert provider._base_url == "https://cardano-preprod.blockfrost.io/api/v0/"

    def test_init_with_preview(self):
        """Test initialization with preview network."""
        provider = BlockfrostProvider(NetworkMagic.PREVIEW, TEST_PROJECT_ID)

        assert provider._network == NetworkMagic.PREVIEW
        assert provider._project_id == TEST_PROJECT_ID
        assert provider._base_url == "https://cardano-preview.blockfrost.io/api/v0/"

    def test_init_with_sanchonet(self):
        """Test initialization with sanchonet network."""
        provider = BlockfrostProvider(NetworkMagic.SANCHONET, TEST_PROJECT_ID)

        assert provider._network == NetworkMagic.SANCHONET
        assert provider._project_id == TEST_PROJECT_ID
        assert provider._base_url == "https://cardano-sanchonet.blockfrost.io/api/v0/"

    def test_init_with_custom_base_url(self):
        """Test initialization with custom base URL."""
        custom_url = "https://custom.blockfrost.io/api/v0"
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID, base_url=custom_url)

        assert provider._base_url == "https://custom.blockfrost.io/api/v0/"

    def test_init_with_custom_base_url_trailing_slash(self):
        """Test initialization with custom base URL that has trailing slash."""
        custom_url = "https://custom.blockfrost.io/api/v0/"
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID, base_url=custom_url)

        assert provider._base_url == "https://custom.blockfrost.io/api/v0/"


class TestBlockfrostProviderHeaders:
    """Tests for BlockfrostProvider._headers method."""

    def test_headers_returns_correct_format(self):
        """Test that headers are correctly formatted."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        headers = provider._headers()

        assert "project_id" in headers
        assert "Content-Type" in headers
        assert headers["project_id"] == TEST_PROJECT_ID
        assert headers["Content-Type"] == "application/json"


class TestBlockfrostProviderGetName:
    """Tests for BlockfrostProvider.get_name method."""

    def test_get_name_returns_blockfrost(self):
        """Test that provider name is Blockfrost."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        assert provider.get_name() == "Blockfrost"


class TestBlockfrostProviderGetNetworkMagic:
    """Tests for BlockfrostProvider.get_network_magic method."""

    def test_get_network_magic_mainnet(self):
        """Test network magic for mainnet."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        assert provider.get_network_magic() == int(NetworkMagic.MAINNET)

    def test_get_network_magic_preprod(self):
        """Test network magic for preprod."""
        provider = BlockfrostProvider(NetworkMagic.PREPROD, TEST_PROJECT_ID)
        assert provider.get_network_magic() == int(NetworkMagic.PREPROD)


class TestBlockfrostProviderGet:
    """Tests for BlockfrostProvider._get method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_success(self, mock_urlopen):
        """Test successful GET request."""
        mock_response = Mock()
        mock_response.read.return_value = b'{"key": "value"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        result = provider._get("test/endpoint")

        assert result == {"key": "value"}

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_404_returns_none(self, mock_urlopen):
        """Test GET request with 404 returns None."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        result = provider._get("test/endpoint")

        assert result is None

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_http_error_raises_cardano_error(self, mock_urlopen):
        """Test GET request with HTTP error raises CardanoError."""
        mock_fp = Mock()
        mock_fp.read.return_value = b"Error message"
        mock_urlopen.side_effect = HTTPError(
            url="test", code=500, msg="Server Error", hdrs={}, fp=mock_fp
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider._get("test/endpoint")

        assert "Blockfrost API error 500" in str(exc_info.value)

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_url_error_raises_cardano_error(self, mock_urlopen):
        """Test GET request with URL error raises CardanoError."""
        mock_urlopen.side_effect = URLError("Connection failed")

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider._get("test/endpoint")

        assert "Network error" in str(exc_info.value)


class TestBlockfrostProviderPost:
    """Tests for BlockfrostProvider._post method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_post_success(self, mock_urlopen):
        """Test successful POST request."""
        mock_response = Mock()
        mock_response.read.return_value = b'{"result": "success"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        result = provider._post("test/endpoint", b"test data")

        assert result == {"result": "success"}

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_post_with_custom_content_type(self, mock_urlopen):
        """Test POST request with custom content type."""
        mock_response = Mock()
        mock_response.read.return_value = b'{"result": "success"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        result = provider._post("test/endpoint", b"test data", content_type="application/cbor")

        assert result == {"result": "success"}

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_post_http_error_raises_cardano_error(self, mock_urlopen):
        """Test POST request with HTTP error raises CardanoError."""
        mock_fp = Mock()
        mock_fp.read.return_value = b"Error message"
        mock_urlopen.side_effect = HTTPError(
            url="test", code=400, msg="Bad Request", hdrs={}, fp=mock_fp
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider._post("test/endpoint", b"test data")

        assert "Blockfrost API error 400" in str(exc_info.value)


class TestBlockfrostProviderGetParameters:
    """Tests for BlockfrostProvider.get_parameters method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_parameters_success(self, mock_urlopen):
        """Test successful retrieval of protocol parameters."""
        mock_data = {
            "min_fee_a": 44,
            "min_fee_b": 155381,
            "max_block_size": 90112,
            "max_tx_size": 16384,
            "max_block_header_size": 1100,
            "key_deposit": "2000000",
            "pool_deposit": "500000000",
            "e_max": 18,
            "n_opt": 500,
            "a0": 0.3,
            "rho": 0.003,
            "tau": 0.2,
            "protocol_major_ver": 8,
            "protocol_minor_ver": 0,
            "min_pool_cost": "340000000",
            "price_mem": 0.0577,
            "price_step": 0.0000721,
            "max_tx_ex_mem": "14000000",
            "max_tx_ex_steps": "10000000000",
            "max_block_ex_mem": "62000000",
            "max_block_ex_steps": "20000000000",
            "max_val_size": "5000",
            "collateral_percent": 150,
            "max_collateral_inputs": 3,
            "coins_per_utxo_size": "4310",
        }
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        params = provider.get_parameters()

        assert params is not None
        assert params.min_fee_a == 44
        assert params.min_fee_b == 155381

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_parameters_with_cost_models(self, mock_urlopen):
        """Test retrieval of protocol parameters with cost models."""
        mock_data = {
            "min_fee_a": 44,
            "min_fee_b": 155381,
            "cost_models_raw": {
                "PlutusV1": [205665, 812, 1, 1, 1000, 571, 0, 1, 1000, 24177, 4, 1],
                "PlutusV2": [205665, 812, 1, 1, 1000, 571, 0, 1, 1000, 24177, 4, 1],
            },
            "protocol_major_ver": 8,
            "protocol_minor_ver": 0,
        }
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        params = provider.get_parameters()

        assert params is not None
        assert params.cost_models is not None

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_parameters_api_error(self, mock_urlopen):
        """Test get_parameters with API error."""
        mock_fp = Mock()
        mock_fp.read.return_value = b'{"message": "API error"}'
        mock_urlopen.side_effect = HTTPError(
            url="test", code=500, msg="Server Error", hdrs={}, fp=mock_fp
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError):
            provider.get_parameters()


class TestBlockfrostProviderGetUnspentOutputs:
    """Tests for BlockfrostProvider.get_unspent_outputs method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_empty(self, mock_urlopen):
        """Test get_unspent_outputs with no UTXOs."""
        mock_response = Mock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.get_unspent_outputs(TEST_ADDRESS)

        assert utxos == []

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_with_data(self, mock_urlopen):
        """Test get_unspent_outputs with UTXO data."""
        mock_data = [
            {
                "tx_hash": TEST_TX_HASH,
                "output_index": 0,
                "amount": [{"unit": "lovelace", "quantity": "1000000"}],
                "address": TEST_ADDRESS,
            }
        ]
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.get_unspent_outputs(TEST_ADDRESS)

        assert len(utxos) == 1
        assert utxos[0].output.value.coin == 1000000

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_404(self, mock_urlopen):
        """Test get_unspent_outputs with 404 returns empty list."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.get_unspent_outputs(TEST_ADDRESS)

        assert utxos == []

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_with_address_object(self, mock_urlopen):
        """Test get_unspent_outputs with Address object."""
        mock_response = Mock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        address = Address.from_string(TEST_ADDRESS)
        utxos = provider.get_unspent_outputs(address)

        assert utxos == []


class TestBlockfrostProviderGetRewardsBalance:
    """Tests for BlockfrostProvider.get_rewards_balance method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_rewards_balance_success(self, mock_urlopen):
        """Test successful rewards balance retrieval."""
        mock_data = {"withdrawable_amount": "5000000"}
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        balance = provider.get_rewards_balance("stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn")

        assert balance == 5000000

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_rewards_balance_404_returns_zero(self, mock_urlopen):
        """Test get_rewards_balance with 404 returns 0."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        balance = provider.get_rewards_balance("stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn")

        assert balance == 0

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_rewards_balance_missing_field(self, mock_urlopen):
        """Test get_rewards_balance with missing withdrawable_amount field."""
        mock_data = {}
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        balance = provider.get_rewards_balance("stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn")

        assert balance == 0


class TestBlockfrostProviderGetUnspentOutputsWithAsset:
    """Tests for BlockfrostProvider.get_unspent_outputs_with_asset method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_with_asset_empty(self, mock_urlopen):
        """Test get_unspent_outputs_with_asset with no UTXOs."""
        mock_response = Mock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.get_unspent_outputs_with_asset(TEST_ADDRESS, TEST_ASSET_ID)

        assert utxos == []

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_outputs_with_asset_404(self, mock_urlopen):
        """Test get_unspent_outputs_with_asset with 404 returns empty list."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.get_unspent_outputs_with_asset(TEST_ADDRESS, TEST_ASSET_ID)

        assert utxos == []


class TestBlockfrostProviderGetUnspentOutputByNft:
    """Tests for BlockfrostProvider.get_unspent_output_by_nft method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_output_by_nft_not_found(self, mock_urlopen):
        """Test get_unspent_output_by_nft with NFT not found."""
        mock_response = Mock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider.get_unspent_output_by_nft(TEST_ASSET_ID)

        assert "NFT not found" in str(exc_info.value)

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_get_unspent_output_by_nft_multiple_addresses(self, mock_urlopen):
        """Test get_unspent_output_by_nft with NFT in multiple addresses."""
        mock_data = [
            {"address": TEST_ADDRESS, "quantity": "1"},
            {"address": "addr_test1qzz", "quantity": "1"},
        ]
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(mock_data).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider.get_unspent_output_by_nft(TEST_ASSET_ID)

        assert "NFT must be held by only one address" in str(exc_info.value)


class TestBlockfrostProviderResolveUnspentOutputs:
    """Tests for BlockfrostProvider.resolve_unspent_outputs method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_resolve_unspent_outputs_empty_list(self, mock_urlopen):
        """Test resolve_unspent_outputs with empty input list."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        utxos = provider.resolve_unspent_outputs([])

        assert len(utxos) == 0


class TestBlockfrostProviderResolveDatum:
    """Tests for BlockfrostProvider.resolve_datum method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_resolve_datum_not_found(self, mock_urlopen):
        """Test resolve_datum with datum not found."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError) as exc_info:
            provider.resolve_datum(TEST_DATUM_HASH)

        assert "Datum not found" in str(exc_info.value)


class TestBlockfrostProviderConfirmTransaction:
    """Tests for BlockfrostProvider.confirm_transaction method."""

    @patch("cometa.providers.blockfrost_provider.time")
    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_confirm_transaction_already_confirmed(self, mock_urlopen, mock_time):
        """Test confirm_transaction with already confirmed transaction."""
        mock_response = Mock()
        mock_response.read.return_value = b"[]"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        confirmed = provider.confirm_transaction(TEST_TX_HASH, timeout_ms=1000)

        assert confirmed is True

    @patch("cometa.providers.blockfrost_provider.time")
    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_confirm_transaction_timeout(self, mock_urlopen, mock_time):
        """Test confirm_transaction with timeout."""
        mock_urlopen.side_effect = HTTPError(
            url="test", code=404, msg="Not Found", hdrs={}, fp=None
        )

        mock_time.time.side_effect = [0, 1, 2, 3]
        mock_time.sleep = Mock()

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        confirmed = provider.confirm_transaction(TEST_TX_HASH, timeout_ms=100)

        assert confirmed is False


class TestBlockfrostProviderSubmitTransaction:
    """Tests for BlockfrostProvider.submit_transaction method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_submit_transaction_success(self, mock_urlopen):
        """Test successful transaction submission."""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps(TEST_TX_HASH).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)
        tx_id = provider.submit_transaction("82a400818258200000000000000000000000000000000000000000000000000000000000000000000181825839000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000f4240021a0002929f031a0081967da0f5f6")

        assert tx_id == TEST_TX_HASH

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_submit_transaction_error(self, mock_urlopen):
        """Test transaction submission with error."""
        mock_fp = Mock()
        mock_fp.read.return_value = b'{"message": "Transaction validation error"}'
        mock_urlopen.side_effect = HTTPError(
            url="test", code=400, msg="Bad Request", hdrs={}, fp=mock_fp
        )

        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        valid_tx_cbor = "82a400818258200000000000000000000000000000000000000000000000000000000000000000000181825839000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000f4240021a0002929f031a0081967da0f5f6"

        with pytest.raises(CardanoError) as exc_info:
            provider.submit_transaction(valid_tx_cbor)

        assert "Failed to submit transaction" in str(exc_info.value)


class TestBlockfrostProviderEvaluateTransaction:
    """Tests for BlockfrostProvider.evaluate_transaction method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_evaluate_transaction_invalid_cbor(self, mock_urlopen):
        """Test evaluate_transaction with invalid CBOR."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        with pytest.raises(CardanoError):
            provider.evaluate_transaction("invalid_cbor")


class TestBlockfrostProviderParseUtxoJson:
    """Tests for BlockfrostProvider._parse_utxo_json method."""

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_parse_utxo_json_with_lovelace_only(self, mock_urlopen):
        """Test parsing UTXO JSON with only lovelace."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        utxo_data = {
            "tx_hash": TEST_TX_HASH,
            "output_index": 0,
            "amount": [{"unit": "lovelace", "quantity": "5000000"}],
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 5000000

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_parse_utxo_json_with_multi_asset(self, mock_urlopen):
        """Test parsing UTXO JSON with multi-asset."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        policy_id = "1ec85dcee27f2d90ec1f9a1e4ce74a667dc9be8b184463223f9c9601"
        asset_name = "4350584c"
        unit = policy_id + asset_name

        utxo_data = {
            "tx_hash": TEST_TX_HASH,
            "output_index": 0,
            "amount": [
                {"unit": "lovelace", "quantity": "5000000"},
                {"unit": unit, "quantity": "100"},
            ],
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.value.coin == 5000000
        assert utxo.output.value.multi_asset is not None

    @patch("cometa.providers.blockfrost_provider.urlopen")
    def test_parse_utxo_json_with_datum_hash(self, mock_urlopen):
        """Test parsing UTXO JSON with datum hash."""
        provider = BlockfrostProvider(NetworkMagic.MAINNET, TEST_PROJECT_ID)

        utxo_data = {
            "tx_hash": TEST_TX_HASH,
            "output_index": 0,
            "amount": [{"unit": "lovelace", "quantity": "5000000"}],
            "data_hash": TEST_DATUM_HASH,
        }

        utxo = provider._parse_utxo_json(TEST_ADDRESS, utxo_data)

        assert utxo is not None
        assert utxo.output.datum is not None


class TestBlockfrostHelperFunctions:
    """Tests for helper functions in blockfrost_provider module."""

    def test_network_magic_to_prefix_mainnet(self):
        """Test network magic to prefix conversion for mainnet."""
        from cometa.providers.blockfrost_provider import _network_magic_to_prefix

        prefix = _network_magic_to_prefix(NetworkMagic.MAINNET)
        assert prefix == "cardano-mainnet"

    def test_network_magic_to_prefix_preprod(self):
        """Test network magic to prefix conversion for preprod."""
        from cometa.providers.blockfrost_provider import _network_magic_to_prefix

        prefix = _network_magic_to_prefix(NetworkMagic.PREPROD)
        assert prefix == "cardano-preprod"

    def test_network_magic_to_prefix_preview(self):
        """Test network magic to prefix conversion for preview."""
        from cometa.providers.blockfrost_provider import _network_magic_to_prefix

        prefix = _network_magic_to_prefix(NetworkMagic.PREVIEW)
        assert prefix == "cardano-preview"

    def test_network_magic_to_prefix_sanchonet(self):
        """Test network magic to prefix conversion for sanchonet."""
        from cometa.providers.blockfrost_provider import _network_magic_to_prefix

        prefix = _network_magic_to_prefix(NetworkMagic.SANCHONET)
        assert prefix == "cardano-sanchonet"

    def test_network_magic_to_prefix_unknown(self):
        """Test network magic to prefix conversion for unknown network."""
        from cometa.providers.blockfrost_provider import _network_magic_to_prefix

        prefix = _network_magic_to_prefix(999999)
        assert prefix == "unknown"
