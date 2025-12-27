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
from cometa import NetworkId


class TestNetworkId:
    """Tests for the NetworkId enum."""

    def test_network_id_values(self):
        """Test that NetworkId enum values are correct."""
        assert NetworkId.TESTNET == 0
        assert NetworkId.MAINNET == 1

    def test_network_id_from_int(self):
        """Test creating NetworkId from integer values."""
        assert NetworkId(0) == NetworkId.TESTNET
        assert NetworkId(1) == NetworkId.MAINNET

    def test_network_id_comparison(self):
        """Test comparison between NetworkId values."""
        assert NetworkId.TESTNET != NetworkId.MAINNET
        assert NetworkId.TESTNET == NetworkId.TESTNET
        assert NetworkId.MAINNET == NetworkId.MAINNET

    def test_network_id_names(self):
        """Test that NetworkId enum has correct names."""
        assert NetworkId.TESTNET.name == "TESTNET"
        assert NetworkId.MAINNET.name == "MAINNET"

    def test_network_id_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            NetworkId(2)
        with pytest.raises(ValueError):
            NetworkId(-1)
        with pytest.raises(ValueError):
            NetworkId(100)

    def test_network_id_is_int_enum(self):
        """Test that NetworkId values can be used as integers."""
        assert isinstance(NetworkId.TESTNET, int)
        assert isinstance(NetworkId.MAINNET, int)
        assert NetworkId.TESTNET + 1 == 1
        assert NetworkId.MAINNET - 1 == 0

    def test_network_id_iteration(self):
        """Test iteration over NetworkId enum."""
        values = list(NetworkId)
        assert len(values) == 2
        assert NetworkId.TESTNET in values
        assert NetworkId.MAINNET in values

    def test_network_id_membership(self):
        """Test membership testing with NetworkId."""
        assert 0 in NetworkId.__members__.values()
        assert 1 in NetworkId.__members__.values()
        assert "TESTNET" in NetworkId.__members__
        assert "MAINNET" in NetworkId.__members__

    def test_network_id_string_representation(self):
        """Test string representation of NetworkId values."""
        assert str(NetworkId.TESTNET) == "NetworkId.TESTNET"
        assert str(NetworkId.MAINNET) == "NetworkId.MAINNET"

    def test_network_id_repr(self):
        """Test repr of NetworkId values."""
        assert repr(NetworkId.TESTNET) == "<NetworkId.TESTNET: 0>"
        assert repr(NetworkId.MAINNET) == "<NetworkId.MAINNET: 1>"

    def test_network_id_bool_conversion(self):
        """Test boolean conversion of NetworkId values."""
        assert bool(NetworkId.TESTNET) is False
        assert bool(NetworkId.MAINNET) is True

    def test_network_id_arithmetic(self):
        """Test arithmetic operations with NetworkId values."""
        assert NetworkId.TESTNET + NetworkId.MAINNET == 1
        assert NetworkId.MAINNET * 2 == 2
        assert NetworkId.MAINNET // 1 == 1

    def test_network_id_hash(self):
        """Test that NetworkId values are hashable."""
        network_set = {NetworkId.TESTNET, NetworkId.MAINNET}
        assert len(network_set) == 2
        assert NetworkId.TESTNET in network_set
        assert NetworkId.MAINNET in network_set

    def test_network_id_as_dict_key(self):
        """Test using NetworkId as dictionary key."""
        network_dict = {
            NetworkId.TESTNET: "testnet",
            NetworkId.MAINNET: "mainnet"
        }
        assert network_dict[NetworkId.TESTNET] == "testnet"
        assert network_dict[NetworkId.MAINNET] == "mainnet"

    def test_network_id_ordering(self):
        """Test ordering comparison between NetworkId values."""
        assert NetworkId.TESTNET < NetworkId.MAINNET
        assert NetworkId.MAINNET > NetworkId.TESTNET
        assert NetworkId.TESTNET <= NetworkId.TESTNET
        assert NetworkId.MAINNET >= NetworkId.MAINNET
