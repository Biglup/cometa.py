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
from cometa import NetworkMagic


class TestNetworkMagic:
    """Tests for the NetworkMagic enum."""

    # pylint: disable=no-self-use

    def test_network_magic_values(self):
        """Test that NetworkMagic enum values are correct."""
        assert NetworkMagic.PREPROD == 1
        assert NetworkMagic.PREVIEW == 2
        assert NetworkMagic.SANCHONET == 4
        assert NetworkMagic.MAINNET == 764824073

    def test_network_magic_from_int(self):
        """Test creating NetworkMagic from integer values."""
        assert NetworkMagic(1) == NetworkMagic.PREPROD
        assert NetworkMagic(2) == NetworkMagic.PREVIEW
        assert NetworkMagic(4) == NetworkMagic.SANCHONET
        assert NetworkMagic(764824073) == NetworkMagic.MAINNET

    def test_network_magic_comparison(self):
        """Test comparison between NetworkMagic values."""
        assert NetworkMagic.PREPROD != NetworkMagic.MAINNET
        assert NetworkMagic.PREPROD == NetworkMagic.PREPROD
        assert NetworkMagic.PREVIEW == NetworkMagic.PREVIEW
        assert NetworkMagic.SANCHONET == NetworkMagic.SANCHONET
        assert NetworkMagic.MAINNET == NetworkMagic.MAINNET

    def test_network_magic_names(self):
        """Test that NetworkMagic enum has correct names."""
        assert NetworkMagic.PREPROD.name == "PREPROD"
        assert NetworkMagic.PREVIEW.name == "PREVIEW"
        assert NetworkMagic.SANCHONET.name == "SANCHONET"
        assert NetworkMagic.MAINNET.name == "MAINNET"

    def test_network_magic_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            NetworkMagic(0)
        with pytest.raises(ValueError):
            NetworkMagic(3)
        with pytest.raises(ValueError):
            NetworkMagic(-1)
        with pytest.raises(ValueError):
            NetworkMagic(100)

    def test_network_magic_is_int_enum(self):
        """Test that NetworkMagic values can be used as integers."""
        assert isinstance(NetworkMagic.PREPROD, int)
        assert isinstance(NetworkMagic.PREVIEW, int)
        assert isinstance(NetworkMagic.SANCHONET, int)
        assert isinstance(NetworkMagic.MAINNET, int)
        assert NetworkMagic.PREPROD + 1 == 2
        assert NetworkMagic.PREVIEW - 1 == 1

    def test_network_magic_iteration(self):
        """Test iteration over NetworkMagic enum."""
        values = list(NetworkMagic)
        assert len(values) == 4
        assert NetworkMagic.PREPROD in values
        assert NetworkMagic.PREVIEW in values
        assert NetworkMagic.SANCHONET in values
        assert NetworkMagic.MAINNET in values

    def test_network_magic_membership(self):
        """Test membership testing with NetworkMagic."""
        assert 1 in NetworkMagic.__members__.values()
        assert 2 in NetworkMagic.__members__.values()
        assert 4 in NetworkMagic.__members__.values()
        assert 764824073 in NetworkMagic.__members__.values()
        assert "PREPROD" in NetworkMagic.__members__
        assert "PREVIEW" in NetworkMagic.__members__
        assert "SANCHONET" in NetworkMagic.__members__
        assert "MAINNET" in NetworkMagic.__members__

    def test_network_magic_to_string_mainnet(self):
        """Test converting MAINNET to string (from C test: canConvertMainnet)."""
        result = str(NetworkMagic.MAINNET)
        assert result == "mainnet"

    def test_network_magic_to_string_preprod(self):
        """Test converting PREPROD to string (from C test: canConvertPreprod)."""
        result = str(NetworkMagic.PREPROD)
        assert result == "preprod"

    def test_network_magic_to_string_preview(self):
        """Test converting PREVIEW to string (from C test: canConvertPreview)."""
        result = str(NetworkMagic.PREVIEW)
        assert result == "preview"

    def test_network_magic_to_string_sanchonet(self):
        """Test converting SANCHONET to string (from C test: canConvertSanchonet)."""
        result = str(NetworkMagic.SANCHONET)
        assert result == "sanchonet"

    def test_network_magic_repr(self):
        """Test repr of NetworkMagic values."""
        assert repr(NetworkMagic.PREPROD) == "NetworkMagic.PREPROD"
        assert repr(NetworkMagic.PREVIEW) == "NetworkMagic.PREVIEW"
        assert repr(NetworkMagic.SANCHONET) == "NetworkMagic.SANCHONET"
        assert repr(NetworkMagic.MAINNET) == "NetworkMagic.MAINNET"

    def test_network_magic_bool_conversion(self):
        """Test boolean conversion of NetworkMagic values."""
        assert bool(NetworkMagic.PREPROD) is True
        assert bool(NetworkMagic.PREVIEW) is True
        assert bool(NetworkMagic.SANCHONET) is True
        assert bool(NetworkMagic.MAINNET) is True

    def test_network_magic_arithmetic(self):
        """Test arithmetic operations with NetworkMagic values."""
        assert NetworkMagic.PREPROD + NetworkMagic.PREVIEW == 3
        assert NetworkMagic.PREVIEW * 2 == 4
        assert NetworkMagic.SANCHONET // 2 == 2
        assert NetworkMagic.MAINNET % 10 == 3

    def test_network_magic_hash(self):
        """Test that NetworkMagic values are hashable."""
        network_set = {
            NetworkMagic.PREPROD,
            NetworkMagic.PREVIEW,
            NetworkMagic.SANCHONET,
            NetworkMagic.MAINNET
        }
        assert len(network_set) == 4
        assert NetworkMagic.PREPROD in network_set
        assert NetworkMagic.PREVIEW in network_set
        assert NetworkMagic.SANCHONET in network_set
        assert NetworkMagic.MAINNET in network_set

    def test_network_magic_as_dict_key(self):
        """Test using NetworkMagic as dictionary key."""
        network_dict = {
            NetworkMagic.PREPROD: "preprod",
            NetworkMagic.PREVIEW: "preview",
            NetworkMagic.SANCHONET: "sanchonet",
            NetworkMagic.MAINNET: "mainnet"
        }
        assert network_dict[NetworkMagic.PREPROD] == "preprod"
        assert network_dict[NetworkMagic.PREVIEW] == "preview"
        assert network_dict[NetworkMagic.SANCHONET] == "sanchonet"
        assert network_dict[NetworkMagic.MAINNET] == "mainnet"

    def test_network_magic_ordering(self):
        """Test ordering comparison between NetworkMagic values."""
        assert NetworkMagic.PREPROD < NetworkMagic.PREVIEW
        assert NetworkMagic.PREVIEW < NetworkMagic.SANCHONET
        assert NetworkMagic.SANCHONET < NetworkMagic.MAINNET
        assert NetworkMagic.MAINNET > NetworkMagic.PREPROD
        assert NetworkMagic.PREPROD <= NetworkMagic.PREPROD
        assert NetworkMagic.MAINNET >= NetworkMagic.MAINNET

    def test_network_magic_string_contains_lowercase(self):
        """Test that string representation uses lowercase names."""
        assert str(NetworkMagic.PREPROD) == str(NetworkMagic.PREPROD).lower()
        assert str(NetworkMagic.PREVIEW) == str(NetworkMagic.PREVIEW).lower()
        assert str(NetworkMagic.SANCHONET) == str(NetworkMagic.SANCHONET).lower()
        assert str(NetworkMagic.MAINNET) == str(NetworkMagic.MAINNET).lower()

    def test_network_magic_all_have_string_representation(self):
        """Test that all NetworkMagic values have string representation."""
        for magic in NetworkMagic:
            string_repr = str(magic)
            assert isinstance(string_repr, str)
            assert len(string_repr) > 0

    def test_network_magic_unique_values(self):
        """Test that all NetworkMagic values are unique."""
        values = [magic.value for magic in NetworkMagic]
        assert len(values) == len(set(values))

    def test_network_magic_type_checking(self):
        """Test type checking of NetworkMagic instances."""
        from enum import IntEnum
        assert isinstance(NetworkMagic.MAINNET, NetworkMagic)
        assert isinstance(NetworkMagic.MAINNET, IntEnum)
        assert isinstance(NetworkMagic.MAINNET, int)
