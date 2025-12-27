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
    ByronAddress,
    ByronAddressAttributes,
    ByronAddressType,
    Blake2bHash,
    NetworkId,
    CardanoError,
    Address
)


BYRON_MAINNET_YOROI = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi"
BYRON_MAINNET_YOROI_BYTES = bytes([
    0x82, 0xd8, 0x18, 0x58, 0x21, 0x83, 0x58, 0x1c, 0xba, 0x97, 0x0a, 0xd3, 0x66, 0x54, 0xd8, 0xdd,
    0x8f, 0x74, 0x27, 0x4b, 0x73, 0x34, 0x52, 0xdd, 0xea, 0xb9, 0xa6, 0x2a, 0x39, 0x77, 0x46, 0xbe,
    0x3c, 0x42, 0xcc, 0xdd, 0xa0, 0x00, 0x1a, 0x90, 0x26, 0xda, 0x5b
])
BYRON_YOROI_ROOT_HEX = "ba970ad36654d8dd8f74274b733452ddeab9a62a397746be3c42ccdd"

BYRON_TESTNET_DAEDALUS = "37btjrVyb4KEB2STADSsj3MYSAdj52X5FrFWpw2r7Wmj2GDzXjFRsHWuZqrw7zSkwopv8Ci3VWeg6bisU9dgJxW5hb2MZYeduNKbQJrqz3zVBsu9nT"
BYRON_TESTNET_DAEDALUS_BYTES = bytes([
    0x82, 0xd8, 0x18, 0x58, 0x49, 0x83, 0x58, 0x1c, 0x9c, 0x70, 0x85, 0x38, 0xa7, 0x63, 0xff, 0x27,
    0x16, 0x99, 0x87, 0xa4, 0x89, 0xe3, 0x50, 0x57, 0xef, 0x3c, 0xd3, 0x77, 0x8c, 0x05, 0xe9, 0x6f,
    0x7b, 0xa9, 0x45, 0x0e, 0xa2, 0x01, 0x58, 0x1e, 0x58, 0x1c, 0x9c, 0x17, 0x22, 0xf7, 0xe4, 0x46,
    0x68, 0x92, 0x56, 0xe1, 0xa3, 0x02, 0x60, 0xf3, 0x51, 0x0d, 0x55, 0x8d, 0x99, 0xd0, 0xc3, 0x91,
    0xf2, 0xba, 0x89, 0xcb, 0x69, 0x77, 0x02, 0x45, 0x1a, 0x41, 0x70, 0xcb, 0x17, 0x00, 0x1a, 0x69,
    0x79, 0x12, 0x6c
])


class TestByronAddressFromCredentials:
    """Tests for ByronAddress.from_credentials factory method."""

    def test_can_create_from_valid_credentials(self):
        """Test creating Byron address from valid root hash and attributes."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        assert addr is not None
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_can_create_with_pubkey_type(self):
        """Test creating Byron address with PUBKEY type."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        assert addr.address_type == ByronAddressType.PUBKEY

    def test_can_create_with_script_type(self):
        """Test creating Byron address with SCRIPT type."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.SCRIPT)

        assert addr.address_type == ByronAddressType.SCRIPT

    def test_can_create_with_redeem_type(self):
        """Test creating Byron address with REDEEM type."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.REDEEM)

        assert addr.address_type == ByronAddressType.REDEEM

    def test_can_create_with_mainnet_attributes(self):
        """Test creating Byron address with mainnet attributes."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        assert addr.network_id == NetworkId.MAINNET

    def test_can_create_with_testnet_attributes(self):
        """Test creating Byron address with testnet attributes."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.testnet(1097911063)
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        assert addr.network_id == NetworkId.TESTNET

    def test_can_create_with_derivation_path(self):
        """Test creating Byron address with a derivation path."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        derivation_path = bytes([0x9c, 0x17, 0x22, 0xf7])
        attrs = ByronAddressAttributes(derivation_path=derivation_path, magic=-1)
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        retrieved_attrs = addr.attributes
        assert retrieved_attrs.derivation_path == derivation_path

    def test_can_create_with_empty_derivation_path(self):
        """Test creating Byron address with empty derivation path."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes(derivation_path=b"", magic=-1)
        addr = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        retrieved_attrs = addr.attributes
        assert retrieved_attrs.derivation_path == b""


class TestByronAddressFromAddress:
    """Tests for ByronAddress.from_address factory method."""

    def test_can_convert_from_generic_address(self):
        """Test converting a generic Address to ByronAddress."""
        byron_addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        generic_addr = byron_addr.to_address()
        converted = ByronAddress.from_address(generic_addr)

        assert converted is not None
        assert str(converted) == str(byron_addr)

    def test_raises_error_for_invalid_address_type(self):
        """Test that converting non-Byron address raises error."""
        from cometa import EnterpriseAddress, Credential

        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        enterprise = EnterpriseAddress.from_credentials(NetworkId.MAINNET, payment)
        generic_addr = enterprise.to_address()

        with pytest.raises(CardanoError):
            ByronAddress.from_address(generic_addr)


class TestByronAddressFromBase58:
    """Tests for ByronAddress.from_base58 factory method."""

    def test_can_create_from_valid_base58(self):
        """Test creating Byron address from valid Base58 string."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert addr is not None
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_can_create_mainnet_yoroi_address(self):
        """Test creating mainnet Yoroi address from Base58."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert addr.network_id == NetworkId.MAINNET
        assert addr.address_type == ByronAddressType.PUBKEY

    def test_can_create_testnet_daedalus_address(self):
        """Test creating testnet Daedalus address from Base58."""
        addr = ByronAddress.from_base58(BYRON_TESTNET_DAEDALUS)

        assert addr.network_id == NetworkId.TESTNET
        assert addr.address_type == ByronAddressType.PUBKEY

    def test_raises_error_for_invalid_base58(self):
        """Test that invalid Base58 string raises error."""
        with pytest.raises(CardanoError):
            ByronAddress.from_base58("invalid_base58_string")

    def test_raises_error_for_empty_string(self):
        """Test that empty string raises error."""
        with pytest.raises(CardanoError):
            ByronAddress.from_base58("")

    def test_raises_error_for_wrong_prefix(self):
        """Test that string with wrong prefix raises error."""
        with pytest.raises(CardanoError):
            ByronAddress.from_base58("addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x")


class TestByronAddressFromBytes:
    """Tests for ByronAddress.from_bytes factory method."""

    def test_can_create_from_valid_bytes(self):
        """Test creating Byron address from valid bytes."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)

        assert addr is not None
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_can_create_mainnet_from_bytes(self):
        """Test creating mainnet address from bytes."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)

        assert addr.network_id == NetworkId.MAINNET

    def test_can_create_testnet_from_bytes(self):
        """Test creating testnet address from bytes."""
        addr = ByronAddress.from_bytes(BYRON_TESTNET_DAEDALUS_BYTES)

        assert addr.network_id == NetworkId.TESTNET

    def test_accepts_bytearray(self):
        """Test that bytearray input is accepted."""
        addr = ByronAddress.from_bytes(bytearray(BYRON_MAINNET_YOROI_BYTES))

        assert addr is not None
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_raises_error_for_invalid_bytes(self):
        """Test that invalid bytes raise error."""
        with pytest.raises(CardanoError):
            ByronAddress.from_bytes(bytes([0x01, 0x02, 0x03]))

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raise error."""
        with pytest.raises(CardanoError):
            ByronAddress.from_bytes(bytes())


class TestByronAddressProperties:
    """Tests for ByronAddress properties."""

    def test_root_property_returns_hash(self):
        """Test that root property returns Blake2bHash."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        root = addr.root

        assert root is not None
        assert isinstance(root, Blake2bHash)
        assert root.to_hex() == BYRON_YOROI_ROOT_HEX

    def test_attributes_property_returns_attributes(self):
        """Test that attributes property returns ByronAddressAttributes."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        attrs = addr.attributes

        assert attrs is not None
        assert isinstance(attrs, ByronAddressAttributes)
        assert attrs.magic == -1

    def test_attributes_with_network_magic(self):
        """Test attributes with network magic for testnet."""
        addr = ByronAddress.from_base58(BYRON_TESTNET_DAEDALUS)
        attrs = addr.attributes

        assert attrs.magic == 1097911063

    def test_address_type_property_returns_type(self):
        """Test that address_type property returns ByronAddressType."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr_type = addr.address_type

        assert addr_type == ByronAddressType.PUBKEY

    def test_network_id_property_mainnet(self):
        """Test network_id property for mainnet address."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert addr.network_id == NetworkId.MAINNET

    def test_network_id_property_testnet(self):
        """Test network_id property for testnet address."""
        addr = ByronAddress.from_base58(BYRON_TESTNET_DAEDALUS)

        assert addr.network_id == NetworkId.TESTNET


class TestByronAddressToAddress:
    """Tests for ByronAddress.to_address method."""

    def test_can_convert_to_generic_address(self):
        """Test converting ByronAddress to generic Address."""
        byron_addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        generic_addr = byron_addr.to_address()

        assert generic_addr is not None
        assert isinstance(generic_addr, Address)
        assert str(generic_addr) == str(byron_addr)

    def test_converted_address_can_be_converted_back(self):
        """Test that converted address can be converted back to ByronAddress."""
        byron_addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        generic_addr = byron_addr.to_address()
        byron_addr2 = ByronAddress.from_address(generic_addr)

        assert str(byron_addr2) == str(byron_addr)


class TestByronAddressToBytes:
    """Tests for ByronAddress.to_bytes method."""

    def test_can_convert_to_bytes(self):
        """Test converting Byron address to bytes."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        result = addr.to_bytes()

        assert result == BYRON_MAINNET_YOROI_BYTES

    def test_bytes_roundtrip(self):
        """Test that bytes conversion roundtrip works."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr_bytes = addr1.to_bytes()
        addr2 = ByronAddress.from_bytes(addr_bytes)

        assert str(addr1) == str(addr2)

    def test_testnet_address_to_bytes(self):
        """Test converting testnet address to bytes."""
        addr = ByronAddress.from_base58(BYRON_TESTNET_DAEDALUS)
        result = addr.to_bytes()

        assert result == BYRON_TESTNET_DAEDALUS_BYTES


class TestByronAddressToBase58:
    """Tests for ByronAddress.to_base58 method."""

    def test_can_convert_to_base58(self):
        """Test converting Byron address to Base58 string."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)
        result = addr.to_base58()

        assert result == BYRON_MAINNET_YOROI

    def test_base58_roundtrip(self):
        """Test that Base58 conversion roundtrip works."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        base58_str = addr1.to_base58()
        addr2 = ByronAddress.from_base58(base58_str)

        assert str(addr1) == str(addr2)

    def test_testnet_address_to_base58(self):
        """Test converting testnet address to Base58."""
        addr = ByronAddress.from_bytes(BYRON_TESTNET_DAEDALUS_BYTES)
        result = addr.to_base58()

        assert result == BYRON_TESTNET_DAEDALUS


class TestByronAddressMagicMethods:
    """Tests for ByronAddress magic methods."""

    def test_str_returns_base58(self):
        """Test __str__ returns Base58 representation."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)

        assert str(addr) == BYRON_MAINNET_YOROI

    def test_bytes_returns_serialized_bytes(self):
        """Test __bytes__ returns serialized bytes."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert bytes(addr) == BYRON_MAINNET_YOROI_BYTES

    def test_repr_includes_address_string(self):
        """Test __repr__ includes the address string."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        repr_str = repr(addr)

        assert "ByronAddress" in repr_str
        assert BYRON_MAINNET_YOROI in repr_str

    def test_hash_is_consistent(self):
        """Test __hash__ returns consistent value."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr2 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert hash(addr1) == hash(addr2)

    def test_hash_allows_use_in_set(self):
        """Test that Byron addresses can be used in sets."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr2 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        addr_set = {addr1, addr2}
        assert len(addr_set) == 1

    def test_hash_allows_use_as_dict_key(self):
        """Test that Byron addresses can be used as dict keys."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        addr_dict = {addr: "value"}
        assert addr_dict[addr] == "value"

    def test_eq_returns_true_for_same_address(self):
        """Test __eq__ returns True for identical addresses."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr2 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert addr1 == addr2

    def test_eq_returns_false_for_different_addresses(self):
        """Test __eq__ returns False for different addresses."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr2 = ByronAddress.from_base58(BYRON_TESTNET_DAEDALUS)

        assert addr1 != addr2

    def test_eq_returns_false_for_non_byron_address(self):
        """Test __eq__ returns False when compared with non-ByronAddress."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)

        assert addr != "not an address"
        assert addr != 123
        assert addr != None


class TestByronAddressContextManager:
    """Tests for ByronAddress context manager support."""

    def test_can_use_as_context_manager(self):
        """Test that Byron address can be used as context manager."""
        with ByronAddress.from_base58(BYRON_MAINNET_YOROI) as addr:
            assert addr is not None
            assert str(addr) == BYRON_MAINNET_YOROI

    def test_address_valid_after_context(self):
        """Test that address is still valid after context exits."""
        with ByronAddress.from_base58(BYRON_MAINNET_YOROI) as addr:
            address_str = str(addr)

        assert address_str == BYRON_MAINNET_YOROI


class TestByronAddressEdgeCases:
    """Tests for edge cases and error handling."""

    def test_multiple_conversions_maintain_consistency(self):
        """Test that multiple conversions maintain data consistency."""
        addr1 = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr_bytes = addr1.to_bytes()
        addr2 = ByronAddress.from_bytes(addr_bytes)
        base58_str = addr2.to_base58()
        addr3 = ByronAddress.from_base58(base58_str)

        assert str(addr1) == str(addr2) == str(addr3)
        assert addr1 == addr2 == addr3

    def test_attributes_are_preserved(self):
        """Test that attributes are preserved through conversions."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()
        addr1 = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)

        addr_bytes = addr1.to_bytes()
        addr2 = ByronAddress.from_bytes(addr_bytes)

        assert addr1.attributes.magic == addr2.attributes.magic
        assert addr1.address_type == addr2.address_type
        assert addr1.network_id == addr2.network_id

    def test_different_types_have_different_addresses(self):
        """Test that different address types produce different addresses."""
        root = Blake2bHash.from_hex(BYRON_YOROI_ROOT_HEX)
        attrs = ByronAddressAttributes.mainnet()

        addr_pubkey = ByronAddress.from_credentials(root, attrs, ByronAddressType.PUBKEY)
        addr_script = ByronAddress.from_credentials(root, attrs, ByronAddressType.SCRIPT)
        addr_redeem = ByronAddress.from_credentials(root, attrs, ByronAddressType.REDEEM)

        assert str(addr_pubkey) != str(addr_script)
        assert str(addr_pubkey) != str(addr_redeem)
        assert str(addr_script) != str(addr_redeem)
