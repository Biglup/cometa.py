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
from cometa import BaseAddress, NetworkId, Credential, CardanoError


class TestBaseAddressFromCredentials:
    """Tests for BaseAddress.from_credentials factory method."""

    def test_can_create_from_key_hash_credentials(self):
        """Test creating base address from key hash credentials."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)

        assert addr is not None
        assert str(addr) == "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"

    def test_can_create_from_script_credentials(self):
        """Test creating base address from script credentials."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_script_hash(script_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)

        assert addr is not None
        assert str(addr) == "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"

    def test_can_create_with_testnet(self):
        """Test creating base address for testnet."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.TESTNET, payment, stake)

        assert addr is not None
        assert str(addr) == "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"

    def test_can_create_with_payment_script_stake_script(self):
        """Test creating base address with both script credentials."""
        payment_script = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        stake_script = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"

        payment = Credential.from_script_hash(payment_script)
        stake = Credential.from_script_hash(stake_script)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)

        assert addr is not None
        assert str(addr) == "addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g"


class TestBaseAddressFromAddress:
    """Tests for BaseAddress.from_address factory method."""

    def test_can_convert_from_generic_address(self):
        """Test converting a generic Address to BaseAddress."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        base_addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        generic_addr = base_addr.to_address()

        converted = BaseAddress.from_address(generic_addr)

        assert converted is not None
        assert str(converted) == str(base_addr)

    def test_raises_error_for_invalid_address_type(self):
        """Test that converting non-base address raises error."""
        from cometa import EnterpriseAddress

        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        enterprise = EnterpriseAddress.from_credentials(NetworkId.MAINNET, payment)
        generic_addr = enterprise.to_address()

        with pytest.raises(CardanoError):
            BaseAddress.from_address(generic_addr)


class TestBaseAddressFromBech32:
    """Tests for BaseAddress.from_bech32 factory method."""

    def test_can_parse_mainnet_payment_key_stake_key(self):
        """Test parsing mainnet base address with key hash credentials."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_mainnet_payment_script_stake_key(self):
        """Test parsing mainnet base address with payment script."""
        bech32 = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_mainnet_payment_key_stake_script(self):
        """Test parsing mainnet base address with stake script."""
        bech32 = "addr1yx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs2z78ve"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_mainnet_payment_script_stake_script(self):
        """Test parsing mainnet base address with both scripts."""
        bech32 = "addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_key_stake_key(self):
        """Test parsing testnet base address."""
        bech32 = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_script_stake_key(self):
        """Test parsing testnet base address with payment script."""
        bech32 = "addr_test1zrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgsxj90mg"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_key_stake_script(self):
        """Test parsing testnet base address with stake script."""
        bech32 = "addr_test1yz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shsf5r8qx"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_script_stake_script(self):
        """Test parsing testnet base address with both scripts."""
        bech32 = "addr_test1xrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs4p04xh"
        addr = BaseAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_raises_error_for_empty_string(self):
        """Test that empty string raises error."""
        with pytest.raises(CardanoError):
            BaseAddress.from_bech32("")

    def test_raises_error_for_invalid_bech32(self):
        """Test that invalid bech32 raises error."""
        with pytest.raises(CardanoError):
            BaseAddress.from_bech32("invalid_address")

    def test_raises_error_for_wrong_prefix(self):
        """Test that wrong prefix raises error."""
        with pytest.raises(CardanoError):
            BaseAddress.from_bech32("split1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfjcf7r")


class TestBaseAddressFromBytes:
    """Tests for BaseAddress.from_bytes factory method."""

    def test_can_parse_from_bytes(self):
        """Test parsing base address from raw bytes."""
        expected_bytes = bytes([
            0x01, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x33, 0x7b, 0x62,
            0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46, 0x00, 0x3c, 0x69, 0xfe,
            0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = BaseAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"

    def test_can_parse_from_bytearray(self):
        """Test parsing base address from bytearray."""
        expected_bytes = bytearray([
            0x01, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x33, 0x7b, 0x62,
            0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46, 0x00, 0x3c, 0x69, 0xfe,
            0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = BaseAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raises error."""
        with pytest.raises(CardanoError):
            BaseAddress.from_bytes(b"")

    def test_raises_error_for_invalid_bytes(self):
        """Test that invalid bytes raises error."""
        with pytest.raises(CardanoError):
            BaseAddress.from_bytes(b"\x00")


class TestBaseAddressProperties:
    """Tests for BaseAddress property accessors."""

    def test_payment_credential_returns_correct_hash(self):
        """Test that payment_credential returns correct credential."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        credential = addr.payment_credential

        assert credential is not None
        assert credential.hash_hex == payment_hash

    def test_stake_credential_returns_correct_hash(self):
        """Test that stake_credential returns correct credential."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        credential = addr.stake_credential

        assert credential is not None
        assert credential.hash_hex == stake_hash

    def test_network_id_returns_mainnet(self):
        """Test that network_id returns MAINNET for mainnet address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)

        assert addr.network_id == NetworkId.MAINNET

    def test_network_id_returns_testnet(self):
        """Test that network_id returns TESTNET for testnet address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.TESTNET, payment, stake)

        assert addr.network_id == NetworkId.TESTNET


class TestBaseAddressToAddress:
    """Tests for BaseAddress.to_address method."""

    def test_can_convert_to_generic_address(self):
        """Test converting BaseAddress to generic Address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        base_addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        generic_addr = base_addr.to_address()

        assert generic_addr is not None
        assert str(generic_addr) == str(base_addr)


class TestBaseAddressToBytes:
    """Tests for BaseAddress.to_bytes method."""

    def test_to_bytes_returns_correct_bytes(self):
        """Test that to_bytes returns correct byte representation."""
        expected_bytes = bytes([
            0x01, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x33, 0x7b, 0x62,
            0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46, 0x00, 0x3c, 0x69, 0xfe,
            0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = BaseAddress.from_bytes(expected_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == expected_bytes

    def test_bytes_roundtrip(self):
        """Test that from_bytes -> to_bytes roundtrip works."""
        original_bytes = bytes([
            0x01, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x33, 0x7b, 0x62,
            0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46, 0x00, 0x3c, 0x69, 0xfe,
            0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = BaseAddress.from_bytes(original_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == original_bytes


class TestBaseAddressToBech32:
    """Tests for BaseAddress.to_bech32 method."""

    def test_to_bech32_returns_correct_string(self):
        """Test that to_bech32 returns correct bech32 string."""
        expected_bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(expected_bech32)
        result = addr.to_bech32()

        assert result == expected_bech32

    def test_bech32_roundtrip(self):
        """Test that from_bech32 -> to_bech32 roundtrip works."""
        original = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(original)
        result = addr.to_bech32()

        assert result == original


class TestBaseAddressMagicMethods:
    """Tests for BaseAddress magic methods."""

    def test_str_returns_bech32(self):
        """Test that __str__ returns bech32 representation."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)

        assert str(addr) == bech32

    def test_bytes_returns_serialized_bytes(self):
        """Test that __bytes__ returns serialized bytes."""
        expected_bytes = bytes([
            0x01, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x33, 0x7b, 0x62,
            0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46, 0x00, 0x3c, 0x69, 0xfe,
            0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = BaseAddress.from_bytes(expected_bytes)

        assert bytes(addr) == expected_bytes

    def test_repr_contains_class_and_string(self):
        """Test that __repr__ contains class name and string representation."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)
        repr_str = repr(addr)

        assert "BaseAddress" in repr_str
        assert bech32 in repr_str

    def test_hash_is_consistent(self):
        """Test that hash is consistent for the same address."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)

        hash1 = hash(addr)
        hash2 = hash(addr)

        assert hash1 == hash2

    def test_equal_addresses_have_same_hash(self):
        """Test that equal addresses have the same hash."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr1 = BaseAddress.from_bech32(bech32)
        addr2 = BaseAddress.from_bech32(bech32)

        assert hash(addr1) == hash(addr2)

    def test_equality_with_same_address(self):
        """Test that two addresses with same data are equal."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr1 = BaseAddress.from_bech32(bech32)
        addr2 = BaseAddress.from_bech32(bech32)

        assert addr1 == addr2

    def test_equality_with_different_address(self):
        """Test that two different addresses are not equal."""
        bech32_1 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        bech32_2 = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"

        addr1 = BaseAddress.from_bech32(bech32_1)
        addr2 = BaseAddress.from_bech32(bech32_2)

        assert addr1 != addr2

    def test_inequality_with_non_base_address(self):
        """Test that BaseAddress is not equal to other types."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)

        assert addr != "not a base address"
        assert addr != 123
        assert addr is not None
        assert addr != (1, 2, 3)

    def test_can_use_in_set(self):
        """Test that BaseAddresses can be used in a set."""
        bech32_1 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        bech32_2 = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"

        addr1 = BaseAddress.from_bech32(bech32_1)
        addr2 = BaseAddress.from_bech32(bech32_1)
        addr3 = BaseAddress.from_bech32(bech32_2)

        addr_set = {addr1, addr2, addr3}
        assert len(addr_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that BaseAddresses can be used as dictionary keys."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr1 = BaseAddress.from_bech32(bech32)
        addr2 = BaseAddress.from_bech32(bech32)

        addr_dict = {addr1: "value1"}
        addr_dict[addr2] = "value2"

        assert len(addr_dict) == 1
        assert addr_dict[addr1] == "value2"


class TestBaseAddressContextManager:
    """Tests for BaseAddress context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that BaseAddress can be used as context manager."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"

        with BaseAddress.from_bech32(bech32) as addr:
            assert addr is not None
            assert str(addr) == bech32

    def test_context_manager_returns_self(self):
        """Test that __enter__ returns self."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr = BaseAddress.from_bech32(bech32)

        result = addr.__enter__()
        assert result is addr


class TestBaseAddressEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_round_trip_credentials_to_bech32_to_bytes(self):
        """Test full round trip conversion."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr1 = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        bech32 = addr1.to_bech32()
        addr2 = BaseAddress.from_bech32(bech32)
        addr_bytes = addr2.to_bytes()
        addr3 = BaseAddress.from_bytes(addr_bytes)

        assert str(addr1) == str(addr2)
        assert str(addr2) == str(addr3)
        assert addr1 == addr2
        assert addr2 == addr3

    def test_multiple_instances_are_independent(self):
        """Test that multiple instances are independent."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr1 = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        addr2 = BaseAddress.from_credentials(NetworkId.TESTNET, payment, stake)

        assert addr1.network_id == NetworkId.MAINNET
        assert addr2.network_id == NetworkId.TESTNET
        assert str(addr1) != str(addr2)

    def test_can_retrieve_original_credentials(self):
        """Test that original credentials can be retrieved."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)

        retrieved_payment = addr.payment_credential
        retrieved_stake = addr.stake_credential

        assert retrieved_payment.hash_hex == payment_hash
        assert retrieved_stake.hash_hex == stake_hash

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr1 = BaseAddress.from_bech32(bech32)
        addr2 = BaseAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        bech32 = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
        addr1 = BaseAddress.from_bech32(bech32)
        addr2 = BaseAddress.from_bech32(bech32)
        addr3 = BaseAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr3
        assert addr1 == addr3
