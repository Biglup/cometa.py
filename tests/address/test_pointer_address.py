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
from cometa import PointerAddress, NetworkId, Credential, StakePointer, CardanoError


class TestPointerAddressFromCredentials:
    """Tests for PointerAddress.from_credentials factory method."""

    def test_can_create_from_key_hash_credential(self):
        """Test creating pointer address from key hash credential."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr is not None
        assert str(addr) == "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"

    def test_can_create_from_script_credential(self):
        """Test creating pointer address from script credential."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        payment = Credential.from_script_hash(script_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr is not None
        assert str(addr) == "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"

    def test_can_create_with_testnet_key(self):
        """Test creating pointer address for testnet with key hash."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.TESTNET, payment, pointer)

        assert addr is not None
        assert str(addr) == "addr_test1gz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrdw5vky"

    def test_can_create_with_testnet_script(self):
        """Test creating pointer address for testnet with script hash."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        payment = Credential.from_script_hash(script_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.TESTNET, payment, pointer)

        assert addr is not None
        assert str(addr) == "addr_test12rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcryqrvmw"

    def test_can_create_with_different_stake_pointer(self):
        """Test creating pointer address with different stake pointer values."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=5756214, tx_index=1, cert_index=0)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr is not None


class TestPointerAddressFromAddress:
    """Tests for PointerAddress.from_address factory method."""

    def test_can_convert_from_generic_address(self):
        """Test converting a generic Address to PointerAddress."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        pointer_addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        generic_addr = pointer_addr.to_address()

        converted = PointerAddress.from_address(generic_addr)

        assert converted is not None
        assert str(converted) == str(pointer_addr)

    def test_raises_error_for_invalid_address_type(self):
        """Test that converting non-pointer address raises error."""
        from cometa import BaseAddress

        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        base_addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        generic_addr = base_addr.to_address()

        with pytest.raises(CardanoError):
            PointerAddress.from_address(generic_addr)


class TestPointerAddressFromBech32:
    """Tests for PointerAddress.from_bech32 factory method."""

    def test_can_parse_mainnet_payment_key(self):
        """Test parsing mainnet pointer address with key hash."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_mainnet_payment_script(self):
        """Test parsing mainnet pointer address with script hash."""
        bech32 = "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"
        addr = PointerAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_key(self):
        """Test parsing testnet pointer address with key hash."""
        bech32 = "addr_test1gz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrdw5vky"
        addr = PointerAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_payment_script(self):
        """Test parsing testnet pointer address with script hash."""
        bech32 = "addr_test12rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcryqrvmw"
        addr = PointerAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_raises_error_for_empty_string(self):
        """Test that empty string raises error."""
        with pytest.raises(CardanoError):
            PointerAddress.from_bech32("")

    def test_raises_error_for_invalid_bech32(self):
        """Test that invalid bech32 raises error."""
        with pytest.raises(CardanoError):
            PointerAddress.from_bech32("invalid_pointer_address")

    def test_raises_error_for_wrong_prefix(self):
        """Test that wrong prefix raises error."""
        with pytest.raises(CardanoError):
            PointerAddress.from_bech32("split1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfjcf7r")


class TestPointerAddressFromBytes:
    """Tests for PointerAddress.from_bytes factory method."""

    def test_can_parse_from_bytes_key_hash(self):
        """Test parsing pointer address from raw bytes with key hash."""
        expected_bytes = bytes([
            0x41, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"

    def test_can_parse_from_bytes_script_hash(self):
        """Test parsing pointer address from raw bytes with script hash."""
        expected_bytes = bytes([
            0x51, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
            0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"

    def test_can_parse_from_bytearray(self):
        """Test parsing pointer address from bytearray."""
        expected_bytes = bytearray([
            0x41, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raises error."""
        with pytest.raises(CardanoError):
            PointerAddress.from_bytes(b"")

    def test_raises_error_for_invalid_bytes(self):
        """Test that invalid bytes raises error."""
        with pytest.raises(CardanoError):
            PointerAddress.from_bytes(b"\x00")


class TestPointerAddressProperties:
    """Tests for PointerAddress property accessors."""

    def test_payment_credential_returns_correct_hash_for_key(self):
        """Test that payment_credential returns correct key hash credential."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        credential = addr.payment_credential

        assert credential is not None
        assert credential.hash_hex == payment_hash

    def test_payment_credential_returns_correct_hash_for_script(self):
        """Test that payment_credential returns correct script hash credential."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        payment = Credential.from_script_hash(script_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        credential = addr.payment_credential

        assert credential is not None
        assert credential.hash_hex == script_hash

    def test_stake_pointer_returns_correct_values(self):
        """Test that stake_pointer returns correct pointer values."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        retrieved_pointer = addr.stake_pointer

        assert retrieved_pointer is not None
        assert retrieved_pointer.slot == 2498243
        assert retrieved_pointer.tx_index == 27
        assert retrieved_pointer.cert_index == 3

    def test_network_id_returns_mainnet(self):
        """Test that network_id returns MAINNET for mainnet address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr.network_id == NetworkId.MAINNET

    def test_network_id_returns_testnet(self):
        """Test that network_id returns TESTNET for testnet address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.TESTNET, payment, pointer)

        assert addr.network_id == NetworkId.TESTNET


class TestPointerAddressToAddress:
    """Tests for PointerAddress.to_address method."""

    def test_can_convert_to_generic_address(self):
        """Test converting PointerAddress to generic Address."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        pointer_addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        generic_addr = pointer_addr.to_address()

        assert generic_addr is not None
        assert str(generic_addr) == str(pointer_addr)


class TestPointerAddressToBytes:
    """Tests for PointerAddress.to_bytes method."""

    def test_to_bytes_returns_correct_bytes_for_key(self):
        """Test that to_bytes returns correct byte representation for key hash."""
        expected_bytes = bytes([
            0x41, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == expected_bytes

    def test_to_bytes_returns_correct_bytes_for_script(self):
        """Test that to_bytes returns correct byte representation for script hash."""
        expected_bytes = bytes([
            0x51, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
            0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == expected_bytes

    def test_bytes_roundtrip(self):
        """Test that from_bytes -> to_bytes roundtrip works."""
        original_bytes = bytes([
            0x41, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(original_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == original_bytes


class TestPointerAddressToBech32:
    """Tests for PointerAddress.to_bech32 method."""

    def test_to_bech32_returns_correct_string(self):
        """Test that to_bech32 returns correct bech32 string."""
        expected_bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(expected_bech32)
        result = addr.to_bech32()

        assert result == expected_bech32

    def test_bech32_roundtrip(self):
        """Test that from_bech32 -> to_bech32 roundtrip works."""
        original = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(original)
        result = addr.to_bech32()

        assert result == original


class TestPointerAddressMagicMethods:
    """Tests for PointerAddress magic methods."""

    def test_str_returns_bech32(self):
        """Test that __str__ returns bech32 representation."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)

        assert str(addr) == bech32

    def test_bytes_returns_serialized_bytes(self):
        """Test that __bytes__ returns serialized bytes."""
        expected_bytes = bytes([
            0x41, 0x94, 0x93, 0x31, 0x5c, 0xd9, 0x2e, 0xb5, 0xd8, 0xc4, 0x30, 0x4e, 0x67, 0xb7, 0xe1, 0x6a,
            0xe3, 0x6d, 0x61, 0xd3, 0x45, 0x02, 0x69, 0x46, 0x57, 0x81, 0x1a, 0x2c, 0x8e, 0x81, 0x98, 0xbd,
            0x43, 0x1b, 0x03
        ])

        addr = PointerAddress.from_bytes(expected_bytes)

        assert bytes(addr) == expected_bytes

    def test_repr_contains_class_and_string(self):
        """Test that __repr__ contains class name and string representation."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)
        repr_str = repr(addr)

        assert "PointerAddress" in repr_str
        assert bech32 in repr_str

    def test_hash_is_consistent(self):
        """Test that hash is consistent for the same address."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)

        hash1 = hash(addr)
        hash2 = hash(addr)

        assert hash1 == hash2

    def test_equal_addresses_have_same_hash(self):
        """Test that equal addresses have the same hash."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr1 = PointerAddress.from_bech32(bech32)
        addr2 = PointerAddress.from_bech32(bech32)

        assert hash(addr1) == hash(addr2)

    def test_equality_with_same_address(self):
        """Test that two addresses with same data are equal."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr1 = PointerAddress.from_bech32(bech32)
        addr2 = PointerAddress.from_bech32(bech32)

        assert addr1 == addr2

    def test_equality_with_different_address(self):
        """Test that two different addresses are not equal."""
        bech32_1 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        bech32_2 = "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"

        addr1 = PointerAddress.from_bech32(bech32_1)
        addr2 = PointerAddress.from_bech32(bech32_2)

        assert addr1 != addr2

    def test_inequality_with_non_pointer_address(self):
        """Test that PointerAddress is not equal to other types."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)

        assert addr != "not a pointer address"
        assert addr != 123
        assert addr is not None
        assert addr != (1, 2, 3)

    def test_can_use_in_set(self):
        """Test that PointerAddresses can be used in a set."""
        bech32_1 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        bech32_2 = "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"

        addr1 = PointerAddress.from_bech32(bech32_1)
        addr2 = PointerAddress.from_bech32(bech32_1)
        addr3 = PointerAddress.from_bech32(bech32_2)

        addr_set = {addr1, addr2, addr3}
        assert len(addr_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that PointerAddresses can be used as dictionary keys."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr1 = PointerAddress.from_bech32(bech32)
        addr2 = PointerAddress.from_bech32(bech32)

        addr_dict = {addr1: "value1"}
        addr_dict[addr2] = "value2"

        assert len(addr_dict) == 1
        assert addr_dict[addr1] == "value2"


class TestPointerAddressContextManager:
    """Tests for PointerAddress context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that PointerAddress can be used as context manager."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"

        with PointerAddress.from_bech32(bech32) as addr:
            assert addr is not None
            assert str(addr) == bech32

    def test_context_manager_returns_self(self):
        """Test that __enter__ returns self."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr = PointerAddress.from_bech32(bech32)

        result = addr.__enter__()
        assert result is addr


class TestPointerAddressEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_round_trip_credentials_to_bech32_to_bytes(self):
        """Test full round trip conversion."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr1 = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        bech32 = addr1.to_bech32()
        addr2 = PointerAddress.from_bech32(bech32)
        addr_bytes = addr2.to_bytes()
        addr3 = PointerAddress.from_bytes(addr_bytes)

        assert str(addr1) == str(addr2)
        assert str(addr2) == str(addr3)
        assert addr1 == addr2
        assert addr2 == addr3

    def test_multiple_instances_are_independent(self):
        """Test that multiple instances are independent."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr1 = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        addr2 = PointerAddress.from_credentials(NetworkId.TESTNET, payment, pointer)

        assert addr1.network_id == NetworkId.MAINNET
        assert addr2.network_id == NetworkId.TESTNET
        assert str(addr1) != str(addr2)

    def test_can_retrieve_original_credential(self):
        """Test that original credential can be retrieved."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        retrieved_payment = addr.payment_credential

        assert retrieved_payment.hash_hex == payment_hash

    def test_can_retrieve_original_stake_pointer(self):
        """Test that original stake pointer can be retrieved."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        retrieved_pointer = addr.stake_pointer

        assert retrieved_pointer.slot == pointer.slot
        assert retrieved_pointer.tx_index == pointer.tx_index
        assert retrieved_pointer.cert_index == pointer.cert_index

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr1 = PointerAddress.from_bech32(bech32)
        addr2 = PointerAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        bech32 = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
        addr1 = PointerAddress.from_bech32(bech32)
        addr2 = PointerAddress.from_bech32(bech32)
        addr3 = PointerAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr3
        assert addr1 == addr3

    def test_conversion_to_and_from_generic_address(self):
        """Test conversion to generic Address and back."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        original = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)
        generic = original.to_address()
        converted = PointerAddress.from_address(generic)

        assert str(original) == str(converted)
        assert original == converted

    def test_key_and_script_addresses_are_different(self):
        """Test that addresses with key and script credentials are different."""
        payment_key_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment_script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"

        payment_key = Credential.from_key_hash(payment_key_hash)
        payment_script = Credential.from_script_hash(payment_script_hash)
        pointer = StakePointer(slot=2498243, tx_index=27, cert_index=3)

        addr_key = PointerAddress.from_credentials(NetworkId.MAINNET, payment_key, pointer)
        addr_script = PointerAddress.from_credentials(NetworkId.MAINNET, payment_script, pointer)

        assert addr_key != addr_script
        assert str(addr_key) != str(addr_script)
        assert bytes(addr_key) != bytes(addr_script)

    def test_different_stake_pointers_create_different_addresses(self):
        """Test that different stake pointers create different addresses."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer1 = StakePointer(slot=2498243, tx_index=27, cert_index=3)
        pointer2 = StakePointer(slot=5756214, tx_index=1, cert_index=0)

        addr1 = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer1)
        addr2 = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer2)

        assert addr1 != addr2
        assert str(addr1) != str(addr2)
        assert bytes(addr1) != bytes(addr2)

    def test_pointer_with_zero_values(self):
        """Test creating pointer address with all zero pointer values."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=0, tx_index=0, cert_index=0)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr is not None
        retrieved_pointer = addr.stake_pointer
        assert retrieved_pointer.slot == 0
        assert retrieved_pointer.tx_index == 0
        assert retrieved_pointer.cert_index == 0

    def test_pointer_with_large_values(self):
        """Test creating pointer address with large pointer values."""
        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        payment = Credential.from_key_hash(payment_hash)
        pointer = StakePointer(slot=18446744073709551615, tx_index=18446744073709551615, cert_index=18446744073709551615)

        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, pointer)

        assert addr is not None
        retrieved_pointer = addr.stake_pointer
        assert retrieved_pointer.slot == 18446744073709551615
        assert retrieved_pointer.tx_index == 18446744073709551615
        assert retrieved_pointer.cert_index == 18446744073709551615
