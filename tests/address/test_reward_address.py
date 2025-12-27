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
from cometa import RewardAddress, NetworkId, Credential, CardanoError


class TestRewardAddressFromCredentials:
    """Tests for RewardAddress.from_credentials factory method."""

    def test_can_create_from_key_hash_credential(self):
        """Test creating reward address from key hash credential."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)

        assert addr is not None
        assert str(addr) == "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"

    def test_can_create_from_script_credential(self):
        """Test creating reward address from script credential."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        stake = Credential.from_script_hash(script_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)

        assert addr is not None
        assert str(addr) == "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"

    def test_can_create_with_testnet_key(self):
        """Test creating reward address for testnet with key hash."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.TESTNET, stake)

        assert addr is not None
        assert str(addr) == "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"

    def test_can_create_with_testnet_script(self):
        """Test creating reward address for testnet with script hash."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        stake = Credential.from_script_hash(script_hash)

        addr = RewardAddress.from_credentials(NetworkId.TESTNET, stake)

        assert addr is not None
        assert str(addr) == "stake_test17rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcljw6kf"


class TestRewardAddressFromAddress:
    """Tests for RewardAddress.from_address factory method."""

    def test_can_convert_from_generic_address(self):
        """Test converting a generic Address to RewardAddress."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        reward = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        generic_addr = reward.to_address()

        converted = RewardAddress.from_address(generic_addr)

        assert converted is not None
        assert str(converted) == str(reward)

    def test_raises_error_for_invalid_address_type(self):
        """Test that converting non-reward address raises error."""
        from cometa import BaseAddress

        payment_hash = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"

        payment = Credential.from_key_hash(payment_hash)
        stake = Credential.from_key_hash(stake_hash)

        base_addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        generic_addr = base_addr.to_address()

        with pytest.raises(CardanoError):
            RewardAddress.from_address(generic_addr)


class TestRewardAddressFromBech32:
    """Tests for RewardAddress.from_bech32 factory method."""

    def test_can_parse_mainnet_stake_key(self):
        """Test parsing mainnet reward address with key hash."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_mainnet_stake_script(self):
        """Test parsing mainnet reward address with script hash."""
        bech32 = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"
        addr = RewardAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_stake_key(self):
        """Test parsing testnet reward address with key hash."""
        bech32 = "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"
        addr = RewardAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_can_parse_testnet_stake_script(self):
        """Test parsing testnet reward address with script hash."""
        bech32 = "stake_test17rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcljw6kf"
        addr = RewardAddress.from_bech32(bech32)

        assert addr is not None
        assert str(addr) == bech32

    def test_raises_error_for_empty_string(self):
        """Test that empty string raises error."""
        with pytest.raises(CardanoError):
            RewardAddress.from_bech32("")

    def test_raises_error_for_invalid_bech32(self):
        """Test that invalid bech32 raises error."""
        with pytest.raises(CardanoError):
            RewardAddress.from_bech32("invalid_address")

    def test_raises_error_for_wrong_prefix(self):
        """Test that wrong prefix raises error."""
        with pytest.raises(CardanoError):
            RewardAddress.from_bech32("split1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfjcf7r")


class TestRewardAddressFromBytes:
    """Tests for RewardAddress.from_bytes factory method."""

    def test_can_parse_from_bytes_key_hash(self):
        """Test parsing reward address from raw bytes with key hash."""
        expected_bytes = bytes([
            0xe1, 0x33, 0x7b, 0x62, 0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46,
            0x00, 0x3c, 0x69, 0xfe, 0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = RewardAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"

    def test_can_parse_from_bytes_script_hash(self):
        """Test parsing reward address from raw bytes with script hash."""
        expected_bytes = bytes([
            0xf1, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
            0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f
        ])

        addr = RewardAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"

    def test_can_parse_from_bytearray(self):
        """Test parsing reward address from bytearray."""
        expected_bytes = bytearray([
            0xe1, 0x33, 0x7b, 0x62, 0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46,
            0x00, 0x3c, 0x69, 0xfe, 0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = RewardAddress.from_bytes(expected_bytes)

        assert addr is not None
        assert str(addr) == "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"

    def test_raises_error_for_empty_bytes(self):
        """Test that empty bytes raises error."""
        with pytest.raises(CardanoError):
            RewardAddress.from_bytes(b"")

    def test_raises_error_for_invalid_bytes(self):
        """Test that invalid bytes raises error."""
        with pytest.raises(CardanoError):
            RewardAddress.from_bytes(b"\x00")


class TestRewardAddressProperties:
    """Tests for RewardAddress property accessors."""

    def test_credential_returns_correct_hash_for_key(self):
        """Test that credential returns correct key hash credential."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        credential = addr.credential

        assert credential is not None
        assert credential.hash_hex == stake_hash

    def test_credential_returns_correct_hash_for_script(self):
        """Test that credential returns correct script hash credential."""
        script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
        stake = Credential.from_script_hash(script_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        credential = addr.credential

        assert credential is not None
        assert credential.hash_hex == script_hash

    def test_network_id_returns_mainnet(self):
        """Test that network_id returns MAINNET for mainnet address."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)

        assert addr.network_id == NetworkId.MAINNET

    def test_network_id_returns_testnet(self):
        """Test that network_id returns TESTNET for testnet address."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.TESTNET, stake)

        assert addr.network_id == NetworkId.TESTNET


class TestRewardAddressToAddress:
    """Tests for RewardAddress.to_address method."""

    def test_can_convert_to_generic_address(self):
        """Test converting RewardAddress to generic Address."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        reward = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        generic_addr = reward.to_address()

        assert generic_addr is not None
        assert str(generic_addr) == str(reward)


class TestRewardAddressToBytes:
    """Tests for RewardAddress.to_bytes method."""

    def test_to_bytes_returns_correct_bytes_for_key(self):
        """Test that to_bytes returns correct byte representation for key hash."""
        expected_bytes = bytes([
            0xe1, 0x33, 0x7b, 0x62, 0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46,
            0x00, 0x3c, 0x69, 0xfe, 0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = RewardAddress.from_bytes(expected_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == expected_bytes

    def test_to_bytes_returns_correct_bytes_for_script(self):
        """Test that to_bytes returns correct byte representation for script hash."""
        expected_bytes = bytes([
            0xf1, 0xc3, 0x7b, 0x1b, 0x5d, 0xc0, 0x66, 0x9f, 0x1d, 0x3c, 0x61, 0xa6, 0xfd, 0xdb, 0x2e, 0x8f,
            0xde, 0x96, 0xbe, 0x87, 0xb8, 0x81, 0xc6, 0x0b, 0xce, 0x8e, 0x8d, 0x54, 0x2f
        ])

        addr = RewardAddress.from_bytes(expected_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == expected_bytes

    def test_bytes_roundtrip(self):
        """Test that from_bytes -> to_bytes roundtrip works."""
        original_bytes = bytes([
            0xe1, 0x33, 0x7b, 0x62, 0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46,
            0x00, 0x3c, 0x69, 0xfe, 0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = RewardAddress.from_bytes(original_bytes)
        result_bytes = addr.to_bytes()

        assert result_bytes == original_bytes


class TestRewardAddressToBech32:
    """Tests for RewardAddress.to_bech32 method."""

    def test_to_bech32_returns_correct_string(self):
        """Test that to_bech32 returns correct bech32 string."""
        expected_bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(expected_bech32)
        result = addr.to_bech32()

        assert result == expected_bech32

    def test_bech32_roundtrip(self):
        """Test that from_bech32 -> to_bech32 roundtrip works."""
        original = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(original)
        result = addr.to_bech32()

        assert result == original


class TestRewardAddressMagicMethods:
    """Tests for RewardAddress magic methods."""

    def test_str_returns_bech32(self):
        """Test that __str__ returns bech32 representation."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)

        assert str(addr) == bech32

    def test_bytes_returns_serialized_bytes(self):
        """Test that __bytes__ returns serialized bytes."""
        expected_bytes = bytes([
            0xe1, 0x33, 0x7b, 0x62, 0xcf, 0xff, 0x64, 0x03, 0xa0, 0x6a, 0x3a, 0xcb, 0xc3, 0x4f, 0x8c, 0x46,
            0x00, 0x3c, 0x69, 0xfe, 0x79, 0xa3, 0x62, 0x8c, 0xef, 0xa9, 0xc4, 0x72, 0x51
        ])

        addr = RewardAddress.from_bytes(expected_bytes)

        assert bytes(addr) == expected_bytes

    def test_repr_contains_class_and_string(self):
        """Test that __repr__ contains class name and string representation."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)
        repr_str = repr(addr)

        assert "RewardAddress" in repr_str
        assert bech32 in repr_str

    def test_hash_is_consistent(self):
        """Test that hash is consistent for the same address."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)

        hash1 = hash(addr)
        hash2 = hash(addr)

        assert hash1 == hash2

    def test_equal_addresses_have_same_hash(self):
        """Test that equal addresses have the same hash."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr1 = RewardAddress.from_bech32(bech32)
        addr2 = RewardAddress.from_bech32(bech32)

        assert hash(addr1) == hash(addr2)

    def test_equality_with_same_address(self):
        """Test that two addresses with same data are equal."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr1 = RewardAddress.from_bech32(bech32)
        addr2 = RewardAddress.from_bech32(bech32)

        assert addr1 == addr2

    def test_equality_with_different_address(self):
        """Test that two different addresses are not equal."""
        bech32_1 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        bech32_2 = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"

        addr1 = RewardAddress.from_bech32(bech32_1)
        addr2 = RewardAddress.from_bech32(bech32_2)

        assert addr1 != addr2

    def test_inequality_with_non_reward_address(self):
        """Test that RewardAddress is not equal to other types."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)

        assert addr != "not a reward address"
        assert addr != 123
        assert addr is not None
        assert addr != (1, 2, 3)

    def test_can_use_in_set(self):
        """Test that RewardAddresses can be used in a set."""
        bech32_1 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        bech32_2 = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"

        addr1 = RewardAddress.from_bech32(bech32_1)
        addr2 = RewardAddress.from_bech32(bech32_1)
        addr3 = RewardAddress.from_bech32(bech32_2)

        addr_set = {addr1, addr2, addr3}
        assert len(addr_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that RewardAddresses can be used as dictionary keys."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr1 = RewardAddress.from_bech32(bech32)
        addr2 = RewardAddress.from_bech32(bech32)

        addr_dict = {addr1: "value1"}
        addr_dict[addr2] = "value2"

        assert len(addr_dict) == 1
        assert addr_dict[addr1] == "value2"


class TestRewardAddressContextManager:
    """Tests for RewardAddress context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that RewardAddress can be used as context manager."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"

        with RewardAddress.from_bech32(bech32) as addr:
            assert addr is not None
            assert str(addr) == bech32

    def test_context_manager_returns_self(self):
        """Test that __enter__ returns self."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr = RewardAddress.from_bech32(bech32)

        result = addr.__enter__()
        assert result is addr


class TestRewardAddressEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_round_trip_credentials_to_bech32_to_bytes(self):
        """Test full round trip conversion."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr1 = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        bech32 = addr1.to_bech32()
        addr2 = RewardAddress.from_bech32(bech32)
        addr_bytes = addr2.to_bytes()
        addr3 = RewardAddress.from_bytes(addr_bytes)

        assert str(addr1) == str(addr2)
        assert str(addr2) == str(addr3)
        assert addr1 == addr2
        assert addr2 == addr3

    def test_multiple_instances_are_independent(self):
        """Test that multiple instances are independent."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr1 = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        addr2 = RewardAddress.from_credentials(NetworkId.TESTNET, stake)

        assert addr1.network_id == NetworkId.MAINNET
        assert addr2.network_id == NetworkId.TESTNET
        assert str(addr1) != str(addr2)

    def test_can_retrieve_original_credential(self):
        """Test that original credential can be retrieved."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        retrieved_stake = addr.credential

        assert retrieved_stake.hash_hex == stake_hash

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr1 = RewardAddress.from_bech32(bech32)
        addr2 = RewardAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        bech32 = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
        addr1 = RewardAddress.from_bech32(bech32)
        addr2 = RewardAddress.from_bech32(bech32)
        addr3 = RewardAddress.from_bech32(bech32)

        assert addr1 == addr2
        assert addr2 == addr3
        assert addr1 == addr3

    def test_conversion_to_and_from_generic_address(self):
        """Test conversion to generic Address and back."""
        stake_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake = Credential.from_key_hash(stake_hash)

        original = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        generic = original.to_address()
        converted = RewardAddress.from_address(generic)

        assert str(original) == str(converted)
        assert original == converted

    def test_key_and_script_addresses_are_different(self):
        """Test that addresses with key and script credentials are different."""
        stake_key_hash = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
        stake_script_hash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"

        stake_key = Credential.from_key_hash(stake_key_hash)
        stake_script = Credential.from_script_hash(stake_script_hash)

        addr_key = RewardAddress.from_credentials(NetworkId.MAINNET, stake_key)
        addr_script = RewardAddress.from_credentials(NetworkId.MAINNET, stake_script)

        assert addr_key != addr_script
        assert str(addr_key) != str(addr_script)
        assert bytes(addr_key) != bytes(addr_script)
