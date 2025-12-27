"""
Tests for address bindings using CIP-19 test vectors.
"""

import pytest
from cometa.address import (
    Address,
    AddressType,
    BaseAddress,
    EnterpriseAddress,
    PointerAddress,
    RewardAddress,
    ByronAddress,
    ByronAddressType,
    ByronAddressAttributes,
    StakePointer,
)
from cometa.common import NetworkId, Credential
from cometa.errors import CardanoError


# CIP-19 Test Vectors
PAYMENT_KEY_HASH_HEX = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
STAKE_KEY_HASH_HEX = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
SCRIPT_HASH_HEX = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"

# Base addresses
BASE_PAYMENT_KEY_STAKE_KEY = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"
BASE_PAYMENT_KEY_STAKE_KEY_BYTES = bytes.fromhex(
    "019493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
)
BASE_PAYMENT_SCRIPT_STAKE_KEY = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"
BASE_PAYMENT_KEY_STAKE_SCRIPT = "addr1yx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs2z78ve"
BASE_PAYMENT_SCRIPT_STAKE_SCRIPT = "addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g"
TESTNET_BASE_PAYMENT_KEY_STAKE_KEY = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"

# Enterprise addresses
ENTERPRISE_KEY = "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8"
ENTERPRISE_KEY_BYTES = bytes.fromhex("619493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e")
ENTERPRISE_SCRIPT = "addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx"
ENTERPRISE_SCRIPT_BYTES = bytes.fromhex("71c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f")
TESTNET_ENTERPRISE_KEY = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"

# Reward addresses
REWARD_KEY = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
REWARD_KEY_BYTES = bytes.fromhex("e1337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251")
REWARD_SCRIPT = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"
REWARD_SCRIPT_BYTES = bytes.fromhex("f1c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f")
TESTNET_REWARD_KEY = "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn"

# Pointer addresses
POINTER_KEY = "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k"
POINTER_KEY_BYTES = bytes.fromhex("419493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e8198bd431b03")
POINTER_SCRIPT = "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"
POINTER_SCRIPT_BYTES = bytes.fromhex("51c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f8198bd431b03")
TESTNET_POINTER_KEY = "addr_test1gz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrdw5vky"

# Byron addresses
BYRON_MAINNET_YOROI = "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi"
BYRON_MAINNET_YOROI_BYTES = bytes.fromhex(
    "82d818582183581cba970ad36654d8dd8f74274b733452ddeab9a62a397746be3c42ccdda0001a9026da5b"
)
BYRON_TESTNET_DAEDALUS = "37btjrVyb4KEB2STADSsj3MYSAdj52X5FrFWpw2r7Wmj2GDzXjFRsHWuZqrw7zSkwopv8Ci3VWeg6bisU9dgJxW5hb2MZYeduNKbQJrqz3zVBsu9nT"

# Stake pointer for test vectors
STAKE_POINTER = StakePointer(slot=2498243, tx_index=27, cert_index=3)


class TestAddress:
    """Tests for generic Address class."""

    def test_from_string_base_address(self):
        """Parse a base address from string."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.type == AddressType.BASE_PAYMENT_KEY_STAKE_KEY
        assert addr.network_id == NetworkId.MAINNET
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_from_string_enterprise_address(self):
        """Parse an enterprise address from string."""
        addr = Address.from_string(ENTERPRISE_KEY)
        assert addr.type == AddressType.ENTERPRISE_KEY
        assert addr.network_id == NetworkId.MAINNET

    def test_from_string_reward_address(self):
        """Parse a reward address from string."""
        addr = Address.from_string(REWARD_KEY)
        assert addr.type == AddressType.REWARD_KEY
        assert addr.network_id == NetworkId.MAINNET

    def test_from_string_pointer_address(self):
        """Parse a pointer address from string."""
        addr = Address.from_string(POINTER_KEY)
        assert addr.type == AddressType.POINTER_KEY
        assert addr.network_id == NetworkId.MAINNET

    def test_from_string_byron_address(self):
        """Parse a Byron address from string."""
        addr = Address.from_string(BYRON_MAINNET_YOROI)
        assert addr.type == AddressType.BYRON
        assert addr.network_id == NetworkId.MAINNET

    def test_from_bytes(self):
        """Create address from bytes."""
        addr = Address.from_bytes(BASE_PAYMENT_KEY_STAKE_KEY_BYTES)
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_to_bytes(self):
        """Convert address to bytes."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_bytes() == BASE_PAYMENT_KEY_STAKE_KEY_BYTES

    def test_is_valid(self):
        """Validate address strings."""
        assert Address.is_valid(BASE_PAYMENT_KEY_STAKE_KEY)
        assert Address.is_valid(ENTERPRISE_KEY)
        assert Address.is_valid(BYRON_MAINNET_YOROI)
        assert not Address.is_valid("invalid_address")
        assert not Address.is_valid("")

    def test_is_valid_bech32(self):
        """Validate Bech32 address strings."""
        assert Address.is_valid_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        assert Address.is_valid_bech32(ENTERPRISE_KEY)
        assert not Address.is_valid_bech32(BYRON_MAINNET_YOROI)

    def test_is_valid_byron(self):
        """Validate Byron address strings."""
        assert Address.is_valid_byron(BYRON_MAINNET_YOROI)
        assert not Address.is_valid_byron(BASE_PAYMENT_KEY_STAKE_KEY)

    def test_is_mainnet(self):
        """Check mainnet address detection."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.is_mainnet
        assert not addr.is_testnet

    def test_is_testnet(self):
        """Check testnet address detection."""
        addr = Address.from_string(TESTNET_BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.is_testnet
        assert not addr.is_mainnet

    def test_equality(self):
        """Test address equality."""
        addr1 = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        addr2 = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        addr3 = Address.from_string(ENTERPRISE_KEY)
        assert addr1 == addr2
        assert addr1 != addr3

    def test_hash(self):
        """Test address hashing for sets/dicts."""
        addr1 = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        addr2 = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        addresses = {addr1, addr2}
        assert len(addresses) == 1

    def test_to_base_address(self):
        """Convert generic address to base address."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        base = addr.to_base_address()
        assert base is not None
        assert str(base) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_to_enterprise_address(self):
        """Convert generic address to enterprise address."""
        addr = Address.from_string(ENTERPRISE_KEY)
        ent = addr.to_enterprise_address()
        assert ent is not None
        assert str(ent) == ENTERPRISE_KEY

    def test_to_reward_address(self):
        """Convert generic address to reward address."""
        addr = Address.from_string(REWARD_KEY)
        reward = addr.to_reward_address()
        assert reward is not None
        assert str(reward) == REWARD_KEY

    def test_to_pointer_address(self):
        """Convert generic address to pointer address."""
        addr = Address.from_string(POINTER_KEY)
        ptr = addr.to_pointer_address()
        assert ptr is not None
        assert str(ptr) == POINTER_KEY

    def test_to_byron_address(self):
        """Convert generic address to Byron address."""
        addr = Address.from_string(BYRON_MAINNET_YOROI)
        byron = addr.to_byron_address()
        assert byron is not None
        assert str(byron) == BYRON_MAINNET_YOROI

    def test_invalid_string_raises_error(self):
        """Invalid address string raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("invalid")

    def test_from_string_empty_raises_error(self):
        """Empty string raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("")

    def test_from_string_too_short_raises_error(self):
        """String too short raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("a")

    def test_from_string_invalid_hrp_raises_error(self):
        """Invalid HRP raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("addrqx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x")

    def test_from_string_no_data_raises_error(self):
        """Address with no data raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("addr_test1")

    def test_from_string_invalid_encoding_raises_error(self):
        """Invalid encoding raises error."""
        with pytest.raises(CardanoError):
            Address.from_string("addr_test12222222222222222222222")

    def test_from_bytes_empty_raises_error(self):
        """Empty bytes raises error."""
        with pytest.raises(CardanoError):
            Address.from_bytes(b"")

    def test_from_bytes_invalid_base_address_raises_error(self):
        """Invalid base address bytes raises error."""
        invalid_bytes = BASE_PAYMENT_KEY_STAKE_KEY_BYTES[:-1]
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_bytes)

    def test_from_bytes_invalid_enterprise_address_raises_error(self):
        """Invalid enterprise address bytes raises error."""
        invalid_bytes = ENTERPRISE_KEY_BYTES[:-1]
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_bytes)

    def test_from_bytes_invalid_pointer_address_raises_error(self):
        """Invalid pointer address bytes raises error."""
        invalid_bytes = POINTER_KEY_BYTES[:29]
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_bytes)

    def test_from_bytes_invalid_reward_address_raises_error(self):
        """Invalid reward address bytes raises error."""
        invalid_bytes = REWARD_KEY_BYTES[:-1]
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_bytes)

    def test_from_bytes_invalid_byron_address_raises_error(self):
        """Invalid Byron address bytes raises error."""
        invalid_byron = bytes.fromhex("82d818582183581cba97")
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_byron)

    def test_from_bytes_invalid_address_type_raises_error(self):
        """Invalid address type byte raises error."""
        invalid_type = bytes.fromhex("90d818582183581cba97")
        with pytest.raises(CardanoError):
            Address.from_bytes(invalid_type)

    def test_len_magic_method(self):
        """Test __len__ magic method."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert len(addr) == len(BASE_PAYMENT_KEY_STAKE_KEY_BYTES)

    def test_bytes_magic_method(self):
        """Test __bytes__ magic method."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert bytes(addr) == BASE_PAYMENT_KEY_STAKE_KEY_BYTES

    def test_repr(self):
        """Test __repr__ method."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        repr_str = repr(addr)
        assert "Address(" in repr_str
        assert BASE_PAYMENT_KEY_STAKE_KEY in repr_str

    def test_to_base_address_returns_none_for_non_base(self):
        """to_base_address returns None for non-base address."""
        addr = Address.from_string(ENTERPRISE_KEY)
        assert addr.to_base_address() is None

    def test_to_enterprise_address_returns_none_for_non_enterprise(self):
        """to_enterprise_address returns None for non-enterprise address."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_enterprise_address() is None

    def test_to_reward_address_returns_none_for_non_reward(self):
        """to_reward_address returns None for non-reward address."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_reward_address() is None

    def test_to_pointer_address_returns_none_for_non_pointer(self):
        """to_pointer_address returns None for non-pointer address."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_pointer_address() is None

    def test_to_byron_address_returns_none_for_non_byron(self):
        """to_byron_address returns None for non-Byron address."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_byron_address() is None

    def test_is_valid_with_empty_string(self):
        """is_valid returns False for empty string."""
        assert not Address.is_valid("")

    def test_is_valid_bech32_with_invalid_string(self):
        """is_valid_bech32 returns False for invalid string."""
        assert not Address.is_valid_bech32("invalid_address")
        assert not Address.is_valid_bech32("")
        assert not Address.is_valid_bech32("addr_test1")
        assert not Address.is_valid_bech32("addrqx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x")

    def test_is_valid_byron_with_invalid_string(self):
        """is_valid_byron returns False for invalid string."""
        assert not Address.is_valid_byron("invalid_address")
        assert not Address.is_valid_byron("")
        assert not Address.is_valid_byron("ilwwww2222222222222222222222")

    def test_context_manager(self):
        """Test address as context manager."""
        with Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY) as addr:
            assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_equality_with_different_types(self):
        """Test equality comparison with non-Address type."""
        addr = Address.from_string(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr != "not an address"
        assert addr != 123
        assert addr != None

    def test_multiple_address_types_roundtrip(self):
        """Test roundtrip for various address types."""
        test_addresses = [
            BASE_PAYMENT_KEY_STAKE_KEY,
            BASE_PAYMENT_SCRIPT_STAKE_KEY,
            BASE_PAYMENT_KEY_STAKE_SCRIPT,
            BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
            ENTERPRISE_KEY,
            ENTERPRISE_SCRIPT,
            REWARD_KEY,
            REWARD_SCRIPT,
            POINTER_KEY,
            POINTER_SCRIPT,
            BYRON_MAINNET_YOROI,
            TESTNET_BASE_PAYMENT_KEY_STAKE_KEY,
            TESTNET_ENTERPRISE_KEY,
            TESTNET_REWARD_KEY,
            TESTNET_POINTER_KEY,
        ]
        for addr_str in test_addresses:
            addr = Address.from_string(addr_str)
            assert str(addr) == addr_str
            roundtrip = Address.from_bytes(addr.to_bytes())
            assert str(roundtrip) == addr_str


class TestBaseAddress:
    """Tests for BaseAddress class."""

    def test_from_bech32(self):
        """Create base address from Bech32."""
        addr = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_from_bytes(self):
        """Create base address from bytes."""
        addr = BaseAddress.from_bytes(BASE_PAYMENT_KEY_STAKE_KEY_BYTES)
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_to_bytes(self):
        """Convert base address to bytes."""
        addr = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.to_bytes() == BASE_PAYMENT_KEY_STAKE_KEY_BYTES

    def test_to_bech32(self):
        """Convert base address to Bech32."""
        addr = BaseAddress.from_bytes(BASE_PAYMENT_KEY_STAKE_KEY_BYTES)
        assert addr.to_bech32() == BASE_PAYMENT_KEY_STAKE_KEY

    def test_payment_credential(self):
        """Access payment credential."""
        addr = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        cred = addr.payment_credential
        assert cred.hash_hex == PAYMENT_KEY_HASH_HEX
        assert cred.is_key_hash

    def test_stake_credential(self):
        """Access stake credential."""
        addr = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        cred = addr.stake_credential
        assert cred.hash_hex == STAKE_KEY_HASH_HEX
        assert cred.is_key_hash

    def test_network_id(self):
        """Access network ID."""
        addr = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        assert addr.network_id == NetworkId.MAINNET

    def test_from_credentials(self):
        """Create base address from credentials."""
        payment = Credential.from_key_hash(PAYMENT_KEY_HASH_HEX)
        stake = Credential.from_key_hash(STAKE_KEY_HASH_HEX)
        addr = BaseAddress.from_credentials(NetworkId.MAINNET, payment, stake)
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_to_address(self):
        """Convert to generic Address."""
        base = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        addr = base.to_address()
        assert str(addr) == BASE_PAYMENT_KEY_STAKE_KEY

    def test_roundtrip(self):
        """Roundtrip through bytes."""
        original = BaseAddress.from_bech32(BASE_PAYMENT_KEY_STAKE_KEY)
        recovered = BaseAddress.from_bytes(original.to_bytes())
        assert str(original) == str(recovered)


class TestEnterpriseAddress:
    """Tests for EnterpriseAddress class."""

    def test_from_bech32(self):
        """Create enterprise address from Bech32."""
        addr = EnterpriseAddress.from_bech32(ENTERPRISE_KEY)
        assert str(addr) == ENTERPRISE_KEY

    def test_from_bytes(self):
        """Create enterprise address from bytes."""
        addr = EnterpriseAddress.from_bytes(ENTERPRISE_KEY_BYTES)
        assert str(addr) == ENTERPRISE_KEY

    def test_to_bytes(self):
        """Convert enterprise address to bytes."""
        addr = EnterpriseAddress.from_bech32(ENTERPRISE_KEY)
        assert addr.to_bytes() == ENTERPRISE_KEY_BYTES

    def test_payment_credential(self):
        """Access payment credential."""
        addr = EnterpriseAddress.from_bech32(ENTERPRISE_KEY)
        cred = addr.payment_credential
        assert cred.hash_hex == PAYMENT_KEY_HASH_HEX
        assert cred.is_key_hash

    def test_network_id(self):
        """Access network ID."""
        addr = EnterpriseAddress.from_bech32(ENTERPRISE_KEY)
        assert addr.network_id == NetworkId.MAINNET

    def test_from_credentials(self):
        """Create enterprise address from credentials."""
        payment = Credential.from_key_hash(PAYMENT_KEY_HASH_HEX)
        addr = EnterpriseAddress.from_credentials(NetworkId.MAINNET, payment)
        assert str(addr) == ENTERPRISE_KEY

    def test_script_credential(self):
        """Test with script credential."""
        addr = EnterpriseAddress.from_bech32(ENTERPRISE_SCRIPT)
        cred = addr.payment_credential
        assert cred.hash_hex == SCRIPT_HASH_HEX
        assert cred.is_script_hash


class TestRewardAddress:
    """Tests for RewardAddress class."""

    def test_from_bech32(self):
        """Create reward address from Bech32."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        assert str(addr) == REWARD_KEY

    def test_from_bytes(self):
        """Create reward address from bytes."""
        addr = RewardAddress.from_bytes(REWARD_KEY_BYTES)
        assert str(addr) == REWARD_KEY

    def test_to_bytes(self):
        """Convert reward address to bytes."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        assert addr.to_bytes() == REWARD_KEY_BYTES

    def test_credential(self):
        """Access stake credential."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        cred = addr.credential
        assert cred.hash_hex == STAKE_KEY_HASH_HEX
        assert cred.is_key_hash

    def test_network_id(self):
        """Access network ID."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        assert addr.network_id == NetworkId.MAINNET

    def test_from_credentials(self):
        """Create reward address from credentials."""
        stake = Credential.from_key_hash(STAKE_KEY_HASH_HEX)
        addr = RewardAddress.from_credentials(NetworkId.MAINNET, stake)
        assert str(addr) == REWARD_KEY

    def test_script_credential(self):
        """Test with script credential."""
        addr = RewardAddress.from_bech32(REWARD_SCRIPT)
        cred = addr.credential
        assert cred.hash_hex == SCRIPT_HASH_HEX
        assert cred.is_script_hash


class TestPointerAddress:
    """Tests for PointerAddress class."""

    def test_from_bech32(self):
        """Create pointer address from Bech32."""
        addr = PointerAddress.from_bech32(POINTER_KEY)
        assert str(addr) == POINTER_KEY

    def test_from_bytes(self):
        """Create pointer address from bytes."""
        addr = PointerAddress.from_bytes(POINTER_KEY_BYTES)
        assert str(addr) == POINTER_KEY

    def test_to_bytes(self):
        """Convert pointer address to bytes."""
        addr = PointerAddress.from_bech32(POINTER_KEY)
        assert addr.to_bytes() == POINTER_KEY_BYTES

    def test_payment_credential(self):
        """Access payment credential."""
        addr = PointerAddress.from_bech32(POINTER_KEY)
        cred = addr.payment_credential
        assert cred.hash_hex == PAYMENT_KEY_HASH_HEX

    def test_stake_pointer(self):
        """Access stake pointer."""
        addr = PointerAddress.from_bech32(POINTER_KEY)
        pointer = addr.stake_pointer
        assert pointer.slot == STAKE_POINTER.slot
        assert pointer.tx_index == STAKE_POINTER.tx_index
        assert pointer.cert_index == STAKE_POINTER.cert_index

    def test_network_id(self):
        """Access network ID."""
        addr = PointerAddress.from_bech32(POINTER_KEY)
        assert addr.network_id == NetworkId.MAINNET

    def test_from_credentials(self):
        """Create pointer address from credentials."""
        payment = Credential.from_key_hash(PAYMENT_KEY_HASH_HEX)
        addr = PointerAddress.from_credentials(NetworkId.MAINNET, payment, STAKE_POINTER)
        assert str(addr) == POINTER_KEY


class TestByronAddress:
    """Tests for ByronAddress class."""

    def test_from_base58(self):
        """Create Byron address from Base58."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_from_bytes(self):
        """Create Byron address from bytes."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)
        assert str(addr) == BYRON_MAINNET_YOROI

    def test_to_bytes(self):
        """Convert Byron address to bytes."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        assert addr.to_bytes() == BYRON_MAINNET_YOROI_BYTES

    def test_to_base58(self):
        """Convert Byron address to Base58."""
        addr = ByronAddress.from_bytes(BYRON_MAINNET_YOROI_BYTES)
        assert addr.to_base58() == BYRON_MAINNET_YOROI

    def test_network_id(self):
        """Access network ID."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        assert addr.network_id == NetworkId.MAINNET

    def test_address_type(self):
        """Access Byron address type."""
        addr = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        assert addr.address_type == ByronAddressType.PUBKEY

    def test_to_address(self):
        """Convert to generic Address."""
        byron = ByronAddress.from_base58(BYRON_MAINNET_YOROI)
        addr = byron.to_address()
        assert str(addr) == BYRON_MAINNET_YOROI


class TestStakePointer:
    """Tests for StakePointer class."""

    def test_creation(self):
        """Create stake pointer."""
        pointer = StakePointer(slot=100, tx_index=5, cert_index=2)
        assert pointer.slot == 100
        assert pointer.tx_index == 5
        assert pointer.cert_index == 2

    def test_immutable(self):
        """Stake pointer should be immutable."""
        pointer = StakePointer(slot=100, tx_index=5, cert_index=2)
        with pytest.raises(Exception):  # frozen dataclass raises error on assignment
            pointer.slot = 200

    def test_negative_slot_raises(self):
        """Negative slot should raise error."""
        with pytest.raises(ValueError):
            StakePointer(slot=-1, tx_index=5, cert_index=2)

    def test_negative_tx_index_raises(self):
        """Negative tx_index should raise error."""
        with pytest.raises(ValueError):
            StakePointer(slot=100, tx_index=-1, cert_index=2)

    def test_negative_cert_index_raises(self):
        """Negative cert_index should raise error."""
        with pytest.raises(ValueError):
            StakePointer(slot=100, tx_index=5, cert_index=-1)


class TestByronAddressAttributes:
    """Tests for ByronAddressAttributes class."""

    def test_mainnet(self):
        """Create mainnet attributes."""
        attrs = ByronAddressAttributes.mainnet()
        assert attrs.derivation_path == b""
        assert attrs.magic == -1
        assert not attrs.has_network_magic

    def test_testnet(self):
        """Create testnet attributes with magic."""
        attrs = ByronAddressAttributes.testnet(magic=764824073)
        assert attrs.derivation_path == b""
        assert attrs.magic == 764824073
        assert attrs.has_network_magic


class TestAddressType:
    """Tests for AddressType enum."""

    def test_base_types(self):
        """Test base address type values."""
        assert AddressType.BASE_PAYMENT_KEY_STAKE_KEY == 0b0000
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY == 0b0001
        assert AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT == 0b0010
        assert AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT == 0b0011

    def test_pointer_types(self):
        """Test pointer address type values."""
        assert AddressType.POINTER_KEY == 0b0100
        assert AddressType.POINTER_SCRIPT == 0b0101

    def test_enterprise_types(self):
        """Test enterprise address type values."""
        assert AddressType.ENTERPRISE_KEY == 0b0110
        assert AddressType.ENTERPRISE_SCRIPT == 0b0111

    def test_byron_type(self):
        """Test Byron address type value."""
        assert AddressType.BYRON == 0b1000

    def test_reward_types(self):
        """Test reward address type values."""
        assert AddressType.REWARD_KEY == 0b1110
        assert AddressType.REWARD_SCRIPT == 0b1111
