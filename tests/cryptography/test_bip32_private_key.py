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
from cometa.cryptography import (
    Bip32PrivateKey,
    Bip32PublicKey,
    Ed25519PrivateKey,
    harden
)
from cometa.errors import CardanoError


BIP32_PRIVATE_KEY_SIZE = 96
BIP32_PRIVATE_KEY_HEX = "a0ab55b174ba8cd95e2362d035f377b4dc779a0fae65767e3b8dd790fa748250f3ef2cc372c207d7902607ffef01872a4c785cd27e7342de7f4332f2d5fdc3a8d0c110e1d6a061d3558eb6a3138a3982253c6616e1bf4d8bd31e92de8328affe"

BIP32_PRIVATE_KEY_BYTES = bytes([
    0xa0, 0xab, 0x55, 0xb1, 0x74, 0xba, 0x8c, 0xd9,
    0x5e, 0x23, 0x62, 0xd0, 0x35, 0xf3, 0x77, 0xb4,
    0xdc, 0x77, 0x9a, 0x0f, 0xae, 0x65, 0x76, 0x7e,
    0x3b, 0x8d, 0xd7, 0x90, 0xfa, 0x74, 0x82, 0x50,
    0xf3, 0xef, 0x2c, 0xc3, 0x72, 0xc2, 0x07, 0xd7,
    0x90, 0x26, 0x07, 0xff, 0xef, 0x01, 0x87, 0x2a,
    0x4c, 0x78, 0x5c, 0xd2, 0x7e, 0x73, 0x42, 0xde,
    0x7f, 0x43, 0x32, 0xf2, 0xd5, 0xfd, 0xc3, 0xa8,
    0xd0, 0xc1, 0x10, 0xe1, 0xd6, 0xa0, 0x61, 0xd3,
    0x55, 0x8e, 0xb6, 0xa3, 0x13, 0x8a, 0x39, 0x82,
    0x25, 0x3c, 0x66, 0x16, 0xe1, 0xbf, 0x4d, 0x8b,
    0xd3, 0x1e, 0x92, 0xde, 0x83, 0x28, 0xaf, 0xfe
])

BIP39_PASSWORD = bytes([
    0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x70, 0x61, 0x73,
    0x73, 0x77, 0x6f, 0x72, 0x64, 0x5f, 0x40, 0x23,
    0x24, 0x25, 0x5e, 0x26
])

BIP39_ENTROPY = bytes([
    0xca, 0xec, 0x96, 0xd0, 0x9f, 0xc2, 0x02, 0x0a,
    0xb2, 0x30, 0x19, 0x9e, 0x01, 0x88, 0xcd, 0x6a,
    0x55, 0x4e, 0x2d, 0xa2, 0xcb, 0xa3, 0x2d, 0xe9,
    0xff, 0x6c, 0x09, 0x08, 0xc7, 0xf0, 0x4d, 0x65
])

EXPECTED_KEY_FROM_ENTROPY_HEX = "60292301b8dd20a74b58a0bd4ecdeb244a95e757c7a2d25962ada75e271d045ff827c85a5530bfe76975b4189c5fd6d32d4fe43c81373f386fde2fa0e6d0255a2ac1f1560a893ea7937c5bfbfdeab459b1a396f1174b9c5a673a640d01880c35"

HARDENED_DERIVED_KEY_HEX = "3809937b61bd4f180a1e9bd15237e7bc20e36b9037dd95ef60d84f6004758250a22e1bfc0d81e9adb7760bcba7f5214416b3e9f27c8d58794a3a7fead2d5b6958d515cb54181fb2f5fc3af329e80949c082fb52f7b07e359bd7835a6762148bf"

UNHARDENED_BASE_KEY_HEX = "d8287e922756977dc0b79659e6eebcae3a1fb29a22ce1449c94f125462586951390af99a0350130451e9bf4f4691f37c352dc7025d52d9132f61a82f61d3803d00b5f1652f5cbe257e567c883dc2b16e0a9568b19c5b81ea8bd197fc95e8bdcf"

UNHARDENED_DERIVED_KEY_HEX = "08f9d7de597d31fade994b8a1e9d3e3afe53ac8393297e8f4d96225d725869517ae54c631588abb408fcab0676a4da6b60c82b3a3d7045a26a576c7901e5e9579db12d11a3559131a47f51f854a6234725ab8767d3fcc4c9908be55508f3c712"

EXPECTED_PUBLIC_KEY_HEX = "311f8914b8934efbe7cbb8cc4745853de12e8ea402df6f9f69b18d2792c6bed8d0c110e1d6a061d3558eb6a3138a3982253c6616e1bf4d8bd31e92de8328affe"

ED25519_PRIVATE_KEY_BYTES = bytes([
    0xa0, 0xab, 0x55, 0xb1, 0x74, 0xba, 0x8c, 0xd9,
    0x5e, 0x23, 0x62, 0xd0, 0x35, 0xf3, 0x77, 0xb4,
    0xdc, 0x77, 0x9a, 0x0f, 0xae, 0x65, 0x76, 0x7e,
    0x3b, 0x8d, 0xd7, 0x90, 0xfa, 0x74, 0x82, 0x50,
    0xf3, 0xef, 0x2c, 0xc3, 0x72, 0xc2, 0x07, 0xd7,
    0x90, 0x26, 0x07, 0xff, 0xef, 0x01, 0x87, 0x2a,
    0x4c, 0x78, 0x5c, 0xd2, 0x7e, 0x73, 0x42, 0xde,
    0x7f, 0x43, 0x32, 0xf2, 0xd5, 0xfd, 0xc3, 0xa8
])


class TestBip32PrivateKeyFromBytes:
    """Tests for Bip32PrivateKey.from_bytes()"""

    def test_from_bytes_creates_private_key(self):
        """Test creating BIP32 private key from raw bytes"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert priv_key is not None
        assert priv_key.to_bytes() == BIP32_PRIVATE_KEY_BYTES

    def test_from_bytes_with_valid_96_byte_key(self):
        """Test from_bytes with valid 96-byte private key"""
        data = bytes(96)
        priv_key = Bip32PrivateKey.from_bytes(data)
        assert len(priv_key.to_bytes()) == 96
        assert priv_key.to_bytes() == data

    def test_from_bytes_with_bytearray(self):
        """Test from_bytes with bytearray"""
        data = bytearray(BIP32_PRIVATE_KEY_BYTES)
        priv_key = Bip32PrivateKey.from_bytes(data)
        assert priv_key.to_bytes() == bytes(data)

    def test_from_bytes_preserves_test_vector_data(self):
        """Test from_bytes preserves test vector data correctly"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        result_bytes = priv_key.to_bytes()
        assert len(result_bytes) == 96
        for i in range(96):
            assert result_bytes[i] == BIP32_PRIVATE_KEY_BYTES[i]

    def test_from_bytes_with_empty_data_raises_error(self):
        """Test from_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_bytes(b"")

    def test_from_bytes_with_none_raises_error(self):
        """Test from_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Bip32PrivateKey.from_bytes(None)

    def test_from_bytes_with_wrong_size_raises_error(self):
        """Test from_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_bytes(bytes(32))

    def test_from_bytes_with_zero_length_raises_error(self):
        """Test from_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_bytes(bytes(0))

    def test_from_bytes_with_too_large_size_raises_error(self):
        """Test from_bytes with too large size raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_bytes(bytes(128))


class TestBip32PrivateKeyFromHex:
    """Tests for Bip32PrivateKey.from_hex()"""

    def test_from_hex_creates_private_key(self):
        """Test creating BIP32 private key from hex string"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        assert priv_key is not None
        assert priv_key.to_hex() == BIP32_PRIVATE_KEY_HEX

    def test_from_hex_with_valid_192_char_hex(self):
        """Test from_hex with valid 192-character hex string"""
        hex_str = "00" * 96
        priv_key = Bip32PrivateKey.from_hex(hex_str)
        assert len(priv_key.to_bytes()) == 96
        assert priv_key.to_hex() == hex_str

    def test_from_hex_with_test_vector(self):
        """Test from_hex with test vector hex string"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        assert priv_key.to_hex() == BIP32_PRIVATE_KEY_HEX
        assert priv_key.to_bytes() == BIP32_PRIVATE_KEY_BYTES

    def test_from_hex_with_empty_string_raises_error(self):
        """Test from_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_hex("")

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test from_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_hex(hex_str)

    def test_from_hex_with_wrong_size_raises_error(self):
        """Test from_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_hex("00" * 32)

    def test_from_hex_with_zero_length_raises_error(self):
        """Test from_hex with zero length raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_hex("")

    def test_from_hex_with_none_raises_error(self):
        """Test from_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Bip32PrivateKey.from_hex(None)


class TestBip32PrivateKeyFromBip39Entropy:
    """Tests for Bip32PrivateKey.from_bip39_entropy()"""

    def test_from_bip39_entropy_creates_key_with_password(self):
        """Test creating BIP32 key from BIP39 entropy with password"""
        priv_key = Bip32PrivateKey.from_bip39_entropy(BIP39_PASSWORD, BIP39_ENTROPY)
        assert priv_key is not None
        assert len(priv_key.to_bytes()) == 96

    def test_from_bip39_entropy_produces_expected_key(self):
        """Test from_bip39_entropy produces expected key with test vector"""
        priv_key = Bip32PrivateKey.from_bip39_entropy(BIP39_PASSWORD, BIP39_ENTROPY)
        assert priv_key.to_hex() == EXPECTED_KEY_FROM_ENTROPY_HEX

    def test_from_bip39_entropy_with_empty_password(self):
        """Test from_bip39_entropy with empty password"""
        priv_key = Bip32PrivateKey.from_bip39_entropy(b"", BIP39_ENTROPY)
        assert priv_key is not None
        assert len(priv_key.to_bytes()) == 96

    def test_from_bip39_entropy_with_string_password(self):
        """Test from_bip39_entropy with string password"""
        priv_key = Bip32PrivateKey.from_bip39_entropy("test_password", BIP39_ENTROPY)
        assert priv_key is not None
        assert len(priv_key.to_bytes()) == 96

    def test_from_bip39_entropy_with_bytearray_entropy(self):
        """Test from_bip39_entropy with bytearray entropy"""
        entropy = bytearray(BIP39_ENTROPY)
        priv_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        assert priv_key is not None

    def test_from_bip39_entropy_is_deterministic(self):
        """Test from_bip39_entropy produces same key for same inputs"""
        key1 = Bip32PrivateKey.from_bip39_entropy(BIP39_PASSWORD, BIP39_ENTROPY)
        key2 = Bip32PrivateKey.from_bip39_entropy(BIP39_PASSWORD, BIP39_ENTROPY)
        assert key1.to_bytes() == key2.to_bytes()

    def test_from_bip39_entropy_with_none_entropy_raises_error(self):
        """Test from_bip39_entropy with None entropy raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Bip32PrivateKey.from_bip39_entropy(b"", None)

    def test_from_bip39_entropy_with_empty_entropy_raises_error(self):
        """Test from_bip39_entropy with empty entropy raises error"""
        with pytest.raises(CardanoError):
            Bip32PrivateKey.from_bip39_entropy(b"", b"")

    def test_from_bip39_entropy_with_different_entropy_sizes(self):
        """Test from_bip39_entropy with different entropy sizes"""
        priv_key_16 = Bip32PrivateKey.from_bip39_entropy(b"", bytes(16))
        assert priv_key_16 is not None
        priv_key_24 = Bip32PrivateKey.from_bip39_entropy(b"", bytes(24))
        assert priv_key_24 is not None
        priv_key_32 = Bip32PrivateKey.from_bip39_entropy(b"", bytes(32))
        assert priv_key_32 is not None


class TestBip32PrivateKeyDerive:
    """Tests for Bip32PrivateKey.derive()"""

    def test_derive_with_hardened_indices(self):
        """Test derive with hardened derivation indices"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([harden(1852), harden(1815), harden(0)])
        assert derived is not None
        assert isinstance(derived, Bip32PrivateKey)

    def test_derive_hardened_produces_expected_key(self):
        """Test derive with hardened path produces expected key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([harden(1852), harden(1815), harden(0)])
        assert derived.to_hex() == HARDENED_DERIVED_KEY_HEX

    def test_derive_with_unhardened_indices(self):
        """Test derive with unhardened derivation indices"""
        priv_key = Bip32PrivateKey.from_hex(UNHARDENED_BASE_KEY_HEX)
        derived = priv_key.derive([1852, 1815, 0])
        assert derived is not None
        assert isinstance(derived, Bip32PrivateKey)

    def test_derive_unhardened_produces_expected_key(self):
        """Test derive with unhardened path produces expected key"""
        priv_key = Bip32PrivateKey.from_hex(UNHARDENED_BASE_KEY_HEX)
        derived = priv_key.derive([1852, 1815, 0])
        assert derived.to_hex() == UNHARDENED_DERIVED_KEY_HEX

    def test_derive_with_single_index(self):
        """Test derive with single index"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([0])
        assert derived is not None
        assert isinstance(derived, Bip32PrivateKey)

    def test_derive_with_multiple_indices(self):
        """Test derive with multiple indices"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([harden(1852), harden(1815), harden(0), 0, 0])
        assert derived is not None
        assert isinstance(derived, Bip32PrivateKey)

    def test_derive_produces_different_key(self):
        """Test derive produces different key than parent"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([0])
        assert priv_key.to_bytes() != derived.to_bytes()

    def test_derive_is_deterministic(self):
        """Test derive produces same result for same indices"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived1 = priv_key.derive([harden(1852), harden(1815), harden(0)])
        derived2 = priv_key.derive([harden(1852), harden(1815), harden(0)])
        assert derived1.to_bytes() == derived2.to_bytes()

    def test_derive_with_empty_indices_raises_error(self):
        """Test derive with empty indices list raises error"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        with pytest.raises(CardanoError):
            priv_key.derive([])

    def test_derive_different_paths_produce_different_keys(self):
        """Test different derivation paths produce different keys"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived1 = priv_key.derive([0])
        derived2 = priv_key.derive([1])
        assert derived1.to_bytes() != derived2.to_bytes()


class TestBip32PrivateKeyGetPublicKey:
    """Tests for Bip32PrivateKey.get_public_key()"""

    def test_get_public_key_returns_bip32_public_key(self):
        """Test get_public_key returns Bip32PublicKey instance"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        pub_key = priv_key.get_public_key()
        assert isinstance(pub_key, Bip32PublicKey)

    def test_get_public_key_produces_64_byte_key(self):
        """Test get_public_key produces 64-byte public key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        pub_key = priv_key.get_public_key()
        assert len(pub_key.to_bytes()) == 64

    def test_get_public_key_produces_expected_key(self):
        """Test get_public_key produces expected public key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        pub_key = priv_key.get_public_key()
        assert pub_key.to_hex() == EXPECTED_PUBLIC_KEY_HEX

    def test_get_public_key_is_deterministic(self):
        """Test get_public_key produces same result consistently"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        pub_key1 = priv_key.get_public_key()
        pub_key2 = priv_key.get_public_key()
        assert pub_key1.to_bytes() == pub_key2.to_bytes()


class TestBip32PrivateKeyToEd25519Key:
    """Tests for Bip32PrivateKey.to_ed25519_key()"""

    def test_to_ed25519_key_returns_ed25519_private_key(self):
        """Test to_ed25519_key returns Ed25519PrivateKey instance"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        ed25519_key = priv_key.to_ed25519_key()
        assert isinstance(ed25519_key, Ed25519PrivateKey)

    def test_to_ed25519_key_produces_64_byte_key(self):
        """Test to_ed25519_key produces 64-byte extended Ed25519 key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        ed25519_key = priv_key.to_ed25519_key()
        assert len(ed25519_key.to_bytes()) == 64

    def test_to_ed25519_key_extracts_first_64_bytes(self):
        """Test to_ed25519_key extracts first 64 bytes of BIP32 key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        ed25519_key = priv_key.to_ed25519_key()
        assert ed25519_key.to_bytes() == ED25519_PRIVATE_KEY_BYTES

    def test_to_ed25519_key_is_deterministic(self):
        """Test to_ed25519_key produces same result for same BIP32 key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        ed25519_key1 = priv_key.to_ed25519_key()
        ed25519_key2 = priv_key.to_ed25519_key()
        assert ed25519_key1.to_bytes() == ed25519_key2.to_bytes()


class TestBip32PrivateKeyToBytes:
    """Tests for Bip32PrivateKey.to_bytes()"""

    def test_to_bytes_returns_correct_data(self):
        """Test to_bytes returns correct raw bytes"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert priv_key.to_bytes() == BIP32_PRIVATE_KEY_BYTES

    def test_to_bytes_with_created_private_key(self):
        """Test to_bytes with created private key"""
        data = bytes(96)
        priv_key = Bip32PrivateKey.from_bytes(data)
        result = priv_key.to_bytes()
        assert len(result) == 96
        assert isinstance(result, bytes)
        assert result == data

    def test_to_bytes_returns_96_bytes(self):
        """Test to_bytes always returns 96 bytes"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        result = priv_key.to_bytes()
        assert len(result) == 96

    def test_to_bytes_preserves_all_byte_values(self):
        """Test to_bytes preserves all byte values"""
        data = bytes(range(96))
        priv_key = Bip32PrivateKey.from_bytes(data)
        assert priv_key.to_bytes() == data


class TestBip32PrivateKeyToHex:
    """Tests for Bip32PrivateKey.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        hex_str = priv_key.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length(self):
        """Test to_hex returns correct length"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        hex_str = priv_key.to_hex()
        assert len(hex_str) == 192

    def test_to_hex_returns_valid_hex(self):
        """Test to_hex returns valid hexadecimal string"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        hex_str = priv_key.to_hex()
        assert hex_str == BIP32_PRIVATE_KEY_HEX

    def test_to_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = BIP32_PRIVATE_KEY_HEX
        priv_key = Bip32PrivateKey.from_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex


class TestBip32PrivateKeyEquality:
    """Tests for Bip32PrivateKey equality operations"""

    def test_equality_with_same_private_key(self):
        """Test equality with same private key values"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert key1 == key2

    def test_inequality_with_different_private_key(self):
        """Test inequality with different private key values"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(bytes(96))
        assert key1 != key2

    def test_equality_with_non_private_key_returns_false(self):
        """Test equality with non-Bip32PrivateKey returns False"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert not (priv_key == "not a private key")
        assert not (priv_key == 123)
        assert not (priv_key == None)

    def test_equality_hex_and_bytes_constructed(self):
        """Test equality between hex and bytes constructed private keys"""
        key1 = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        key2 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert key1 == key2


class TestBip32PrivateKeyHash:
    """Tests for Bip32PrivateKey.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows private key to be used in set"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key3 = Bip32PrivateKey.from_bytes(bytes(96))
        key_set = {key1, key2, key3}
        assert len(key_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows private key to be used as dict key"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(bytes(96))
        key_dict = {key1: "value1", key2: "value2"}
        assert len(key_dict) == 2
        assert key_dict[key1] == "value1"

    def test_equal_private_keys_have_same_hash(self):
        """Test equal private keys have same hash value"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        assert hash(key1) == hash(key2)


class TestBip32PrivateKeyRepr:
    """Tests for Bip32PrivateKey.__repr__()"""

    def test_repr_hides_key_material(self):
        """Test __repr__ does not expose key material"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        repr_str = repr(priv_key)
        assert "Bip32PrivateKey" in repr_str
        assert "<hidden>" in repr_str
        assert BIP32_PRIVATE_KEY_HEX not in repr_str

    def test_repr_is_safe(self):
        """Test __repr__ provides safe representation"""
        priv_key = Bip32PrivateKey.from_bytes(bytes(96))
        repr_str = repr(priv_key)
        assert "Bip32PrivateKey" in repr_str
        for byte_val in BIP32_PRIVATE_KEY_BYTES:
            assert hex(byte_val) not in repr_str.lower()


class TestBip32PrivateKeyStr:
    """Tests for Bip32PrivateKey.__str__()"""

    def test_str_hides_key_material(self):
        """Test __str__ does not expose key material"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        str_repr = str(priv_key)
        assert "Bip32PrivateKey" in str_repr
        assert "<hidden>" in str_repr
        assert BIP32_PRIVATE_KEY_HEX not in str_repr


class TestBip32PrivateKeyContextManager:
    """Tests for Bip32PrivateKey context manager protocol"""

    def test_context_manager_usage(self):
        """Test private key can be used as context manager"""
        with Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES) as priv_key:
            assert len(priv_key.to_bytes()) == 96
            pub_key = priv_key.get_public_key()
        assert len(pub_key.to_bytes()) == 64

    def test_context_manager_preserves_data(self):
        """Test context manager preserves private key data"""
        with Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX) as priv_key:
            result = priv_key.to_hex()
        assert result == BIP32_PRIVATE_KEY_HEX


class TestBip32PrivateKeyEdgeCases:
    """Tests for Bip32PrivateKey edge cases"""

    def test_private_key_with_all_zeros(self):
        """Test private key with all zero bytes"""
        data = bytes(96)
        priv_key = Bip32PrivateKey.from_bytes(data)
        assert priv_key.to_bytes() == data
        assert priv_key.to_hex() == "00" * 96

    def test_private_key_with_all_ones(self):
        """Test private key with all 0xFF bytes"""
        data = bytes([0xFF] * 96)
        priv_key = Bip32PrivateKey.from_bytes(data)
        assert priv_key.to_bytes() == data
        assert priv_key.to_hex() == "ff" * 96

    def test_consecutive_private_keys_are_independent(self):
        """Test that consecutive private key creations are independent"""
        key1 = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        key2 = Bip32PrivateKey.from_bytes(bytes(96))
        assert key1 != key2

    def test_private_key_preserves_byte_order(self):
        """Test private key preserves byte order"""
        data = bytes(range(96))
        priv_key = Bip32PrivateKey.from_bytes(data)
        result = priv_key.to_bytes()
        for i in range(96):
            assert result[i] == i

    def test_hex_case_insensitivity(self):
        """Test from_hex handles uppercase hex"""
        key1 = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX.upper())
        key2 = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX.lower())
        assert key1 == key2

    def test_multiple_to_bytes_calls_consistent(self):
        """Test multiple to_bytes calls return consistent results"""
        priv_key = Bip32PrivateKey.from_bytes(BIP32_PRIVATE_KEY_BYTES)
        result1 = priv_key.to_bytes()
        result2 = priv_key.to_bytes()
        assert result1 == result2

    def test_multiple_to_hex_calls_consistent(self):
        """Test multiple to_hex calls return consistent results"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        result1 = priv_key.to_hex()
        result2 = priv_key.to_hex()
        assert result1 == result2


class TestBip32PrivateKeyRoundTrips:
    """Tests for Bip32PrivateKey round-trip conversions"""

    def test_bytes_round_trip(self):
        """Test bytes round-trip conversion"""
        original_bytes = BIP32_PRIVATE_KEY_BYTES
        priv_key = Bip32PrivateKey.from_bytes(original_bytes)
        result_bytes = priv_key.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = BIP32_PRIVATE_KEY_HEX
        priv_key = Bip32PrivateKey.from_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex

    def test_bytes_to_hex_to_bytes(self):
        """Test bytes -> hex -> bytes conversion"""
        original_bytes = BIP32_PRIVATE_KEY_BYTES
        key1 = Bip32PrivateKey.from_bytes(original_bytes)
        hex_str = key1.to_hex()
        key2 = Bip32PrivateKey.from_hex(hex_str)
        result_bytes = key2.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_to_bytes_to_hex(self):
        """Test hex -> bytes -> hex conversion"""
        original_hex = BIP32_PRIVATE_KEY_HEX
        key1 = Bip32PrivateKey.from_hex(original_hex)
        byte_data = key1.to_bytes()
        key2 = Bip32PrivateKey.from_bytes(byte_data)
        result_hex = key2.to_hex()
        assert result_hex == original_hex


class TestBip32PrivateKeyDerivationChains:
    """Tests for Bip32PrivateKey derivation chains"""

    def test_derive_chain_is_deterministic(self):
        """Test derivation chain produces consistent results"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived1 = priv_key.derive([0]).derive([1]).derive([2])
        derived2 = priv_key.derive([0]).derive([1]).derive([2])
        assert derived1.to_bytes() == derived2.to_bytes()

    def test_derive_chain_different_from_direct_path(self):
        """Test stepwise derivation equals direct multi-index derivation"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived_direct = priv_key.derive([0, 1, 2])
        derived_chain = priv_key.derive([0]).derive([1]).derive([2])
        assert derived_direct.to_bytes() == derived_chain.to_bytes()


class TestBip32PrivateKeySecurity:
    """Tests for Bip32PrivateKey security features"""

    def test_repr_never_exposes_key(self):
        """Test __repr__ never exposes key material"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        repr_str = repr(priv_key)
        assert "<hidden>" in repr_str
        assert "Bip32PrivateKey" in repr_str
        longer_hex_parts = [BIP32_PRIVATE_KEY_HEX[i:i+8] for i in range(0, len(BIP32_PRIVATE_KEY_HEX), 8)]
        for hex_part in longer_hex_parts:
            assert hex_part not in repr_str

    def test_str_never_exposes_key(self):
        """Test __str__ never exposes key material"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        str_repr = str(priv_key)
        assert "<hidden>" in str_repr
        assert "Bip32PrivateKey" in str_repr
        longer_hex_parts = [BIP32_PRIVATE_KEY_HEX[i:i+8] for i in range(0, len(BIP32_PRIVATE_KEY_HEX), 8)]
        for hex_part in longer_hex_parts:
            assert hex_part not in str_repr


class TestBip32PrivateKeyIntegration:
    """Integration tests for Bip32PrivateKey"""

    def test_full_wallet_derivation_path(self):
        """Test complete wallet derivation path"""
        entropy = BIP39_ENTROPY
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        account_key = root_key.derive([harden(1852), harden(1815), harden(0)])
        payment_key = account_key.derive([0, 0])
        assert payment_key is not None
        assert isinstance(payment_key, Bip32PrivateKey)

    def test_public_key_derivation_from_derived_key(self):
        """Test deriving public key from derived private key"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([harden(1852), harden(1815), harden(0)])
        pub_key = derived.get_public_key()
        assert isinstance(pub_key, Bip32PublicKey)
        assert len(pub_key.to_bytes()) == 64

    def test_ed25519_conversion_from_derived_key(self):
        """Test converting derived BIP32 key to Ed25519"""
        priv_key = Bip32PrivateKey.from_hex(BIP32_PRIVATE_KEY_HEX)
        derived = priv_key.derive([harden(1852), harden(1815), harden(0)])
        ed25519_key = derived.to_ed25519_key()
        assert isinstance(ed25519_key, Ed25519PrivateKey)
        assert len(ed25519_key.to_bytes()) == 64

    def test_different_passwords_produce_different_keys(self):
        """Test different passwords with same entropy produce different keys"""
        key1 = Bip32PrivateKey.from_bip39_entropy(b"password1", BIP39_ENTROPY)
        key2 = Bip32PrivateKey.from_bip39_entropy(b"password2", BIP39_ENTROPY)
        assert key1.to_bytes() != key2.to_bytes()

    def test_different_entropy_produces_different_keys(self):
        """Test different entropy with same password produces different keys"""
        entropy1 = BIP39_ENTROPY
        entropy2 = bytes([0xFF] * 32)
        key1 = Bip32PrivateKey.from_bip39_entropy(b"", entropy1)
        key2 = Bip32PrivateKey.from_bip39_entropy(b"", entropy2)
        assert key1.to_bytes() != key2.to_bytes()


class TestHardenFunction:
    """Tests for the harden() helper function"""

    def test_harden_zero_index(self):
        """Test hardening index 0"""
        hardened = harden(0)
        assert hardened == 0x80000000
        assert hardened == 2147483648

    def test_harden_cardano_purpose(self):
        """Test hardening Cardano purpose index (1852)"""
        hardened = harden(1852)
        assert hardened == 0x8000073c
        assert hardened == 2147485500

    def test_harden_ada_coin_type(self):
        """Test hardening ADA coin type index (1815)"""
        hardened = harden(1815)
        assert hardened == 0x80000717
        assert hardened == 2147485463

    def test_harden_max_unhardened_index(self):
        """Test hardening maximum unhardened index"""
        max_unhardened = 2147483647
        hardened = harden(max_unhardened)
        assert hardened == 0xFFFFFFFF
        assert hardened == 4294967295

    def test_harden_various_indices(self):
        """Test hardening various indices"""
        assert harden(1) == 0x80000001
        assert harden(100) == 0x80000064
        assert harden(1000) == 0x800003E8

    def test_harden_preserves_lower_bits(self):
        """Test harden preserves lower 31 bits"""
        index = 12345
        hardened = harden(index)
        assert (hardened & 0x7FFFFFFF) == index
        assert (hardened & 0x80000000) != 0
