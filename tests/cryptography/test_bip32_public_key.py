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
from cometa.cryptography import Bip32PublicKey, Ed25519PublicKey, Blake2bHash
from cometa.errors import CardanoError


BIP32_PUBLIC_KEY_SIZE = 64
BIP32_PUBLIC_KEY_HEX = "6fd8d9c696b01525cc45f15583fc9447c66e1c71fd1a11c8885368404cd0a4ab00b5f1652f5cbe257e567c883dc2b16e0a9568b19c5b81ea8bd197fc95e8bdcf"

BIP32_PUBLIC_KEY_BYTES = bytes([
    0x6f, 0xd8, 0xd9, 0xc6, 0x96, 0xb0, 0x15, 0x25,
    0xcc, 0x45, 0xf1, 0x55, 0x83, 0xfc, 0x94, 0x47,
    0xc6, 0x6e, 0x1c, 0x71, 0xfd, 0x1a, 0x11, 0xc8,
    0x88, 0x53, 0x68, 0x40, 0x4c, 0xd0, 0xa4, 0xab,
    0x00, 0xb5, 0xf1, 0x65, 0x2f, 0x5c, 0xbe, 0x25,
    0x7e, 0x56, 0x7c, 0x88, 0x3d, 0xc2, 0xb1, 0x6e,
    0x0a, 0x95, 0x68, 0xb1, 0x9c, 0x5b, 0x81, 0xea,
    0x8b, 0xd1, 0x97, 0xfc, 0x95, 0xe8, 0xbd, 0xcf
])

ED25519_PUBLIC_KEY_BYTES = bytes([
    0x6f, 0xd8, 0xd9, 0xc6, 0x96, 0xb0, 0x15, 0x25,
    0xcc, 0x45, 0xf1, 0x55, 0x83, 0xfc, 0x94, 0x47,
    0xc6, 0x6e, 0x1c, 0x71, 0xfd, 0x1a, 0x11, 0xc8,
    0x88, 0x53, 0x68, 0x40, 0x4c, 0xd0, 0xa4, 0xab
])

DERIVED_KEY_HEX = "b857a8cd1dbbfed1824359d9d9e58bc8ffb9f66812b404f4c6ffc315629835bf9db12d11a3559131a47f51f854a6234725ab8767d3fcc4c9908be55508f3c712"


class TestBip32PublicKeyFromBytes:
    """Tests for Bip32PublicKey.from_bytes()"""

    def test_from_bytes_creates_public_key(self):
        """Test creating BIP32 public key from raw bytes"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert pub_key is not None
        assert pub_key.to_bytes() == BIP32_PUBLIC_KEY_BYTES

    def test_from_bytes_with_valid_64_byte_key(self):
        """Test from_bytes with valid 64-byte public key"""
        data = bytes(64)
        pub_key = Bip32PublicKey.from_bytes(data)
        assert len(pub_key.to_bytes()) == 64
        assert pub_key.to_bytes() == data

    def test_from_bytes_with_bytearray(self):
        """Test from_bytes with bytearray"""
        data = bytearray(BIP32_PUBLIC_KEY_BYTES)
        pub_key = Bip32PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == bytes(data)

    def test_from_bytes_preserves_test_vector_data(self):
        """Test from_bytes preserves test vector data correctly"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        result_bytes = pub_key.to_bytes()
        assert len(result_bytes) == 64
        for i in range(64):
            assert result_bytes[i] == BIP32_PUBLIC_KEY_BYTES[i]

    def test_from_bytes_with_empty_data_raises_error(self):
        """Test from_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_bytes(b"")

    def test_from_bytes_with_none_raises_error(self):
        """Test from_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Bip32PublicKey.from_bytes(None)

    def test_from_bytes_with_wrong_size_raises_error(self):
        """Test from_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_bytes(bytes(32))

    def test_from_bytes_with_zero_length_raises_error(self):
        """Test from_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_bytes(bytes(0))

    def test_from_bytes_with_too_large_size_raises_error(self):
        """Test from_bytes with too large size raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_bytes(bytes(128))


class TestBip32PublicKeyFromHex:
    """Tests for Bip32PublicKey.from_hex()"""

    def test_from_hex_creates_public_key(self):
        """Test creating BIP32 public key from hex string"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        assert pub_key is not None
        assert pub_key.to_hex() == BIP32_PUBLIC_KEY_HEX

    def test_from_hex_with_valid_128_char_hex(self):
        """Test from_hex with valid 128-character hex string"""
        hex_str = "00" * 64
        pub_key = Bip32PublicKey.from_hex(hex_str)
        assert len(pub_key.to_bytes()) == 64
        assert pub_key.to_hex() == hex_str

    def test_from_hex_with_test_vector(self):
        """Test from_hex with test vector hex string"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        assert pub_key.to_hex() == BIP32_PUBLIC_KEY_HEX
        assert pub_key.to_bytes() == BIP32_PUBLIC_KEY_BYTES

    def test_from_hex_with_empty_string_raises_error(self):
        """Test from_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_hex("")

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test from_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_hex(hex_str)

    def test_from_hex_with_wrong_size_raises_error(self):
        """Test from_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_hex("00" * 32)

    def test_from_hex_with_zero_length_raises_error(self):
        """Test from_hex with zero length raises error"""
        with pytest.raises(CardanoError):
            Bip32PublicKey.from_hex("")

    def test_from_hex_with_none_raises_error(self):
        """Test from_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Bip32PublicKey.from_hex(None)


class TestBip32PublicKeyToBytes:
    """Tests for Bip32PublicKey.to_bytes()"""

    def test_to_bytes_returns_correct_data(self):
        """Test to_bytes returns correct raw bytes"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert pub_key.to_bytes() == BIP32_PUBLIC_KEY_BYTES

    def test_to_bytes_with_created_public_key(self):
        """Test to_bytes with created public key"""
        data = bytes(64)
        pub_key = Bip32PublicKey.from_bytes(data)
        result = pub_key.to_bytes()
        assert len(result) == 64
        assert isinstance(result, bytes)
        assert result == data

    def test_to_bytes_returns_64_bytes(self):
        """Test to_bytes always returns 64 bytes"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        result = pub_key.to_bytes()
        assert len(result) == 64

    def test_to_bytes_preserves_all_byte_values(self):
        """Test to_bytes preserves all byte values"""
        data = bytes(range(64))
        pub_key = Bip32PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data


class TestBip32PublicKeyToHex:
    """Tests for Bip32PublicKey.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        hex_str = pub_key.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length(self):
        """Test to_hex returns correct length"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        hex_str = pub_key.to_hex()
        assert len(hex_str) == 128

    def test_to_hex_returns_valid_hex(self):
        """Test to_hex returns valid hexadecimal string"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        hex_str = pub_key.to_hex()
        assert hex_str == BIP32_PUBLIC_KEY_HEX

    def test_to_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = BIP32_PUBLIC_KEY_HEX
        pub_key = Bip32PublicKey.from_hex(original_hex)
        result_hex = pub_key.to_hex()
        assert result_hex == original_hex

    def test_str_magic_method(self):
        """Test __str__ magic method"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert str(pub_key) == pub_key.to_hex()


class TestBip32PublicKeyDerive:
    """Tests for Bip32PublicKey.derive()"""

    def test_derive_with_valid_unhardened_indices(self):
        """Test derive with valid unhardened derivation indices"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived = pub_key.derive([1852, 1815, 0])
        assert derived is not None
        assert isinstance(derived, Bip32PublicKey)
        assert derived.to_hex() == DERIVED_KEY_HEX

    def test_derive_with_single_index(self):
        """Test derive with single index"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived = pub_key.derive([0])
        assert derived is not None
        assert isinstance(derived, Bip32PublicKey)

    def test_derive_with_multiple_indices(self):
        """Test derive with multiple indices"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived = pub_key.derive([1852, 1815, 0, 0, 0])
        assert derived is not None
        assert isinstance(derived, Bip32PublicKey)

    def test_derive_produces_different_key(self):
        """Test derive produces different key than parent"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived = pub_key.derive([0])
        assert pub_key.to_bytes() != derived.to_bytes()

    def test_derive_is_deterministic(self):
        """Test derive produces same result for same indices"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived1 = pub_key.derive([1852, 1815, 0])
        derived2 = pub_key.derive([1852, 1815, 0])
        assert derived1.to_bytes() == derived2.to_bytes()

    def test_derive_with_empty_indices_raises_error(self):
        """Test derive with empty indices list raises error"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        with pytest.raises(CardanoError):
            pub_key.derive([])

    def test_derive_with_hardened_index_raises_error(self):
        """Test derive with hardened index raises error"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        hardened_index = 0x80000000
        with pytest.raises(CardanoError):
            pub_key.derive([hardened_index])

    def test_derive_different_paths_produce_different_keys(self):
        """Test different derivation paths produce different keys"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived1 = pub_key.derive([0])
        derived2 = pub_key.derive([1])
        assert derived1.to_bytes() != derived2.to_bytes()


class TestBip32PublicKeyToEd25519Key:
    """Tests for Bip32PublicKey.to_ed25519_key()"""

    def test_to_ed25519_key_returns_ed25519_public_key(self):
        """Test to_ed25519_key returns Ed25519PublicKey instance"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        ed25519_key = pub_key.to_ed25519_key()
        assert isinstance(ed25519_key, Ed25519PublicKey)

    def test_to_ed25519_key_produces_32_byte_key(self):
        """Test to_ed25519_key produces 32-byte key"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        ed25519_key = pub_key.to_ed25519_key()
        assert len(ed25519_key.to_bytes()) == 32

    def test_to_ed25519_key_extracts_first_32_bytes(self):
        """Test to_ed25519_key extracts first 32 bytes of BIP32 key"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        ed25519_key = pub_key.to_ed25519_key()
        assert ed25519_key.to_bytes() == ED25519_PUBLIC_KEY_BYTES

    def test_to_ed25519_key_is_deterministic(self):
        """Test to_ed25519_key produces same result for same BIP32 key"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        ed25519_key1 = pub_key.to_ed25519_key()
        ed25519_key2 = pub_key.to_ed25519_key()
        assert ed25519_key1.to_bytes() == ed25519_key2.to_bytes()


class TestBip32PublicKeyToHash:
    """Tests for Bip32PublicKey.to_hash()"""

    def test_to_hash_returns_blake2b_hash(self):
        """Test to_hash returns Blake2bHash instance"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        key_hash = pub_key.to_hash()
        assert isinstance(key_hash, Blake2bHash)

    def test_to_hash_produces_28_byte_hash(self):
        """Test to_hash produces 28-byte (224-bit) Blake2b hash"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        key_hash = pub_key.to_hash()
        assert len(key_hash.to_bytes()) == 28

    def test_to_hash_is_deterministic(self):
        """Test to_hash produces same hash for same public key"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        hash1 = pub_key.to_hash()
        hash2 = pub_key.to_hash()
        assert hash1.to_bytes() == hash2.to_bytes()

    def test_to_hash_different_keys_produce_different_hashes(self):
        """Test to_hash produces different hashes for different keys"""
        pub_key1 = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        pub_key2 = Bip32PublicKey.from_hex("00" * 64)
        hash1 = pub_key1.to_hash()
        hash2 = pub_key2.to_hash()
        assert hash1.to_bytes() != hash2.to_bytes()


class TestBip32PublicKeyEquality:
    """Tests for Bip32PublicKey equality operations"""

    def test_equality_with_same_public_key(self):
        """Test equality with same public key values"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert key1 == key2

    def test_inequality_with_different_public_key(self):
        """Test inequality with different public key values"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(bytes(64))
        assert key1 != key2

    def test_equality_with_non_public_key_returns_false(self):
        """Test equality with non-Bip32PublicKey returns False"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert not (pub_key == "not a public key")
        assert not (pub_key == 123)
        assert not (pub_key == None)

    def test_equality_hex_and_bytes_constructed(self):
        """Test equality between hex and bytes constructed public keys"""
        key1 = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        key2 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert key1 == key2


class TestBip32PublicKeyHash:
    """Tests for Bip32PublicKey.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows public key to be used in set"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key3 = Bip32PublicKey.from_bytes(bytes(64))
        key_set = {key1, key2, key3}
        assert len(key_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows public key to be used as dict key"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(bytes(64))
        key_dict = {key1: "value1", key2: "value2"}
        assert len(key_dict) == 2
        assert key_dict[key1] == "value1"

    def test_equal_public_keys_have_same_hash(self):
        """Test equal public keys have same hash value"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        assert hash(key1) == hash(key2)


class TestBip32PublicKeyRepr:
    """Tests for Bip32PublicKey.__repr__()"""

    def test_repr_includes_public_key_prefix(self):
        """Test __repr__ includes Bip32PublicKey prefix"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        repr_str = repr(pub_key)
        assert "Bip32PublicKey" in repr_str

    def test_repr_includes_hex_preview(self):
        """Test __repr__ includes hex preview"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        repr_str = repr(pub_key)
        assert BIP32_PUBLIC_KEY_HEX[:16] in repr_str

    def test_repr_is_informative(self):
        """Test __repr__ provides useful information"""
        pub_key = Bip32PublicKey.from_bytes(bytes(64))
        repr_str = repr(pub_key)
        assert "Bip32PublicKey" in repr_str
        assert "..." in repr_str


class TestBip32PublicKeyContextManager:
    """Tests for Bip32PublicKey context manager protocol"""

    def test_context_manager_usage(self):
        """Test public key can be used as context manager"""
        with Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES) as pub_key:
            assert len(pub_key.to_bytes()) == 64
            hex_str = pub_key.to_hex()
        assert len(hex_str) == 128

    def test_context_manager_preserves_data(self):
        """Test context manager preserves public key data"""
        with Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX) as pub_key:
            result = pub_key.to_hex()
        assert result == BIP32_PUBLIC_KEY_HEX


class TestBip32PublicKeyEdgeCases:
    """Tests for Bip32PublicKey edge cases"""

    def test_public_key_with_all_zeros(self):
        """Test public key with all zero bytes"""
        data = bytes(64)
        pub_key = Bip32PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data
        assert pub_key.to_hex() == "00" * 64

    def test_public_key_with_all_ones(self):
        """Test public key with all 0xFF bytes"""
        data = bytes([0xFF] * 64)
        pub_key = Bip32PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data
        assert pub_key.to_hex() == "ff" * 64

    def test_consecutive_public_keys_are_independent(self):
        """Test that consecutive public key creations are independent"""
        key1 = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        key2 = Bip32PublicKey.from_bytes(bytes(64))
        assert key1 != key2

    def test_public_key_preserves_byte_order(self):
        """Test public key preserves byte order"""
        data = bytes(range(64))
        pub_key = Bip32PublicKey.from_bytes(data)
        result = pub_key.to_bytes()
        for i in range(64):
            assert result[i] == i

    def test_hex_case_insensitivity(self):
        """Test from_hex handles uppercase hex"""
        key1 = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX.upper())
        key2 = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX.lower())
        assert key1 == key2

    def test_multiple_to_bytes_calls_consistent(self):
        """Test multiple to_bytes calls return consistent results"""
        pub_key = Bip32PublicKey.from_bytes(BIP32_PUBLIC_KEY_BYTES)
        result1 = pub_key.to_bytes()
        result2 = pub_key.to_bytes()
        assert result1 == result2

    def test_multiple_to_hex_calls_consistent(self):
        """Test multiple to_hex calls return consistent results"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        result1 = pub_key.to_hex()
        result2 = pub_key.to_hex()
        assert result1 == result2


class TestBip32PublicKeyRoundTrips:
    """Tests for Bip32PublicKey round-trip conversions"""

    def test_bytes_round_trip(self):
        """Test bytes round-trip conversion"""
        original_bytes = BIP32_PUBLIC_KEY_BYTES
        pub_key = Bip32PublicKey.from_bytes(original_bytes)
        result_bytes = pub_key.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = BIP32_PUBLIC_KEY_HEX
        pub_key = Bip32PublicKey.from_hex(original_hex)
        result_hex = pub_key.to_hex()
        assert result_hex == original_hex

    def test_bytes_to_hex_to_bytes(self):
        """Test bytes -> hex -> bytes conversion"""
        original_bytes = BIP32_PUBLIC_KEY_BYTES
        key1 = Bip32PublicKey.from_bytes(original_bytes)
        hex_str = key1.to_hex()
        key2 = Bip32PublicKey.from_hex(hex_str)
        result_bytes = key2.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_to_bytes_to_hex(self):
        """Test hex -> bytes -> hex conversion"""
        original_hex = BIP32_PUBLIC_KEY_HEX
        key1 = Bip32PublicKey.from_hex(original_hex)
        byte_data = key1.to_bytes()
        key2 = Bip32PublicKey.from_bytes(byte_data)
        result_hex = key2.to_hex()
        assert result_hex == original_hex


class TestBip32PublicKeyDerivationChains:
    """Tests for Bip32PublicKey derivation chains"""

    def test_derive_chain_is_deterministic(self):
        """Test derivation chain produces consistent results"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived1 = pub_key.derive([0]).derive([1]).derive([2])
        derived2 = pub_key.derive([0]).derive([1]).derive([2])
        assert derived1.to_bytes() == derived2.to_bytes()

    def test_derive_chain_different_from_direct_path(self):
        """Test stepwise derivation equals direct multi-index derivation"""
        pub_key = Bip32PublicKey.from_hex(BIP32_PUBLIC_KEY_HEX)
        derived_direct = pub_key.derive([0, 1, 2])
        derived_chain = pub_key.derive([0]).derive([1]).derive([2])
        assert derived_direct.to_bytes() == derived_chain.to_bytes()
