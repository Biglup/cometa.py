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
from cometa.cryptography import Ed25519PublicKey, Ed25519Signature, Blake2bHash
from cometa.errors import CardanoError


PUBLIC_KEY_HEX = "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c"

PUBLIC_KEY_BYTES = bytes([
    0x2f, 0xa3, 0xf6, 0x86, 0xdf, 0x87, 0x69, 0x95,
    0x16, 0x7e, 0x7c, 0x2e, 0x5d, 0x74, 0xc4, 0xc7,
    0xb6, 0xe4, 0x8f, 0x80, 0x68, 0xfe, 0x0e, 0x44,
    0x20, 0x83, 0x44, 0xd4, 0x80, 0xf7, 0x90, 0x4c
])

ED25519_TEST_VECTOR_1 = {
    "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "message": "",
    "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
}

ED25519_TEST_VECTOR_2 = {
    "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "message": "72",
    "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
}

ED25519_TEST_VECTOR_3 = {
    "public_key": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "message": "af82",
    "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
}


class TestEd25519PublicKeyFromBytes:
    """Tests for Ed25519PublicKey.from_bytes()"""

    def test_from_bytes_creates_public_key(self):
        """Test creating public key from raw bytes"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert pub_key is not None
        assert pub_key.to_bytes() == PUBLIC_KEY_BYTES

    def test_from_bytes_with_valid_public_key(self):
        """Test from_bytes with valid 32-byte public key"""
        data = bytes(32)
        pub_key = Ed25519PublicKey.from_bytes(data)
        assert len(pub_key.to_bytes()) == 32
        assert pub_key.to_bytes() == data

    def test_from_bytes_with_bytearray(self):
        """Test from_bytes with bytearray"""
        data = bytearray(PUBLIC_KEY_BYTES)
        pub_key = Ed25519PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == bytes(data)

    def test_from_bytes_with_test_vector(self):
        """Test from_bytes preserves test vector data correctly"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        result_bytes = pub_key.to_bytes()
        assert len(result_bytes) == 32
        for i in range(32):
            assert result_bytes[i] == PUBLIC_KEY_BYTES[i]

    def test_from_bytes_with_empty_data_raises_error(self):
        """Test from_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_bytes(b"")

    def test_from_bytes_with_none_raises_error(self):
        """Test from_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Ed25519PublicKey.from_bytes(None)

    def test_from_bytes_with_wrong_size_raises_error(self):
        """Test from_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_bytes(bytes(64))

    def test_from_bytes_with_zero_length_raises_error(self):
        """Test from_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_bytes(bytes(0))


class TestEd25519PublicKeyFromHex:
    """Tests for Ed25519PublicKey.from_hex()"""

    def test_from_hex_creates_public_key(self):
        """Test creating public key from hex string"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        assert pub_key is not None
        assert pub_key.to_hex() == PUBLIC_KEY_HEX

    def test_from_hex_with_valid_hex(self):
        """Test from_hex with valid 64-character hex string"""
        hex_str = "00" * 32
        pub_key = Ed25519PublicKey.from_hex(hex_str)
        assert len(pub_key.to_bytes()) == 32
        assert pub_key.to_hex() == hex_str

    def test_from_hex_with_test_vector(self):
        """Test from_hex with test vector hex string"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        assert pub_key.to_hex() == PUBLIC_KEY_HEX
        assert pub_key.to_bytes() == PUBLIC_KEY_BYTES

    def test_from_hex_with_empty_string_raises_error(self):
        """Test from_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_hex("")

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test from_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_hex(hex_str)

    def test_from_hex_with_wrong_size_raises_error(self):
        """Test from_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_hex("00" * 64)

    def test_from_hex_with_zero_length_raises_error(self):
        """Test from_hex with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519PublicKey.from_hex("")

    def test_from_hex_with_none_raises_error(self):
        """Test from_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Ed25519PublicKey.from_hex(None)


class TestEd25519PublicKeyToBytes:
    """Tests for Ed25519PublicKey.to_bytes()"""

    def test_to_bytes_returns_correct_data(self):
        """Test to_bytes returns correct raw bytes"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert pub_key.to_bytes() == PUBLIC_KEY_BYTES

    def test_to_bytes_with_created_public_key(self):
        """Test to_bytes with created public key"""
        data = bytes(32)
        pub_key = Ed25519PublicKey.from_bytes(data)
        result = pub_key.to_bytes()
        assert len(result) == 32
        assert isinstance(result, bytes)
        assert result == data

    def test_to_bytes_returns_32_bytes(self):
        """Test to_bytes always returns 32 bytes"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        result = pub_key.to_bytes()
        assert len(result) == 32

    def test_to_bytes_preserves_all_byte_values(self):
        """Test to_bytes preserves all byte values"""
        data = bytes(range(32))
        pub_key = Ed25519PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data


class TestEd25519PublicKeyToHex:
    """Tests for Ed25519PublicKey.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        hex_str = pub_key.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length(self):
        """Test to_hex returns correct length"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        hex_str = pub_key.to_hex()
        assert len(hex_str) == 64

    def test_to_hex_returns_valid_hex(self):
        """Test to_hex returns valid hexadecimal string"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        hex_str = pub_key.to_hex()
        assert hex_str == PUBLIC_KEY_HEX

    def test_to_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = PUBLIC_KEY_HEX
        pub_key = Ed25519PublicKey.from_hex(original_hex)
        result_hex = pub_key.to_hex()
        assert result_hex == original_hex

    def test_str_magic_method(self):
        """Test __str__ magic method"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert str(pub_key) == pub_key.to_hex()


class TestEd25519PublicKeyToHash:
    """Tests for Ed25519PublicKey.to_hash()"""

    def test_to_hash_returns_blake2b_hash(self):
        """Test to_hash returns Blake2bHash instance"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        key_hash = pub_key.to_hash()
        assert isinstance(key_hash, Blake2bHash)

    def test_to_hash_produces_28_byte_hash(self):
        """Test to_hash produces 28-byte (224-bit) Blake2b hash"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        key_hash = pub_key.to_hash()
        assert len(key_hash.to_bytes()) == 28

    def test_to_hash_is_deterministic(self):
        """Test to_hash produces same hash for same public key"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        hash1 = pub_key.to_hash()
        hash2 = pub_key.to_hash()
        assert hash1.to_bytes() == hash2.to_bytes()

    def test_to_hash_different_keys_produce_different_hashes(self):
        """Test to_hash produces different hashes for different keys"""
        pub_key1 = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        pub_key2 = Ed25519PublicKey.from_hex("00" * 32)
        hash1 = pub_key1.to_hash()
        hash2 = pub_key2.to_hash()
        assert hash1.to_bytes() != hash2.to_bytes()

    def test_to_hash_with_test_vector(self):
        """Test to_hash with test vector"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_1["public_key"])
        key_hash = pub_key.to_hash()
        assert isinstance(key_hash, Blake2bHash)
        assert len(key_hash.to_bytes()) == 28


class TestEd25519PublicKeyVerify:
    """Tests for Ed25519PublicKey.verify()"""

    def test_verify_returns_true_for_valid_signature(self):
        """Test verify returns True for valid signature with correct key"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_2["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_2["signature"])
        message = bytes.fromhex(ED25519_TEST_VECTOR_2["message"])
        assert pub_key.verify(signature, message) is True

    def test_verify_returns_false_for_wrong_public_key(self):
        """Test verify returns False for wrong public key"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_1["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_2["signature"])
        message = bytes.fromhex(ED25519_TEST_VECTOR_2["message"])
        assert pub_key.verify(signature, message) is False

    def test_verify_with_empty_message(self):
        """Test verify with empty message"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_1["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_1["signature"])
        message = b""
        assert pub_key.verify(signature, message) is True

    def test_verify_with_longer_message(self):
        """Test verify with longer message"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_3["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_3["signature"])
        message = bytes.fromhex(ED25519_TEST_VECTOR_3["message"])
        assert pub_key.verify(signature, message) is True

    def test_verify_returns_false_for_modified_message(self):
        """Test verify returns False for modified message"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_2["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_2["signature"])
        message = bytes.fromhex(ED25519_TEST_VECTOR_2["message"])
        modified_message = message + b"\x00"
        assert pub_key.verify(signature, modified_message) is False

    def test_verify_with_bytearray_message(self):
        """Test verify accepts bytearray message"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_2["public_key"])
        signature = Ed25519Signature.from_hex(ED25519_TEST_VECTOR_2["signature"])
        message = bytearray.fromhex(ED25519_TEST_VECTOR_2["message"])
        assert pub_key.verify(signature, message) is True

    def test_verify_returns_false_for_invalid_signature(self):
        """Test verify returns False for invalid signature"""
        pub_key = Ed25519PublicKey.from_hex(ED25519_TEST_VECTOR_2["public_key"])
        signature = Ed25519Signature.from_hex("00" * 64)
        message = bytes.fromhex(ED25519_TEST_VECTOR_2["message"])
        assert pub_key.verify(signature, message) is False


class TestEd25519PublicKeyEquality:
    """Tests for Ed25519PublicKey equality operations"""

    def test_equality_with_same_public_key(self):
        """Test equality with same public key values"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert key1 == key2

    def test_inequality_with_different_public_key(self):
        """Test inequality with different public key values"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(bytes(32))
        assert key1 != key2

    def test_equality_with_non_public_key_returns_false(self):
        """Test equality with non-Ed25519PublicKey returns False"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert not (pub_key == "not a public key")
        assert not (pub_key == 123)
        assert not (pub_key == None)

    def test_equality_hex_and_bytes_constructed(self):
        """Test equality between hex and bytes constructed public keys"""
        key1 = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        key2 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert key1 == key2


class TestEd25519PublicKeyHash:
    """Tests for Ed25519PublicKey.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows public key to be used in set"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key3 = Ed25519PublicKey.from_bytes(bytes(32))
        key_set = {key1, key2, key3}
        assert len(key_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows public key to be used as dict key"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(bytes(32))
        key_dict = {key1: "value1", key2: "value2"}
        assert len(key_dict) == 2
        assert key_dict[key1] == "value1"

    def test_equal_public_keys_have_same_hash(self):
        """Test equal public keys have same hash value"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        assert hash(key1) == hash(key2)


class TestEd25519PublicKeyRepr:
    """Tests for Ed25519PublicKey.__repr__()"""

    def test_repr_includes_public_key_prefix(self):
        """Test __repr__ includes Ed25519PublicKey prefix"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        repr_str = repr(pub_key)
        assert "Ed25519PublicKey" in repr_str

    def test_repr_includes_hex_preview(self):
        """Test __repr__ includes hex preview"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        repr_str = repr(pub_key)
        assert PUBLIC_KEY_HEX[:16] in repr_str

    def test_repr_is_informative(self):
        """Test __repr__ provides useful information"""
        pub_key = Ed25519PublicKey.from_bytes(bytes(32))
        repr_str = repr(pub_key)
        assert "Ed25519PublicKey" in repr_str
        assert "..." in repr_str


class TestEd25519PublicKeyContextManager:
    """Tests for Ed25519PublicKey context manager protocol"""

    def test_context_manager_usage(self):
        """Test public key can be used as context manager"""
        with Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES) as pub_key:
            assert len(pub_key.to_bytes()) == 32
            hex_str = pub_key.to_hex()
        assert len(hex_str) == 64

    def test_context_manager_preserves_data(self):
        """Test context manager preserves public key data"""
        with Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX) as pub_key:
            result = pub_key.to_hex()
        assert result == PUBLIC_KEY_HEX


class TestEd25519PublicKeyEdgeCases:
    """Tests for Ed25519PublicKey edge cases"""

    def test_public_key_with_all_zeros(self):
        """Test public key with all zero bytes"""
        data = bytes(32)
        pub_key = Ed25519PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data
        assert pub_key.to_hex() == "00" * 32

    def test_public_key_with_all_ones(self):
        """Test public key with all 0xFF bytes"""
        data = bytes([0xFF] * 32)
        pub_key = Ed25519PublicKey.from_bytes(data)
        assert pub_key.to_bytes() == data
        assert pub_key.to_hex() == "ff" * 32

    def test_consecutive_public_keys_are_independent(self):
        """Test that consecutive public key creations are independent"""
        key1 = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        key2 = Ed25519PublicKey.from_bytes(bytes(32))
        assert key1 != key2

    def test_public_key_preserves_byte_order(self):
        """Test public key preserves byte order"""
        data = bytes(range(32))
        pub_key = Ed25519PublicKey.from_bytes(data)
        result = pub_key.to_bytes()
        for i in range(32):
            assert result[i] == i

    def test_hex_case_insensitivity(self):
        """Test from_hex handles uppercase hex"""
        key1 = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX.upper())
        key2 = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX.lower())
        assert key1 == key2

    def test_multiple_to_bytes_calls_consistent(self):
        """Test multiple to_bytes calls return consistent results"""
        pub_key = Ed25519PublicKey.from_bytes(PUBLIC_KEY_BYTES)
        result1 = pub_key.to_bytes()
        result2 = pub_key.to_bytes()
        assert result1 == result2

    def test_multiple_to_hex_calls_consistent(self):
        """Test multiple to_hex calls return consistent results"""
        pub_key = Ed25519PublicKey.from_hex(PUBLIC_KEY_HEX)
        result1 = pub_key.to_hex()
        result2 = pub_key.to_hex()
        assert result1 == result2


class TestEd25519PublicKeyRoundTrips:
    """Tests for Ed25519PublicKey round-trip conversions"""

    def test_bytes_round_trip(self):
        """Test bytes round-trip conversion"""
        original_bytes = PUBLIC_KEY_BYTES
        pub_key = Ed25519PublicKey.from_bytes(original_bytes)
        result_bytes = pub_key.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = PUBLIC_KEY_HEX
        pub_key = Ed25519PublicKey.from_hex(original_hex)
        result_hex = pub_key.to_hex()
        assert result_hex == original_hex

    def test_bytes_to_hex_to_bytes(self):
        """Test bytes -> hex -> bytes conversion"""
        original_bytes = PUBLIC_KEY_BYTES
        key1 = Ed25519PublicKey.from_bytes(original_bytes)
        hex_str = key1.to_hex()
        key2 = Ed25519PublicKey.from_hex(hex_str)
        result_bytes = key2.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_to_bytes_to_hex(self):
        """Test hex -> bytes -> hex conversion"""
        original_hex = PUBLIC_KEY_HEX
        key1 = Ed25519PublicKey.from_hex(original_hex)
        byte_data = key1.to_bytes()
        key2 = Ed25519PublicKey.from_bytes(byte_data)
        result_hex = key2.to_hex()
        assert result_hex == original_hex
