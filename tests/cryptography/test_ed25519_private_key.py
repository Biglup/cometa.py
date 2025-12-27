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
from cometa.cryptography import Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature
from cometa.errors import CardanoError


PRIVATE_KEY_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUBLIC_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

PRIVATE_KEY_BYTES = bytes([
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
])

EXTENDED_PRIVATE_KEY_HEX = "a0ab55b174ba8cd95e2362d035f377b4dc779a0fae65767e3b8dd790fa748250f3ef2cc372c207d7902607ffef01872a4c785cd27e7342de7f4332f2d5fdc3a8"
EXTENDED_PUBLIC_KEY_HEX = "311f8914b8934efbe7cbb8cc4745853de12e8ea402df6f9f69b18d2792c6bed8"

EXTENDED_PRIVATE_KEY_BYTES = bytes([
    0xa0, 0xab, 0x55, 0xb1, 0x74, 0xba, 0x8c, 0xd9,
    0x5e, 0x23, 0x62, 0xd0, 0x35, 0xf3, 0x77, 0xb4,
    0xdc, 0x77, 0x9a, 0x0f, 0xae, 0x65, 0x76, 0x7e,
    0x3b, 0x8d, 0xd7, 0x90, 0xfa, 0x74, 0x82, 0x50,
    0xf3, 0xef, 0x2c, 0xc3, 0x72, 0xc2, 0x07, 0xd7,
    0x90, 0x26, 0x07, 0xff, 0xef, 0x01, 0x87, 0x2a,
    0x4c, 0x78, 0x5c, 0xd2, 0x7e, 0x73, 0x42, 0xde,
    0x7f, 0x43, 0x32, 0xf2, 0xd5, 0xfd, 0xc3, 0xa8
])

MESSAGE_VECTOR_EXTENDED = bytes([
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
])

SIGNATURE_VECTOR_EXTENDED = "843aa4353184193bdf01aab7f636ac53f86746dd97a2a2e01fe7923c37bfec40b68a73881a26ba57dc974abc1123d0866b542a5447e03677134a8f4e1db2bc0c"

ED25519_TEST_VECTOR = {
    "private_key": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "message": "af82",
    "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
}


class TestEd25519PrivateKeyFromNormalBytes:
    """Tests for Ed25519PrivateKey.from_normal_bytes()"""

    def test_from_normal_bytes_creates_private_key(self):
        """Test creating private key from normal 32-byte seed"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert priv_key is not None
        assert len(priv_key.to_bytes()) == 32

    def test_from_normal_bytes_with_valid_seed(self):
        """Test from_normal_bytes with valid 32-byte seed"""
        data = bytes(32)
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        assert len(priv_key.to_bytes()) == 32
        assert priv_key.to_bytes() == data

    def test_from_normal_bytes_with_bytearray(self):
        """Test from_normal_bytes with bytearray"""
        data = bytearray(PRIVATE_KEY_BYTES)
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        assert priv_key.to_bytes() == bytes(data)

    def test_from_normal_bytes_preserves_data(self):
        """Test from_normal_bytes preserves all byte values"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        result_bytes = priv_key.to_bytes()
        assert len(result_bytes) == 32
        for i in range(32):
            assert result_bytes[i] == PRIVATE_KEY_BYTES[i]

    def test_from_normal_bytes_with_empty_data_raises_error(self):
        """Test from_normal_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_bytes(b"")

    def test_from_normal_bytes_with_none_raises_error(self):
        """Test from_normal_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Ed25519PrivateKey.from_normal_bytes(None)

    def test_from_normal_bytes_with_wrong_size_raises_error(self):
        """Test from_normal_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_bytes(bytes(64))

    def test_from_normal_bytes_with_zero_length_raises_error(self):
        """Test from_normal_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_bytes(bytes(0))

    def test_from_normal_bytes_with_short_data_raises_error(self):
        """Test from_normal_bytes with data shorter than 32 bytes raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_bytes(bytes(16))


class TestEd25519PrivateKeyFromExtendedBytes:
    """Tests for Ed25519PrivateKey.from_extended_bytes()"""

    def test_from_extended_bytes_creates_private_key(self):
        """Test creating private key from extended 64-byte key"""
        priv_key = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        assert priv_key is not None
        assert len(priv_key.to_bytes()) == 64

    def test_from_extended_bytes_with_valid_key(self):
        """Test from_extended_bytes with valid 64-byte key"""
        data = bytes(64)
        priv_key = Ed25519PrivateKey.from_extended_bytes(data)
        assert len(priv_key.to_bytes()) == 64
        assert priv_key.to_bytes() == data

    def test_from_extended_bytes_with_bytearray(self):
        """Test from_extended_bytes with bytearray"""
        data = bytearray(EXTENDED_PRIVATE_KEY_BYTES)
        priv_key = Ed25519PrivateKey.from_extended_bytes(data)
        assert priv_key.to_bytes() == bytes(data)

    def test_from_extended_bytes_preserves_data(self):
        """Test from_extended_bytes preserves all byte values"""
        priv_key = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        result_bytes = priv_key.to_bytes()
        assert len(result_bytes) == 64
        for i in range(64):
            assert result_bytes[i] == EXTENDED_PRIVATE_KEY_BYTES[i]

    def test_from_extended_bytes_with_empty_data_raises_error(self):
        """Test from_extended_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_bytes(b"")

    def test_from_extended_bytes_with_none_raises_error(self):
        """Test from_extended_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Ed25519PrivateKey.from_extended_bytes(None)

    def test_from_extended_bytes_with_wrong_size_raises_error(self):
        """Test from_extended_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_bytes(bytes(32))

    def test_from_extended_bytes_with_zero_length_raises_error(self):
        """Test from_extended_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_bytes(bytes(0))


class TestEd25519PrivateKeyFromNormalHex:
    """Tests for Ed25519PrivateKey.from_normal_hex()"""

    def test_from_normal_hex_creates_private_key(self):
        """Test creating private key from normal hex string"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        assert priv_key is not None
        assert priv_key.to_hex() == PRIVATE_KEY_HEX

    def test_from_normal_hex_with_valid_hex(self):
        """Test from_normal_hex with valid 64-character hex string"""
        hex_str = "00" * 32
        priv_key = Ed25519PrivateKey.from_normal_hex(hex_str)
        assert len(priv_key.to_bytes()) == 32
        assert priv_key.to_hex() == hex_str

    def test_from_normal_hex_preserves_data(self):
        """Test from_normal_hex preserves key data correctly"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        assert priv_key.to_hex() == PRIVATE_KEY_HEX
        assert priv_key.to_bytes() == PRIVATE_KEY_BYTES

    def test_from_normal_hex_with_empty_string_raises_error(self):
        """Test from_normal_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_hex("")

    def test_from_normal_hex_with_odd_length_hex_raises_error(self):
        """Test from_normal_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_hex(hex_str)

    def test_from_normal_hex_with_wrong_size_raises_error(self):
        """Test from_normal_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_hex("00" * 64)

    def test_from_normal_hex_with_zero_length_raises_error(self):
        """Test from_normal_hex with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_normal_hex("")

    def test_from_normal_hex_with_none_raises_error(self):
        """Test from_normal_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Ed25519PrivateKey.from_normal_hex(None)


class TestEd25519PrivateKeyFromExtendedHex:
    """Tests for Ed25519PrivateKey.from_extended_hex()"""

    def test_from_extended_hex_creates_private_key(self):
        """Test creating private key from extended hex string"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        assert priv_key is not None
        assert priv_key.to_hex() == EXTENDED_PRIVATE_KEY_HEX

    def test_from_extended_hex_with_valid_hex(self):
        """Test from_extended_hex with valid 128-character hex string"""
        hex_str = "00" * 64
        priv_key = Ed25519PrivateKey.from_extended_hex(hex_str)
        assert len(priv_key.to_bytes()) == 64
        assert priv_key.to_hex() == hex_str

    def test_from_extended_hex_preserves_data(self):
        """Test from_extended_hex preserves key data correctly"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        assert priv_key.to_hex() == EXTENDED_PRIVATE_KEY_HEX
        assert priv_key.to_bytes() == EXTENDED_PRIVATE_KEY_BYTES

    def test_from_extended_hex_with_empty_string_raises_error(self):
        """Test from_extended_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_hex("")

    def test_from_extended_hex_with_odd_length_hex_raises_error(self):
        """Test from_extended_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_hex(hex_str)

    def test_from_extended_hex_with_wrong_size_raises_error(self):
        """Test from_extended_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Ed25519PrivateKey.from_extended_hex("00" * 32)

    def test_from_extended_hex_with_none_raises_error(self):
        """Test from_extended_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Ed25519PrivateKey.from_extended_hex(None)


class TestEd25519PrivateKeyGetPublicKey:
    """Tests for Ed25519PrivateKey.get_public_key()"""

    def test_get_public_key_from_normal_key(self):
        """Test deriving public key from normal private key"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        pub_key = priv_key.get_public_key()
        assert isinstance(pub_key, Ed25519PublicKey)
        assert pub_key.to_hex() == PUBLIC_KEY_HEX

    def test_get_public_key_from_extended_key(self):
        """Test deriving public key from extended private key"""
        priv_key = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        pub_key = priv_key.get_public_key()
        assert isinstance(pub_key, Ed25519PublicKey)
        assert pub_key.to_hex() == EXTENDED_PUBLIC_KEY_HEX

    def test_get_public_key_is_deterministic(self):
        """Test get_public_key produces same public key consistently"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        pub_key1 = priv_key.get_public_key()
        pub_key2 = priv_key.get_public_key()
        assert pub_key1.to_bytes() == pub_key2.to_bytes()

    def test_get_public_key_returns_32_bytes(self):
        """Test get_public_key returns 32-byte public key"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        pub_key = priv_key.get_public_key()
        assert len(pub_key.to_bytes()) == 32


class TestEd25519PrivateKeySign:
    """Tests for Ed25519PrivateKey.sign()"""

    def test_sign_from_normal_key(self):
        """Test signing with normal private key"""
        priv_key = Ed25519PrivateKey.from_normal_hex(ED25519_TEST_VECTOR["private_key"])
        message = bytes.fromhex(ED25519_TEST_VECTOR["message"])
        signature = priv_key.sign(message)
        assert isinstance(signature, Ed25519Signature)
        assert signature.to_hex() == ED25519_TEST_VECTOR["signature"]

    def test_sign_from_extended_key(self):
        """Test signing with extended private key"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        signature = priv_key.sign(MESSAGE_VECTOR_EXTENDED)
        assert isinstance(signature, Ed25519Signature)
        assert signature.to_hex() == SIGNATURE_VECTOR_EXTENDED

    def test_sign_with_empty_message(self):
        """Test signing empty message"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        signature = priv_key.sign(b"")
        assert isinstance(signature, Ed25519Signature)
        assert len(signature.to_bytes()) == 64

    def test_sign_with_bytearray_message(self):
        """Test sign accepts bytearray message"""
        priv_key = Ed25519PrivateKey.from_normal_hex(ED25519_TEST_VECTOR["private_key"])
        message = bytearray.fromhex(ED25519_TEST_VECTOR["message"])
        signature = priv_key.sign(message)
        assert signature.to_hex() == ED25519_TEST_VECTOR["signature"]

    def test_sign_is_deterministic(self):
        """Test sign produces same signature for same message"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        message = b"test message"
        sig1 = priv_key.sign(message)
        sig2 = priv_key.sign(message)
        assert sig1.to_bytes() == sig2.to_bytes()

    def test_sign_produces_verifiable_signature(self):
        """Test signature can be verified with corresponding public key"""
        priv_key = Ed25519PrivateKey.from_normal_hex(ED25519_TEST_VECTOR["private_key"])
        pub_key = priv_key.get_public_key()
        message = bytes.fromhex(ED25519_TEST_VECTOR["message"])
        signature = priv_key.sign(message)
        assert pub_key.verify(signature, message) is True

    def test_sign_different_messages_produce_different_signatures(self):
        """Test signing different messages produces different signatures"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        sig1 = priv_key.sign(b"message1")
        sig2 = priv_key.sign(b"message2")
        assert sig1.to_bytes() != sig2.to_bytes()


class TestEd25519PrivateKeyToBytes:
    """Tests for Ed25519PrivateKey.to_bytes()"""

    def test_to_bytes_returns_correct_data_normal(self):
        """Test to_bytes returns correct data for normal key"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert priv_key.to_bytes() == PRIVATE_KEY_BYTES

    def test_to_bytes_returns_correct_data_extended(self):
        """Test to_bytes returns correct data for extended key"""
        priv_key = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        assert priv_key.to_bytes() == EXTENDED_PRIVATE_KEY_BYTES

    def test_to_bytes_returns_32_bytes_for_normal(self):
        """Test to_bytes returns 32 bytes for normal key"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        result = priv_key.to_bytes()
        assert len(result) == 32

    def test_to_bytes_returns_64_bytes_for_extended(self):
        """Test to_bytes returns 64 bytes for extended key"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        result = priv_key.to_bytes()
        assert len(result) == 64

    def test_to_bytes_preserves_all_byte_values(self):
        """Test to_bytes preserves all byte values"""
        data = bytes(range(32))
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        assert priv_key.to_bytes() == data


class TestEd25519PrivateKeyToHex:
    """Tests for Ed25519PrivateKey.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        hex_str = priv_key.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length_normal(self):
        """Test to_hex returns correct length for normal key"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        hex_str = priv_key.to_hex()
        assert len(hex_str) == 64

    def test_to_hex_correct_length_extended(self):
        """Test to_hex returns correct length for extended key"""
        priv_key = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        hex_str = priv_key.to_hex()
        assert len(hex_str) == 128

    def test_to_hex_returns_valid_hex_normal(self):
        """Test to_hex returns valid hexadecimal string for normal key"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        hex_str = priv_key.to_hex()
        assert hex_str == PRIVATE_KEY_HEX

    def test_to_hex_returns_valid_hex_extended(self):
        """Test to_hex returns valid hexadecimal string for extended key"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        hex_str = priv_key.to_hex()
        assert hex_str == EXTENDED_PRIVATE_KEY_HEX

    def test_to_hex_round_trip_normal(self):
        """Test hex round-trip conversion for normal key"""
        original_hex = PRIVATE_KEY_HEX
        priv_key = Ed25519PrivateKey.from_normal_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex

    def test_to_hex_round_trip_extended(self):
        """Test hex round-trip conversion for extended key"""
        original_hex = EXTENDED_PRIVATE_KEY_HEX
        priv_key = Ed25519PrivateKey.from_extended_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex


class TestEd25519PrivateKeyEquality:
    """Tests for Ed25519PrivateKey equality operations"""

    def test_equality_with_same_private_key(self):
        """Test equality with same private key values"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert key1 == key2

    def test_inequality_with_different_private_key(self):
        """Test inequality with different private key values"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        assert key1 != key2

    def test_equality_with_non_private_key_returns_false(self):
        """Test equality with non-Ed25519PrivateKey returns False"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert not (priv_key == "not a private key")
        assert not (priv_key == 123)
        assert not (priv_key == None)

    def test_equality_hex_and_bytes_constructed(self):
        """Test equality between hex and bytes constructed private keys"""
        key1 = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        key2 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert key1 == key2

    def test_inequality_normal_and_extended_keys(self):
        """Test inequality between normal and extended keys"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_extended_bytes(EXTENDED_PRIVATE_KEY_BYTES)
        assert key1 != key2


class TestEd25519PrivateKeyHash:
    """Tests for Ed25519PrivateKey.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows private key to be used in set"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key3 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        key_set = {key1, key2, key3}
        assert len(key_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows private key to be used as dict key"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        key_dict = {key1: "value1", key2: "value2"}
        assert len(key_dict) == 2
        assert key_dict[key1] == "value1"

    def test_equal_private_keys_have_same_hash(self):
        """Test equal private keys have same hash value"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        assert hash(key1) == hash(key2)


class TestEd25519PrivateKeyRepr:
    """Tests for Ed25519PrivateKey.__repr__()"""

    def test_repr_hides_key_material(self):
        """Test __repr__ does not expose key material"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        repr_str = repr(priv_key)
        assert "Ed25519PrivateKey" in repr_str
        assert "<hidden>" in repr_str
        assert PRIVATE_KEY_HEX not in repr_str

    def test_repr_is_safe(self):
        """Test __repr__ provides safe representation"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        repr_str = repr(priv_key)
        assert "Ed25519PrivateKey" in repr_str
        for byte in PRIVATE_KEY_BYTES:
            assert hex(byte) not in repr_str.lower()


class TestEd25519PrivateKeyStr:
    """Tests for Ed25519PrivateKey.__str__()"""

    def test_str_hides_key_material(self):
        """Test __str__ does not expose key material"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        str_repr = str(priv_key)
        assert "Ed25519PrivateKey" in str_repr
        assert "<hidden>" in str_repr
        assert PRIVATE_KEY_HEX not in str_repr


class TestEd25519PrivateKeyContextManager:
    """Tests for Ed25519PrivateKey context manager protocol"""

    def test_context_manager_usage(self):
        """Test private key can be used as context manager"""
        with Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES) as priv_key:
            assert len(priv_key.to_bytes()) == 32
            pub_key = priv_key.get_public_key()
        assert len(pub_key.to_bytes()) == 32

    def test_context_manager_preserves_data(self):
        """Test context manager preserves private key data"""
        with Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX) as priv_key:
            result = priv_key.to_hex()
        assert result == PRIVATE_KEY_HEX


class TestEd25519PrivateKeyEdgeCases:
    """Tests for Ed25519PrivateKey edge cases"""

    def test_private_key_with_all_zeros(self):
        """Test private key with all zero bytes"""
        data = bytes(32)
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        assert priv_key.to_bytes() == data
        assert priv_key.to_hex() == "00" * 32

    def test_private_key_with_all_ones(self):
        """Test private key with all 0xFF bytes"""
        data = bytes([0xFF] * 32)
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        assert priv_key.to_bytes() == data
        assert priv_key.to_hex() == "ff" * 32

    def test_consecutive_private_keys_are_independent(self):
        """Test that consecutive private key creations are independent"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        assert key1 != key2

    def test_private_key_preserves_byte_order(self):
        """Test private key preserves byte order"""
        data = bytes(range(32))
        priv_key = Ed25519PrivateKey.from_normal_bytes(data)
        result = priv_key.to_bytes()
        for i in range(32):
            assert result[i] == i

    def test_hex_case_insensitivity(self):
        """Test from_normal_hex handles uppercase hex"""
        key1 = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX.upper())
        key2 = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX.lower())
        assert key1 == key2

    def test_multiple_to_bytes_calls_consistent(self):
        """Test multiple to_bytes calls return consistent results"""
        priv_key = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        result1 = priv_key.to_bytes()
        result2 = priv_key.to_bytes()
        assert result1 == result2

    def test_multiple_to_hex_calls_consistent(self):
        """Test multiple to_hex calls return consistent results"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        result1 = priv_key.to_hex()
        result2 = priv_key.to_hex()
        assert result1 == result2

    def test_extended_key_with_all_zeros(self):
        """Test extended private key with all zero bytes"""
        data = bytes(64)
        priv_key = Ed25519PrivateKey.from_extended_bytes(data)
        assert priv_key.to_bytes() == data
        assert priv_key.to_hex() == "00" * 64


class TestEd25519PrivateKeyRoundTrips:
    """Tests for Ed25519PrivateKey round-trip conversions"""

    def test_bytes_round_trip_normal(self):
        """Test bytes round-trip conversion for normal key"""
        original_bytes = PRIVATE_KEY_BYTES
        priv_key = Ed25519PrivateKey.from_normal_bytes(original_bytes)
        result_bytes = priv_key.to_bytes()
        assert result_bytes == original_bytes

    def test_bytes_round_trip_extended(self):
        """Test bytes round-trip conversion for extended key"""
        original_bytes = EXTENDED_PRIVATE_KEY_BYTES
        priv_key = Ed25519PrivateKey.from_extended_bytes(original_bytes)
        result_bytes = priv_key.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_round_trip_normal(self):
        """Test hex round-trip conversion for normal key"""
        original_hex = PRIVATE_KEY_HEX
        priv_key = Ed25519PrivateKey.from_normal_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex

    def test_hex_round_trip_extended(self):
        """Test hex round-trip conversion for extended key"""
        original_hex = EXTENDED_PRIVATE_KEY_HEX
        priv_key = Ed25519PrivateKey.from_extended_hex(original_hex)
        result_hex = priv_key.to_hex()
        assert result_hex == original_hex

    def test_bytes_to_hex_to_bytes_normal(self):
        """Test bytes -> hex -> bytes conversion for normal key"""
        original_bytes = PRIVATE_KEY_BYTES
        key1 = Ed25519PrivateKey.from_normal_bytes(original_bytes)
        hex_str = key1.to_hex()
        key2 = Ed25519PrivateKey.from_normal_hex(hex_str)
        result_bytes = key2.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_to_bytes_to_hex_normal(self):
        """Test hex -> bytes -> hex conversion for normal key"""
        original_hex = PRIVATE_KEY_HEX
        key1 = Ed25519PrivateKey.from_normal_hex(original_hex)
        byte_data = key1.to_bytes()
        key2 = Ed25519PrivateKey.from_normal_bytes(byte_data)
        result_hex = key2.to_hex()
        assert result_hex == original_hex


class TestEd25519PrivateKeySecurity:
    """Tests for Ed25519PrivateKey security features"""

    def test_repr_never_exposes_key(self):
        """Test __repr__ never exposes key material"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        repr_str = repr(priv_key)
        assert "<hidden>" in repr_str
        assert "Ed25519PrivateKey" in repr_str
        longer_hex_parts = [PRIVATE_KEY_HEX[i:i+8] for i in range(0, len(PRIVATE_KEY_HEX), 8)]
        for hex_part in longer_hex_parts:
            assert hex_part not in repr_str

    def test_str_never_exposes_key(self):
        """Test __str__ never exposes key material"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        str_repr = str(priv_key)
        assert "<hidden>" in str_repr
        assert "Ed25519PrivateKey" in str_repr
        longer_hex_parts = [PRIVATE_KEY_HEX[i:i+8] for i in range(0, len(PRIVATE_KEY_HEX), 8)]
        for hex_part in longer_hex_parts:
            assert hex_part not in str_repr


class TestEd25519PrivateKeyIntegration:
    """Integration tests for Ed25519PrivateKey"""

    def test_sign_and_verify_workflow(self):
        """Test complete sign and verify workflow"""
        priv_key = Ed25519PrivateKey.from_normal_hex(PRIVATE_KEY_HEX)
        pub_key = priv_key.get_public_key()
        message = b"Important Cardano transaction"
        signature = priv_key.sign(message)
        assert pub_key.verify(signature, message) is True

    def test_extended_key_sign_and_verify(self):
        """Test extended key sign and verify workflow"""
        priv_key = Ed25519PrivateKey.from_extended_hex(EXTENDED_PRIVATE_KEY_HEX)
        pub_key = priv_key.get_public_key()
        message = MESSAGE_VECTOR_EXTENDED
        signature = priv_key.sign(message)
        assert pub_key.verify(signature, message) is True

    def test_different_keys_produce_different_signatures(self):
        """Test different private keys produce different signatures for same message"""
        key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        key2 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        message = b"same message"
        sig1 = key1.sign(message)
        sig2 = key2.sign(message)
        assert sig1.to_bytes() != sig2.to_bytes()

    def test_wrong_public_key_fails_verification(self):
        """Test signature verification fails with wrong public key"""
        priv_key1 = Ed25519PrivateKey.from_normal_bytes(PRIVATE_KEY_BYTES)
        priv_key2 = Ed25519PrivateKey.from_normal_bytes(bytes(32))
        pub_key2 = priv_key2.get_public_key()
        message = b"test message"
        signature = priv_key1.sign(message)
        assert pub_key2.verify(signature, message) is False
