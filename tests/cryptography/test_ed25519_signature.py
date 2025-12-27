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
from cometa.cryptography import Ed25519Signature
from cometa.errors import CardanoError


SIGNATURE_HEX = "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b"

SIGNATURE_BYTES = bytes([
    0x2f, 0xa3, 0xf6, 0x86, 0xdf, 0x87, 0x69, 0x95, 0x16, 0x7e, 0x7c, 0x2e, 0x5d, 0x74, 0xc4, 0xc7,
    0xb6, 0xe4, 0x8f, 0x80, 0x68, 0xfe, 0x0e, 0x44, 0x20, 0x83, 0x44, 0xd4, 0x80, 0xf7, 0x90, 0x4c,
    0x36, 0x96, 0x3e, 0x44, 0x11, 0x5f, 0xe3, 0xeb, 0x2a, 0x3a, 0xc8, 0x69, 0x4c, 0x28, 0xbc, 0xb4,
    0xf5, 0xa0, 0xf3, 0x27, 0x6f, 0x2e, 0x79, 0x48, 0x7d, 0x82, 0x19, 0x05, 0x7a, 0x50, 0x6e, 0x4b
])


class TestEd25519SignatureFromBytes:
    """Tests for Ed25519Signature.from_bytes()"""

    def test_from_bytes_creates_signature(self):
        """Test creating signature from raw bytes"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert signature is not None
        assert signature.to_bytes() == SIGNATURE_BYTES

    def test_from_bytes_with_valid_signature(self):
        """Test from_bytes with valid 64-byte signature"""
        data = bytes(64)
        signature = Ed25519Signature.from_bytes(data)
        assert len(signature.to_bytes()) == 64
        assert signature.to_bytes() == data

    def test_from_bytes_with_bytearray(self):
        """Test from_bytes with bytearray"""
        data = bytearray(SIGNATURE_BYTES)
        signature = Ed25519Signature.from_bytes(data)
        assert signature.to_bytes() == bytes(data)

    def test_from_bytes_with_test_vector(self):
        """Test from_bytes preserves test vector data correctly"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        result_bytes = signature.to_bytes()
        assert len(result_bytes) == 64
        for i in range(64):
            assert result_bytes[i] == SIGNATURE_BYTES[i]

    def test_from_bytes_with_empty_data_raises_error(self):
        """Test from_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_bytes(b"")

    def test_from_bytes_with_none_raises_error(self):
        """Test from_bytes with None raises error"""
        with pytest.raises((CardanoError, TypeError)):
            Ed25519Signature.from_bytes(None)

    def test_from_bytes_with_wrong_size_raises_error(self):
        """Test from_bytes with wrong size raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_bytes(bytes(32))

    def test_from_bytes_with_zero_length_raises_error(self):
        """Test from_bytes with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_bytes(bytes(0))


class TestEd25519SignatureFromHex:
    """Tests for Ed25519Signature.from_hex()"""

    def test_from_hex_creates_signature(self):
        """Test creating signature from hex string"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        assert signature is not None
        assert signature.to_hex() == SIGNATURE_HEX

    def test_from_hex_with_valid_hex(self):
        """Test from_hex with valid 128-character hex string"""
        hex_str = "00" * 64
        signature = Ed25519Signature.from_hex(hex_str)
        assert len(signature.to_bytes()) == 64
        assert signature.to_hex() == hex_str

    def test_from_hex_with_test_vector(self):
        """Test from_hex with test vector hex string"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        assert signature.to_hex() == SIGNATURE_HEX
        assert signature.to_bytes() == SIGNATURE_BYTES

    def test_from_hex_with_empty_string_raises_error(self):
        """Test from_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_hex("")

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test from_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Ed25519Signature.from_hex(hex_str)

    def test_from_hex_with_wrong_size_raises_error(self):
        """Test from_hex with wrong size hex string raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_hex("00" * 32)

    def test_from_hex_with_zero_length_raises_error(self):
        """Test from_hex with zero length raises error"""
        with pytest.raises(CardanoError):
            Ed25519Signature.from_hex("")

    def test_from_hex_with_none_raises_error(self):
        """Test from_hex with None raises error"""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Ed25519Signature.from_hex(None)


class TestEd25519SignatureToBytes:
    """Tests for Ed25519Signature.to_bytes()"""

    def test_to_bytes_returns_correct_data(self):
        """Test to_bytes returns correct raw bytes"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert signature.to_bytes() == SIGNATURE_BYTES

    def test_to_bytes_with_created_signature(self):
        """Test to_bytes with created signature"""
        data = bytes(64)
        signature = Ed25519Signature.from_bytes(data)
        result = signature.to_bytes()
        assert len(result) == 64
        assert isinstance(result, bytes)
        assert result == data

    def test_to_bytes_returns_64_bytes(self):
        """Test to_bytes always returns 64 bytes"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        result = signature.to_bytes()
        assert len(result) == 64

    def test_to_bytes_preserves_all_byte_values(self):
        """Test to_bytes preserves all byte values"""
        data = bytes(range(64))
        signature = Ed25519Signature.from_bytes(data)
        assert signature.to_bytes() == data


class TestEd25519SignatureToHex:
    """Tests for Ed25519Signature.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        hex_str = signature.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length(self):
        """Test to_hex returns correct length"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        hex_str = signature.to_hex()
        assert len(hex_str) == 128

    def test_to_hex_returns_valid_hex(self):
        """Test to_hex returns valid hexadecimal string"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        hex_str = signature.to_hex()
        assert hex_str == SIGNATURE_HEX

    def test_to_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = SIGNATURE_HEX
        signature = Ed25519Signature.from_hex(original_hex)
        result_hex = signature.to_hex()
        assert result_hex == original_hex

    def test_str_magic_method(self):
        """Test __str__ magic method"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert str(signature) == signature.to_hex()


class TestEd25519SignatureEquality:
    """Tests for Ed25519Signature equality operations"""

    def test_equality_with_same_signature(self):
        """Test equality with same signature values"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert sig1 == sig2

    def test_inequality_with_different_signature(self):
        """Test inequality with different signature values"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(bytes(64))
        assert sig1 != sig2

    def test_equality_with_non_signature_returns_false(self):
        """Test equality with non-Ed25519Signature returns False"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert not (signature == "not a signature")
        assert not (signature == 123)
        assert not (signature == None)

    def test_equality_hex_and_bytes_constructed(self):
        """Test equality between hex and bytes constructed signatures"""
        sig1 = Ed25519Signature.from_hex(SIGNATURE_HEX)
        sig2 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert sig1 == sig2


class TestEd25519SignatureHash:
    """Tests for Ed25519Signature.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows signature to be used in set"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig3 = Ed25519Signature.from_bytes(bytes(64))
        sig_set = {sig1, sig2, sig3}
        assert len(sig_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows signature to be used as dict key"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(bytes(64))
        sig_dict = {sig1: "value1", sig2: "value2"}
        assert len(sig_dict) == 2
        assert sig_dict[sig1] == "value1"

    def test_equal_signatures_have_same_hash(self):
        """Test equal signatures have same hash value"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        assert hash(sig1) == hash(sig2)


class TestEd25519SignatureRepr:
    """Tests for Ed25519Signature.__repr__()"""

    def test_repr_includes_signature_prefix(self):
        """Test __repr__ includes Ed25519Signature prefix"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        repr_str = repr(signature)
        assert "Ed25519Signature" in repr_str

    def test_repr_includes_hex_preview(self):
        """Test __repr__ includes hex preview"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        repr_str = repr(signature)
        assert SIGNATURE_HEX[:16] in repr_str

    def test_repr_is_informative(self):
        """Test __repr__ provides useful information"""
        signature = Ed25519Signature.from_bytes(bytes(64))
        repr_str = repr(signature)
        assert "Ed25519Signature" in repr_str
        assert "..." in repr_str


class TestEd25519SignatureContextManager:
    """Tests for Ed25519Signature context manager protocol"""

    def test_context_manager_usage(self):
        """Test signature can be used as context manager"""
        with Ed25519Signature.from_bytes(SIGNATURE_BYTES) as signature:
            assert len(signature.to_bytes()) == 64
            hex_str = signature.to_hex()
        assert len(hex_str) == 128

    def test_context_manager_preserves_data(self):
        """Test context manager preserves signature data"""
        with Ed25519Signature.from_hex(SIGNATURE_HEX) as signature:
            result = signature.to_hex()
        assert result == SIGNATURE_HEX


class TestEd25519SignatureEdgeCases:
    """Tests for Ed25519Signature edge cases"""

    def test_signature_with_all_zeros(self):
        """Test signature with all zero bytes"""
        data = bytes(64)
        signature = Ed25519Signature.from_bytes(data)
        assert signature.to_bytes() == data
        assert signature.to_hex() == "00" * 64

    def test_signature_with_all_ones(self):
        """Test signature with all 0xFF bytes"""
        data = bytes([0xFF] * 64)
        signature = Ed25519Signature.from_bytes(data)
        assert signature.to_bytes() == data
        assert signature.to_hex() == "ff" * 64

    def test_consecutive_signatures_are_independent(self):
        """Test that consecutive signature creations are independent"""
        sig1 = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        sig2 = Ed25519Signature.from_bytes(bytes(64))
        assert sig1 != sig2

    def test_signature_preserves_byte_order(self):
        """Test signature preserves byte order"""
        data = bytes(range(64))
        signature = Ed25519Signature.from_bytes(data)
        result = signature.to_bytes()
        for i in range(64):
            assert result[i] == i

    def test_hex_case_insensitivity(self):
        """Test from_hex handles uppercase hex"""
        sig1 = Ed25519Signature.from_hex(SIGNATURE_HEX.upper())
        sig2 = Ed25519Signature.from_hex(SIGNATURE_HEX.lower())
        assert sig1 == sig2

    def test_multiple_to_bytes_calls_consistent(self):
        """Test multiple to_bytes calls return consistent results"""
        signature = Ed25519Signature.from_bytes(SIGNATURE_BYTES)
        result1 = signature.to_bytes()
        result2 = signature.to_bytes()
        assert result1 == result2

    def test_multiple_to_hex_calls_consistent(self):
        """Test multiple to_hex calls return consistent results"""
        signature = Ed25519Signature.from_hex(SIGNATURE_HEX)
        result1 = signature.to_hex()
        result2 = signature.to_hex()
        assert result1 == result2


class TestEd25519SignatureRoundTrips:
    """Tests for Ed25519Signature round-trip conversions"""

    def test_bytes_round_trip(self):
        """Test bytes round-trip conversion"""
        original_bytes = SIGNATURE_BYTES
        signature = Ed25519Signature.from_bytes(original_bytes)
        result_bytes = signature.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_round_trip(self):
        """Test hex round-trip conversion"""
        original_hex = SIGNATURE_HEX
        signature = Ed25519Signature.from_hex(original_hex)
        result_hex = signature.to_hex()
        assert result_hex == original_hex

    def test_bytes_to_hex_to_bytes(self):
        """Test bytes -> hex -> bytes conversion"""
        original_bytes = SIGNATURE_BYTES
        signature1 = Ed25519Signature.from_bytes(original_bytes)
        hex_str = signature1.to_hex()
        signature2 = Ed25519Signature.from_hex(hex_str)
        result_bytes = signature2.to_bytes()
        assert result_bytes == original_bytes

    def test_hex_to_bytes_to_hex(self):
        """Test hex -> bytes -> hex conversion"""
        original_hex = SIGNATURE_HEX
        signature1 = Ed25519Signature.from_hex(original_hex)
        byte_data = signature1.to_bytes()
        signature2 = Ed25519Signature.from_bytes(byte_data)
        result_hex = signature2.to_hex()
        assert result_hex == original_hex
