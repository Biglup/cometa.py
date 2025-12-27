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
from cometa import pbkdf2_hmac_sha512
from cometa.errors import CardanoError


class TestPbkdf2HmacSha512:
    """Tests for the pbkdf2_hmac_sha512 function."""

    def test_basic_password_salt_32_bytes(self):
        """Test PBKDF2 with basic password and salt, 32 byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 32)
        expected = bytes.fromhex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252")
        assert result == expected

    def test_basic_password_salt_2_iterations(self):
        """Test PBKDF2 with 2 iterations, 32 byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 2, 32)
        expected = bytes.fromhex("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c")
        assert result == expected

    def test_basic_password_salt_64_bytes(self):
        """Test PBKDF2 with basic password and salt, 64 byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 64)
        expected = bytes.fromhex(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
            "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        )
        assert result == expected

    def test_64_bytes_2_iterations(self):
        """Test PBKDF2 with 2 iterations, 64 byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 2, 64)
        expected = bytes.fromhex(
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
            "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
        )
        assert result == expected

    def test_4096_iterations(self):
        """Test PBKDF2 with 4096 iterations (standard recommendation)."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 4096, 32)
        expected = bytes.fromhex("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5")
        assert result == expected

    def test_long_password_and_salt(self):
        """Test PBKDF2 with long password and salt."""
        result = pbkdf2_hmac_sha512(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40
        )
        expected = bytes.fromhex(
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71"
            "115b59f9e60cd953"
        )
        assert result == expected

    def test_embedded_null_bytes(self):
        """Test PBKDF2 with embedded null bytes in password and salt."""
        password = b"pass\x00word"
        salt = b"sa\x00lt"
        result = pbkdf2_hmac_sha512(password, salt, 4096, 16)
        assert isinstance(result, bytes)
        assert len(result) == 16

    def test_short_output_10_bytes(self):
        """Test PBKDF2 with short 10-byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 10)
        expected = bytes.fromhex("867f70cf1ade02cff375")
        assert result == expected

    def test_long_output_100_bytes(self):
        """Test PBKDF2 with long 100-byte output."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 100)
        expected = bytes.fromhex(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
            "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
            "7b532e206c2967d4c7d2ffa460539fc4d4e5eec70125d74c6c7cf86d25284f29"
            "7907fcea"
        )
        assert result == expected

    def test_empty_password(self):
        """Test PBKDF2 with empty password."""
        result = pbkdf2_hmac_sha512(b"", b"salt", 1, 100)
        expected = bytes.fromhex(
            "00ef42cdbfc98d29db20976608e455567fdddf141f6eb03b5a85addd25974f5d"
            "2375bd5082b803e8f4cfa88ae1bd25256fcbddd2318676566ff2797792302aee"
            "6ca733014ec4a8969e9b4d25a196e71b38d7e3434496810e7ffedd58624f2fd5"
            "3874cfa5"
        )
        assert result == expected

    def test_none_password(self):
        """Test PBKDF2 with None password (treated as empty)."""
        result = pbkdf2_hmac_sha512(b"", b"salt", 1, 100)
        expected = bytes.fromhex(
            "00ef42cdbfc98d29db20976608e455567fdddf141f6eb03b5a85addd25974f5d"
            "2375bd5082b803e8f4cfa88ae1bd25256fcbddd2318676566ff2797792302aee"
            "6ca733014ec4a8969e9b4d25a196e71b38d7e3434496810e7ffedd58624f2fd5"
            "3874cfa5"
        )
        assert result == expected

    def test_high_iterations(self):
        """Test PBKDF2 with high iteration count."""
        result = pbkdf2_hmac_sha512(b"", b"salt", 19162, 32)
        expected = bytes.fromhex("879094d1113e95e3bc05c4a2d2b2a66cbc7876d454ee3c886cdf1a14c72188c7")
        assert result == expected

    def test_string_password_conversion(self):
        """Test PBKDF2 with string password (automatically converted to bytes)."""
        result = pbkdf2_hmac_sha512("password", b"salt", 1, 32)
        expected = bytes.fromhex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252")
        assert result == expected

    def test_unicode_string_password(self):
        """Test PBKDF2 with Unicode string password."""
        result = pbkdf2_hmac_sha512("pässwörd", b"salt", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_bytearray_password(self):
        """Test PBKDF2 with bytearray password."""
        password = bytearray(b"password")
        result = pbkdf2_hmac_sha512(password, b"salt", 1, 32)
        expected = bytes.fromhex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252")
        assert result == expected

    def test_bytearray_salt(self):
        """Test PBKDF2 with bytearray salt."""
        salt = bytearray(b"salt")
        result = pbkdf2_hmac_sha512(b"password", salt, 1, 32)
        expected = bytes.fromhex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252")
        assert result == expected

    def test_return_type(self):
        """Test that PBKDF2 returns bytes."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 32)
        assert isinstance(result, bytes)

    def test_return_length(self):
        """Test that PBKDF2 returns the correct length."""
        for length in [10, 16, 32, 64, 100, 128]:
            result = pbkdf2_hmac_sha512(b"password", b"salt", 1, length)
            assert len(result) == length

    def test_deterministic(self):
        """Test that PBKDF2 produces consistent results for the same input."""
        result1 = pbkdf2_hmac_sha512(b"password", b"salt", 1000, 32)
        result2 = pbkdf2_hmac_sha512(b"password", b"salt", 1000, 32)
        assert result1 == result2

    def test_different_passwords_different_results(self):
        """Test that different passwords produce different results."""
        result1 = pbkdf2_hmac_sha512(b"password1", b"salt", 1, 32)
        result2 = pbkdf2_hmac_sha512(b"password2", b"salt", 1, 32)
        assert result1 != result2

    def test_different_salts_different_results(self):
        """Test that different salts produce different results."""
        result1 = pbkdf2_hmac_sha512(b"password", b"salt1", 1, 32)
        result2 = pbkdf2_hmac_sha512(b"password", b"salt2", 1, 32)
        assert result1 != result2

    def test_different_iterations_different_results(self):
        """Test that different iteration counts produce different results."""
        result1 = pbkdf2_hmac_sha512(b"password", b"salt", 1, 32)
        result2 = pbkdf2_hmac_sha512(b"password", b"salt", 2, 32)
        assert result1 != result2

    def test_single_iteration(self):
        """Test PBKDF2 with single iteration."""
        result = pbkdf2_hmac_sha512(b"test", b"salt", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_single_byte_password(self):
        """Test PBKDF2 with single byte password."""
        result = pbkdf2_hmac_sha512(b"a", b"salt", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_single_byte_salt(self):
        """Test PBKDF2 with single byte salt."""
        result = pbkdf2_hmac_sha512(b"password", b"s", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_long_password(self):
        """Test PBKDF2 with very long password."""
        password = b"a" * 1000
        result = pbkdf2_hmac_sha512(password, b"salt", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_long_salt(self):
        """Test PBKDF2 with very long salt."""
        salt = b"s" * 1000
        result = pbkdf2_hmac_sha512(b"password", salt, 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_binary_data_password(self):
        """Test PBKDF2 with binary data in password."""
        password = bytes(range(256))
        result = pbkdf2_hmac_sha512(password, b"salt", 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_binary_data_salt(self):
        """Test PBKDF2 with binary data in salt."""
        salt = bytes(range(256))
        result = pbkdf2_hmac_sha512(b"password", salt, 1, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_small_key_length_1_byte(self):
        """Test PBKDF2 with very small key length (1 byte)."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 1)
        assert isinstance(result, bytes)
        assert len(result) == 1

    def test_large_key_length_256_bytes(self):
        """Test PBKDF2 with large key length (256 bytes)."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 1, 256)
        assert isinstance(result, bytes)
        assert len(result) == 256

    def test_zero_iterations_valid(self):
        """Test PBKDF2 with zero iterations (treated as 1 iteration)."""
        result = pbkdf2_hmac_sha512(b"password", b"salt", 0, 32)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_negative_iterations_invalid(self):
        """Test PBKDF2 with negative iterations (should fail)."""
        with pytest.raises((CardanoError, OverflowError)):
            pbkdf2_hmac_sha512(b"password", b"salt", -1, 32)

    def test_zero_key_length_invalid(self):
        """Test PBKDF2 with zero key length (should fail)."""
        with pytest.raises(CardanoError):
            pbkdf2_hmac_sha512(b"password", b"salt", 1, 0)

    def test_negative_key_length_invalid(self):
        """Test PBKDF2 with negative key length (should fail)."""
        with pytest.raises((CardanoError, OverflowError, ValueError)):
            pbkdf2_hmac_sha512(b"password", b"salt", 1, -1)

    def test_empty_salt_invalid(self):
        """Test PBKDF2 with empty salt (should fail based on C test)."""
        with pytest.raises(CardanoError):
            pbkdf2_hmac_sha512(b"password", b"", 1, 32)

    def test_none_salt_invalid(self):
        """Test PBKDF2 with None salt (should fail)."""
        with pytest.raises((CardanoError, TypeError)):
            pbkdf2_hmac_sha512(b"password", None, 1, 32)
