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
from cometa import emip3_encrypt, emip3_decrypt
from cometa.errors import CardanoError


class TestEmip3Encrypt:
    """Tests for the emip3_encrypt function."""

    def test_basic_encryption(self):
        """Test basic encryption with bytes data and passphrase."""
        data = b"secret data"
        passphrase = b"my-passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_encryption_output_length(self):
        """Test that encrypted output includes salt, nonce, MAC, and ciphertext."""
        data = b"test"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        min_length = 32 + 12 + 16 + len(data)
        assert len(encrypted) >= min_length

    def test_string_passphrase(self):
        """Test encryption with string passphrase (should be auto-encoded to UTF-8)."""
        data = b"secret data"
        passphrase = "my-passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_bytearray_data(self):
        """Test encryption with bytearray data."""
        data = bytearray(b"secret data")
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_bytearray_passphrase(self):
        """Test encryption with bytearray passphrase."""
        data = b"secret data"
        passphrase = bytearray(b"password")
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_empty_data(self):
        """Test encryption with empty data."""
        data = b""
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) == 32 + 12 + 16

    def test_empty_passphrase(self):
        """Test encryption with empty passphrase."""
        data = b"secret data"
        passphrase = b""
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_long_data(self):
        """Test encryption with long data."""
        data = b"x" * 1000
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_long_passphrase(self):
        """Test encryption with long passphrase."""
        data = b"secret data"
        passphrase = b"x" * 100
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_binary_data(self):
        """Test encryption with binary data containing all byte values."""
        data = bytes(range(256))
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_unicode_passphrase(self):
        """Test encryption with Unicode characters in passphrase."""
        data = b"secret data"
        passphrase = "пароль世界"
        encrypted = emip3_encrypt(data, passphrase)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > len(data)

    def test_deterministic_with_same_inputs(self):
        """Test that same inputs produce different outputs (due to random salt/nonce)."""
        data = b"secret data"
        passphrase = b"password"
        encrypted1 = emip3_encrypt(data, passphrase)
        encrypted2 = emip3_encrypt(data, passphrase)
        assert encrypted1 != encrypted2

    def test_different_data_different_output(self):
        """Test that different data produces different encrypted output."""
        passphrase = b"password"
        encrypted1 = emip3_encrypt(b"data1", passphrase)
        encrypted2 = emip3_encrypt(b"data2", passphrase)
        assert encrypted1 != encrypted2

    def test_different_passphrase_different_output(self):
        """Test that different passphrases produce different encrypted output."""
        data = b"secret data"
        encrypted1 = emip3_encrypt(data, b"password1")
        encrypted2 = emip3_encrypt(data, b"password2")
        assert encrypted1 != encrypted2


class TestEmip3Decrypt:
    """Tests for the emip3_decrypt function."""

    def test_basic_decryption(self):
        """Test basic decryption with correct passphrase."""
        data = b"secret data"
        passphrase = b"my-passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_decryption_with_string_passphrase(self):
        """Test decryption with string passphrase."""
        data = b"secret data"
        passphrase = "my-passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_decryption_with_bytearray_encrypted(self):
        """Test decryption with bytearray encrypted data."""
        data = b"secret data"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        encrypted_array = bytearray(encrypted)
        decrypted = emip3_decrypt(encrypted_array, passphrase)
        assert decrypted == data

    def test_decryption_with_bytearray_passphrase(self):
        """Test decryption with bytearray passphrase."""
        data = b"secret data"
        passphrase = bytearray(b"password")
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_wrong_passphrase(self):
        """Test decryption with wrong passphrase fails."""
        data = b"secret data"
        passphrase = b"correct-password"
        encrypted = emip3_encrypt(data, passphrase)
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(encrypted, b"wrong-password")

    def test_corrupted_data(self):
        """Test decryption with corrupted data fails."""
        data = b"secret data"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        corrupted = bytearray(encrypted)
        corrupted[50] ^= 0xFF
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(bytes(corrupted), passphrase)

    def test_truncated_data(self):
        """Test decryption with truncated data fails."""
        data = b"secret data"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        truncated = encrypted[:-10]
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(truncated, passphrase)

    def test_too_short_data(self):
        """Test decryption with data shorter than minimum length fails."""
        passphrase = b"password"
        short_data = b"too short"
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(short_data, passphrase)

    def test_decryption_empty_encrypted_data(self):
        """Test decryption with empty encrypted data fails."""
        passphrase = b"password"
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(b"", passphrase)

    def test_decryption_with_empty_passphrase(self):
        """Test round-trip with empty passphrase."""
        data = b"secret data"
        passphrase = b""
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data


class TestEmip3RoundTrip:
    """Tests for round-trip encryption and decryption."""

    def test_roundtrip_empty_data(self):
        """Test round-trip with empty data."""
        data = b""
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_small_data(self):
        """Test round-trip with small data."""
        data = b"x"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_medium_data(self):
        """Test round-trip with medium-sized data."""
        data = b"This is some test data that is longer than a single block"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_large_data(self):
        """Test round-trip with large data."""
        data = b"x" * 10000
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_binary_data(self):
        """Test round-trip with binary data containing all byte values."""
        data = bytes(range(256))
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_null_bytes(self):
        """Test round-trip with null bytes."""
        data = b"\x00\x00\x00\x00"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_roundtrip_mixed_types(self):
        """Test round-trip with mixed input types."""
        data = bytearray(b"secret data")
        passphrase = "password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(bytearray(encrypted), bytearray(passphrase.encode()))
        assert decrypted == bytes(data)

    def test_roundtrip_unicode_passphrase(self):
        """Test round-trip with Unicode passphrase."""
        data = b"secret data"
        passphrase = "пароль世界"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_multiple_roundtrips(self):
        """Test multiple round-trips preserve data."""
        data = b"secret data"
        passphrase = b"password"
        for _ in range(5):
            encrypted = emip3_encrypt(data, passphrase)
            decrypted = emip3_decrypt(encrypted, passphrase)
            assert decrypted == data


class TestEmip3TestVectors:
    """Tests using test vectors from the C test file."""

    @pytest.mark.parametrize("hex_data,passphrase,encrypted_hex", [
        (
            "00010203040506070809",
            b"password",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000009ce1d7784a05efd109ad89c29fea0775bf085ac03988089b3a93"
        ),
        (
            "00010203040506070809",
            b"",
            "0430bb0e1941fd9ec98909e766447883b4af77242a81c7ef2ba8d339f0deeae383227e257c0d6f28ad372a1bc9b87a30e3544258b21a2b576746f5fb83746c7a8e1fa37e2ca3"
        ),
        (
            "0001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809",
            b"password",
            "8daaa90b5e998ac815d0ad9675c5bf328fcf48d12a49aabf01f99d1fc8e4512da687709825ae705bfdbdc7d8b0c662add2bccadbadb9a519d03f9205484f8ba0d66f3d66cd2864c26e8d563fd01a23a066c42b7a94db41e71d70171722012119bc90c51c9ca3a2f1d5041474a544"
        ),
        (
            "00",
            b"password2222",
            "ae02db6264aeb86d3dfb8fa33af204ac8189b116d38b7e701c37922034b359c1beaa734fc7fa80d4ab9271e3082aa69bd7e0b355315c986eb740369264"
        ),
        (
            "a5010102583900d73b4d5548f4d00a1947e9284ccdcdc565dd4b85b36e88533c54ed9bfa2e192363674c755f5efe81c620f18bddf8cf63f181d1366fffef34032720062158203fe822fca223192577130a288b766fcac5b2b8972d89fc229bbc00af60aeaf67",
            b"password",
            "a8de4eedfe023ee4e00986099c293d6e61ddbb3fbe3c449085820fc42316c52af99236a7387280198214149d6342506bf0e36c3c9244f9af6e3e6ba62821dd984c13e49b7513d96abe529fa1375511c9baab72cc13ed20e4b19cbe09b5e13245da1a9552ff2e35c90e815973c0a77dc401cbef86850cb16cb50b2bda4c7f00c687fcc7409c8f0f08f8af2e66115da8c992daebd42ae3faa563bcc53bb9d1a9b4a96b"
        ),
    ])
    def test_decrypt_c_test_vectors(self, hex_data, passphrase, encrypted_hex):
        """Test decryption of test vectors from C test file."""
        encrypted = bytes.fromhex(encrypted_hex)
        expected_data = bytes.fromhex(hex_data)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == expected_data

    @pytest.mark.parametrize("hex_data,passphrase", [
        ("00010203040506070809", b"password"),
        ("00010203040506070809", b""),
        (
            "0001020304050607080900010203040506070809000102030405060708090001020304050607080900010203040506070809",
            b"password"
        ),
        ("00", b"password2222"),
        (
            "a5010102583900d73b4d5548f4d00a1947e9284ccdcdc565dd4b85b36e88533c54ed9bfa2e192363674c755f5efe81c620f18bddf8cf63f181d1366fffef34032720062158203fe822fca223192577130a288b766fcac5b2b8972d89fc229bbc00af60aeaf67",
            b"password"
        ),
    ])
    def test_encrypt_decrypt_test_vectors(self, hex_data, passphrase):
        """Test round-trip encryption/decryption with test vector data."""
        data = bytes.fromhex(hex_data)
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data


class TestEmip3EdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_minimum_encrypted_size(self):
        """Test that minimum encrypted size is salt + nonce + MAC (60 bytes)."""
        data = b""
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        assert len(encrypted) == 60

    def test_case_sensitive_passphrase(self):
        """Test that passphrase is case-sensitive."""
        data = b"secret data"
        encrypted = emip3_encrypt(data, b"Password")
        with pytest.raises(CardanoError, match="EMIP-003 decryption failed"):
            emip3_decrypt(encrypted, b"password")

    def test_special_characters_passphrase(self):
        """Test encryption with special characters in passphrase."""
        data = b"secret data"
        passphrase = b"p@ssw0rd!#$%^&*()"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_whitespace_in_passphrase(self):
        """Test encryption with whitespace in passphrase."""
        data = b"secret data"
        passphrase = b"pass word with spaces"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_passphrase_with_newlines(self):
        """Test encryption with newlines in passphrase."""
        data = b"secret data"
        passphrase = b"pass\nword\nwith\nnewlines"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_data_with_newlines(self):
        """Test encryption of data with newlines."""
        data = b"line1\nline2\nline3"
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_very_long_data(self):
        """Test encryption with very long data (1MB)."""
        data = b"x" * 1024 * 1024
        passphrase = b"password"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_alternating_salt_extraction(self):
        """Test that salt is random and different for each encryption."""
        data = b"test"
        passphrase = b"password"
        encrypted1 = emip3_encrypt(data, passphrase)
        encrypted2 = emip3_encrypt(data, passphrase)
        salt1 = encrypted1[:32]
        salt2 = encrypted2[:32]
        assert salt1 != salt2

    def test_alternating_nonce_extraction(self):
        """Test that nonce is random and different for each encryption."""
        data = b"test"
        passphrase = b"password"
        encrypted1 = emip3_encrypt(data, passphrase)
        encrypted2 = emip3_encrypt(data, passphrase)
        nonce1 = encrypted1[32:44]
        nonce2 = encrypted2[32:44]
        assert nonce1 != nonce2
