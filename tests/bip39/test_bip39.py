"""
Tests for BIP39 mnemonic bindings.
"""

import pytest
from cometa import (
    entropy_to_mnemonic,
    mnemonic_to_entropy,
    CardanoError,
)


class TestEntropyToMnemonic:
    """Tests for entropy_to_mnemonic function."""

    def test_16_bytes_entropy_produces_12_words(self):
        """16 bytes of entropy should produce 12 words."""
        entropy = bytes(16)  # All zeros
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 12

    def test_20_bytes_entropy_produces_15_words(self):
        """20 bytes of entropy should produce 15 words."""
        entropy = bytes(20)
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 15

    def test_24_bytes_entropy_produces_18_words(self):
        """24 bytes of entropy should produce 18 words."""
        entropy = bytes(24)
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 18

    def test_28_bytes_entropy_produces_21_words(self):
        """28 bytes of entropy should produce 21 words."""
        entropy = bytes(28)
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 21

    def test_32_bytes_entropy_produces_24_words(self):
        """32 bytes of entropy should produce 24 words."""
        entropy = bytes(32)
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 24

    def test_known_vector_all_zeros_128bit(self):
        """Test known BIP39 test vector: 128 bits of zeros."""
        entropy = bytes.fromhex("00000000000000000000000000000000")
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 12
        assert words[0] == "abandon"
        assert words[-1] == "about"

    def test_known_vector_all_ones_128bit(self):
        """Test known BIP39 test vector: 128 bits of ones."""
        entropy = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 12
        assert words[0] == "zoo"

    def test_known_vector_256bit(self):
        """Test known BIP39 test vector: 256 bits."""
        entropy = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 24
        assert words[0] == "abandon"

    def test_invalid_entropy_size_raises_error(self):
        """Invalid entropy sizes should raise CardanoError."""
        with pytest.raises(CardanoError):
            entropy_to_mnemonic(bytes(15))

        with pytest.raises(CardanoError):
            entropy_to_mnemonic(bytes(17))

        with pytest.raises(CardanoError):
            entropy_to_mnemonic(bytes(0))

    def test_accepts_bytearray(self):
        """Should accept bytearray as well as bytes."""
        entropy = bytearray(16)
        words = entropy_to_mnemonic(entropy)
        assert len(words) == 12


class TestMnemonicToEntropy:
    """Tests for mnemonic_to_entropy function."""

    def test_12_words_to_16_bytes(self):
        """12 words should produce 16 bytes of entropy."""
        words = ["abandon"] * 11 + ["about"]
        entropy = mnemonic_to_entropy(words)
        assert len(entropy) == 16

    def test_15_words_to_20_bytes(self):
        """15 words should produce 20 bytes of entropy."""
        original_entropy = bytes(20)
        words = entropy_to_mnemonic(original_entropy)
        entropy = mnemonic_to_entropy(words)
        assert len(entropy) == 20

    def test_18_words_to_24_bytes(self):
        """18 words should produce 24 bytes of entropy."""
        original_entropy = bytes(24)
        words = entropy_to_mnemonic(original_entropy)
        entropy = mnemonic_to_entropy(words)
        assert len(entropy) == 24

    def test_21_words_to_28_bytes(self):
        """21 words should produce 28 bytes of entropy."""
        original_entropy = bytes(28)
        words = entropy_to_mnemonic(original_entropy)
        entropy = mnemonic_to_entropy(words)
        assert len(entropy) == 28

    def test_24_words_to_32_bytes(self):
        """24 words should produce 32 bytes of entropy."""
        original_entropy = bytes(32)
        words = entropy_to_mnemonic(original_entropy)
        entropy = mnemonic_to_entropy(words)
        assert len(entropy) == 32

    def test_roundtrip_conversion(self):
        """Converting entropy to mnemonic and back should preserve entropy."""
        original = bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        words = entropy_to_mnemonic(original)
        recovered = mnemonic_to_entropy(words)
        assert recovered == original

    def test_roundtrip_all_entropy_sizes(self):
        """Roundtrip should work for all valid entropy sizes."""
        for size in [16, 20, 24, 28, 32]:
            original = bytes(range(size))
            words = entropy_to_mnemonic(original)
            recovered = mnemonic_to_entropy(words)
            assert recovered == original, f"Roundtrip failed for {size} bytes"

    def test_invalid_word_count_raises_error(self):
        """Invalid word counts should raise CardanoError."""
        with pytest.raises(CardanoError):
            mnemonic_to_entropy(["abandon"] * 11)

        with pytest.raises(CardanoError):
            mnemonic_to_entropy(["abandon"] * 13)

        with pytest.raises(CardanoError):
            mnemonic_to_entropy([])

    def test_invalid_words_raise_error(self):
        """Invalid words not in wordlist should raise CardanoError."""
        with pytest.raises(CardanoError):
            mnemonic_to_entropy(["notaword"] * 12)

    def test_invalid_checksum_raises_error(self):
        """Invalid checksum should raise CardanoError."""
        with pytest.raises(CardanoError):
            mnemonic_to_entropy(["abandon"] * 12)


class TestBIP39KnownVectors:
    """Tests using official BIP39 test vectors."""

    def test_vector_1(self):
        """Test vector: all zeros 128-bit."""
        entropy = bytes.fromhex("00000000000000000000000000000000")
        expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_2(self):
        """Test vector: 7f7f... pattern 128-bit."""
        entropy = bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        expected = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_3(self):
        """Test vector: 8080... pattern 128-bit."""
        entropy = bytes.fromhex("80808080808080808080808080808080")
        expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_4(self):
        """Test vector: all ones 128-bit."""
        entropy = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_5(self):
        """Test vector: all zeros 256-bit."""
        entropy = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_6(self):
        """Test vector: all ones 256-bit."""
        entropy = bytes.fromhex(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected
