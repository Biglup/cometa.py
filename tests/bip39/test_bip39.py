"""
Tests for BIP39 mnemonic bindings.

This test module validates the BIP39 mnemonic functionality using official
BIP39 test vectors from the C implementation. It tests both entropy-to-mnemonic
and mnemonic-to-entropy conversions for all supported entropy sizes.
"""

# pylint: disable=no-self-use

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

    def test_vector_7_192bit_zeros(self):
        """Test vector: all zeros 192-bit."""
        entropy = bytes.fromhex("000000000000000000000000000000000000000000000000")
        expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_8_192bit_7f(self):
        """Test vector: 7f7f... pattern 192-bit."""
        entropy = bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        expected = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_9_192bit_80(self):
        """Test vector: 8080... pattern 192-bit."""
        entropy = bytes.fromhex("808080808080808080808080808080808080808080808080")
        expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_10_192bit_ff(self):
        """Test vector: all ones 192-bit."""
        entropy = bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffff")
        expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_11_256bit_7f(self):
        """Test vector: 7F7F... pattern 256-bit."""
        entropy = bytes.fromhex("7F7F7F7F7F7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
        expected = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_12_256bit_80(self):
        """Test vector: 8080... pattern 256-bit."""
        entropy = bytes.fromhex("8080808080808080808080808080808080808080808080808080808080808080")
        expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_13_random_128bit(self):
        """Test vector: random 128-bit entropy."""
        entropy = bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2")
        expected = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_14_random_192bit(self):
        """Test vector: random 192-bit entropy."""
        entropy = bytes.fromhex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b")
        expected = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_15_random_256bit(self):
        """Test vector: random 256-bit entropy."""
        entropy = bytes.fromhex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c")
        expected = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_16_random_128bit_2(self):
        """Test vector: random 128-bit entropy (2)."""
        entropy = bytes.fromhex("c0ba5a8e914111210f2bd131f3d5e08d")
        expected = "scheme spot photo card baby mountain device kick cradle pact join borrow"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_17_random_192bit_2(self):
        """Test vector: random 192-bit entropy (2)."""
        entropy = bytes.fromhex("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3")
        expected = "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_18_random_256bit_2(self):
        """Test vector: random 256-bit entropy (2)."""
        entropy = bytes.fromhex("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863")
        expected = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_19_random_128bit_3(self):
        """Test vector: random 128-bit entropy (3)."""
        entropy = bytes.fromhex("23db8160a31d3e0dca3688ed941adbf3")
        expected = "cat swing flag economy stadium alone churn speed unique patch report train"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_20_random_192bit_3(self):
        """Test vector: random 192-bit entropy (3)."""
        entropy = bytes.fromhex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0")
        expected = "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_21_random_256bit_3(self):
        """Test vector: random 256-bit entropy (3)."""
        entropy = bytes.fromhex("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")
        expected = "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_22_random_128bit_4(self):
        """Test vector: random 128-bit entropy (4)."""
        entropy = bytes.fromhex("f30f8c1da665478f49b001d94c5fc452")
        expected = "vessel ladder alter error federal sibling chat ability sun glass valve picture"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_23_random_192bit_4(self):
        """Test vector: random 192-bit entropy (4)."""
        entropy = bytes.fromhex("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05")
        expected = "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected

    def test_vector_24_random_256bit_4(self):
        """Test vector: random 256-bit entropy (4)."""
        entropy = bytes.fromhex("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")
        expected = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
        words = entropy_to_mnemonic(entropy)
        assert " ".join(words) == expected


class TestComprehensiveInvalidArguments:
    """Comprehensive tests for invalid arguments and edge cases."""

    def test_entropy_to_mnemonic_with_invalid_sizes(self):
        """Test entropy_to_mnemonic with various invalid entropy sizes."""
        invalid_sizes = [0, 1, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 64, 128]
        for size in invalid_sizes:
            with pytest.raises(CardanoError):
                entropy_to_mnemonic(bytes(size))

    def test_mnemonic_to_entropy_with_invalid_word_counts(self):
        """Test mnemonic_to_entropy with various invalid word counts."""
        invalid_counts = [0, 1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 30, 50]
        for count in invalid_counts:
            with pytest.raises(CardanoError):
                mnemonic_to_entropy(["abandon"] * count)

    def test_mnemonic_to_entropy_with_single_invalid_word(self):
        """Test mnemonic_to_entropy with a single invalid word."""
        invalid_words = [
            ["invalid", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow"],
            ["legal", "notaword", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow"],
            ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "invalid123"],
        ]
        for words in invalid_words:
            with pytest.raises(CardanoError):
                mnemonic_to_entropy(words)

    def test_mnemonic_to_entropy_with_invalid_checksum(self):
        """Test mnemonic_to_entropy with valid words but invalid checksum."""
        invalid_checksums = [
            ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon"],
            ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "legal"],
            ["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo"],
        ]
        for words in invalid_checksums:
            with pytest.raises(CardanoError):
                mnemonic_to_entropy(words)

    def test_entropy_to_mnemonic_returns_list_of_strings(self):
        """Verify that entropy_to_mnemonic returns a list of strings."""
        entropy = bytes(16)
        words = entropy_to_mnemonic(entropy)
        assert isinstance(words, list)
        assert all(isinstance(word, str) for word in words)

    def test_mnemonic_to_entropy_returns_bytes(self):
        """Verify that mnemonic_to_entropy returns bytes."""
        words = ["abandon"] * 11 + ["about"]
        entropy = mnemonic_to_entropy(words)
        assert isinstance(entropy, bytes)


class TestAllBIP39Vectors:
    """Test all BIP39 test vectors from the C implementation."""

    def test_all_c_test_vectors_entropy_to_mnemonic(self):
        """Test all entropy-to-mnemonic conversions from C test vectors."""
        test_vectors = [
            (bytes.fromhex("00000000000000000000000000000000"),
             ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"]),
            (bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
             ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow"]),
            (bytes.fromhex("80808080808080808080808080808080"),
             ["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "above"]),
            (bytes.fromhex("ffffffffffffffffffffffffffffffff"),
             ["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "wrong"]),
            (bytes.fromhex("000000000000000000000000000000000000000000000000"),
             ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "agent"]),
            (bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
             ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "will"]),
            (bytes.fromhex("808080808080808080808080808080808080808080808080"),
             ["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "always"]),
            (bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffff"),
             ["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "when"]),
            (bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
             ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art"]),
            (bytes.fromhex("7F7F7F7F7F7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
             ["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "title"]),
            (bytes.fromhex("8080808080808080808080808080808080808080808080808080808080808080"),
             ["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "bless"]),
            (bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
             ["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "vote"]),
            (bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2"),
             ["ozone", "drill", "grab", "fiber", "curtain", "grace", "pudding", "thank", "cruise", "elder", "eight", "picnic"]),
            (bytes.fromhex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"),
             ["gravity", "machine", "north", "sort", "system", "female", "filter", "attitude", "volume", "fold", "club", "stay", "feature", "office", "ecology", "stable", "narrow", "fog"]),
            (bytes.fromhex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"),
             ["hamster", "diagram", "private", "dutch", "cause", "delay", "private", "meat", "slide", "toddler", "razor", "book", "happy", "fancy", "gospel", "tennis", "maple", "dilemma", "loan", "word", "shrug", "inflict", "delay", "length"]),
            (bytes.fromhex("c0ba5a8e914111210f2bd131f3d5e08d"),
             ["scheme", "spot", "photo", "card", "baby", "mountain", "device", "kick", "cradle", "pact", "join", "borrow"]),
            (bytes.fromhex("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3"),
             ["horn", "tenant", "knee", "talent", "sponsor", "spell", "gate", "clip", "pulse", "soap", "slush", "warm", "silver", "nephew", "swap", "uncle", "crack", "brave"]),
            (bytes.fromhex("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"),
             ["panda", "eyebrow", "bullet", "gorilla", "call", "smoke", "muffin", "taste", "mesh", "discover", "soft", "ostrich", "alcohol", "speed", "nation", "flash", "devote", "level", "hobby", "quick", "inner", "drive", "ghost", "inside"]),
            (bytes.fromhex("23db8160a31d3e0dca3688ed941adbf3"),
             ["cat", "swing", "flag", "economy", "stadium", "alone", "churn", "speed", "unique", "patch", "report", "train"]),
            (bytes.fromhex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0"),
             ["light", "rule", "cinnamon", "wrap", "drastic", "word", "pride", "squirrel", "upgrade", "then", "income", "fatal", "apart", "sustain", "crack", "supply", "proud", "access"]),
            (bytes.fromhex("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad"),
             ["all", "hour", "make", "first", "leader", "extend", "hole", "alien", "behind", "guard", "gospel", "lava", "path", "output", "census", "museum", "junior", "mass", "reopen", "famous", "sing", "advance", "salt", "reform"]),
            (bytes.fromhex("f30f8c1da665478f49b001d94c5fc452"),
             ["vessel", "ladder", "alter", "error", "federal", "sibling", "chat", "ability", "sun", "glass", "valve", "picture"]),
            (bytes.fromhex("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"),
             ["scissors", "invite", "lock", "maple", "supreme", "raw", "rapid", "void", "congress", "muscle", "digital", "elegant", "little", "brisk", "hair", "mango", "congress", "clump"]),
            (bytes.fromhex("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"),
             ["void", "come", "effort", "suffer", "camp", "survey", "warrior", "heavy", "shoot", "primary", "clutch", "crush", "open", "amazing", "screen", "patrol", "group", "space", "point", "ten", "exist", "slush", "involve", "unfold"]),
        ]

        for entropy, expected_words in test_vectors:
            words = entropy_to_mnemonic(entropy)
            assert words == expected_words, f"Failed for entropy {entropy.hex()}"

    def test_all_c_test_vectors_mnemonic_to_entropy(self):
        """Test all mnemonic-to-entropy conversions from C test vectors."""
        test_vectors = [
            (["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"],
             bytes.fromhex("00000000000000000000000000000000")),
            (["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow"],
             bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")),
            (["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "above"],
             bytes.fromhex("80808080808080808080808080808080")),
            (["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "wrong"],
             bytes.fromhex("ffffffffffffffffffffffffffffffff")),
            (["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "agent"],
             bytes.fromhex("000000000000000000000000000000000000000000000000")),
            (["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "will"],
             bytes.fromhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")),
            (["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "always"],
             bytes.fromhex("808080808080808080808080808080808080808080808080")),
            (["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "when"],
             bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffff")),
            (["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art"],
             bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")),
            (["legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "title"],
             bytes.fromhex("7F7F7F7F7F7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")),
            (["letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid", "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "bless"],
             bytes.fromhex("8080808080808080808080808080808080808080808080808080808080808080")),
            (["zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "vote"],
             bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
            (["ozone", "drill", "grab", "fiber", "curtain", "grace", "pudding", "thank", "cruise", "elder", "eight", "picnic"],
             bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2")),
            (["gravity", "machine", "north", "sort", "system", "female", "filter", "attitude", "volume", "fold", "club", "stay", "feature", "office", "ecology", "stable", "narrow", "fog"],
             bytes.fromhex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b")),
            (["hamster", "diagram", "private", "dutch", "cause", "delay", "private", "meat", "slide", "toddler", "razor", "book", "happy", "fancy", "gospel", "tennis", "maple", "dilemma", "loan", "word", "shrug", "inflict", "delay", "length"],
             bytes.fromhex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c")),
            (["scheme", "spot", "photo", "card", "baby", "mountain", "device", "kick", "cradle", "pact", "join", "borrow"],
             bytes.fromhex("c0ba5a8e914111210f2bd131f3d5e08d")),
            (["horn", "tenant", "knee", "talent", "sponsor", "spell", "gate", "clip", "pulse", "soap", "slush", "warm", "silver", "nephew", "swap", "uncle", "crack", "brave"],
             bytes.fromhex("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3")),
            (["panda", "eyebrow", "bullet", "gorilla", "call", "smoke", "muffin", "taste", "mesh", "discover", "soft", "ostrich", "alcohol", "speed", "nation", "flash", "devote", "level", "hobby", "quick", "inner", "drive", "ghost", "inside"],
             bytes.fromhex("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863")),
            (["cat", "swing", "flag", "economy", "stadium", "alone", "churn", "speed", "unique", "patch", "report", "train"],
             bytes.fromhex("23db8160a31d3e0dca3688ed941adbf3")),
            (["light", "rule", "cinnamon", "wrap", "drastic", "word", "pride", "squirrel", "upgrade", "then", "income", "fatal", "apart", "sustain", "crack", "supply", "proud", "access"],
             bytes.fromhex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0")),
            (["all", "hour", "make", "first", "leader", "extend", "hole", "alien", "behind", "guard", "gospel", "lava", "path", "output", "census", "museum", "junior", "mass", "reopen", "famous", "sing", "advance", "salt", "reform"],
             bytes.fromhex("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad")),
            (["vessel", "ladder", "alter", "error", "federal", "sibling", "chat", "ability", "sun", "glass", "valve", "picture"],
             bytes.fromhex("f30f8c1da665478f49b001d94c5fc452")),
            (["scissors", "invite", "lock", "maple", "supreme", "raw", "rapid", "void", "congress", "muscle", "digital", "elegant", "little", "brisk", "hair", "mango", "congress", "clump"],
             bytes.fromhex("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05")),
            (["void", "come", "effort", "suffer", "camp", "survey", "warrior", "heavy", "shoot", "primary", "clutch", "crush", "open", "amazing", "screen", "patrol", "group", "space", "point", "ten", "exist", "slush", "involve", "unfold"],
             bytes.fromhex("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")),
        ]

        for words, expected_entropy in test_vectors:
            entropy = mnemonic_to_entropy(words)
            assert entropy == expected_entropy, f"Failed for words {' '.join(words)}"
