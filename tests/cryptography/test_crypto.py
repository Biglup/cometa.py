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
from cometa import (
    Blake2bHash,
    Blake2bHashSize,
    Blake2bHashSet,
    Ed25519Signature,
    Ed25519PublicKey,
    Ed25519PrivateKey,
    Bip32PublicKey,
    Bip32PrivateKey,
    harden,
    crc32,
    pbkdf2_hmac_sha512,
    emip3_encrypt,
    emip3_decrypt,
    CborReader,
    CborWriter,
)


class TestBlake2bHashSize:
    """Tests for the Blake2bHashSize enum."""

    def test_hash_sizes(self):
        assert Blake2bHashSize.HASH_224 == 28
        assert Blake2bHashSize.HASH_256 == 32
        assert Blake2bHashSize.HASH_512 == 64


class TestEd25519Signature:
    """Tests for the Ed25519Signature class."""

    TEST_SIG = "00" * 64

    def test_from_hex(self):
        sig = Ed25519Signature.from_hex(self.TEST_SIG)
        assert sig.to_hex() == self.TEST_SIG

    def test_from_bytes(self):
        sig_bytes = bytes(64)
        sig = Ed25519Signature.from_bytes(sig_bytes)
        assert sig.to_bytes() == sig_bytes

    def test_equality(self):
        sig1 = Ed25519Signature.from_hex(self.TEST_SIG)
        sig2 = Ed25519Signature.from_hex(self.TEST_SIG)
        sig3 = Ed25519Signature.from_hex("ff" * 64)
        assert sig1 == sig2
        assert sig1 != sig3

    def test_hash(self):
        sig1 = Ed25519Signature.from_hex(self.TEST_SIG)
        sig2 = Ed25519Signature.from_hex(self.TEST_SIG)
        assert hash(sig1) == hash(sig2)

    def test_repr(self):
        sig = Ed25519Signature.from_hex(self.TEST_SIG)
        assert "Ed25519Signature" in repr(sig)


class TestEd25519PublicKey:
    """Tests for the Ed25519PublicKey class."""

    TEST_PUB_KEY = "00" * 32

    def test_from_hex(self):
        pub_key = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        assert pub_key.to_hex() == self.TEST_PUB_KEY

    def test_from_bytes(self):
        key_bytes = bytes(32)
        pub_key = Ed25519PublicKey.from_bytes(key_bytes)
        assert pub_key.to_bytes() == key_bytes

    def test_to_hash(self):
        pub_key = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        key_hash = pub_key.to_hash()
        assert len(key_hash.to_bytes()) == 28

    def test_equality(self):
        pub1 = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        pub2 = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        pub3 = Ed25519PublicKey.from_hex("ff" * 32)
        assert pub1 == pub2
        assert pub1 != pub3

    def test_hash(self):
        pub1 = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        pub2 = Ed25519PublicKey.from_hex(self.TEST_PUB_KEY)
        assert hash(pub1) == hash(pub2)


class TestEd25519PrivateKey:
    """Tests for the Ed25519PrivateKey class."""

    TEST_PRIV_KEY = "00" * 32

    def test_from_normal_hex(self):
        priv_key = Ed25519PrivateKey.from_normal_hex(self.TEST_PRIV_KEY)
        assert len(priv_key.to_bytes()) >= 32

    def test_from_normal_bytes(self):
        key_bytes = bytes(32)
        priv_key = Ed25519PrivateKey.from_normal_bytes(key_bytes)
        assert priv_key is not None

    def test_get_public_key(self):
        priv_key = Ed25519PrivateKey.from_normal_hex(self.TEST_PRIV_KEY)
        pub_key = priv_key.get_public_key()
        assert pub_key is not None
        assert len(pub_key.to_bytes()) == 32

    def test_sign_and_verify(self):
        priv_key = Ed25519PrivateKey.from_normal_hex(self.TEST_PRIV_KEY)
        pub_key = priv_key.get_public_key()
        message = b"Hello, Cardano!"
        signature = priv_key.sign(message)
        assert pub_key.verify(signature, message)

    def test_sign_wrong_message_fails(self):
        priv_key = Ed25519PrivateKey.from_normal_hex(self.TEST_PRIV_KEY)
        pub_key = priv_key.get_public_key()
        message = b"Hello, Cardano!"
        signature = priv_key.sign(message)
        assert not pub_key.verify(signature, b"Wrong message")

    def test_repr_hides_key(self):
        priv_key = Ed25519PrivateKey.from_normal_hex(self.TEST_PRIV_KEY)
        repr_str = repr(priv_key)
        assert "hidden" in repr_str
        assert self.TEST_PRIV_KEY not in repr_str


class TestBip32Keys:
    """Tests for the Bip32PrivateKey and Bip32PublicKey classes."""

    def test_from_bip39_entropy(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        assert root_key is not None

    def test_derive(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        child = root_key.derive([harden(1852), harden(1815), harden(0)])
        assert child is not None

    def test_get_public_key(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        pub_key = root_key.get_public_key()
        assert pub_key is not None

    def test_to_ed25519_key(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        account_key = root_key.derive([harden(1852), harden(1815), harden(0)])
        ed25519_key = account_key.to_ed25519_key()
        assert ed25519_key is not None

    def test_harden_function(self):
        assert harden(0) == 2147483648
        assert harden(1852) == 2147485500
        assert harden(1815) == 2147485463

    def test_public_key_derive(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        account_key = root_key.derive([harden(1852), harden(1815), harden(0)])
        pub_key = account_key.get_public_key()
        child_pub = pub_key.derive([0, 0])
        assert child_pub is not None

    def test_bip32_public_to_hash(self):
        entropy = bytes.fromhex("00" * 16)
        root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
        pub_key = root_key.get_public_key()
        key_hash = pub_key.to_hash()
        assert len(key_hash.to_bytes()) == 28


class TestBlake2bHashSet:
    """Tests for the Blake2bHashSet class."""

    def test_new_empty_set(self):
        hash_set = Blake2bHashSet()
        assert len(hash_set) == 0

    def test_add_hash(self):
        hash_set = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        hash_set.add(h)
        assert len(hash_set) == 1

    def test_get_hash(self):
        hash_set = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        hash_set.add(h)
        retrieved = hash_set.get(0)
        assert retrieved == h

    def test_iteration(self):
        hash_set = Blake2bHashSet()
        h1 = Blake2bHash.from_hex("00" * 32)
        h2 = Blake2bHash.from_hex("ff" * 32)
        hash_set.add(h1)
        hash_set.add(h2)
        hashes = list(hash_set)
        assert len(hashes) == 2

    def test_contains(self):
        hash_set = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        hash_set.add(h)
        assert h in hash_set

    def test_cbor_roundtrip(self):
        hash_set = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        hash_set.add(h)

        writer = CborWriter()
        hash_set.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = Blake2bHashSet.from_cbor(reader)
        assert len(restored) == len(hash_set)


class TestCrc32:
    """Tests for the crc32 function."""

    def test_crc32_basic(self):
        result = crc32(b"Hello, world!")
        assert isinstance(result, int)
        assert result > 0

    def test_crc32_empty(self):
        result = crc32(b"")
        assert result == 0

    def test_crc32_deterministic(self):
        data = b"Test data for CRC32"
        result1 = crc32(data)
        result2 = crc32(data)
        assert result1 == result2


class TestPbkdf2:
    """Tests for the pbkdf2_hmac_sha512 function."""

    def test_pbkdf2_basic(self):
        key = pbkdf2_hmac_sha512(b"password", b"salt", 1000, 32)
        assert len(key) == 32

    def test_pbkdf2_deterministic(self):
        key1 = pbkdf2_hmac_sha512(b"password", b"salt", 1000, 32)
        key2 = pbkdf2_hmac_sha512(b"password", b"salt", 1000, 32)
        assert key1 == key2

    def test_pbkdf2_different_passwords(self):
        key1 = pbkdf2_hmac_sha512(b"password1", b"salt", 1000, 32)
        key2 = pbkdf2_hmac_sha512(b"password2", b"salt", 1000, 32)
        assert key1 != key2

    def test_pbkdf2_different_salts(self):
        key1 = pbkdf2_hmac_sha512(b"password", b"salt1", 1000, 32)
        key2 = pbkdf2_hmac_sha512(b"password", b"salt2", 1000, 32)
        assert key1 != key2

    def test_pbkdf2_string_password(self):
        key = pbkdf2_hmac_sha512("password", b"salt", 1000, 32)
        assert len(key) == 32


class TestEmip3:
    """Tests for the EMIP-003 encryption functions."""

    def test_encrypt_decrypt_roundtrip(self):
        data = b"Secret message"
        passphrase = b"my-secure-passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data

    def test_encrypt_increases_size(self):
        data = b"Test data"
        passphrase = b"passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        assert len(encrypted) > len(data)

    def test_decrypt_wrong_passphrase_fails(self):
        data = b"Secret data"
        encrypted = emip3_encrypt(data, b"correct-passphrase")
        with pytest.raises(Exception):
            emip3_decrypt(encrypted, b"wrong-passphrase")

    def test_string_passphrase(self):
        data = b"Test data"
        encrypted = emip3_encrypt(data, "string-passphrase")
        decrypted = emip3_decrypt(encrypted, "string-passphrase")
        assert decrypted == data

    def test_empty_data(self):
        data = b""
        passphrase = b"passphrase"
        encrypted = emip3_encrypt(data, passphrase)
        decrypted = emip3_decrypt(encrypted, passphrase)
        assert decrypted == data
