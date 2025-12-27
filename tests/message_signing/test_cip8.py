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
    Ed25519PrivateKey,
    CIP8SignResult,
    cip8_sign,
    cip8_sign_with_key_hash,
    NetworkId,
    Credential,
    BaseAddress,
    Address,
    Blake2bHash,
    CardanoError,
)


PRIVATE_KEY_HEX = (
    "d06d3744d9089b21b1fbb736a45d359ed5d5b4028800e70aa1a2968183cb6852"
    "8ef06f1c2b289a85e09738d528869dd1f69f436ada4b471b12e950a2b9e780b6"
)
ADDRESS_TO_SIGN_WITH = "addr_test1qqja52pwpq7v7amg34r6x9dpp5le04n6cmqf2zpnurt2lm48wgx7j5cur9w0zxv7ky333eef3akg092hhcmp3teeth3qktnslv"
PUBKEY_HASH = "25da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"


class TestCIP8:
    """Tests for CIP-8 message signing."""

    @pytest.fixture
    def private_key(self):
        """Create a test private key from known seed."""
        seed = bytes(32)
        return Ed25519PrivateKey.from_normal_bytes(seed)

    @pytest.fixture
    def test_address(self, private_key):
        """Create a test address from the private key."""
        public_key = private_key.get_public_key()
        key_hash = public_key.to_hash()
        payment_credential = Credential.from_key_hash(key_hash)
        base_addr = BaseAddress.from_credentials(NetworkId.TESTNET, payment_credential, payment_credential)
        return base_addr.to_address()

    @pytest.fixture
    def test_signing_key(self):
        """Create test signing key from known hex."""
        return Ed25519PrivateKey.from_extended_hex(PRIVATE_KEY_HEX)

    @pytest.fixture
    def test_address_from_vector(self):
        """Create test address from test vector."""
        return Address.from_string(ADDRESS_TO_SIGN_WITH)

    @pytest.fixture
    def test_key_hash(self):
        """Create test key hash from test vector."""
        return Blake2bHash.from_hex(PUBKEY_HASH)

    def test_sign_message(self, private_key, test_address):
        """Test signing a message with CIP-8."""
        message = b"Hello, Cardano!"
        result = cip8_sign(message, test_address, private_key)

        assert isinstance(result, CIP8SignResult)
        assert isinstance(result.cose_sign1, bytes)
        assert isinstance(result.cose_key, bytes)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_sign_with_test_vector(self, test_signing_key, test_address_from_vector):
        """Test signing with known test vectors from C test."""
        message = bytes([0xab, 0xc1, 0x23])
        result = cip8_sign(message, test_address_from_vector, test_signing_key)

        assert isinstance(result, CIP8SignResult)
        cose_sign1_hex = result.cose_sign1.hex()
        cose_key_hex = result.cose_key.hex()

        expected_sign1 = (
            "845882a301270458390025da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"
            "a7720de9531c195cf1199eb12318e7298f6c879557be3618af395de2676164647265737358"
            "390025da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afeea7720de9531c19"
            "5cf1199eb12318e7298f6c879557be3618af395de2a166686173686564f443abc12358"
            "40cf4f8356899ef40f4c21869b50a3d5dc95414a8d3c1aae088b7518a65069cdf8413318"
            "77c16f11f6a88bbfe402e8fbb338a5646ff2d931d5e955c6717cf1c404"
        )
        expected_key = (
            "a501010258390025da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"
            "a7720de9531c195cf1199eb12318e7298f6c879557be3618af395de20327200621582088"
            "cb67866b59520bffcfe9c421ef5d9e0db88815637796f597d3305126c8c78c"
        )

        assert cose_sign1_hex == expected_sign1
        assert cose_key_hex == expected_key

    def test_sign_with_key_hash_test_vector(self, test_signing_key, test_key_hash):
        """Test signing with key hash using known test vectors from C test."""
        message = bytes([0xab, 0xc1, 0x23])
        result = cip8_sign_with_key_hash(message, test_key_hash, test_signing_key)

        assert isinstance(result, CIP8SignResult)
        cose_sign1_hex = result.cose_sign1.hex()
        cose_key_hex = result.cose_key.hex()

        expected_sign1 = (
            "845848a3012704581c25da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"
            "676b657948617368581c25da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"
            "a166686173686564f443abc123584021b71bfddb8794a41f6420c70968085b8bc4ca61d55980"
            "da8378eac2ceb9531efff499fd7f111a1f8d64674246aeddbfc4aed82c79f9f6cfa7f66b4a791b5c04"
        )
        expected_key = (
            "a5010102581c25da282e083ccf77688d47a315a10d3f97d67ac6c0950833e0d6afee"
            "0327200621582088cb67866b59520bffcfe9c421ef5d9e0db88815637796f597d3305126c8c78c"
        )

        assert cose_sign1_hex == expected_sign1
        assert cose_key_hex == expected_key

    def test_sign_empty_message(self, private_key, test_address):
        """Test signing an empty message raises error."""
        message = b""
        with pytest.raises(CardanoError):
            cip8_sign(message, test_address, private_key)

    def test_sign_with_key_hash_empty_message(self, test_signing_key, test_key_hash):
        """Test signing empty message with key hash raises error."""
        message = b""
        with pytest.raises(CardanoError):
            cip8_sign_with_key_hash(message, test_key_hash, test_signing_key)

    def test_sign_long_message(self, private_key, test_address):
        """Test signing a longer message."""
        message = b"A" * 1000
        result = cip8_sign(message, test_address, private_key)

        assert isinstance(result, CIP8SignResult)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_sign_binary_message(self, private_key, test_address):
        """Test signing binary data."""
        message = bytes(range(256))
        result = cip8_sign(message, test_address, private_key)

        assert isinstance(result, CIP8SignResult)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_sign_with_key_hash(self):
        """Test signing with a key hash instead of address."""
        seed = bytes([1] + [0] * 31)
        private_key = Ed25519PrivateKey.from_normal_bytes(seed)
        public_key = private_key.get_public_key()
        key_hash = public_key.to_hash()
        message = b"Hello, dRep!"

        result = cip8_sign_with_key_hash(message, key_hash, private_key)

        assert isinstance(result, CIP8SignResult)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_different_messages_produce_different_signatures(self):
        """Test that different messages produce different signatures."""
        seed = bytes([2] + [0] * 31)
        private_key = Ed25519PrivateKey.from_normal_bytes(seed)
        public_key = private_key.get_public_key()
        key_hash = public_key.to_hash()
        payment_credential = Credential.from_key_hash(key_hash)
        base_addr = BaseAddress.from_credentials(NetworkId.TESTNET, payment_credential, payment_credential)
        test_address = base_addr.to_address()

        message1 = b"Message 1"
        message2 = b"Message 2"

        result1 = cip8_sign(message1, test_address, private_key)
        result2 = cip8_sign(message2, test_address, private_key)

        assert result1.cose_sign1 != result2.cose_sign1
        assert result1.cose_key == result2.cose_key

    def test_sign_arbitrary_message_produces_output(self, test_signing_key, test_address_from_vector):
        """Test signing arbitrary message produces non-empty output."""
        message = b"hello CIP8"
        result = cip8_sign(message, test_address_from_vector, test_signing_key)

        assert isinstance(result, CIP8SignResult)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_sign_result_repr(self, private_key, test_address):
        """Test the string representation of CIP8SignResult."""
        message = b"Test"
        result = cip8_sign(message, test_address, private_key)

        repr_str = repr(result)
        assert "CIP8SignResult" in repr_str
        assert "cose_sign1" in repr_str
        assert "cose_key" in repr_str
        assert "bytes" in repr_str


class TestCIP8SignResult:
    """Tests for CIP8SignResult class."""

    def test_cip8_sign_result_creation(self):
        """Test creating a CIP8SignResult instance."""
        cose_sign1 = b"test_sign1_data"
        cose_key = b"test_key_data"
        result = CIP8SignResult(cose_sign1, cose_key)

        assert result.cose_sign1 == cose_sign1
        assert result.cose_key == cose_key

    def test_cip8_sign_result_attributes(self):
        """Test CIP8SignResult attributes are accessible."""
        cose_sign1 = b"\x01\x02\x03"
        cose_key = b"\x04\x05\x06"
        result = CIP8SignResult(cose_sign1, cose_key)

        assert isinstance(result.cose_sign1, bytes)
        assert isinstance(result.cose_key, bytes)
        assert len(result.cose_sign1) == 3
        assert len(result.cose_key) == 3

    def test_cip8_sign_result_repr(self):
        """Test CIP8SignResult repr shows byte lengths."""
        cose_sign1 = b"x" * 100
        cose_key = b"y" * 50
        result = CIP8SignResult(cose_sign1, cose_key)

        repr_str = repr(result)
        assert "100 bytes" in repr_str
        assert "50 bytes" in repr_str
