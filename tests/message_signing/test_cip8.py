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
)


class TestCIP8:
    """Tests for CIP-8 message signing."""

    @pytest.fixture
    def private_key(self):
        """Create a test private key from known seed."""
        # Use a deterministic seed for testing
        seed = bytes(32)  # All zeros for testing
        return Ed25519PrivateKey.from_normal_bytes(seed)

    @pytest.fixture
    def test_address(self, private_key):
        """Create a test address from the private key."""
        public_key = private_key.get_public_key()
        key_hash = public_key.to_hash()
        payment_credential = Credential.from_key_hash(key_hash)
        # Create a base address with same credential for payment and stake
        base_addr = BaseAddress.from_credentials(NetworkId.TESTNET, payment_credential, payment_credential)
        return base_addr.to_address()

    def test_sign_message(self, private_key, test_address):
        """Test signing a message with CIP-8."""
        message = b"Hello, Cardano!"
        result = cip8_sign(message, test_address, private_key)

        assert isinstance(result, CIP8SignResult)
        assert isinstance(result.cose_sign1, bytes)
        assert isinstance(result.cose_key, bytes)
        assert len(result.cose_sign1) > 0
        assert len(result.cose_key) > 0

    def test_sign_empty_message(self, private_key, test_address):
        """Test signing an empty message - C library doesn't support empty messages."""
        from cometa import CardanoError

        message = b""
        # The C library returns error code 7 for empty messages
        with pytest.raises(CardanoError):
            cip8_sign(message, test_address, private_key)

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
        # Use a different seed to get a different key
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

        # COSE_Sign1 should be different for different messages
        assert result1.cose_sign1 != result2.cose_sign1
        # COSE_Key should be the same (same key)
        assert result1.cose_key == result2.cose_key

    def test_sign_result_repr(self, private_key, test_address):
        """Test the string representation of CIP8SignResult."""
        message = b"Test"
        result = cip8_sign(message, test_address, private_key)

        repr_str = repr(result)
        assert "CIP8SignResult" in repr_str
        assert "cose_sign1" in repr_str
        assert "cose_key" in repr_str
        assert "bytes" in repr_str
