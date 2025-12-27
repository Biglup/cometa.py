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
import cometa
from cometa import (
    Ed25519PrivateKey,
    SoftwareEd25519SecureKeyHandler,
    Transaction,
    CborReader,
)


PASSWORD = b"password"
WRONG_PASSWORD = b"wrong-password"
ED25519_PRIVATE_KEY_HEX = (
    "f04462421183d227bbc0fa60799ef338169c05eed7aa6aac19bc4db20557df51"
    "e154255decce80ae4ab8a61af6abde05e7fbc049861cc040a7afe4fb0a875899"
)
ED25519_PUBLIC_KEY_HEX = "07473467683e6a30a13d471a68641f311a14e2b37a38ea592e5d6efc2b446bce"
TX_CBOR = (
    "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b000b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b582088e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a10481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c71213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799fd8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9fd8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980fffff5f6"
)


def get_passphrase():
    """Returns the correct passphrase."""
    return bytes(PASSWORD)


def get_wrong_passphrase():
    """Returns an incorrect passphrase."""
    return bytes(WRONG_PASSWORD)


def get_transaction():
    """Parse and return the test transaction."""
    reader = CborReader.from_hex(TX_CBOR)
    return Transaction.from_cbor(reader)


class TestSoftwareEd25519SecureKeyHandlerCreation:
    """Tests for SoftwareEd25519SecureKeyHandler creation methods."""

    def test_from_ed25519_key_creates_valid_handler(self):
        """Test creating handler from Ed25519 private key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert handler is not None
        assert isinstance(handler, SoftwareEd25519SecureKeyHandler)

    def test_from_ed25519_key_with_bytearray_passphrase(self):
        """Test creating handler with bytearray passphrase."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        passphrase = bytearray(PASSWORD)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=passphrase,
            get_passphrase=get_passphrase
        )
        assert handler is not None
        assert isinstance(handler, SoftwareEd25519SecureKeyHandler)

    def test_from_ed25519_key_with_different_passphrases(self):
        """Test creating handler with different passphrases."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)

        handler1 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"passphrase1",
            get_passphrase=lambda: b"passphrase1"
        )

        handler2 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"passphrase2",
            get_passphrase=lambda: b"passphrase2"
        )

        assert handler1 is not None
        assert handler2 is not None
        pub1 = handler1.get_public_key()
        pub2 = handler2.get_public_key()
        assert pub1.to_hex() == pub2.to_hex()

    def test_from_ed25519_key_invalid_private_key_type(self):
        """Test creating handler with invalid private key type."""
        with pytest.raises(AttributeError):
            SoftwareEd25519SecureKeyHandler.from_ed25519_key(
                private_key="not a private key",
                passphrase=PASSWORD,
                get_passphrase=get_passphrase
            )

    def test_from_ed25519_key_invalid_passphrase_type(self):
        """Test creating handler with invalid passphrase type."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        with pytest.raises((TypeError, AttributeError)):
            SoftwareEd25519SecureKeyHandler.from_ed25519_key(
                private_key=private_key,
                passphrase=12345,
                get_passphrase=get_passphrase
            )

    def test_from_ed25519_key_invalid_callback_type(self):
        """Test creating handler with invalid callback type."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase="not a callable"
        )
        with pytest.raises(TypeError):
            handler.get_public_key()


class TestSoftwareEd25519SecureKeyHandlerSerialization:
    """Tests for SoftwareEd25519SecureKeyHandler serialization methods."""

    def test_serialize_returns_bytes(self):
        """Test that serialize returns bytes."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = handler.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

    def test_serialize_has_correct_format(self):
        """Test that serialized data has the correct binary format."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = handler.serialize()

        assert len(serialized) >= 14

        import struct
        magic = struct.unpack(">I", serialized[0:4])[0]
        assert magic == 0x0A0A0A0A

        version = serialized[4]
        assert version == 0x01

        key_type = serialized[5]
        assert key_type == 0x00

    def test_serialize_deterministic(self):
        """Test that serialize produces deterministic output."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized1 = handler.serialize()
        serialized2 = handler.serialize()
        assert serialized1 == serialized2

    def test_deserialize_valid_data(self):
        """Test deserializing valid data."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        original_handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = original_handler.serialize()

        deserialized_handler = SoftwareEd25519SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )

        assert deserialized_handler is not None
        assert isinstance(deserialized_handler, SoftwareEd25519SecureKeyHandler)

    def test_deserialize_preserves_key_material(self):
        """Test that deserialization preserves the key material."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        original_handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        original_public_key = original_handler.get_public_key()

        serialized = original_handler.serialize()
        deserialized_handler = SoftwareEd25519SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )
        deserialized_public_key = deserialized_handler.get_public_key()

        assert original_public_key.to_hex() == deserialized_public_key.to_hex()

    def test_deserialize_data_too_short(self):
        """Test deserializing data that is too short."""
        short_data = b"tooshort"
        with pytest.raises(ValueError, match="too short"):
            SoftwareEd25519SecureKeyHandler.deserialize(
                short_data,
                get_passphrase
            )

    def test_deserialize_invalid_magic(self):
        """Test deserializing data with invalid magic number."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized[0] = 0xFF
        serialized[1] = 0xFF
        serialized[2] = 0xFF
        serialized[3] = 0xFF

        import struct
        data_to_checksum = serialized[:-4]
        from cometa.cryptography.crc32 import crc32
        checksum = crc32(bytes(data_to_checksum))
        struct.pack_into(">I", serialized, len(serialized) - 4, checksum)

        with pytest.raises(ValueError, match="incorrect magic number"):
            SoftwareEd25519SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_invalid_version(self):
        """Test deserializing data with invalid version."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized[4] = 0xFF

        import struct
        data_to_checksum = serialized[:-4]
        from cometa.cryptography.crc32 import crc32
        checksum = crc32(bytes(data_to_checksum))
        struct.pack_into(">I", serialized, len(serialized) - 4, checksum)

        with pytest.raises(ValueError, match="Unsupported version"):
            SoftwareEd25519SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_invalid_key_type(self):
        """Test deserializing data with invalid key type."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized[5] = 0xFF

        import struct
        data_to_checksum = serialized[:-4]
        from cometa.cryptography.crc32 import crc32
        checksum = crc32(bytes(data_to_checksum))
        struct.pack_into(">I", serialized, len(serialized) - 4, checksum)

        with pytest.raises(ValueError, match="Unsupported key type"):
            SoftwareEd25519SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_checksum_mismatch(self):
        """Test deserializing data with incorrect checksum."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized[-1] ^= 0xFF

        with pytest.raises(ValueError, match="checksum mismatch"):
            SoftwareEd25519SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_length_mismatch(self):
        """Test deserializing data with length mismatch."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized = serialized[:-5]

        with pytest.raises(ValueError):
            SoftwareEd25519SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_serialize_deserialize_round_trip(self):
        """Test full round-trip serialization and deserialization."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        original_handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        serialized = original_handler.serialize()
        deserialized_handler = SoftwareEd25519SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )

        reserialized = deserialized_handler.serialize()
        assert serialized == reserialized


class TestSoftwareEd25519SecureKeyHandlerPublicKey:
    """Tests for getting public keys."""

    def test_get_public_key_returns_valid_key(self):
        """Test that get_public_key returns a valid Ed25519PublicKey."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        public_key = handler.get_public_key()
        assert public_key is not None
        from cometa.cryptography.ed25519_public_key import Ed25519PublicKey
        assert isinstance(public_key, Ed25519PublicKey)

    def test_get_public_key_matches_expected_value(self):
        """Test that get_public_key returns the expected public key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        public_key = handler.get_public_key()
        assert public_key.to_hex() == ED25519_PUBLIC_KEY_HEX

    def test_get_public_key_consistent(self):
        """Test that get_public_key returns consistent results."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        public_key1 = handler.get_public_key()
        public_key2 = handler.get_public_key()
        assert public_key1.to_hex() == public_key2.to_hex()

    def test_get_public_key_with_wrong_passphrase(self):
        """Test that get_public_key fails with wrong passphrase."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        with pytest.raises(cometa.CardanoError):
            handler.get_public_key()


class TestSoftwareEd25519SecureKeyHandlerPrivateKey:
    """Tests for getting private keys."""

    def test_get_private_key_returns_valid_key(self):
        """Test that get_private_key returns a valid Ed25519PrivateKey."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        retrieved_key = handler.get_private_key()
        assert retrieved_key is not None
        assert isinstance(retrieved_key, Ed25519PrivateKey)

    def test_get_private_key_matches_original(self):
        """Test that get_private_key returns the original key."""
        original_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=original_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        retrieved_key = handler.get_private_key()
        assert retrieved_key.to_hex() == ED25519_PRIVATE_KEY_HEX

    def test_get_private_key_consistent(self):
        """Test that get_private_key returns consistent results."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        key1 = handler.get_private_key()
        key2 = handler.get_private_key()
        assert key1.to_hex() == key2.to_hex()

    def test_get_private_key_with_wrong_passphrase(self):
        """Test that get_private_key fails with wrong passphrase."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        with pytest.raises(cometa.CardanoError):
            handler.get_private_key()


class TestSoftwareEd25519SecureKeyHandlerSignTransaction:
    """Tests for signing transactions."""

    def test_sign_transaction_returns_witness_set(self):
        """Test that sign_transaction returns a VkeyWitnessSet."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction)

        from cometa.witness_set.vkey_witness_set import VkeyWitnessSet
        assert isinstance(witnesses, VkeyWitnessSet)

    def test_sign_transaction_produces_one_witness(self):
        """Test that sign_transaction produces exactly one witness."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction)
        assert len(witnesses) == 1

    def test_sign_transaction_witness_has_correct_vkey(self):
        """Test that the witness has the correct verification key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction)
        assert witnesses[0].vkey.hex() == ED25519_PUBLIC_KEY_HEX

    def test_sign_transaction_witness_has_correct_signature(self):
        """Test that the witness has the correct signature."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction)
        expected_signature = (
            "5f9f725da55e2a89e725f2c147512c0508956aae6a99cb2f3150c73c812c7373"
            "f57311dcee14cb02ad1ab7b1940aecc5bbf0769a9b77aafb996393b08d48830b"
        )
        assert witnesses[0].signature.hex() == expected_signature

    def test_sign_transaction_deterministic(self):
        """Test that signing produces deterministic signatures."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()

        witnesses1 = handler.sign_transaction(transaction)
        witnesses2 = handler.sign_transaction(transaction)

        assert witnesses1[0].signature.hex() == witnesses2[0].signature.hex()

    def test_sign_transaction_with_wrong_passphrase(self):
        """Test that signing fails with wrong passphrase."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        transaction = get_transaction()
        with pytest.raises(cometa.CardanoError):
            handler.sign_transaction(transaction)

    def test_sign_transaction_with_invalid_transaction(self):
        """Test that signing fails with invalid transaction."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        with pytest.raises(AttributeError):
            handler.sign_transaction("not a transaction")


class TestSoftwareEd25519SecureKeyHandlerSignData:
    """Tests for signing arbitrary data."""

    def test_sign_data_returns_dict(self):
        """Test that sign_data returns a dict."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result = handler.sign_data("deadbeef")
        assert isinstance(result, dict)

    def test_sign_data_contains_required_keys(self):
        """Test that sign_data result contains 'signature' and 'key'."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result = handler.sign_data("deadbeef")
        assert "signature" in result
        assert "key" in result

    def test_sign_data_key_is_correct(self):
        """Test that the public key in the result is correct."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result = handler.sign_data("deadbeef")
        assert result["key"] == ED25519_PUBLIC_KEY_HEX

    def test_sign_data_signature_is_hex_string(self):
        """Test that the signature is a hex string."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result = handler.sign_data("deadbeef")
        assert isinstance(result["signature"], str)
        assert len(result["signature"]) == 128
        bytes.fromhex(result["signature"])

    def test_sign_data_deterministic(self):
        """Test that signing the same data produces the same signature."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result1 = handler.sign_data("deadbeef")
        result2 = handler.sign_data("deadbeef")
        assert result1["signature"] == result2["signature"]

    def test_sign_data_different_data_different_signature(self):
        """Test that signing different data produces different signatures."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result1 = handler.sign_data("deadbeef")
        result2 = handler.sign_data("beefdead")
        assert result1["signature"] != result2["signature"]

    def test_sign_data_with_empty_string(self):
        """Test signing empty data."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        result = handler.sign_data("")
        assert "signature" in result
        assert "key" in result

    def test_sign_data_with_long_data(self):
        """Test signing long data."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        long_data = "ab" * 1000
        result = handler.sign_data(long_data)
        assert "signature" in result
        assert len(result["signature"]) == 128

    def test_sign_data_with_invalid_hex(self):
        """Test that signing invalid hex data raises an error."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        with pytest.raises(ValueError):
            handler.sign_data("not valid hex")

    def test_sign_data_with_wrong_passphrase(self):
        """Test that signing fails with wrong passphrase."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        with pytest.raises(cometa.CardanoError):
            handler.sign_data("deadbeef")


class TestSoftwareEd25519SecureKeyHandlerSecurityProperties:
    """Tests for security properties of the key handler."""

    def test_encrypted_data_is_different_from_private_key(self):
        """Test that encrypted data does not contain raw private key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = handler.serialize()
        private_key_hex = ED25519_PRIVATE_KEY_HEX.lower()
        serialized_hex = serialized.hex().lower()
        assert private_key_hex not in serialized_hex

    def test_different_passphrases_produce_different_encrypted_data(self):
        """Test that different passphrases produce different encrypted data."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)

        handler1 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"password1",
            get_passphrase=lambda: b"password1"
        )

        handler2 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"password2",
            get_passphrase=lambda: b"password2"
        )

        serialized1 = handler1.serialize()
        serialized2 = handler2.serialize()

        assert serialized1 != serialized2

    def test_cannot_access_encrypted_data_directly(self):
        """Test that encrypted data is not directly accessible."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert not hasattr(handler, 'private_key')
        assert hasattr(handler, '_encrypted_data')

    def test_wrong_passphrase_callback_prevents_key_access(self):
        """Test that wrong passphrase callback prevents all key operations."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )

        with pytest.raises(cometa.CardanoError):
            handler.get_public_key()

        with pytest.raises(cometa.CardanoError):
            handler.get_private_key()

        transaction = get_transaction()
        with pytest.raises(cometa.CardanoError):
            handler.sign_transaction(transaction)

        with pytest.raises(cometa.CardanoError):
            handler.sign_data("deadbeef")


class TestSoftwareEd25519SecureKeyHandlerEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_handlers_with_same_key(self):
        """Test that multiple handlers can be created from the same key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)

        handler1 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        handler2 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        pub1 = handler1.get_public_key()
        pub2 = handler2.get_public_key()
        assert pub1.to_hex() == pub2.to_hex()

    def test_handler_is_reusable(self):
        """Test that a handler can be used multiple times."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        for _ in range(5):
            pub = handler.get_public_key()
            assert pub.to_hex() == ED25519_PUBLIC_KEY_HEX

    def test_serialized_data_size_is_consistent(self):
        """Test that serialized data has consistent size."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)

        handler1 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"short",
            get_passphrase=lambda: b"short"
        )

        handler2 = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=b"very_long_passphrase_for_testing",
            get_passphrase=lambda: b"very_long_passphrase_for_testing"
        )

        size1 = len(handler1.serialize())
        size2 = len(handler2.serialize())

        assert size1 == size2

    def test_passphrase_callback_is_called_each_time(self):
        """Test that the passphrase callback is invoked for each operation."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)

        call_count = [0]
        def counting_callback():
            call_count[0] += 1
            return PASSWORD

        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=counting_callback
        )

        initial_count = call_count[0]
        handler.get_public_key()
        assert call_count[0] > initial_count

        prev_count = call_count[0]
        handler.get_public_key()
        assert call_count[0] > prev_count

    def test_handler_instance_attributes(self):
        """Test that handler has expected instance attributes."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        assert hasattr(handler, '_encrypted_data')
        assert hasattr(handler, '_get_passphrase')
        assert callable(handler._get_passphrase)

    def test_handler_class_constants(self):
        """Test that handler class has expected constants."""
        assert hasattr(SoftwareEd25519SecureKeyHandler, '_MAGIC')
        assert hasattr(SoftwareEd25519SecureKeyHandler, '_VERSION')
        assert hasattr(SoftwareEd25519SecureKeyHandler, '_ED25519_KEY_HANDLER')

        assert SoftwareEd25519SecureKeyHandler._MAGIC == 0x0A0A0A0A
        assert SoftwareEd25519SecureKeyHandler._VERSION == 0x01
        assert SoftwareEd25519SecureKeyHandler._ED25519_KEY_HANDLER == 0x00
