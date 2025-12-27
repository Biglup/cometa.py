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
    SoftwareBip32SecureKeyHandler,
    AccountDerivationPath,
    DerivationPath,
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    Transaction,
    CborReader,
    Bip32PublicKey,
    Ed25519PrivateKey,
)


PASSWORD = b"password"
WRONG_PASSWORD = b"wrong-password"
TEST_ENTROPY = bytes.fromhex(
    "4e828f9a67ddcff57e1f1204c988c89aaa0787f07293d0c3e0d62e53aac6e039"
    "8e730e27c5efe0f2a2f4c4b4c4e4c4e4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4"
)
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


def get_account_path():
    """Returns standard account derivation path."""
    return AccountDerivationPath(
        purpose=harden(KeyDerivationPurpose.STANDARD),
        coin_type=harden(CoinType.CARDANO),
        account=harden(0)
    )


def get_derivation_path(role=KeyDerivationRole.EXTERNAL, index=0):
    """Returns a standard derivation path."""
    return DerivationPath(
        purpose=harden(KeyDerivationPurpose.STANDARD),
        coin_type=harden(CoinType.CARDANO),
        account=harden(0),
        role=role,
        index=index
    )


class TestSoftwareBip32SecureKeyHandlerCreation:
    """Tests for SoftwareBip32SecureKeyHandler creation methods."""

    def test_from_entropy_creates_valid_handler(self):
        """Test creating handler from entropy."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert handler is not None
        assert isinstance(handler, SoftwareBip32SecureKeyHandler)

    def test_from_entropy_with_bytearray_passphrase(self):
        """Test creating handler with bytearray passphrase."""
        passphrase = bytearray(PASSWORD)
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=passphrase,
            get_passphrase=get_passphrase
        )
        assert handler is not None
        assert isinstance(handler, SoftwareBip32SecureKeyHandler)

    def test_from_entropy_with_different_passphrases(self):
        """Test creating handler with different passphrases."""
        handler1 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"passphrase1",
            get_passphrase=lambda: b"passphrase1"
        )

        handler2 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"passphrase2",
            get_passphrase=lambda: b"passphrase2"
        )

        assert handler1 is not None
        assert handler2 is not None
        path = get_account_path()
        pub1 = handler1.get_account_public_key(path)
        pub2 = handler2.get_account_public_key(path)
        assert pub1.to_hex() == pub2.to_hex()

    def test_from_entropy_invalid_entropy_type(self):
        """Test creating handler with invalid entropy type."""
        with pytest.raises((TypeError, AttributeError)):
            SoftwareBip32SecureKeyHandler.from_entropy(
                entropy="not bytes",
                passphrase=PASSWORD,
                get_passphrase=get_passphrase
            )

    def test_from_entropy_invalid_passphrase_type(self):
        """Test creating handler with invalid passphrase type."""
        with pytest.raises((TypeError, AttributeError)):
            SoftwareBip32SecureKeyHandler.from_entropy(
                entropy=TEST_ENTROPY,
                passphrase=12345,
                get_passphrase=get_passphrase
            )

    def test_from_entropy_invalid_callback_type(self):
        """Test creating handler with invalid callback type."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase="not a callable"
        )
        path = get_account_path()
        with pytest.raises(TypeError):
            handler.get_account_public_key(path)

    def test_from_entropy_with_short_entropy(self):
        """Test creating handler with short entropy."""
        short_entropy = bytes(16)
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=short_entropy,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert handler is not None

    def test_from_entropy_with_long_entropy(self):
        """Test creating handler with long entropy."""
        long_entropy = bytes(64)
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=long_entropy,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert handler is not None


class TestSoftwareBip32SecureKeyHandlerSerialization:
    """Tests for SoftwareBip32SecureKeyHandler serialization methods."""

    def test_serialize_returns_bytes(self):
        """Test that serialize returns bytes."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = handler.serialize()
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0

    def test_serialize_has_correct_format(self):
        """Test that serialized data has the correct binary format."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
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
        assert key_type == 0x01

    def test_serialize_deterministic(self):
        """Test that serialize produces deterministic output."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized1 = handler.serialize()
        serialized2 = handler.serialize()
        assert serialized1 == serialized2

    def test_deserialize_valid_data(self):
        """Test deserializing valid data."""
        original_handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = original_handler.serialize()

        deserialized_handler = SoftwareBip32SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )

        assert deserialized_handler is not None
        assert isinstance(deserialized_handler, SoftwareBip32SecureKeyHandler)

    def test_deserialize_preserves_key_material(self):
        """Test that deserialization preserves the key material."""
        original_handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_account_path()
        original_public_key = original_handler.get_account_public_key(path)

        serialized = original_handler.serialize()
        deserialized_handler = SoftwareBip32SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )
        deserialized_public_key = deserialized_handler.get_account_public_key(path)

        assert original_public_key.to_hex() == deserialized_public_key.to_hex()

    def test_deserialize_data_too_short(self):
        """Test deserializing data that is too short."""
        short_data = b"tooshort"
        with pytest.raises(ValueError, match="too short"):
            SoftwareBip32SecureKeyHandler.deserialize(
                short_data,
                get_passphrase
            )

    def test_deserialize_invalid_magic(self):
        """Test deserializing data with invalid magic number."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
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
            SoftwareBip32SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_invalid_version(self):
        """Test deserializing data with invalid version."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
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
            SoftwareBip32SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_invalid_key_type(self):
        """Test deserializing data with invalid key type."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
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
            SoftwareBip32SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_checksum_mismatch(self):
        """Test deserializing data with incorrect checksum."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized[-1] ^= 0xFF

        with pytest.raises(ValueError, match="checksum mismatch"):
            SoftwareBip32SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_deserialize_length_mismatch(self):
        """Test deserializing data with length mismatch."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = bytearray(handler.serialize())
        serialized = serialized[:-5]

        with pytest.raises(ValueError):
            SoftwareBip32SecureKeyHandler.deserialize(
                bytes(serialized),
                get_passphrase
            )

    def test_serialize_deserialize_round_trip(self):
        """Test full round-trip serialization and deserialization."""
        original_handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        serialized = original_handler.serialize()
        deserialized_handler = SoftwareBip32SecureKeyHandler.deserialize(
            serialized,
            get_passphrase
        )

        reserialized = deserialized_handler.serialize()
        assert serialized == reserialized


class TestSoftwareBip32SecureKeyHandlerAccountPublicKey:
    """Tests for getting account public keys."""

    def test_get_account_public_key_returns_valid_key(self):
        """Test that get_account_public_key returns a valid Bip32PublicKey."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_account_path()
        public_key = handler.get_account_public_key(path)
        assert public_key is not None
        assert isinstance(public_key, Bip32PublicKey)

    def test_get_account_public_key_consistent(self):
        """Test that get_account_public_key returns consistent results."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_account_path()
        public_key1 = handler.get_account_public_key(path)
        public_key2 = handler.get_account_public_key(path)
        assert public_key1.to_hex() == public_key2.to_hex()

    def test_get_account_public_key_different_accounts(self):
        """Test getting public keys for different accounts."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        path0 = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        path1 = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(1)
        )

        key0 = handler.get_account_public_key(path0)
        key1 = handler.get_account_public_key(path1)
        assert key0.to_hex() != key1.to_hex()

    def test_get_account_public_key_multisig_purpose(self):
        """Test getting account public key with multisig purpose."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.MULTISIG),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        public_key = handler.get_account_public_key(path)
        assert public_key is not None
        assert isinstance(public_key, Bip32PublicKey)

    def test_get_account_public_key_with_wrong_passphrase(self):
        """Test that get_account_public_key fails with wrong passphrase."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        path = get_account_path()
        with pytest.raises(cometa.CardanoError):
            handler.get_account_public_key(path)

    def test_get_account_public_key_invalid_path_type(self):
        """Test that get_account_public_key fails with invalid path type."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        with pytest.raises(AttributeError):
            handler.get_account_public_key("not a path")


class TestSoftwareBip32SecureKeyHandlerPrivateKey:
    """Tests for getting private keys."""

    def test_get_private_key_returns_valid_key(self):
        """Test that get_private_key returns a valid Ed25519PrivateKey."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        private_key = handler.get_private_key(path)
        assert private_key is not None
        assert isinstance(private_key, Ed25519PrivateKey)

    def test_get_private_key_consistent(self):
        """Test that get_private_key returns consistent results."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        key1 = handler.get_private_key(path)
        key2 = handler.get_private_key(path)
        assert key1.to_hex() == key2.to_hex()

    def test_get_private_key_different_paths(self):
        """Test getting private keys for different paths."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path0 = get_derivation_path(KeyDerivationRole.EXTERNAL, 0)
        path1 = get_derivation_path(KeyDerivationRole.EXTERNAL, 1)

        key0 = handler.get_private_key(path0)
        key1 = handler.get_private_key(path1)
        assert key0.to_hex() != key1.to_hex()

    def test_get_private_key_different_roles(self):
        """Test getting private keys for different roles."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        external_path = get_derivation_path(KeyDerivationRole.EXTERNAL, 0)
        internal_path = get_derivation_path(KeyDerivationRole.INTERNAL, 0)
        staking_path = get_derivation_path(KeyDerivationRole.STAKING, 0)

        external_key = handler.get_private_key(external_path)
        internal_key = handler.get_private_key(internal_path)
        staking_key = handler.get_private_key(staking_path)

        assert external_key.to_hex() != internal_key.to_hex()
        assert external_key.to_hex() != staking_key.to_hex()
        assert internal_key.to_hex() != staking_key.to_hex()

    def test_get_private_key_with_wrong_passphrase(self):
        """Test that get_private_key fails with wrong passphrase."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        path = get_derivation_path()
        with pytest.raises(cometa.CardanoError):
            handler.get_private_key(path)

    def test_get_private_key_invalid_path_type(self):
        """Test that get_private_key fails with invalid path type."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        with pytest.raises(AttributeError):
            handler.get_private_key("not a path")


class TestSoftwareBip32SecureKeyHandlerSignTransaction:
    """Tests for signing transactions."""

    def test_sign_transaction_returns_witness_set(self):
        """Test that sign_transaction returns a VkeyWitnessSet."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        paths = [get_derivation_path()]
        witnesses = handler.sign_transaction(transaction, paths)

        from cometa.witness_set.vkey_witness_set import VkeyWitnessSet
        assert isinstance(witnesses, VkeyWitnessSet)

    def test_sign_transaction_produces_one_witness(self):
        """Test that sign_transaction produces exactly one witness for one path."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        paths = [get_derivation_path()]
        witnesses = handler.sign_transaction(transaction, paths)
        assert len(witnesses) == 1

    def test_sign_transaction_multiple_paths(self):
        """Test signing transaction with multiple paths."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        paths = [
            get_derivation_path(KeyDerivationRole.EXTERNAL, 0),
            get_derivation_path(KeyDerivationRole.EXTERNAL, 1),
            get_derivation_path(KeyDerivationRole.STAKING, 0),
        ]
        witnesses = handler.sign_transaction(transaction, paths)
        assert len(witnesses) == 3

    def test_sign_transaction_deterministic(self):
        """Test that signing produces deterministic signatures."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        paths = [get_derivation_path()]

        witnesses1 = handler.sign_transaction(transaction, paths)
        witnesses2 = handler.sign_transaction(transaction, paths)

        assert witnesses1[0].signature.hex() == witnesses2[0].signature.hex()

    def test_sign_transaction_with_empty_paths(self):
        """Test that signing fails with empty derivation paths."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        with pytest.raises(ValueError, match="Derivation paths are required"):
            handler.sign_transaction(transaction, [])

    def test_sign_transaction_with_wrong_passphrase(self):
        """Test that signing fails with wrong passphrase."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        transaction = get_transaction()
        paths = [get_derivation_path()]
        with pytest.raises(cometa.CardanoError):
            handler.sign_transaction(transaction, paths)

    def test_sign_transaction_with_invalid_transaction(self):
        """Test that signing fails with invalid transaction."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        paths = [get_derivation_path()]
        with pytest.raises(AttributeError):
            handler.sign_transaction("not a transaction", paths)

    def test_sign_transaction_witness_vkey_matches_public_key(self):
        """Test that the witness vkey matches the derived public key."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        path = get_derivation_path()

        witnesses = handler.sign_transaction(transaction, [path])
        private_key = handler.get_private_key(path)
        expected_vkey = private_key.get_public_key().to_bytes()

        assert witnesses[0].vkey == expected_vkey


class TestSoftwareBip32SecureKeyHandlerSignData:
    """Tests for signing arbitrary data."""

    def test_sign_data_returns_dict(self):
        """Test that sign_data returns a dict."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result = handler.sign_data("deadbeef", path)
        assert isinstance(result, dict)

    def test_sign_data_contains_required_keys(self):
        """Test that sign_data result contains 'signature' and 'key'."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result = handler.sign_data("deadbeef", path)
        assert "signature" in result
        assert "key" in result

    def test_sign_data_key_is_correct(self):
        """Test that the public key in the result is correct."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result = handler.sign_data("deadbeef", path)

        private_key = handler.get_private_key(path)
        expected_key = private_key.get_public_key().to_hex()
        assert result["key"] == expected_key

    def test_sign_data_signature_is_hex_string(self):
        """Test that the signature is a hex string."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result = handler.sign_data("deadbeef", path)
        assert isinstance(result["signature"], str)
        assert len(result["signature"]) == 128
        bytes.fromhex(result["signature"])

    def test_sign_data_deterministic(self):
        """Test that signing the same data produces the same signature."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result1 = handler.sign_data("deadbeef", path)
        result2 = handler.sign_data("deadbeef", path)
        assert result1["signature"] == result2["signature"]

    def test_sign_data_different_data_different_signature(self):
        """Test that signing different data produces different signatures."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result1 = handler.sign_data("deadbeef", path)
        result2 = handler.sign_data("beefdead", path)
        assert result1["signature"] != result2["signature"]

    def test_sign_data_different_paths_different_signature(self):
        """Test that signing with different paths produces different signatures."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path1 = get_derivation_path(KeyDerivationRole.EXTERNAL, 0)
        path2 = get_derivation_path(KeyDerivationRole.EXTERNAL, 1)

        result1 = handler.sign_data("deadbeef", path1)
        result2 = handler.sign_data("deadbeef", path2)
        assert result1["signature"] != result2["signature"]
        assert result1["key"] != result2["key"]

    def test_sign_data_with_empty_string(self):
        """Test signing empty data."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        result = handler.sign_data("", path)
        assert "signature" in result
        assert "key" in result

    def test_sign_data_with_long_data(self):
        """Test signing long data."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        long_data = "ab" * 1000
        result = handler.sign_data(long_data, path)
        assert "signature" in result
        assert len(result["signature"]) == 128

    def test_sign_data_with_invalid_hex(self):
        """Test that signing invalid hex data raises an error."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path()
        with pytest.raises(ValueError):
            handler.sign_data("not valid hex", path)

    def test_sign_data_with_wrong_passphrase(self):
        """Test that signing fails with wrong passphrase."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        path = get_derivation_path()
        with pytest.raises(cometa.CardanoError):
            handler.sign_data("deadbeef", path)

    def test_sign_data_invalid_path_type(self):
        """Test that sign_data fails with invalid path type."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        with pytest.raises(AttributeError):
            handler.sign_data("deadbeef", "not a path")


class TestSoftwareBip32SecureKeyHandlerSecurityProperties:
    """Tests for security properties of the key handler."""

    def test_encrypted_data_is_different_from_entropy(self):
        """Test that encrypted data does not contain raw entropy."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        serialized = handler.serialize()
        entropy_hex = TEST_ENTROPY.hex().lower()
        serialized_hex = serialized.hex().lower()
        assert entropy_hex not in serialized_hex

    def test_different_passphrases_produce_different_encrypted_data(self):
        """Test that different passphrases produce different encrypted data."""
        handler1 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"password1",
            get_passphrase=lambda: b"password1"
        )

        handler2 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"password2",
            get_passphrase=lambda: b"password2"
        )

        serialized1 = handler1.serialize()
        serialized2 = handler2.serialize()

        assert serialized1 != serialized2

    def test_cannot_access_encrypted_data_directly(self):
        """Test that encrypted data is not directly accessible."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        assert not hasattr(handler, 'entropy')
        assert not hasattr(handler, 'root_key')
        assert hasattr(handler, '_encrypted_data')

    def test_wrong_passphrase_callback_prevents_key_access(self):
        """Test that wrong passphrase callback prevents all key operations."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_wrong_passphrase
        )
        path = get_account_path()
        derivation_path = get_derivation_path()

        with pytest.raises(cometa.CardanoError):
            handler.get_account_public_key(path)

        with pytest.raises(cometa.CardanoError):
            handler.get_private_key(derivation_path)

        transaction = get_transaction()
        with pytest.raises(cometa.CardanoError):
            handler.sign_transaction(transaction, [derivation_path])

        with pytest.raises(cometa.CardanoError):
            handler.sign_data("deadbeef", derivation_path)


class TestSoftwareBip32SecureKeyHandlerEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_handlers_with_same_entropy(self):
        """Test that multiple handlers can be created from the same entropy."""
        handler1 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        handler2 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        path = get_account_path()
        pub1 = handler1.get_account_public_key(path)
        pub2 = handler2.get_account_public_key(path)
        assert pub1.to_hex() == pub2.to_hex()

    def test_handler_is_reusable(self):
        """Test that a handler can be used multiple times."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_account_path()

        for _ in range(5):
            pub = handler.get_account_public_key(path)
            assert pub is not None

    def test_serialized_data_size_is_consistent(self):
        """Test that serialized data has consistent size."""
        handler1 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"short",
            get_passphrase=lambda: b"short"
        )

        handler2 = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=b"very_long_passphrase_for_testing",
            get_passphrase=lambda: b"very_long_passphrase_for_testing"
        )

        size1 = len(handler1.serialize())
        size2 = len(handler2.serialize())

        assert size1 == size2

    def test_passphrase_callback_is_called_each_time(self):
        """Test that the passphrase callback is invoked for each operation."""
        call_count = [0]
        def counting_callback():
            call_count[0] += 1
            return PASSWORD

        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=counting_callback
        )

        path = get_account_path()
        initial_count = call_count[0]
        handler.get_account_public_key(path)
        assert call_count[0] > initial_count

        prev_count = call_count[0]
        handler.get_account_public_key(path)
        assert call_count[0] > prev_count

    def test_handler_instance_attributes(self):
        """Test that handler has expected instance attributes."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        assert hasattr(handler, '_encrypted_data')
        assert hasattr(handler, '_get_passphrase')
        assert callable(handler._get_passphrase)

    def test_handler_class_constants(self):
        """Test that handler class has expected constants."""
        assert hasattr(SoftwareBip32SecureKeyHandler, '_MAGIC')
        assert hasattr(SoftwareBip32SecureKeyHandler, '_VERSION')
        assert hasattr(SoftwareBip32SecureKeyHandler, '_BIP32_KEY_HANDLER')

        assert SoftwareBip32SecureKeyHandler._MAGIC == 0x0A0A0A0A
        assert SoftwareBip32SecureKeyHandler._VERSION == 0x01
        assert SoftwareBip32SecureKeyHandler._BIP32_KEY_HANDLER == 0x01

    def test_derivation_with_all_roles(self):
        """Test that handler can derive keys for all roles."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )

        roles = [
            KeyDerivationRole.EXTERNAL,
            KeyDerivationRole.INTERNAL,
            KeyDerivationRole.STAKING,
            KeyDerivationRole.DREP,
            KeyDerivationRole.COMMITTEE_COLD,
            KeyDerivationRole.COMMITTEE_HOT,
        ]

        keys = []
        for role in roles:
            path = get_derivation_path(role, 0)
            key = handler.get_private_key(path)
            keys.append(key.to_hex())

        for i, key1 in enumerate(keys):
            for j, key2 in enumerate(keys):
                if i != j:
                    assert key1 != key2

    def test_derivation_with_large_index(self):
        """Test deriving keys with large address indices."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=TEST_ENTROPY,
            passphrase=PASSWORD,
            get_passphrase=get_passphrase
        )
        path = get_derivation_path(KeyDerivationRole.EXTERNAL, 1000000)
        key = handler.get_private_key(path)
        assert key is not None
