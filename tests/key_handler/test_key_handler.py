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
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    AccountDerivationPath,
    DerivationPath,
    SoftwareBip32SecureKeyHandler,
    SoftwareEd25519SecureKeyHandler,
    Transaction,
    CborReader,
)


# Test vectors
PASSWORD = b"password"
WRONG_PASSWORD = b"wrong-password"
ENTROPY_BYTES = bytes.fromhex(
    "387183ffe785d467ab662c01acbcf79400e2430dde6c9aee74cf0602de0d82e8"
)
ED25519_PRIVATE_KEY_HEX = (
    "f04462421183d227bbc0fa60799ef338169c05eed7aa6aac19bc4db20557df51"
    "e154255decce80ae4ab8a61af6abde05e7fbc049861cc040a7afe4fb0a875899"
)
ED25519_PUBLIC_KEY_HEX = "07473467683e6a30a13d471a68641f311a14e2b37a38ea592e5d6efc2b446bce"
EXTENDED_ACCOUNT_0_PUB_KEY = (
    "1b39889a420374e41917cf420d88a84d9b40d7eeef533ac37f323076c5f7106a"
    "15ef170481a5c4333be2b4cf498525512ac4a3427e1a0e9c9f42cfcb42ba6deb"
)
TX_CBOR = (
    "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b000b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b582088e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a10481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c71213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799fd8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9fd8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980fffff5f6"
)
LIBCARDANO_C_SERIALIZED_BIP32_KEY_HANDLER = (
    "0a0a0a0a01010000005c97db5e09b3a4919ec75ed1126056241a1e5278731c2e0b"
    "01bea0a5f42c22db4131e0a4bbe75633677eb0e60e2ecd3520178f85c7e0d4be77"
    "a449087fe9674ee52f946b07c1b56d228c496ec0d36dd44212ba8af0f6eed1a821"
    "94dd69f479c603"
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


class TestSoftwareBip32SecureKeyHandler:
    """Tests for SoftwareBip32SecureKeyHandler."""

    def test_can_be_created_from_entropy_and_derive_public_key(self):
        """Test creating handler from entropy and deriving a public key."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=bytes(ENTROPY_BYTES),
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )

        account_path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )

        public_key = handler.get_account_public_key(account_path)
        assert public_key.to_hex() == EXTENDED_ACCOUNT_0_PUB_KEY

    def test_can_sign_a_transaction(self):
        """Test signing a transaction."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=bytes(ENTROPY_BYTES),
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )

        derivation_paths = [
            DerivationPath(
                purpose=harden(KeyDerivationPurpose.STANDARD),
                coin_type=harden(CoinType.CARDANO),
                account=harden(0),
                role=KeyDerivationRole.EXTERNAL,
                index=0
            ),
            DerivationPath(
                purpose=harden(KeyDerivationPurpose.STANDARD),
                coin_type=harden(CoinType.CARDANO),
                account=harden(0),
                role=KeyDerivationRole.STAKING,
                index=0
            )
        ]

        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction, derivation_paths)
        assert len(witnesses) == 2
        assert witnesses[0].vkey.hex() == "07473467683e6a30a13d471a68641f311a14e2b37a38ea592e5d6efc2b446bce"
        assert witnesses[0].signature.hex() == (
            "5f9f725da55e2a89e725f2c147512c0508956aae6a99cb2f3150c73c812c7373"
            "f57311dcee14cb02ad1ab7b1940aecc5bbf0769a9b77aafb996393b08d48830b"
        )
        assert witnesses[1].vkey.hex() == "48f090d48246134d6307267451fcefbe4cd9df1530b9ac9a267e3e8cf28b6c61"
        assert witnesses[1].signature.hex() == (
            "9219b195082d71a1b6b9109862a6a053dc8b5342d3a31cc9067330c8f83824a9"
            "2803a5fe39087fb8c73c746c6e278e98be24b1ddc0c1408c7d5a02776a7e3f07"
        )

    def test_can_be_serialized_and_deserialized_correctly(self):
        """Test serialization and deserialization."""
        original_handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=bytes(ENTROPY_BYTES),
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )
        serialized_data = original_handler.serialize()
        deserialized_handler = SoftwareBip32SecureKeyHandler.deserialize(
            serialized_data, get_passphrase
        )

        account_path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        public_key = deserialized_handler.get_account_public_key(account_path)
        assert public_key.to_hex() == EXTENDED_ACCOUNT_0_PUB_KEY

    def test_can_be_created_from_serialized_data_from_libcardano_c(self):
        """Test deserializing data created by libcardano-c."""
        handler = SoftwareBip32SecureKeyHandler.deserialize(
            bytes.fromhex(LIBCARDANO_C_SERIALIZED_BIP32_KEY_HANDLER),
            get_passphrase
        )

        account_path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        public_key = handler.get_account_public_key(account_path)
        assert public_key.to_hex() == EXTENDED_ACCOUNT_0_PUB_KEY

    def test_fails_to_decrypt_with_wrong_passphrase(self):
        """Test that decryption fails with wrong passphrase."""
        handler = SoftwareBip32SecureKeyHandler.from_entropy(
            entropy=bytes(ENTROPY_BYTES),
            passphrase=bytes(PASSWORD),
            get_passphrase=get_wrong_passphrase
        )

        account_path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        with pytest.raises(cometa.CardanoError):
            handler.get_account_public_key(account_path)


class TestSoftwareEd25519SecureKeyHandler:
    """Tests for SoftwareEd25519SecureKeyHandler."""

    def test_can_be_created_from_ed25519_key_and_get_public_key(self):
        """Test creating handler from Ed25519 key and getting public key."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )

        public_key = handler.get_public_key()
        assert public_key.to_hex() == ED25519_PUBLIC_KEY_HEX

    def test_can_sign_a_transaction(self):
        """Test signing a transaction."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )
        transaction = get_transaction()
        witnesses = handler.sign_transaction(transaction)

        assert len(witnesses) == 1
        assert witnesses[0].vkey.hex() == ED25519_PUBLIC_KEY_HEX
        assert witnesses[0].signature.hex() == (
            "5f9f725da55e2a89e725f2c147512c0508956aae6a99cb2f3150c73c812c7373"
            "f57311dcee14cb02ad1ab7b1940aecc5bbf0769a9b77aafb996393b08d48830b"
        )

    def test_can_be_serialized_and_deserialized_correctly(self):
        """Test serialization and deserialization."""
        private_key = Ed25519PrivateKey.from_extended_hex(ED25519_PRIVATE_KEY_HEX)
        original_handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
            private_key=private_key,
            passphrase=bytes(PASSWORD),
            get_passphrase=get_passphrase
        )

        serialized_data = original_handler.serialize()
        deserialized_handler = SoftwareEd25519SecureKeyHandler.deserialize(
            serialized_data, get_passphrase
        )

        public_key = deserialized_handler.get_public_key()
        assert public_key.to_hex() == ED25519_PUBLIC_KEY_HEX


class TestHardenFunction:
    """Tests for the harden helper function."""

    def test_harden_function(self):
        """Test that harden correctly hardens indices."""
        assert harden(1852) == 0x80_00_00_00 + 1852
        assert harden(1815) == 0x80_00_00_00 + 1815
        assert harden(0) == 0x80_00_00_00


class TestEnums:
    """Tests for enum values."""

    def test_coin_type(self):
        """Test CoinType enum values."""
        assert CoinType.CARDANO == 1815

    def test_key_derivation_purpose(self):
        """Test KeyDerivationPurpose enum values."""
        assert KeyDerivationPurpose.STANDARD == 1852
        assert KeyDerivationPurpose.MULTISIG == 1854

    def test_key_derivation_role(self):
        """Test KeyDerivationRole enum values."""
        assert KeyDerivationRole.EXTERNAL == 0
        assert KeyDerivationRole.INTERNAL == 1
        assert KeyDerivationRole.STAKING == 2
        assert KeyDerivationRole.DREP == 3
        assert KeyDerivationRole.COMMITTEE_COLD == 4
        assert KeyDerivationRole.COMMITTEE_HOT == 5
