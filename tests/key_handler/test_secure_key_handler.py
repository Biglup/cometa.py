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
from cometa.key_handler.secure_key_handler import (
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    AccountDerivationPath,
    DerivationPath,
    Bip32SecureKeyHandler,
    Ed25519SecureKeyHandler,
)


class TestHardenFunction:
    """Tests for the harden helper function."""

    def test_harden_with_standard_cardano_purpose(self):
        """Test hardening with standard Cardano purpose (1852)."""
        result = harden(1852)
        assert result == 2147485500
        assert result == 0x80000000 + 1852

    def test_harden_with_multisig_purpose(self):
        """Test hardening with multisig purpose (1854)."""
        result = harden(1854)
        assert result == 2147485502
        assert result == 0x80000000 + 1854

    def test_harden_with_cardano_coin_type(self):
        """Test hardening with Cardano coin type (1815)."""
        result = harden(1815)
        assert result == 2147485463
        assert result == 0x80000000 + 1815

    def test_harden_with_zero(self):
        """Test hardening with zero (account 0)."""
        result = harden(0)
        assert result == 2147483648
        assert result == 0x80000000

    def test_harden_with_one(self):
        """Test hardening with one (account 1)."""
        result = harden(1)
        assert result == 2147483649
        assert result == 0x80000000 + 1

    def test_harden_with_large_number(self):
        """Test hardening with a large number."""
        result = harden(1000000)
        assert result == 2148483648
        assert result == 0x80000000 + 1000000

    def test_harden_with_max_safe_value(self):
        """Test hardening with maximum safe value before overflow."""
        max_safe = 0x7FFFFFFF
        result = harden(max_safe)
        assert result == 0xFFFFFFFF

    def test_harden_returns_int(self):
        """Test that harden returns an integer type."""
        result = harden(1852)
        assert isinstance(result, int)

    def test_harden_with_negative_number(self):
        """Test hardening with a negative number."""
        result = harden(-1)
        assert result == 0x80000000 - 1
        assert result == 2147483647


class TestCoinType:
    """Tests for CoinType enum."""

    def test_cardano_coin_type_value(self):
        """Test that CARDANO has the correct value."""
        assert CoinType.CARDANO == 1815

    def test_cardano_coin_type_is_int_enum(self):
        """Test that CoinType is an IntEnum."""
        assert isinstance(CoinType.CARDANO, int)

    def test_coin_type_member_count(self):
        """Test that CoinType has exactly one member."""
        assert len(CoinType) == 1

    def test_coin_type_member_names(self):
        """Test CoinType member names."""
        assert 'CARDANO' in CoinType.__members__

    def test_coin_type_can_be_compared_to_int(self):
        """Test that CoinType can be compared directly to integers."""
        assert CoinType.CARDANO == 1815
        assert CoinType.CARDANO != 1816

    def test_coin_type_can_be_used_in_arithmetic(self):
        """Test that CoinType can be used in arithmetic operations."""
        result = harden(CoinType.CARDANO)
        assert result == 2147485463


class TestKeyDerivationPurpose:
    """Tests for KeyDerivationPurpose enum."""

    def test_standard_purpose_value(self):
        """Test that STANDARD has the correct value."""
        assert KeyDerivationPurpose.STANDARD == 1852

    def test_multisig_purpose_value(self):
        """Test that MULTISIG has the correct value."""
        assert KeyDerivationPurpose.MULTISIG == 1854

    def test_purpose_is_int_enum(self):
        """Test that KeyDerivationPurpose is an IntEnum."""
        assert isinstance(KeyDerivationPurpose.STANDARD, int)
        assert isinstance(KeyDerivationPurpose.MULTISIG, int)

    def test_purpose_member_count(self):
        """Test that KeyDerivationPurpose has exactly two members."""
        assert len(KeyDerivationPurpose) == 2

    def test_purpose_member_names(self):
        """Test KeyDerivationPurpose member names."""
        assert 'STANDARD' in KeyDerivationPurpose.__members__
        assert 'MULTISIG' in KeyDerivationPurpose.__members__

    def test_purpose_can_be_compared(self):
        """Test that purposes can be compared."""
        assert KeyDerivationPurpose.STANDARD < KeyDerivationPurpose.MULTISIG
        assert KeyDerivationPurpose.MULTISIG > KeyDerivationPurpose.STANDARD

    def test_purpose_can_be_used_with_harden(self):
        """Test that purpose values can be hardened."""
        result = harden(KeyDerivationPurpose.STANDARD)
        assert result == 2147485500


class TestKeyDerivationRole:
    """Tests for KeyDerivationRole enum."""

    def test_external_role_value(self):
        """Test that EXTERNAL has the correct value."""
        assert KeyDerivationRole.EXTERNAL == 0

    def test_internal_role_value(self):
        """Test that INTERNAL has the correct value."""
        assert KeyDerivationRole.INTERNAL == 1

    def test_staking_role_value(self):
        """Test that STAKING has the correct value."""
        assert KeyDerivationRole.STAKING == 2

    def test_drep_role_value(self):
        """Test that DREP has the correct value."""
        assert KeyDerivationRole.DREP == 3

    def test_committee_cold_role_value(self):
        """Test that COMMITTEE_COLD has the correct value."""
        assert KeyDerivationRole.COMMITTEE_COLD == 4

    def test_committee_hot_role_value(self):
        """Test that COMMITTEE_HOT has the correct value."""
        assert KeyDerivationRole.COMMITTEE_HOT == 5

    def test_role_is_int_enum(self):
        """Test that KeyDerivationRole is an IntEnum."""
        assert isinstance(KeyDerivationRole.EXTERNAL, int)
        assert isinstance(KeyDerivationRole.STAKING, int)

    def test_role_member_count(self):
        """Test that KeyDerivationRole has exactly six members."""
        assert len(KeyDerivationRole) == 6

    def test_role_member_names(self):
        """Test KeyDerivationRole member names."""
        expected_members = [
            'EXTERNAL',
            'INTERNAL',
            'STAKING',
            'DREP',
            'COMMITTEE_COLD',
            'COMMITTEE_HOT'
        ]
        for member in expected_members:
            assert member in KeyDerivationRole.__members__

    def test_roles_are_sequential(self):
        """Test that role values are sequential from 0 to 5."""
        assert KeyDerivationRole.EXTERNAL == 0
        assert KeyDerivationRole.INTERNAL == 1
        assert KeyDerivationRole.STAKING == 2
        assert KeyDerivationRole.DREP == 3
        assert KeyDerivationRole.COMMITTEE_COLD == 4
        assert KeyDerivationRole.COMMITTEE_HOT == 5


class TestAccountDerivationPath:
    """Tests for AccountDerivationPath dataclass."""

    def test_create_account_derivation_path(self):
        """Test creating an AccountDerivationPath."""
        path = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        assert path.purpose == harden(1852)
        assert path.coin_type == harden(1815)
        assert path.account == harden(0)

    def test_account_derivation_path_with_standard_values(self):
        """Test creating path with standard Cardano values."""
        path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        assert path.purpose == 2147485500
        assert path.coin_type == 2147485463
        assert path.account == 2147483648

    def test_account_derivation_path_with_different_accounts(self):
        """Test creating paths for different account indices."""
        path0 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        path1 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(1)
        )
        assert path0.account == harden(0)
        assert path1.account == harden(1)
        assert path0.account != path1.account

    def test_account_derivation_path_equality(self):
        """Test equality of AccountDerivationPath instances."""
        path1 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        path2 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        assert path1 == path2

    def test_account_derivation_path_inequality(self):
        """Test inequality of AccountDerivationPath instances."""
        path1 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        path2 = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(1)
        )
        assert path1 != path2

    def test_account_derivation_path_with_multisig(self):
        """Test creating path with multisig purpose."""
        path = AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.MULTISIG),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
        assert path.purpose == harden(1854)

    def test_account_derivation_path_attributes_accessible(self):
        """Test that all attributes are accessible."""
        path = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(5)
        )
        assert hasattr(path, 'purpose')
        assert hasattr(path, 'coin_type')
        assert hasattr(path, 'account')

    def test_account_derivation_path_is_dataclass(self):
        """Test that AccountDerivationPath is a dataclass."""
        path = AccountDerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0)
        )
        assert hasattr(path, '__dataclass_fields__')


class TestDerivationPath:
    """Tests for DerivationPath dataclass."""

    def test_create_derivation_path(self):
        """Test creating a DerivationPath."""
        path = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        assert path.purpose == harden(1852)
        assert path.coin_type == harden(1815)
        assert path.account == harden(0)
        assert path.role == KeyDerivationRole.EXTERNAL
        assert path.index == 0

    def test_derivation_path_inherits_from_account_path(self):
        """Test that DerivationPath inherits from AccountDerivationPath."""
        path = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        assert isinstance(path, AccountDerivationPath)
        assert isinstance(path, DerivationPath)

    def test_derivation_path_external_address(self):
        """Test creating a derivation path for external address."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        assert path.role == KeyDerivationRole.EXTERNAL
        assert path.index == 0

    def test_derivation_path_internal_address(self):
        """Test creating a derivation path for change/internal address."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.INTERNAL,
            index=0
        )
        assert path.role == KeyDerivationRole.INTERNAL

    def test_derivation_path_staking_key(self):
        """Test creating a derivation path for staking key."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.STAKING,
            index=0
        )
        assert path.role == KeyDerivationRole.STAKING

    def test_derivation_path_drep_key(self):
        """Test creating a derivation path for DRep key."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.DREP,
            index=0
        )
        assert path.role == KeyDerivationRole.DREP

    def test_derivation_path_committee_cold_key(self):
        """Test creating a derivation path for committee cold key."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.COMMITTEE_COLD,
            index=0
        )
        assert path.role == KeyDerivationRole.COMMITTEE_COLD

    def test_derivation_path_committee_hot_key(self):
        """Test creating a derivation path for committee hot key."""
        path = DerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0),
            role=KeyDerivationRole.COMMITTEE_HOT,
            index=0
        )
        assert path.role == KeyDerivationRole.COMMITTEE_HOT

    def test_derivation_path_with_different_indices(self):
        """Test creating paths with different address indices."""
        path0 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        path1 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=1
        )
        assert path0.index == 0
        assert path1.index == 1
        assert path0.index != path1.index

    def test_derivation_path_equality(self):
        """Test equality of DerivationPath instances."""
        path1 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        path2 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        assert path1 == path2

    def test_derivation_path_inequality_by_role(self):
        """Test inequality of DerivationPath instances with different roles."""
        path1 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        path2 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.INTERNAL,
            index=0
        )
        assert path1 != path2

    def test_derivation_path_inequality_by_index(self):
        """Test inequality of DerivationPath instances with different indices."""
        path1 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        path2 = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=1
        )
        assert path1 != path2

    def test_derivation_path_has_all_attributes(self):
        """Test that DerivationPath has all expected attributes."""
        path = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=10
        )
        assert hasattr(path, 'purpose')
        assert hasattr(path, 'coin_type')
        assert hasattr(path, 'account')
        assert hasattr(path, 'role')
        assert hasattr(path, 'index')

    def test_derivation_path_is_dataclass(self):
        """Test that DerivationPath is a dataclass."""
        path = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=0
        )
        assert hasattr(path, '__dataclass_fields__')

    def test_derivation_path_with_large_index(self):
        """Test creating a path with a large address index."""
        path = DerivationPath(
            purpose=harden(1852),
            coin_type=harden(1815),
            account=harden(0),
            role=KeyDerivationRole.EXTERNAL,
            index=1000000
        )
        assert path.index == 1000000


class TestBip32SecureKeyHandler:
    """Tests for Bip32SecureKeyHandler abstract base class."""

    def test_cannot_instantiate_directly(self):
        """Test that Bip32SecureKeyHandler cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Bip32SecureKeyHandler()

    def test_has_sign_transaction_method(self):
        """Test that the ABC has sign_transaction as abstract method."""
        assert hasattr(Bip32SecureKeyHandler, 'sign_transaction')
        assert getattr(Bip32SecureKeyHandler.sign_transaction, '__isabstractmethod__', False)

    def test_has_sign_data_method(self):
        """Test that the ABC has sign_data as abstract method."""
        assert hasattr(Bip32SecureKeyHandler, 'sign_data')
        assert getattr(Bip32SecureKeyHandler.sign_data, '__isabstractmethod__', False)

    def test_has_get_private_key_method(self):
        """Test that the ABC has get_private_key as abstract method."""
        assert hasattr(Bip32SecureKeyHandler, 'get_private_key')
        assert getattr(Bip32SecureKeyHandler.get_private_key, '__isabstractmethod__', False)

    def test_has_get_account_public_key_method(self):
        """Test that the ABC has get_account_public_key as abstract method."""
        assert hasattr(Bip32SecureKeyHandler, 'get_account_public_key')
        assert getattr(
            Bip32SecureKeyHandler.get_account_public_key,
            '__isabstractmethod__',
            False
        )

    def test_has_serialize_method(self):
        """Test that the ABC has serialize as abstract method."""
        assert hasattr(Bip32SecureKeyHandler, 'serialize')
        assert getattr(Bip32SecureKeyHandler.serialize, '__isabstractmethod__', False)

    def test_subclass_must_implement_all_methods(self):
        """Test that a subclass must implement all abstract methods."""
        class IncompleteHandler(Bip32SecureKeyHandler):
            pass

        with pytest.raises(TypeError):
            IncompleteHandler()

    def test_subclass_with_all_methods_can_be_instantiated(self):
        """Test that a complete subclass can be instantiated."""
        class CompleteHandler(Bip32SecureKeyHandler):
            def sign_transaction(self, transaction, derivation_paths):
                return None

            def sign_data(self, data, derivation_path):
                return {"signature": "", "key": ""}

            def get_private_key(self, derivation_path):
                return None

            def get_account_public_key(self, path):
                return None

            def serialize(self):
                return b""

        handler = CompleteHandler()
        assert isinstance(handler, Bip32SecureKeyHandler)


class TestEd25519SecureKeyHandler:
    """Tests for Ed25519SecureKeyHandler abstract base class."""

    def test_cannot_instantiate_directly(self):
        """Test that Ed25519SecureKeyHandler cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Ed25519SecureKeyHandler()

    def test_has_sign_transaction_method(self):
        """Test that the ABC has sign_transaction as abstract method."""
        assert hasattr(Ed25519SecureKeyHandler, 'sign_transaction')
        assert getattr(Ed25519SecureKeyHandler.sign_transaction, '__isabstractmethod__', False)

    def test_has_sign_data_method(self):
        """Test that the ABC has sign_data as abstract method."""
        assert hasattr(Ed25519SecureKeyHandler, 'sign_data')
        assert getattr(Ed25519SecureKeyHandler.sign_data, '__isabstractmethod__', False)

    def test_has_get_private_key_method(self):
        """Test that the ABC has get_private_key as abstract method."""
        assert hasattr(Ed25519SecureKeyHandler, 'get_private_key')
        assert getattr(Ed25519SecureKeyHandler.get_private_key, '__isabstractmethod__', False)

    def test_has_get_public_key_method(self):
        """Test that the ABC has get_public_key as abstract method."""
        assert hasattr(Ed25519SecureKeyHandler, 'get_public_key')
        assert getattr(Ed25519SecureKeyHandler.get_public_key, '__isabstractmethod__', False)

    def test_has_serialize_method(self):
        """Test that the ABC has serialize as abstract method."""
        assert hasattr(Ed25519SecureKeyHandler, 'serialize')
        assert getattr(Ed25519SecureKeyHandler.serialize, '__isabstractmethod__', False)

    def test_subclass_must_implement_all_methods(self):
        """Test that a subclass must implement all abstract methods."""
        class IncompleteHandler(Ed25519SecureKeyHandler):
            pass

        with pytest.raises(TypeError):
            IncompleteHandler()

    def test_subclass_with_all_methods_can_be_instantiated(self):
        """Test that a complete subclass can be instantiated."""
        class CompleteHandler(Ed25519SecureKeyHandler):
            def sign_transaction(self, transaction):
                return None

            def sign_data(self, data):
                return {"signature": "", "key": ""}

            def get_private_key(self):
                return None

            def get_public_key(self):
                return None

            def serialize(self):
                return b""

        handler = CompleteHandler()
        assert isinstance(handler, Ed25519SecureKeyHandler)
