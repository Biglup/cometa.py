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
    StakeVoteRegistrationDelegationCert,
    Credential,
    CredentialType,
    DRep,
    DRepType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "850d8200581c00000000000000000000000000000000000000000000000000000000581c000000000000000000000000000000000000000000000000000000008200581c0000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
DREP_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
POOL_KEY_HASH = "00000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HEX = "00000000000000000000000000000000000000000000000000000000"
DREP_KEY_HASH = "00000000000000000000000000000000000000000000000000000000"


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_drep():
    """Creates a default DRep for testing."""
    reader = CborReader.from_hex(DREP_CBOR)
    return DRep.from_cbor(reader)


def new_default_cert():
    """Creates a default stake vote registration delegation certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return StakeVoteRegistrationDelegationCert.from_cbor(reader)


class TestStakeVoteRegistrationDelegationCertNew:
    """Tests for StakeVoteRegistrationDelegationCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new stake vote registration delegation certificate."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0
        assert cert.drep is not None
        assert cert.pool_key_hash is not None

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.credential.type == CredentialType.KEY_HASH

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_key_hash_drep(self):
        """Test creating certificate with key hash DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        hash_value = Blake2bHash.from_hex(DREP_KEY_HASH)
        drep_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        drep = DRep.new(DRepType.KEY_HASH, drep_cred)
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.drep.drep_type == DRepType.KEY_HASH

    def test_new_with_script_hash_drep(self):
        """Test creating certificate with script hash DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        hash_value = Blake2bHash.from_hex(DREP_KEY_HASH)
        drep_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, drep_cred)
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.drep.drep_type == DRepType.SCRIPT_HASH

    def test_new_with_abstain_drep(self):
        """Test creating certificate with abstain DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = DRep.abstain()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.drep.drep_type == DRepType.ABSTAIN

    def test_new_with_no_confidence_drep(self):
        """Test creating certificate with no confidence DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = DRep.no_confidence()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        assert cert is not None
        assert cert.drep.drep_type == DRepType.NO_CONFIDENCE

    def test_new_with_positive_deposit(self):
        """Test creating certificate with positive deposit."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        deposit = 2000000
        cert = StakeVoteRegistrationDelegationCert.new(credential, deposit, drep, pool_key_hash)

        assert cert is not None
        assert cert.deposit == deposit

    def test_new_with_large_deposit(self):
        """Test creating certificate with large deposit value."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        deposit = 1000000000000
        cert = StakeVoteRegistrationDelegationCert.new(credential, deposit, drep, pool_key_hash)

        assert cert is not None
        assert cert.deposit == deposit

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        with pytest.raises((CardanoError, AttributeError)):
            StakeVoteRegistrationDelegationCert.new(None, 0, drep, pool_key_hash)

    def test_new_with_none_drep_raises_error(self):
        """Test that creating with None DRep raises error."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        with pytest.raises((CardanoError, AttributeError)):
            StakeVoteRegistrationDelegationCert.new(credential, 0, None, pool_key_hash)

    def test_new_with_none_pool_key_hash_raises_error(self):
        """Test that creating with None pool key hash raises error."""
        credential = new_default_credential()
        drep = new_default_drep()
        with pytest.raises((CardanoError, AttributeError)):
            StakeVoteRegistrationDelegationCert.new(credential, 0, drep, None)

    def test_new_with_all_none_raises_error(self):
        """Test that creating with all None raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            StakeVoteRegistrationDelegationCert.new(None, 0, None, None)

    def test_new_with_invalid_credential_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        with pytest.raises(AttributeError):
            StakeVoteRegistrationDelegationCert.new("not a credential", 0, drep, pool_key_hash)

    def test_new_with_invalid_drep_type_raises_error(self):
        """Test that creating with invalid DRep type raises error."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        with pytest.raises(AttributeError):
            StakeVoteRegistrationDelegationCert.new(credential, 0, "not a drep", pool_key_hash)

    def test_new_with_invalid_pool_key_hash_type_raises_error(self):
        """Test that creating with invalid pool key hash type raises error."""
        credential = new_default_credential()
        drep = new_default_drep()
        with pytest.raises(AttributeError):
            StakeVoteRegistrationDelegationCert.new(credential, 0, drep, "not a hash")


class TestStakeVoteRegistrationDelegationCertFromCbor:
    """Tests for StakeVoteRegistrationDelegationCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0
        assert cert.drep is not None
        assert cert.pool_key_hash is not None

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert.credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_deposit_matches_expected(self):
        """Test that deserialized deposit matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert.deposit == 0

    def test_from_cbor_pool_key_hash_matches_expected(self):
        """Test that deserialized pool key hash matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert.pool_key_hash.to_hex() == POOL_KEY_HASH

    def test_from_cbor_drep_matches_expected(self):
        """Test that deserialized DRep matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert.drep.drep_type == DRepType.KEY_HASH
        assert cert.drep.credential.hash_hex == DREP_KEY_HASH

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            StakeVoteRegistrationDelegationCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("85ef")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("850def00581c00000000000000000000000000000000000000000000000000000000581c000000000000000000000000000000000000000000000000000000008200581c0000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_pool_hash_raises_error(self):
        """Test that invalid pool hash in CBOR raises error."""
        reader = CborReader.from_hex("850d8200581c00000000000000000000000000000000000000000000000000000000ef1c000000000000000000000000000000000000000000000000000000008200581c0000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_drep_raises_error(self):
        """Test that invalid DRep in CBOR raises error."""
        reader = CborReader.from_hex("850d8200581c00000000000000000000000000000000000000000000000000000000581c00000000000000000000000000000000000000000000000000000000ef00581c0000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_deposit_raises_error(self):
        """Test that invalid deposit in CBOR raises error."""
        reader = CborReader.from_hex("850d8200581c00000000000000000000000000000000000000000000000000000000581c000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000ef")
        with pytest.raises(CardanoError):
            StakeVoteRegistrationDelegationCert.from_cbor(reader)


class TestStakeVoteRegistrationDelegationCertToCbor:
    """Tests for StakeVoteRegistrationDelegationCert.to_cbor() method."""

    def test_to_cbor_serializes_certificate(self):
        """Test serializing a certificate to CBOR."""
        cert = new_default_cert()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR

    def test_to_cbor_roundtrip(self):
        """Test that serialization and deserialization produce same result."""
        cert1 = new_default_cert()
        writer = CborWriter()
        cert1.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.deposit == cert2.deposit
        assert cert1.drep.drep_type == cert2.drep.drep_type
        assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.to_cbor(None)


class TestStakeVoteRegistrationDelegationCertCredentialProperty:
    """Tests for StakeVoteRegistrationDelegationCert.credential property."""

    def test_get_credential_returns_credential(self):
        """Test getting the credential from certificate."""
        cert = new_default_cert()
        credential = cert.credential

        assert credential is not None
        assert credential.hash_hex == CREDENTIAL_HEX

    def test_get_credential_type_matches_expected(self):
        """Test that credential type matches expected."""
        cert = new_default_cert()
        credential = cert.credential

        assert credential.type == CredentialType.KEY_HASH

    def test_set_credential_updates_credential(self):
        """Test setting a new credential."""
        cert = new_default_cert()
        new_cred = new_default_credential()

        cert.credential = new_cred
        retrieved = cert.credential

        assert retrieved.hash_hex == CREDENTIAL_HEX

    def test_set_credential_with_different_credential(self):
        """Test setting credential to different value."""
        cert = new_default_cert()
        hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)

        cert.credential = new_cred
        retrieved = cert.credential

        assert retrieved.hash_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    def test_set_credential_with_script_hash(self):
        """Test setting credential to script hash type."""
        cert = new_default_cert()
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        new_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)

        cert.credential = new_cred
        retrieved = cert.credential

        assert retrieved.type == CredentialType.SCRIPT_HASH

    def test_set_credential_with_none_raises_error(self):
        """Test that setting None credential raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.credential = None

    def test_set_credential_with_invalid_type_raises_error(self):
        """Test that setting invalid credential type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.credential = "not a credential"


class TestStakeVoteRegistrationDelegationCertDepositProperty:
    """Tests for StakeVoteRegistrationDelegationCert.deposit property."""

    def test_get_deposit_returns_deposit(self):
        """Test getting the deposit from certificate."""
        cert = new_default_cert()
        deposit = cert.deposit

        assert deposit == 0

    def test_set_deposit_updates_deposit(self):
        """Test setting a new deposit value."""
        cert = new_default_cert()
        cert.deposit = 100

        assert cert.deposit == 100

    def test_set_deposit_with_different_value(self):
        """Test setting deposit to different value."""
        cert = new_default_cert()
        cert.deposit = 2000000

        assert cert.deposit == 2000000

    def test_set_deposit_with_large_value(self):
        """Test setting deposit to large value."""
        cert = new_default_cert()
        large_deposit = 1000000000000
        cert.deposit = large_deposit

        assert cert.deposit == large_deposit

    def test_set_deposit_to_zero(self):
        """Test setting deposit back to zero."""
        cert = new_default_cert()
        cert.deposit = 1000000
        cert.deposit = 0

        assert cert.deposit == 0

    def test_multiple_deposit_changes(self):
        """Test multiple sequential deposit changes."""
        cert = new_default_cert()

        cert.deposit = 100
        assert cert.deposit == 100

        cert.deposit = 200
        assert cert.deposit == 200

        cert.deposit = 300
        assert cert.deposit == 300


class TestStakeVoteRegistrationDelegationCertDRepProperty:
    """Tests for StakeVoteRegistrationDelegationCert.drep property."""

    def test_get_drep_returns_drep(self):
        """Test getting the DRep from certificate."""
        cert = new_default_cert()
        drep = cert.drep

        assert drep is not None
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential.hash_hex == DREP_KEY_HASH

    def test_set_drep_updates_drep(self):
        """Test setting a new DRep."""
        cert = new_default_cert()
        new_drep = new_default_drep()

        cert.drep = new_drep
        retrieved = cert.drep

        assert retrieved.drep_type == DRepType.KEY_HASH
        assert retrieved.credential.hash_hex == DREP_KEY_HASH

    def test_set_drep_with_different_hash(self):
        """Test setting DRep to different hash value."""
        cert = new_default_cert()
        hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        drep_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        new_drep = DRep.new(DRepType.KEY_HASH, drep_cred)

        cert.drep = new_drep
        retrieved = cert.drep

        assert retrieved.credential.hash_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    def test_set_drep_with_script_hash(self):
        """Test setting DRep to script hash type."""
        cert = new_default_cert()
        hash_value = Blake2bHash.from_hex(DREP_KEY_HASH)
        drep_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        new_drep = DRep.new(DRepType.SCRIPT_HASH, drep_cred)

        cert.drep = new_drep
        retrieved = cert.drep

        assert retrieved.drep_type == DRepType.SCRIPT_HASH

    def test_set_drep_with_abstain(self):
        """Test setting DRep to abstain."""
        cert = new_default_cert()
        new_drep = DRep.abstain()

        cert.drep = new_drep
        retrieved = cert.drep

        assert retrieved.drep_type == DRepType.ABSTAIN

    def test_set_drep_with_no_confidence(self):
        """Test setting DRep to no confidence."""
        cert = new_default_cert()
        new_drep = DRep.no_confidence()

        cert.drep = new_drep
        retrieved = cert.drep

        assert retrieved.drep_type == DRepType.NO_CONFIDENCE

    def test_set_drep_with_none_raises_error(self):
        """Test that setting None DRep raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.drep = None

    def test_set_drep_with_invalid_type_raises_error(self):
        """Test that setting invalid DRep type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.drep = "not a drep"


class TestStakeVoteRegistrationDelegationCertPoolKeyHashProperty:
    """Tests for StakeVoteRegistrationDelegationCert.pool_key_hash property."""

    def test_get_pool_key_hash_returns_hash(self):
        """Test getting the pool key hash from certificate."""
        cert = new_default_cert()
        pool_key_hash = cert.pool_key_hash

        assert pool_key_hash is not None
        assert pool_key_hash.to_hex() == POOL_KEY_HASH

    def test_set_pool_key_hash_updates_hash(self):
        """Test setting a new pool key hash."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex(POOL_KEY_HASH)

        cert.pool_key_hash = new_hash
        retrieved = cert.pool_key_hash

        assert retrieved.to_hex() == POOL_KEY_HASH

    def test_set_pool_key_hash_with_different_hash(self):
        """Test setting pool key hash to different value."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffff")

        cert.pool_key_hash = new_hash
        retrieved = cert.pool_key_hash

        assert retrieved.to_hex() == "ffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    def test_set_pool_key_hash_with_none_raises_error(self):
        """Test that setting None pool key hash raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.pool_key_hash = None

    def test_set_pool_key_hash_with_invalid_type_raises_error(self):
        """Test that setting invalid pool key hash type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.pool_key_hash = "not a hash"


class TestStakeVoteRegistrationDelegationCertToCip116Json:
    """Tests for StakeVoteRegistrationDelegationCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_correctly(self):
        """Test serializing certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"stake_vote_registration_delegation","credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"pool_keyhash":"pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8a7a2d","drep":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"coin":"0"}'
        assert result == expected

    def test_to_cip116_json_includes_tag(self):
        """Test that JSON includes 'stake_vote_registration_delegation' tag."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"stake_vote_registration_delegation"' in result

    def test_to_cip116_json_includes_credential(self):
        """Test that JSON includes credential object."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"credential"' in result
        assert CREDENTIAL_HEX in result

    def test_to_cip116_json_includes_pool_keyhash(self):
        """Test that JSON includes pool_keyhash field."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"pool_keyhash"' in result

    def test_to_cip116_json_includes_drep(self):
        """Test that JSON includes drep field."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"drep"' in result
        assert DREP_KEY_HASH in result

    def test_to_cip116_json_includes_coin(self):
        """Test that JSON includes coin (deposit) field."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"coin":"0"' in result

    def test_to_cip116_json_with_script_hash_credential(self):
        """Test JSON serialization with script hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"script_hash"' in result

    def test_to_cip116_json_with_script_hash_drep(self):
        """Test JSON serialization with script hash DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        hash_value = Blake2bHash.from_hex(DREP_KEY_HASH)
        drep_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, drep_cred)
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"script_hash"' in result

    def test_to_cip116_json_with_abstain_drep(self):
        """Test JSON serialization with abstain DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = DRep.abstain()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"always_abstain"' in result

    def test_to_cip116_json_with_no_confidence_drep(self):
        """Test JSON serialization with no confidence DRep."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = DRep.no_confidence()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"always_no_confidence"' in result

    def test_to_cip116_json_with_positive_deposit(self):
        """Test JSON serialization with positive deposit."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        cert = StakeVoteRegistrationDelegationCert.new(credential, 2000000, drep, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"coin":"2000000"' in result

    def test_to_cip116_json_with_none_writer_raises_error(self):
        """Test that None writer raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, TypeError)):
            cert.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that invalid writer type raises error."""
        cert = new_default_cert()
        with pytest.raises(TypeError):
            cert.to_cip116_json("not a writer")


class TestStakeVoteRegistrationDelegationCertLifecycle:
    """Tests for certificate lifecycle management."""

    def test_certificate_can_be_created_and_destroyed(self):
        """Test that certificate can be properly managed."""
        cert = new_default_cert()
        assert cert is not None
        del cert

    def test_context_manager_support(self):
        """Test using certificate as context manager."""
        with new_default_cert() as cert:
            assert cert is not None
            assert cert.credential is not None
            assert cert.deposit == 0
            assert cert.drep is not None
            assert cert.pool_key_hash is not None

    def test_repr_returns_string(self):
        """Test that repr returns a string representation."""
        cert = new_default_cert()
        result = repr(cert)

        assert isinstance(result, str)
        assert "StakeVoteRegistrationDelegationCert" in result
        assert "deposit=" in result


class TestStakeVoteRegistrationDelegationCertEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_get_credential_calls(self):
        """Test that multiple credential retrievals work correctly."""
        cert = new_default_cert()
        cred1 = cert.credential
        cred2 = cert.credential

        assert cred1.hash_hex == cred2.hash_hex

    def test_multiple_get_deposit_calls(self):
        """Test that multiple deposit retrievals work correctly."""
        cert = new_default_cert()
        deposit1 = cert.deposit
        deposit2 = cert.deposit

        assert deposit1 == deposit2

    def test_multiple_get_drep_calls(self):
        """Test that multiple DRep retrievals work correctly."""
        cert = new_default_cert()
        drep1 = cert.drep
        drep2 = cert.drep

        assert drep1.drep_type == drep2.drep_type

    def test_multiple_get_pool_key_hash_calls(self):
        """Test that multiple pool key hash retrievals work correctly."""
        cert = new_default_cert()
        hash1 = cert.pool_key_hash
        hash2 = cert.pool_key_hash

        assert hash1.to_hex() == hash2.to_hex()

    def test_set_then_get_credential(self):
        """Test setting and getting credential in sequence."""
        cert = new_default_cert()
        original_hex = cert.credential.hash_hex

        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(new_hash, CredentialType.KEY_HASH)
        cert.credential = new_cred

        retrieved = cert.credential
        assert retrieved.hash_hex != original_hex
        assert retrieved.hash_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    def test_set_then_get_deposit(self):
        """Test setting and getting deposit in sequence."""
        cert = new_default_cert()
        original_deposit = cert.deposit

        cert.deposit = 2000000
        retrieved = cert.deposit

        assert retrieved != original_deposit
        assert retrieved == 2000000

    def test_set_then_get_drep(self):
        """Test setting and getting DRep in sequence."""
        cert = new_default_cert()
        original_type = cert.drep.drep_type

        new_drep = DRep.abstain()
        cert.drep = new_drep

        retrieved = cert.drep
        assert retrieved.drep_type == DRepType.ABSTAIN
        assert retrieved.drep_type != original_type or original_type == DRepType.ABSTAIN

    def test_set_then_get_pool_key_hash(self):
        """Test setting and getting pool key hash in sequence."""
        cert = new_default_cert()
        original_hex = cert.pool_key_hash.to_hex()

        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        cert.pool_key_hash = new_hash

        retrieved = cert.pool_key_hash
        assert retrieved.to_hex() != original_hex
        assert retrieved.to_hex() == "ffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    def test_serialize_after_credential_change(self):
        """Test serialization after changing credential."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(new_hash, CredentialType.KEY_HASH)
        cert.credential = new_cred

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR

    def test_serialize_after_deposit_change(self):
        """Test serialization after changing deposit."""
        cert = new_default_cert()
        cert.deposit = 2000000

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR

    def test_serialize_after_drep_change(self):
        """Test serialization after changing DRep."""
        cert = new_default_cert()
        new_drep = DRep.abstain()
        cert.drep = new_drep

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR

    def test_serialize_after_pool_key_hash_change(self):
        """Test serialization after changing pool key hash."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        cert.pool_key_hash = new_hash

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR

    def test_roundtrip_with_different_credentials(self):
        """Test roundtrip with different credential types."""
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        for cred_type in [CredentialType.KEY_HASH, CredentialType.SCRIPT_HASH]:
            hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
            credential = Credential.from_hash(hash_value, cred_type)
            cert1 = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

            assert cert1.credential.type == cert2.credential.type
            assert cert1.credential.hash_hex == cert2.credential.hash_hex

    def test_roundtrip_with_different_deposits(self):
        """Test roundtrip with different deposit values."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        drep = new_default_drep()
        test_deposits = [0, 100, 2000000, 1000000000000]

        for deposit in test_deposits:
            cert1 = StakeVoteRegistrationDelegationCert.new(credential, deposit, drep, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

            assert cert1.deposit == cert2.deposit

    def test_roundtrip_with_different_pool_key_hashes(self):
        """Test roundtrip with different pool key hashes."""
        credential = new_default_credential()
        drep = new_default_drep()
        test_hashes = [
            POOL_KEY_HASH,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ]

        for hash_hex in test_hashes:
            pool_key_hash = Blake2bHash.from_hex(hash_hex)
            cert1 = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

            assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()

    def test_roundtrip_with_different_drep_types(self):
        """Test roundtrip with different DRep types."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        hash_value = Blake2bHash.from_hex(DREP_KEY_HASH)
        drep_cred_key = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        drep_cred_script = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        test_dreps = [
            DRep.abstain(),
            DRep.no_confidence(),
            DRep.new(DRepType.KEY_HASH, drep_cred_key),
            DRep.new(DRepType.SCRIPT_HASH, drep_cred_script)
        ]

        for drep in test_dreps:
            cert1 = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

            assert cert1.drep.drep_type == cert2.drep.drep_type

    def test_modify_all_properties(self):
        """Test modifying all properties."""
        cert = new_default_cert()

        new_hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(new_hash_value, CredentialType.SCRIPT_HASH)
        new_pool_hash = Blake2bHash.from_hex("11111111111111111111111111111111111111111111111111111111")
        new_drep = DRep.no_confidence()

        cert.credential = new_cred
        cert.deposit = 2000000
        cert.drep = new_drep
        cert.pool_key_hash = new_pool_hash

        assert cert.credential.hash_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        assert cert.credential.type == CredentialType.SCRIPT_HASH
        assert cert.deposit == 2000000
        assert cert.drep.drep_type == DRepType.NO_CONFIDENCE
        assert cert.pool_key_hash.to_hex() == "11111111111111111111111111111111111111111111111111111111"

    def test_roundtrip_with_different_drep_hashes(self):
        """Test roundtrip with different DRep key hashes."""
        credential = new_default_credential()
        pool_key_hash = Blake2bHash.from_hex(POOL_KEY_HASH)
        test_hashes = [
            DREP_KEY_HASH,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ]

        for hash_hex in test_hashes:
            hash_value = Blake2bHash.from_hex(hash_hex)
            drep_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
            drep = DRep.new(DRepType.KEY_HASH, drep_cred)
            cert1 = StakeVoteRegistrationDelegationCert.new(credential, 0, drep, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

            assert cert1.drep.credential.hash_hex == cert2.drep.credential.hash_hex

    def test_multiple_property_changes_persist(self):
        """Test that multiple sequential property changes persist correctly."""
        cert = new_default_cert()

        hash1 = Blake2bHash.from_hex("11111111111111111111111111111111111111111111111111111111")
        cred1 = Credential.from_hash(hash1, CredentialType.KEY_HASH)
        cert.credential = cred1
        assert cert.credential.hash_hex == "11111111111111111111111111111111111111111111111111111111"

        hash2 = Blake2bHash.from_hex("22222222222222222222222222222222222222222222222222222222")
        cred2 = Credential.from_hash(hash2, CredentialType.SCRIPT_HASH)
        cert.credential = cred2
        assert cert.credential.hash_hex == "22222222222222222222222222222222222222222222222222222222"
        assert cert.credential.type == CredentialType.SCRIPT_HASH

        cert.deposit = 100
        assert cert.deposit == 100

        cert.deposit = 200
        assert cert.deposit == 200

    def test_json_serialization_after_modifications(self):
        """Test JSON serialization after modifying properties."""
        cert = new_default_cert()

        hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        new_pool_hash = Blake2bHash.from_hex("11111111111111111111111111111111111111111111111111111111")
        new_drep = DRep.abstain()

        cert.credential = new_cred
        cert.deposit = 2000000
        cert.drep = new_drep
        cert.pool_key_hash = new_pool_hash

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"script_hash"' in result
        assert '"always_abstain"' in result
        assert '"coin":"2000000"' in result
        assert '"stake_vote_registration_delegation"' in result

    def test_complete_roundtrip_with_all_modifications(self):
        """Test complete roundtrip after modifying all properties."""
        cert1 = new_default_cert()

        hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        new_pool_hash = Blake2bHash.from_hex("11111111111111111111111111111111111111111111111111111111")
        new_drep = DRep.abstain()

        cert1.credential = new_cred
        cert1.deposit = 2000000
        cert1.drep = new_drep
        cert1.pool_key_hash = new_pool_hash

        writer = CborWriter()
        cert1.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        cert2 = StakeVoteRegistrationDelegationCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.credential.type == cert2.credential.type
        assert cert1.deposit == cert2.deposit
        assert cert1.drep.drep_type == cert2.drep.drep_type
        assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()
