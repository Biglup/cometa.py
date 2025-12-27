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
    StakeDelegationCert,
    Credential,
    CredentialType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "83028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
CREDENTIAL_CBOR = "8200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"
CREDENTIAL_HEX = "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"
POOL_KEY_HASH = "d85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_pool_key_hash():
    """Creates a default pool key hash for testing."""
    return Blake2bHash.from_hex(POOL_KEY_HASH)


def new_default_cert():
    """Creates a default stake delegation certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return StakeDelegationCert.from_cbor(reader)


class TestStakeDelegationCertNew:
    """Tests for StakeDelegationCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new stake delegation certificate."""
        credential = new_default_credential()
        pool_key_hash = new_default_pool_key_hash()
        cert = StakeDelegationCert.new(credential, pool_key_hash)

        assert cert is not None
        assert cert.credential is not None
        assert cert.pool_key_hash is not None

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        pool_key_hash = new_default_pool_key_hash()
        cert = StakeDelegationCert.new(credential, pool_key_hash)

        assert cert is not None
        assert cert.credential.type == CredentialType.KEY_HASH

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        pool_key_hash = new_default_pool_key_hash()
        cert = StakeDelegationCert.new(credential, pool_key_hash)

        assert cert is not None
        assert cert.credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        pool_key_hash = new_default_pool_key_hash()
        with pytest.raises((CardanoError, AttributeError)):
            StakeDelegationCert.new(None, pool_key_hash)

    def test_new_with_none_pool_key_hash_raises_error(self):
        """Test that creating with None pool key hash raises error."""
        credential = new_default_credential()
        with pytest.raises((CardanoError, AttributeError)):
            StakeDelegationCert.new(credential, None)

    def test_new_with_both_none_raises_error(self):
        """Test that creating with both None raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            StakeDelegationCert.new(None, None)

    def test_new_with_invalid_credential_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        pool_key_hash = new_default_pool_key_hash()
        with pytest.raises(AttributeError):
            StakeDelegationCert.new("not a credential", pool_key_hash)

    def test_new_with_invalid_pool_key_hash_type_raises_error(self):
        """Test that creating with invalid pool key hash type raises error."""
        credential = new_default_credential()
        with pytest.raises(AttributeError):
            StakeDelegationCert.new(credential, "not a hash")


class TestStakeDelegationCertFromCbor:
    """Tests for StakeDelegationCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeDelegationCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.pool_key_hash is not None

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeDelegationCert.from_cbor(reader)

        assert cert.credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_pool_key_hash_matches_expected(self):
        """Test that deserialized pool key hash matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = StakeDelegationCert.from_cbor(reader)

        assert cert.pool_key_hash.to_hex() == POOL_KEY_HASH

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            StakeDelegationCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            StakeDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            StakeDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("83ef")
        with pytest.raises(CardanoError):
            StakeDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("8302ef00581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92")
        with pytest.raises(CardanoError):
            StakeDelegationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_pool_hash_raises_error(self):
        """Test that invalid pool hash in CBOR raises error."""
        reader = CborReader.from_hex("83028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810fef1cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92")
        with pytest.raises(CardanoError):
            StakeDelegationCert.from_cbor(reader)


class TestStakeDelegationCertToCbor:
    """Tests for StakeDelegationCert.to_cbor() method."""

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
        cert2 = StakeDelegationCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.to_cbor(None)


class TestStakeDelegationCertCredentialProperty:
    """Tests for StakeDelegationCert.credential property."""

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


class TestStakeDelegationCertPoolKeyHashProperty:
    """Tests for StakeDelegationCert.pool_key_hash property."""

    def test_get_pool_key_hash_returns_hash(self):
        """Test getting the pool key hash from certificate."""
        cert = new_default_cert()
        pool_key_hash = cert.pool_key_hash

        assert pool_key_hash is not None
        assert pool_key_hash.to_hex() == POOL_KEY_HASH

    def test_set_pool_key_hash_updates_hash(self):
        """Test setting a new pool key hash."""
        cert = new_default_cert()
        new_hash = new_default_pool_key_hash()

        cert.pool_key_hash = new_hash
        retrieved = cert.pool_key_hash

        assert retrieved.to_hex() == POOL_KEY_HASH

    def test_set_pool_key_hash_with_different_hash(self):
        """Test setting pool key hash to different value."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

        cert.pool_key_hash = new_hash
        retrieved = cert.pool_key_hash

        assert retrieved.to_hex() == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

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


class TestStakeDelegationCertToCip116Json:
    """Tests for StakeDelegationCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_correctly(self):
        """Test serializing certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"stake_delegation","credential":{"tag":"pubkey_hash","value":"cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"},"pool_keyhash":"pool1mpgg03jxj52qwxvvy7cmj58a96vl9pvxcqqvuw0kumheygxmn34"}'
        assert result == expected

    def test_to_cip116_json_includes_tag(self):
        """Test that JSON includes 'stake_delegation' tag."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"stake_delegation"' in result

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
        assert 'pool1mpgg03jxj52qwxvvy7cmj58a96vl9pvxcqqvuw0kumheygxmn34' in result

    def test_to_cip116_json_with_script_hash_credential(self):
        """Test JSON serialization with script hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        pool_key_hash = new_default_pool_key_hash()
        cert = StakeDelegationCert.new(credential, pool_key_hash)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"script_hash"' in result

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


class TestStakeDelegationCertLifecycle:
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
            assert cert.pool_key_hash is not None

    def test_repr_returns_string(self):
        """Test that repr returns a string representation."""
        cert = new_default_cert()
        result = repr(cert)

        assert isinstance(result, str)
        assert "StakeDelegationCert" in result


class TestStakeDelegationCertEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_get_credential_calls(self):
        """Test that multiple credential retrievals work correctly."""
        cert = new_default_cert()
        cred1 = cert.credential
        cred2 = cert.credential

        assert cred1.hash_hex == cred2.hash_hex

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

    def test_set_then_get_pool_key_hash(self):
        """Test setting and getting pool key hash in sequence."""
        cert = new_default_cert()
        original_hex = cert.pool_key_hash.to_hex()

        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        cert.pool_key_hash = new_hash

        retrieved = cert.pool_key_hash
        assert retrieved.to_hex() != original_hex
        assert retrieved.to_hex() == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

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

    def test_serialize_after_pool_key_hash_change(self):
        """Test serialization after changing pool key hash."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        cert.pool_key_hash = new_hash

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR

    def test_roundtrip_with_different_credentials(self):
        """Test roundtrip with different credential types."""
        pool_key_hash = new_default_pool_key_hash()
        for cred_type in [CredentialType.KEY_HASH, CredentialType.SCRIPT_HASH]:
            hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
            credential = Credential.from_hash(hash_value, cred_type)
            cert1 = StakeDelegationCert.new(credential, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeDelegationCert.from_cbor(reader)

            assert cert1.credential.type == cert2.credential.type
            assert cert1.credential.hash_hex == cert2.credential.hash_hex
            assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()

    def test_roundtrip_with_different_pool_hashes(self):
        """Test roundtrip with different pool key hashes."""
        credential = new_default_credential()
        test_hashes = [
            POOL_KEY_HASH,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "000000000000000000000000000000000000000000000000000000000000"
        ]

        for hash_hex in test_hashes:
            pool_key_hash = Blake2bHash.from_hex(hash_hex)
            cert1 = StakeDelegationCert.new(credential, pool_key_hash)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = StakeDelegationCert.from_cbor(reader)

            assert cert1.pool_key_hash.to_hex() == cert2.pool_key_hash.to_hex()

    def test_modify_both_properties(self):
        """Test modifying both credential and pool key hash."""
        cert = new_default_cert()

        new_hash_value = Blake2bHash.from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        new_cred = Credential.from_hash(new_hash_value, CredentialType.SCRIPT_HASH)
        new_pool_hash = Blake2bHash.from_hex("000000000000000000000000000000000000000000000000000000000000")

        cert.credential = new_cred
        cert.pool_key_hash = new_pool_hash

        assert cert.credential.hash_hex == "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        assert cert.credential.type == CredentialType.SCRIPT_HASH
        assert cert.pool_key_hash.to_hex() == "000000000000000000000000000000000000000000000000000000000000"
