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
    AuthCommitteeHotCert,
    Credential,
    CredentialType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "830e8200581c000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HASH = "00000000000000000000000000000000000000000000000000000000"
EXPECTED_CIP116_JSON = '{"tag":"auth_committee_hot","committee_cold_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"committee_hot_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"}}'


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_cert():
    """Creates a default auth committee hot certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return AuthCommitteeHotCert.from_cbor(reader)


class TestAuthCommitteeHotCertNew:
    """Tests for AuthCommitteeHotCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new auth committee hot certificate."""
        cold_cred = new_default_credential()
        hot_cred = new_default_credential()
        cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.committee_hot_credential is not None

    def test_new_with_key_hash_credentials(self):
        """Test creating certificate with key hash credentials."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HASH)
        cold_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        hot_cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        assert cert is not None
        assert cert.committee_cold_credential.type == CredentialType.KEY_HASH
        assert cert.committee_hot_credential.type == CredentialType.KEY_HASH

    def test_new_with_script_hash_credentials(self):
        """Test creating certificate with script hash credentials."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        cold_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        hot_cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        assert cert is not None
        assert cert.committee_cold_credential.type == CredentialType.SCRIPT_HASH
        assert cert.committee_hot_credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_mixed_credential_types(self):
        """Test creating certificate with different credential types."""
        cold_hash = Blake2bHash.from_hex(CREDENTIAL_HASH)
        hot_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        cold_cred = Credential.from_hash(cold_hash, CredentialType.KEY_HASH)
        hot_cred = Credential.from_hash(hot_hash, CredentialType.SCRIPT_HASH)
        cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        assert cert is not None
        assert cert.committee_cold_credential.type == CredentialType.KEY_HASH
        assert cert.committee_hot_credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_none_cold_credential_raises_error(self):
        """Test that creating with None cold credential raises error."""
        hot_cred = new_default_credential()
        with pytest.raises((CardanoError, AttributeError)):
            AuthCommitteeHotCert.new(None, hot_cred)

    def test_new_with_none_hot_credential_raises_error(self):
        """Test that creating with None hot credential raises error."""
        cold_cred = new_default_credential()
        with pytest.raises((CardanoError, AttributeError)):
            AuthCommitteeHotCert.new(cold_cred, None)

    def test_new_with_both_none_raises_error(self):
        """Test that creating with both None credentials raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            AuthCommitteeHotCert.new(None, None)

    def test_new_with_invalid_cold_type_raises_error(self):
        """Test that creating with invalid cold credential type raises error."""
        hot_cred = new_default_credential()
        with pytest.raises(AttributeError):
            AuthCommitteeHotCert.new("not a credential", hot_cred)

    def test_new_with_invalid_hot_type_raises_error(self):
        """Test that creating with invalid hot credential type raises error."""
        cold_cred = new_default_credential()
        with pytest.raises(AttributeError):
            AuthCommitteeHotCert.new(cold_cred, "not a credential")


class TestAuthCommitteeHotCertFromCbor:
    """Tests for AuthCommitteeHotCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = AuthCommitteeHotCert.from_cbor(reader)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.committee_hot_credential is not None

    def test_from_cbor_credentials_match_expected(self):
        """Test that deserialized credentials match expected values."""
        reader = CborReader.from_hex(CBOR)
        cert = AuthCommitteeHotCert.from_cbor(reader)

        assert cert.committee_cold_credential.hash_hex == CREDENTIAL_HASH
        assert cert.committee_hot_credential.hash_hex == CREDENTIAL_HASH

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            AuthCommitteeHotCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            AuthCommitteeHotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            AuthCommitteeHotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("83ef")
        with pytest.raises(CardanoError):
            AuthCommitteeHotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_first_credential_raises_error(self):
        """Test that invalid first credential in CBOR raises error."""
        reader = CborReader.from_hex("830e82005efc000000000000000000000000000000000000000000000000000000008200581c00000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            AuthCommitteeHotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_second_credential_raises_error(self):
        """Test that invalid second credential in CBOR raises error."""
        reader = CborReader.from_hex("830e8200581c0000000000000000000000000000000000000000000000000000000082005efc00000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            AuthCommitteeHotCert.from_cbor(reader)


class TestAuthCommitteeHotCertToCbor:
    """Tests for AuthCommitteeHotCert.to_cbor() method."""

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

        reader = CborReader.from_hex(writer.to_hex())
        cert2 = AuthCommitteeHotCert.from_cbor(reader)

        assert cert1.committee_cold_credential.hash_hex == cert2.committee_cold_credential.hash_hex
        assert cert1.committee_hot_credential.hash_hex == cert2.committee_hot_credential.hash_hex

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.to_cbor(None)

    def test_to_cbor_with_invalid_writer_raises_error(self):
        """Test that serializing with invalid writer raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.to_cbor("not a writer")


class TestAuthCommitteeHotCertToCip116Json:
    """Tests for AuthCommitteeHotCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_certificate(self):
        """Test serializing a certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON

    def test_to_cip116_json_includes_all_fields(self):
        """Test that CIP-116 JSON includes all required fields."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"tag":"auth_committee_hot"' in result
        assert '"committee_cold_credential"' in result
        assert '"committee_hot_credential"' in result

    def test_to_cip116_json_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            cert.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that serializing with invalid writer raises error."""
        cert = new_default_cert()
        with pytest.raises(TypeError):
            cert.to_cip116_json("not a writer")


class TestAuthCommitteeHotCertCommitteeColdCredentialProperty:
    """Tests for AuthCommitteeHotCert.committee_cold_credential property."""

    def test_get_committee_cold_credential_returns_credential(self):
        """Test getting the cold credential from a certificate."""
        cert = new_default_cert()
        credential = cert.committee_cold_credential

        assert credential is not None
        assert credential.hash_hex == CREDENTIAL_HASH

    def test_set_committee_cold_credential_updates_credential(self):
        """Test setting a new cold credential on a certificate."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)

        cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential.hash_hex == "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"

    def test_set_committee_cold_credential_with_script_hash(self):
        """Test setting cold credential with script hash type."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.SCRIPT_HASH)

        cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential.type == CredentialType.SCRIPT_HASH

    def test_set_committee_cold_credential_with_none_raises_error(self):
        """Test that setting None cold credential raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.committee_cold_credential = None

    def test_set_committee_cold_credential_with_invalid_type_raises_error(self):
        """Test that setting invalid cold credential type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.committee_cold_credential = "not a credential"


class TestAuthCommitteeHotCertCommitteeHotCredentialProperty:
    """Tests for AuthCommitteeHotCert.committee_hot_credential property."""

    def test_get_committee_hot_credential_returns_credential(self):
        """Test getting the hot credential from a certificate."""
        cert = new_default_cert()
        credential = cert.committee_hot_credential

        assert credential is not None
        assert credential.hash_hex == CREDENTIAL_HASH

    def test_set_committee_hot_credential_updates_credential(self):
        """Test setting a new hot credential on a certificate."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)

        cert.committee_hot_credential = new_credential

        assert cert.committee_hot_credential.hash_hex == "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"

    def test_set_committee_hot_credential_with_script_hash(self):
        """Test setting hot credential with script hash type."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.SCRIPT_HASH)

        cert.committee_hot_credential = new_credential

        assert cert.committee_hot_credential.type == CredentialType.SCRIPT_HASH

    def test_set_committee_hot_credential_with_none_raises_error(self):
        """Test that setting None hot credential raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.committee_hot_credential = None

    def test_set_committee_hot_credential_with_invalid_type_raises_error(self):
        """Test that setting invalid hot credential type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.committee_hot_credential = "not a credential"


class TestAuthCommitteeHotCertRepr:
    """Tests for AuthCommitteeHotCert.__repr__() method."""

    def test_repr_returns_string(self):
        """Test that repr returns a string."""
        cert = new_default_cert()
        repr_str = repr(cert)

        assert isinstance(repr_str, str)
        assert "AuthCommitteeHotCert" in repr_str


class TestAuthCommitteeHotCertContextManager:
    """Tests for AuthCommitteeHotCert context manager support."""

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns the certificate itself."""
        cert = new_default_cert()
        with cert as context_cert:
            assert context_cert is cert

    def test_context_manager_exit_does_not_raise(self):
        """Test that __exit__ completes without error."""
        cert = new_default_cert()
        try:
            with cert:
                pass
        except Exception as e:
            pytest.fail(f"Context manager raised unexpected exception: {e}")

    def test_context_manager_can_access_properties(self):
        """Test that properties are accessible within context manager."""
        cert = new_default_cert()
        with cert as context_cert:
            assert context_cert.committee_cold_credential is not None
            assert context_cert.committee_hot_credential is not None


class TestAuthCommitteeHotCertEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_cold_credential_changes(self):
        """Test changing cold credential multiple times."""
        cert = new_default_cert()

        test_hashes = [
            "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "fedcba0987654321fedcba0987654321fedcba0987654321fedcba09",
        ]

        for hash_hex in test_hashes:
            new_hash = Blake2bHash.from_hex(hash_hex)
            new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)
            cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential is not None

    def test_multiple_hot_credential_changes(self):
        """Test changing hot credential multiple times."""
        cert = new_default_cert()

        test_hashes = [
            "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "fedcba0987654321fedcba0987654321fedcba0987654321fedcba09",
        ]

        for hash_hex in test_hashes:
            new_hash = Blake2bHash.from_hex(hash_hex)
            new_credential = Credential.from_hash(new_hash, CredentialType.SCRIPT_HASH)
            cert.committee_hot_credential = new_credential

        assert cert.committee_hot_credential is not None

    def test_cbor_roundtrip_preserves_all_data(self):
        """Test that CBOR roundtrip preserves all certificate data."""
        cold_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        hot_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        cold_cred = Credential.from_hash(cold_hash, CredentialType.SCRIPT_HASH)
        hot_cred = Credential.from_hash(hot_hash, CredentialType.KEY_HASH)
        original_cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        writer = CborWriter()
        original_cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = AuthCommitteeHotCert.from_cbor(reader)

        assert original_cert.committee_cold_credential.type == restored_cert.committee_cold_credential.type
        assert original_cert.committee_cold_credential.hash_hex == restored_cert.committee_cold_credential.hash_hex
        assert original_cert.committee_hot_credential.type == restored_cert.committee_hot_credential.type
        assert original_cert.committee_hot_credential.hash_hex == restored_cert.committee_hot_credential.hash_hex

    def test_swapping_cold_and_hot_credentials(self):
        """Test swapping cold and hot credentials."""
        cert = new_default_cert()

        cold_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        hot_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        cold_cred = Credential.from_hash(cold_hash, CredentialType.KEY_HASH)
        hot_cred = Credential.from_hash(hot_hash, CredentialType.KEY_HASH)

        cert.committee_cold_credential = cold_cred
        cert.committee_hot_credential = hot_cred

        temp_cold_hash = cert.committee_cold_credential.hash_hex
        temp_hot_hash = cert.committee_hot_credential.hash_hex

        cert.committee_cold_credential = hot_cred
        cert.committee_hot_credential = cold_cred

        assert cert.committee_cold_credential.hash_hex == temp_hot_hash
        assert cert.committee_hot_credential.hash_hex == temp_cold_hash

    def test_different_credential_types_for_cold_and_hot(self):
        """Test that cold can be key hash and hot can be script hash."""
        cold_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        hot_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        cold_cred = Credential.from_hash(cold_hash, CredentialType.KEY_HASH)
        hot_cred = Credential.from_hash(hot_hash, CredentialType.SCRIPT_HASH)
        cert = AuthCommitteeHotCert.new(cold_cred, hot_cred)

        writer = CborWriter()
        cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = AuthCommitteeHotCert.from_cbor(reader)

        assert restored_cert.committee_cold_credential.type == CredentialType.KEY_HASH
        assert restored_cert.committee_hot_credential.type == CredentialType.SCRIPT_HASH
