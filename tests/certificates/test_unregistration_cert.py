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
    UnregistrationCert,
    Credential,
    CredentialType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "83088200581c0000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HEX = "00000000000000000000000000000000000000000000000000000000"
CBOR_WITH_DEPOSIT_1000 = "83088200581c000000000000000000000000000000000000000000000000000000001903e8"
EXPECTED_CIP116_JSON = '{"tag":"unregistration","credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"coin":"0"}'


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_cert():
    """Creates a default unregistration certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return UnregistrationCert.from_cbor(reader)


class TestUnregistrationCertNew:
    """Tests for UnregistrationCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new unregistration certificate."""
        credential = new_default_credential()
        cert = UnregistrationCert.new(credential, 0)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        cert = UnregistrationCert.new(credential, 2000000)

        assert cert is not None
        assert cert.credential.type == CredentialType.KEY_HASH
        assert cert.deposit == 2000000

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        cert = UnregistrationCert.new(credential, 2000000)

        assert cert is not None
        assert cert.credential.type == CredentialType.SCRIPT_HASH
        assert cert.deposit == 2000000

    def test_new_with_zero_deposit(self):
        """Test creating certificate with zero deposit."""
        credential = new_default_credential()
        cert = UnregistrationCert.new(credential, 0)

        assert cert is not None
        assert cert.deposit == 0

    def test_new_with_large_deposit(self):
        """Test creating certificate with large deposit amount."""
        credential = new_default_credential()
        large_deposit = 10000000000
        cert = UnregistrationCert.new(credential, large_deposit)

        assert cert is not None
        assert cert.deposit == large_deposit

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            UnregistrationCert.new(None, 0)

    def test_new_with_invalid_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        with pytest.raises(AttributeError):
            UnregistrationCert.new("not a credential", 0)


class TestUnregistrationCertFromCbor:
    """Tests for UnregistrationCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = UnregistrationCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = UnregistrationCert.from_cbor(reader)

        assert cert.credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_deposit_matches_expected(self):
        """Test that deserialized deposit matches expected value."""
        reader = CborReader.from_hex(CBOR_WITH_DEPOSIT_1000)
        cert = UnregistrationCert.from_cbor(reader)

        assert cert.deposit == 1000

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            UnregistrationCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            UnregistrationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            UnregistrationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("83ef")
        with pytest.raises(CardanoError):
            UnregistrationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("8308ef00581c0000000000000000000000000000000000000000000000000000000000")
        with pytest.raises(CardanoError):
            UnregistrationCert.from_cbor(reader)

    def test_from_cbor_with_invalid_deposit_raises_error(self):
        """Test that invalid deposit in CBOR raises error."""
        reader = CborReader.from_hex("83088200581c00000000000000000000000000000000000000000000000000000000ef")
        with pytest.raises(CardanoError):
            UnregistrationCert.from_cbor(reader)


class TestUnregistrationCertToCbor:
    """Tests for UnregistrationCert.to_cbor() method."""

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
        cert2 = UnregistrationCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.deposit == cert2.deposit

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


class TestUnregistrationCertToCip116Json:
    """Tests for UnregistrationCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_certificate(self):
        """Test serializing a certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON

    def test_to_cip116_json_includes_all_fields(self):
        """Test that CIP-116 JSON includes tag, credential, and coin fields."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"tag":"unregistration"' in result
        assert '"credential"' in result
        assert '"coin"' in result

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


class TestUnregistrationCertCredentialProperty:
    """Tests for UnregistrationCert.credential property."""

    def test_get_credential_returns_credential(self):
        """Test getting the credential from a certificate."""
        cert = new_default_cert()
        credential = cert.credential

        assert credential is not None
        assert credential.hash_hex == CREDENTIAL_HEX

    def test_set_credential_updates_credential(self):
        """Test setting a new credential on a certificate."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)

        cert.credential = new_credential

        assert cert.credential.hash_hex == "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"

    def test_set_credential_with_script_hash(self):
        """Test setting credential with script hash type."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.SCRIPT_HASH)

        cert.credential = new_credential

        assert cert.credential.type == CredentialType.SCRIPT_HASH

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


class TestUnregistrationCertDepositProperty:
    """Tests for UnregistrationCert.deposit property."""

    def test_get_deposit_returns_deposit(self):
        """Test getting the deposit from a certificate."""
        cert = new_default_cert()
        deposit = cert.deposit

        assert deposit == 0

    def test_set_deposit_updates_deposit(self):
        """Test setting a new deposit on a certificate."""
        cert = new_default_cert()
        cert.deposit = 1000

        assert cert.deposit == 1000

    def test_set_deposit_with_zero(self):
        """Test setting deposit to zero."""
        cert = new_default_cert()
        cert.deposit = 0

        assert cert.deposit == 0

    def test_set_deposit_with_large_value(self):
        """Test setting deposit to large value."""
        cert = new_default_cert()
        large_deposit = 45000000000000
        cert.deposit = large_deposit

        assert cert.deposit == large_deposit


class TestUnregistrationCertRepr:
    """Tests for UnregistrationCert.__repr__() method."""

    def test_repr_contains_deposit(self):
        """Test that repr contains deposit information."""
        cert = new_default_cert()
        repr_str = repr(cert)

        assert "UnregistrationCert" in repr_str
        assert "deposit" in repr_str
        assert "0" in repr_str

    def test_repr_with_nonzero_deposit(self):
        """Test repr with non-zero deposit."""
        credential = new_default_credential()
        cert = UnregistrationCert.new(credential, 2000000)
        repr_str = repr(cert)

        assert "2000000" in repr_str


class TestUnregistrationCertContextManager:
    """Tests for UnregistrationCert context manager support."""

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
            assert context_cert.deposit == 0
            assert context_cert.credential is not None


class TestUnregistrationCertEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_credential_changes(self):
        """Test changing credential multiple times."""
        cert = new_default_cert()

        test_hashes = [
            "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f",
            "fedcba0987654321fedcba0987654321fedcba0987654321fedcba09",
        ]

        for hash_hex in test_hashes:
            new_hash = Blake2bHash.from_hex(hash_hex)
            new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)
            cert.credential = new_credential

        assert cert.credential is not None

    def test_multiple_deposit_changes(self):
        """Test changing deposit multiple times."""
        cert = new_default_cert()

        deposits = [0, 1000, 2000000, 5000000, 0]
        for deposit in deposits:
            cert.deposit = deposit
            assert cert.deposit == deposit

    def test_cbor_roundtrip_preserves_all_data(self):
        """Test that CBOR roundtrip preserves all certificate data."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        original_cert = UnregistrationCert.new(credential, 2000000)

        writer = CborWriter()
        original_cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = UnregistrationCert.from_cbor(reader)

        assert original_cert.credential.type == restored_cert.credential.type
        assert original_cert.credential.hash_hex == restored_cert.credential.hash_hex
        assert original_cert.deposit == restored_cert.deposit

    def test_certificate_with_maximum_deposit(self):
        """Test creating certificate with maximum possible deposit value."""
        credential = new_default_credential()
        max_deposit = (2**64) - 1
        cert = UnregistrationCert.new(credential, max_deposit)

        assert cert.deposit == max_deposit
