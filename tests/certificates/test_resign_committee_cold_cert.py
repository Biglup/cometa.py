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
    ResignCommitteeColdCert,
    Credential,
    CredentialType,
    Blake2bHash,
    Anchor,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "830f8200581c00000000000000000000000000000000000000000000000000000000f6"
CBOR_WITH_ANCHOR = "830f8200581c00000000000000000000000000000000000000000000000000000000827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HEX = "00000000000000000000000000000000000000000000000000000000"
EXPECTED_CIP116_JSON_NO_ANCHOR = '{"tag":"resign_committee_cold","committee_cold_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"}}'
EXPECTED_CIP116_JSON_WITH_ANCHOR = '{"tag":"resign_committee_cold","committee_cold_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"anchor":{"url":"https://www.someurl.io","data_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}'


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_anchor():
    """Creates a default anchor for testing."""
    reader = CborReader.from_hex(ANCHOR_CBOR)
    return Anchor.from_cbor(reader)


def new_default_cert():
    """Creates a default resign committee cold certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return ResignCommitteeColdCert.from_cbor(reader)


def new_default_cert_with_anchor():
    """Creates a resign committee cold certificate with anchor for testing."""
    reader = CborReader.from_hex(CBOR_WITH_ANCHOR)
    return ResignCommitteeColdCert.from_cbor(reader)


class TestResignCommitteeColdCertNew:
    """Tests for ResignCommitteeColdCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new resign committee cold certificate."""
        credential = new_default_credential()
        cert = ResignCommitteeColdCert.new(credential)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.anchor is None

    def test_new_with_anchor(self):
        """Test creating certificate with anchor."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = ResignCommitteeColdCert.new(credential, anchor)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.anchor is not None

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        cert = ResignCommitteeColdCert.new(credential)

        assert cert is not None
        assert cert.committee_cold_credential.type == CredentialType.KEY_HASH

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        cert = ResignCommitteeColdCert.new(credential)

        assert cert is not None
        assert cert.committee_cold_credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            ResignCommitteeColdCert.new(None)

    def test_new_with_invalid_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        with pytest.raises(AttributeError):
            ResignCommitteeColdCert.new("not a credential")

    def test_new_with_none_anchor_creates_certificate(self):
        """Test creating certificate with explicitly None anchor."""
        credential = new_default_credential()
        cert = ResignCommitteeColdCert.new(credential, None)

        assert cert is not None
        assert cert.anchor is None


class TestResignCommitteeColdCertFromCbor:
    """Tests for ResignCommitteeColdCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = ResignCommitteeColdCert.from_cbor(reader)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.anchor is None

    def test_from_cbor_deserializes_certificate_with_anchor(self):
        """Test deserializing a certificate with anchor from CBOR."""
        reader = CborReader.from_hex(CBOR_WITH_ANCHOR)
        cert = ResignCommitteeColdCert.from_cbor(reader)

        assert cert is not None
        assert cert.committee_cold_credential is not None
        assert cert.anchor is not None

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = ResignCommitteeColdCert.from_cbor(reader)

        assert cert.committee_cold_credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_anchor_matches_expected(self):
        """Test that deserialized anchor matches expected value."""
        reader = CborReader.from_hex(CBOR_WITH_ANCHOR)
        cert = ResignCommitteeColdCert.from_cbor(reader)

        assert cert.anchor is not None
        assert cert.anchor.url == "https://www.someurl.io"

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            ResignCommitteeColdCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            ResignCommitteeColdCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            ResignCommitteeColdCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("83ef")
        with pytest.raises(CardanoError):
            ResignCommitteeColdCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("830fef00581c00000000000000000000000000000000000000000000000000000000f6")
        with pytest.raises(CardanoError):
            ResignCommitteeColdCert.from_cbor(reader)

    def test_from_cbor_with_invalid_anchor_raises_error(self):
        """Test that invalid anchor in CBOR raises error."""
        reader = CborReader.from_hex("830f8200581c00000000000000000000000000000000000000000000000000000000ef")
        with pytest.raises(CardanoError):
            ResignCommitteeColdCert.from_cbor(reader)


class TestResignCommitteeColdCertToCbor:
    """Tests for ResignCommitteeColdCert.to_cbor() method."""

    def test_to_cbor_serializes_certificate(self):
        """Test serializing a certificate to CBOR."""
        cert = new_default_cert()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR

    def test_to_cbor_serializes_certificate_with_anchor(self):
        """Test serializing a certificate with anchor to CBOR."""
        cert = new_default_cert_with_anchor()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR_WITH_ANCHOR

    def test_to_cbor_roundtrip(self):
        """Test that serialization and deserialization produce same result."""
        cert1 = new_default_cert()
        writer = CborWriter()
        cert1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        cert2 = ResignCommitteeColdCert.from_cbor(reader)

        assert cert1.committee_cold_credential.hash_hex == cert2.committee_cold_credential.hash_hex
        assert cert1.anchor is None
        assert cert2.anchor is None

    def test_to_cbor_roundtrip_with_anchor(self):
        """Test that serialization and deserialization with anchor produce same result."""
        cert1 = new_default_cert_with_anchor()
        writer = CborWriter()
        cert1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        cert2 = ResignCommitteeColdCert.from_cbor(reader)

        assert cert1.committee_cold_credential.hash_hex == cert2.committee_cold_credential.hash_hex
        assert cert1.anchor is not None
        assert cert2.anchor is not None
        assert cert1.anchor.url == cert2.anchor.url

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


class TestResignCommitteeColdCertToCip116Json:
    """Tests for ResignCommitteeColdCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_certificate(self):
        """Test serializing a certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON_NO_ANCHOR

    def test_to_cip116_json_serializes_certificate_with_anchor(self):
        """Test serializing a certificate with anchor to CIP-116 JSON."""
        cert = new_default_cert_with_anchor()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON_WITH_ANCHOR

    def test_to_cip116_json_includes_all_fields(self):
        """Test that CIP-116 JSON includes tag and credential fields."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"tag":"resign_committee_cold"' in result
        assert '"committee_cold_credential"' in result

    def test_to_cip116_json_includes_anchor_when_present(self):
        """Test that CIP-116 JSON includes anchor when present."""
        cert = new_default_cert_with_anchor()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"anchor"' in result
        assert '"url"' in result
        assert '"data_hash"' in result

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


class TestResignCommitteeColdCertCommitteeColdCredentialProperty:
    """Tests for ResignCommitteeColdCert.committee_cold_credential property."""

    def test_get_committee_cold_credential_returns_credential(self):
        """Test getting the committee cold credential from a certificate."""
        cert = new_default_cert()
        credential = cert.committee_cold_credential

        assert credential is not None
        assert credential.hash_hex == CREDENTIAL_HEX

    def test_set_committee_cold_credential_updates_credential(self):
        """Test setting a new committee cold credential on a certificate."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)

        cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential.hash_hex == "cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"

    def test_set_committee_cold_credential_with_script_hash(self):
        """Test setting credential with script hash type."""
        cert = new_default_cert()
        new_hash = Blake2bHash.from_hex("ab0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.SCRIPT_HASH)

        cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential.type == CredentialType.SCRIPT_HASH

    def test_set_committee_cold_credential_with_none_raises_error(self):
        """Test that setting None credential raises error."""
        cert = new_default_cert()
        with pytest.raises((CardanoError, AttributeError)):
            cert.committee_cold_credential = None

    def test_set_committee_cold_credential_with_invalid_type_raises_error(self):
        """Test that setting invalid credential type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.committee_cold_credential = "not a credential"


class TestResignCommitteeColdCertAnchorProperty:
    """Tests for ResignCommitteeColdCert.anchor property."""

    def test_get_anchor_returns_none_when_not_set(self):
        """Test getting the anchor when not set returns None."""
        cert = new_default_cert()
        anchor = cert.anchor

        assert anchor is None

    def test_get_anchor_returns_anchor_when_set(self):
        """Test getting the anchor when set returns the anchor."""
        cert = new_default_cert_with_anchor()
        anchor = cert.anchor

        assert anchor is not None
        assert anchor.url == "https://www.someurl.io"

    def test_set_anchor_updates_anchor(self):
        """Test setting a new anchor on a certificate."""
        cert = new_default_cert()
        new_anchor = new_default_anchor()

        cert.anchor = new_anchor

        assert cert.anchor is not None
        assert cert.anchor.url == "https://www.someurl.io"

    def test_set_anchor_with_none_raises_error(self):
        """Test that setting None anchor raises error."""
        cert = new_default_cert_with_anchor()
        assert cert.anchor is not None

        with pytest.raises(CardanoError):
            cert.anchor = None

    def test_set_anchor_with_invalid_type_raises_error(self):
        """Test that setting invalid anchor type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.anchor = "not an anchor"


class TestResignCommitteeColdCertRepr:
    """Tests for ResignCommitteeColdCert.__repr__() method."""

    def test_repr_returns_string(self):
        """Test that repr returns a string."""
        cert = new_default_cert()
        repr_str = repr(cert)

        assert isinstance(repr_str, str)
        assert "ResignCommitteeColdCert" in repr_str


class TestResignCommitteeColdCertContextManager:
    """Tests for ResignCommitteeColdCert context manager support."""

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
            assert context_cert.anchor is None


class TestResignCommitteeColdCertEdgeCases:
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
            cert.committee_cold_credential = new_credential

        assert cert.committee_cold_credential is not None

    def test_multiple_anchor_changes(self):
        """Test changing anchor multiple times."""
        cert = new_default_cert()
        anchor = new_default_anchor()

        cert.anchor = anchor
        assert cert.anchor is not None
        assert cert.anchor.url == "https://www.someurl.io"

    def test_cbor_roundtrip_preserves_all_data(self):
        """Test that CBOR roundtrip preserves all certificate data."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        anchor = new_default_anchor()
        original_cert = ResignCommitteeColdCert.new(credential, anchor)

        writer = CborWriter()
        original_cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = ResignCommitteeColdCert.from_cbor(reader)

        assert original_cert.committee_cold_credential.type == restored_cert.committee_cold_credential.type
        assert original_cert.committee_cold_credential.hash_hex == restored_cert.committee_cold_credential.hash_hex
        assert original_cert.anchor is not None
        assert restored_cert.anchor is not None
        assert original_cert.anchor.url == restored_cert.anchor.url

    def test_certificate_with_different_credential_types(self):
        """Test creating certificates with different credential types."""
        key_hash = Blake2bHash.from_hex(CREDENTIAL_HEX)
        script_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")

        key_cred = Credential.from_hash(key_hash, CredentialType.KEY_HASH)
        script_cred = Credential.from_hash(script_hash, CredentialType.SCRIPT_HASH)

        key_cert = ResignCommitteeColdCert.new(key_cred)
        script_cert = ResignCommitteeColdCert.new(script_cred)

        assert key_cert.committee_cold_credential.type == CredentialType.KEY_HASH
        assert script_cert.committee_cold_credential.type == CredentialType.SCRIPT_HASH

    def test_certificate_anchor_can_be_added_after_creation(self):
        """Test that anchor can be added after certificate creation."""
        credential = new_default_credential()
        cert = ResignCommitteeColdCert.new(credential)

        assert cert.anchor is None

        anchor = new_default_anchor()
        cert.anchor = anchor

        assert cert.anchor is not None
        assert cert.anchor.url == "https://www.someurl.io"

    def test_certificate_setting_none_anchor_raises_error(self):
        """Test that setting None anchor raises error."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = ResignCommitteeColdCert.new(credential, anchor)

        assert cert.anchor is not None

        with pytest.raises(CardanoError):
            cert.anchor = None
