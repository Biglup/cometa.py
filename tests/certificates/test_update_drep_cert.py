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
    UpdateDRepCert,
    Credential,
    CredentialType,
    Blake2bHash,
    Anchor,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "83128200581c00000000000000000000000000000000000000000000000000000000f6"
CBOR_WITH_ANCHOR = "83128200581c00000000000000000000000000000000000000000000000000000000827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HEX = "00000000000000000000000000000000000000000000000000000000"
ANCHOR_URL = "https://www.someurl.io"
ANCHOR_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
EXPECTED_CIP116_JSON_WITHOUT_ANCHOR = '{"tag":"update_drep","drep_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"}}'
EXPECTED_CIP116_JSON_WITH_ANCHOR = '{"tag":"update_drep","drep_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"anchor":{"url":"https://www.someurl.io","data_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}'


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_anchor():
    """Creates a default anchor for testing."""
    reader = CborReader.from_hex(ANCHOR_CBOR)
    return Anchor.from_cbor(reader)


def new_default_cert():
    """Creates a default update DRep certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return UpdateDRepCert.from_cbor(reader)


class TestUpdateDRepCertNew:
    """Tests for UpdateDRepCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new update DRep certificate."""
        credential = new_default_credential()
        cert = UpdateDRepCert.new(credential)

        assert cert is not None
        assert cert.credential is not None
        assert cert.anchor is None

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        cert = UpdateDRepCert.new(credential)

        assert cert is not None
        assert cert.credential.type == CredentialType.KEY_HASH

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        cert = UpdateDRepCert.new(credential)

        assert cert is not None
        assert cert.credential.type == CredentialType.SCRIPT_HASH

    def test_new_with_anchor(self):
        """Test creating certificate with anchor."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = UpdateDRepCert.new(credential, anchor)

        assert cert is not None
        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL

    def test_new_without_anchor(self):
        """Test creating certificate without anchor."""
        credential = new_default_credential()
        cert = UpdateDRepCert.new(credential, None)

        assert cert is not None
        assert cert.anchor is None

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            UpdateDRepCert.new(None)

    def test_new_with_invalid_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        with pytest.raises(AttributeError):
            UpdateDRepCert.new("not a credential")


class TestUpdateDRepCertFromCbor:
    """Tests for UpdateDRepCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = UpdateDRepCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.anchor is None

    def test_from_cbor_deserializes_certificate_with_anchor(self):
        """Test deserializing a certificate with anchor from CBOR."""
        reader = CborReader.from_hex(CBOR_WITH_ANCHOR)
        cert = UpdateDRepCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = UpdateDRepCert.from_cbor(reader)

        assert cert.credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            UpdateDRepCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            UpdateDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            UpdateDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("83ef")
        with pytest.raises(CardanoError):
            UpdateDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("8312ef00581c00000000000000000000000000000000000000000000000000000000f6")
        with pytest.raises(CardanoError):
            UpdateDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_anchor_raises_error(self):
        """Test that invalid anchor in CBOR raises error."""
        reader = CborReader.from_hex("83128200581c00000000000000000000000000000000000000000000000000000000ef")
        with pytest.raises(CardanoError):
            UpdateDRepCert.from_cbor(reader)


class TestUpdateDRepCertToCbor:
    """Tests for UpdateDRepCert.to_cbor() method."""

    def test_to_cbor_serializes_certificate(self):
        """Test serializing a certificate to CBOR."""
        cert = new_default_cert()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR

    def test_to_cbor_serializes_certificate_with_anchor(self):
        """Test serializing a certificate with anchor to CBOR."""
        cert = new_default_cert()
        anchor = new_default_anchor()
        cert.anchor = anchor
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
        cert2 = UpdateDRepCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex

    def test_to_cbor_roundtrip_with_anchor(self):
        """Test roundtrip with anchor."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert1 = UpdateDRepCert.new(credential, anchor)

        writer = CborWriter()
        cert1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        cert2 = UpdateDRepCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
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


class TestUpdateDRepCertToCip116Json:
    """Tests for UpdateDRepCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_certificate(self):
        """Test serializing a certificate to CIP-116 JSON."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON_WITHOUT_ANCHOR

    def test_to_cip116_json_serializes_certificate_with_anchor(self):
        """Test serializing a certificate with anchor to CIP-116 JSON."""
        cert = new_default_cert()
        anchor = new_default_anchor()
        cert.anchor = anchor
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert result == EXPECTED_CIP116_JSON_WITH_ANCHOR

    def test_to_cip116_json_includes_all_fields(self):
        """Test that CIP-116 JSON includes tag and drep_credential fields."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"tag":"update_drep"' in result
        assert '"drep_credential"' in result

    def test_to_cip116_json_with_anchor_includes_anchor_field(self):
        """Test that CIP-116 JSON with anchor includes anchor field."""
        cert = new_default_cert()
        anchor = new_default_anchor()
        cert.anchor = anchor
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


class TestUpdateDRepCertCredentialProperty:
    """Tests for UpdateDRepCert.credential property."""

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


class TestUpdateDRepCertAnchorProperty:
    """Tests for UpdateDRepCert.anchor property."""

    def test_get_anchor_returns_none_when_not_set(self):
        """Test getting anchor when not set returns None."""
        cert = new_default_cert()
        anchor = cert.anchor

        assert anchor is None

    def test_get_anchor_returns_anchor_when_set(self):
        """Test getting anchor when set."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = UpdateDRepCert.new(credential, anchor)

        retrieved_anchor = cert.anchor
        assert retrieved_anchor is not None
        assert retrieved_anchor.url == ANCHOR_URL

    def test_set_anchor_updates_anchor(self):
        """Test setting a new anchor on a certificate."""
        cert = new_default_cert()
        anchor = new_default_anchor()

        cert.anchor = anchor

        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL

    def test_set_anchor_to_none_raises_error(self):
        """Test that setting anchor to None raises error."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = UpdateDRepCert.new(credential, anchor)

        with pytest.raises(CardanoError):
            cert.anchor = None

    def test_set_anchor_with_invalid_type_raises_error(self):
        """Test that setting invalid anchor type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.anchor = "not an anchor"


class TestUpdateDRepCertRepr:
    """Tests for UpdateDRepCert.__repr__() method."""

    def test_repr_returns_string(self):
        """Test that repr returns a string representation."""
        cert = new_default_cert()
        repr_str = repr(cert)

        assert "UpdateDRepCert" in repr_str


class TestUpdateDRepCertContextManager:
    """Tests for UpdateDRepCert context manager support."""

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
            assert context_cert.credential is not None
            assert context_cert.anchor is None


class TestUpdateDRepCertEdgeCases:
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

    def test_multiple_anchor_changes(self):
        """Test changing anchor multiple times."""
        cert = new_default_cert()
        anchor = new_default_anchor()

        cert.anchor = anchor
        assert cert.anchor is not None

        anchor2 = new_default_anchor()
        cert.anchor = anchor2
        assert cert.anchor is not None

    def test_cbor_roundtrip_preserves_all_data(self):
        """Test that CBOR roundtrip preserves all certificate data."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        anchor = new_default_anchor()
        original_cert = UpdateDRepCert.new(credential, anchor)

        writer = CborWriter()
        original_cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = UpdateDRepCert.from_cbor(reader)

        assert original_cert.credential.type == restored_cert.credential.type
        assert original_cert.credential.hash_hex == restored_cert.credential.hash_hex
        assert restored_cert.anchor is not None
        assert original_cert.anchor.url == restored_cert.anchor.url

    def test_cip116_json_with_custom_anchor(self):
        """Test CIP-116 JSON with custom anchor data."""
        credential = new_default_credential()
        hash_value = Blake2bHash.from_hex("2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e")
        anchor = Anchor.new("https://example.com", hash_value)
        cert = UpdateDRepCert.new(credential, anchor)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"url":"https://example.com"' in result
        assert '"data_hash":"2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"' in result

    def test_credential_persists_after_anchor_change(self):
        """Test that credential remains unchanged after anchor modifications."""
        cert = new_default_cert()
        original_credential_hex = cert.credential.hash_hex

        anchor = new_default_anchor()
        cert.anchor = anchor

        assert cert.credential.hash_hex == original_credential_hex

    def test_anchor_persists_after_credential_change(self):
        """Test that anchor remains unchanged after credential modifications."""
        cert = new_default_cert()
        anchor = new_default_anchor()
        cert.anchor = anchor

        new_hash = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        new_credential = Credential.from_hash(new_hash, CredentialType.KEY_HASH)
        cert.credential = new_credential

        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL
