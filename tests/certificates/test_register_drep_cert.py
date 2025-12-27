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
    RegisterDRepCert,
    Credential,
    CredentialType,
    Blake2bHash,
    Anchor,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "84108200581c0000000000000000000000000000000000000000000000000000000000f6"
CBOR_WITH_ANCHOR = "84108200581c0000000000000000000000000000000000000000000000000000000000827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CREDENTIAL_HEX = "00000000000000000000000000000000000000000000000000000000"
ANCHOR_URL = "https://www.someurl.io"
ANCHOR_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
EXPECTED_CIP116_JSON_WITHOUT_ANCHOR = '{"tag":"register_drep","drep_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"coin":"0"}'
EXPECTED_CIP116_JSON_WITH_ANCHOR = '{"tag":"register_drep","drep_credential":{"tag":"pubkey_hash","value":"00000000000000000000000000000000000000000000000000000000"},"coin":"0","anchor":{"url":"https://www.someurl.io","data_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}'


def new_default_credential():
    """Creates a default credential for testing."""
    reader = CborReader.from_hex(CREDENTIAL_CBOR)
    return Credential.from_cbor(reader)


def new_default_anchor():
    """Creates a default anchor for testing."""
    reader = CborReader.from_hex(ANCHOR_CBOR)
    return Anchor.from_cbor(reader)


def new_default_cert():
    """Creates a default register DRep certificate for testing."""
    reader = CborReader.from_hex(CBOR)
    return RegisterDRepCert.from_cbor(reader)


class TestRegisterDRepCertNew:
    """Tests for RegisterDRepCert.new() factory method."""

    def test_new_creates_valid_certificate(self):
        """Test creating a new register DRep certificate."""
        credential = new_default_credential()
        cert = RegisterDRepCert.new(credential, 0)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0
        assert cert.anchor is None

    def test_new_with_key_hash_credential(self):
        """Test creating certificate with key hash credential."""
        hash_value = Blake2bHash.from_hex(CREDENTIAL_HEX)
        credential = Credential.from_hash(hash_value, CredentialType.KEY_HASH)
        cert = RegisterDRepCert.new(credential, 2000000)

        assert cert is not None
        assert cert.credential.type == CredentialType.KEY_HASH
        assert cert.deposit == 2000000

    def test_new_with_script_hash_credential(self):
        """Test creating certificate with script hash credential."""
        hash_value = Blake2bHash.from_hex("cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f")
        credential = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)
        cert = RegisterDRepCert.new(credential, 2000000)

        assert cert is not None
        assert cert.credential.type == CredentialType.SCRIPT_HASH
        assert cert.deposit == 2000000

    def test_new_with_anchor(self):
        """Test creating certificate with anchor."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = RegisterDRepCert.new(credential, 0, anchor)

        assert cert is not None
        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL

    def test_new_without_anchor(self):
        """Test creating certificate without anchor."""
        credential = new_default_credential()
        cert = RegisterDRepCert.new(credential, 0, None)

        assert cert is not None
        assert cert.anchor is None

    def test_new_with_zero_deposit(self):
        """Test creating certificate with zero deposit."""
        credential = new_default_credential()
        cert = RegisterDRepCert.new(credential, 0)

        assert cert is not None
        assert cert.deposit == 0

    def test_new_with_large_deposit(self):
        """Test creating certificate with large deposit amount."""
        credential = new_default_credential()
        large_deposit = 10000000000
        cert = RegisterDRepCert.new(credential, large_deposit)

        assert cert is not None
        assert cert.deposit == large_deposit

    def test_new_with_none_credential_raises_error(self):
        """Test that creating with None credential raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            RegisterDRepCert.new(None, 0)

    def test_new_with_invalid_type_raises_error(self):
        """Test that creating with invalid credential type raises error."""
        with pytest.raises(AttributeError):
            RegisterDRepCert.new("not a credential", 0)


class TestRegisterDRepCertFromCbor:
    """Tests for RegisterDRepCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate(self):
        """Test deserializing a certificate from CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert = RegisterDRepCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0
        assert cert.anchor is None

    def test_from_cbor_deserializes_certificate_with_anchor(self):
        """Test deserializing a certificate with anchor from CBOR."""
        reader = CborReader.from_hex(CBOR_WITH_ANCHOR)
        cert = RegisterDRepCert.from_cbor(reader)

        assert cert is not None
        assert cert.credential is not None
        assert cert.deposit == 0
        assert cert.anchor is not None
        assert cert.anchor.url == ANCHOR_URL

    def test_from_cbor_credential_matches_expected(self):
        """Test that deserialized credential matches expected value."""
        reader = CborReader.from_hex(CBOR)
        cert = RegisterDRepCert.from_cbor(reader)

        assert cert.credential.hash_hex == CREDENTIAL_HEX

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            RegisterDRepCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_uint_type_raises_error(self):
        """Test that invalid uint in CBOR raises error."""
        reader = CborReader.from_hex("84ef")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_raises_error(self):
        """Test that invalid credential in CBOR raises error."""
        reader = CborReader.from_hex("8410ef00581c0000000000000000000000000000000000000000000000000000000000f6")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_deposit_raises_error(self):
        """Test that invalid deposit in CBOR raises error."""
        reader = CborReader.from_hex("84108200581c00000000000000000000000000000000000000000000000000000000eff6")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)

    def test_from_cbor_with_invalid_anchor_raises_error(self):
        """Test that invalid anchor in CBOR raises error."""
        reader = CborReader.from_hex("84108200581c0000000000000000000000000000000000000000000000000000000000ef")
        with pytest.raises(CardanoError):
            RegisterDRepCert.from_cbor(reader)


class TestRegisterDRepCertToCbor:
    """Tests for RegisterDRepCert.to_cbor() method."""

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
        cert2 = RegisterDRepCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.deposit == cert2.deposit

    def test_to_cbor_roundtrip_with_anchor(self):
        """Test roundtrip with anchor."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert1 = RegisterDRepCert.new(credential, 0, anchor)

        writer = CborWriter()
        cert1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        cert2 = RegisterDRepCert.from_cbor(reader)

        assert cert1.credential.hash_hex == cert2.credential.hash_hex
        assert cert1.deposit == cert2.deposit
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


class TestRegisterDRepCertToCip116Json:
    """Tests for RegisterDRepCert.to_cip116_json() method."""

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
        """Test that CIP-116 JSON includes tag, drep_credential, and coin fields."""
        cert = new_default_cert()
        writer = JsonWriter()
        cert.to_cip116_json(writer)

        result = writer.encode()
        assert '"tag":"register_drep"' in result
        assert '"drep_credential"' in result
        assert '"coin"' in result

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


class TestRegisterDRepCertCredentialProperty:
    """Tests for RegisterDRepCert.credential property."""

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


class TestRegisterDRepCertDepositProperty:
    """Tests for RegisterDRepCert.deposit property."""

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


class TestRegisterDRepCertAnchorProperty:
    """Tests for RegisterDRepCert.anchor property."""

    def test_get_anchor_returns_none_when_not_set(self):
        """Test getting anchor when not set returns None."""
        cert = new_default_cert()
        anchor = cert.anchor

        assert anchor is None

    def test_get_anchor_returns_anchor_when_set(self):
        """Test getting anchor when set."""
        credential = new_default_credential()
        anchor = new_default_anchor()
        cert = RegisterDRepCert.new(credential, 0, anchor)

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
        cert = RegisterDRepCert.new(credential, 0, anchor)

        with pytest.raises(CardanoError):
            cert.anchor = None

    def test_set_anchor_with_invalid_type_raises_error(self):
        """Test that setting invalid anchor type raises error."""
        cert = new_default_cert()
        with pytest.raises(AttributeError):
            cert.anchor = "not an anchor"


class TestRegisterDRepCertRepr:
    """Tests for RegisterDRepCert.__repr__() method."""

    def test_repr_contains_deposit(self):
        """Test that repr contains deposit information."""
        cert = new_default_cert()
        repr_str = repr(cert)

        assert "RegisterDRepCert" in repr_str
        assert "deposit" in repr_str
        assert "0" in repr_str

    def test_repr_with_nonzero_deposit(self):
        """Test repr with non-zero deposit."""
        credential = new_default_credential()
        cert = RegisterDRepCert.new(credential, 2000000)
        repr_str = repr(cert)

        assert "2000000" in repr_str


class TestRegisterDRepCertContextManager:
    """Tests for RegisterDRepCert context manager support."""

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
            assert context_cert.anchor is None


class TestRegisterDRepCertEdgeCases:
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
        original_cert = RegisterDRepCert.new(credential, 2000000, anchor)

        writer = CborWriter()
        original_cert.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        restored_cert = RegisterDRepCert.from_cbor(reader)

        assert original_cert.credential.type == restored_cert.credential.type
        assert original_cert.credential.hash_hex == restored_cert.credential.hash_hex
        assert original_cert.deposit == restored_cert.deposit
        assert restored_cert.anchor is not None
        assert original_cert.anchor.url == restored_cert.anchor.url

    def test_certificate_with_maximum_deposit(self):
        """Test creating certificate with maximum possible deposit value."""
        credential = new_default_credential()
        max_deposit = (2**64) - 1
        cert = RegisterDRepCert.new(credential, max_deposit)

        assert cert.deposit == max_deposit
