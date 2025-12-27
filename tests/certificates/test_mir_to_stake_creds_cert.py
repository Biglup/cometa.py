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
    MirToStakeCredsCert,
    MirCertPotType,
    Credential,
    CredentialType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR_USE_RESERVES_TO_CREDS = "8200a18200581c0101010101010101010101010101010101010101010101010101010100"
CBOR_USE_TREASURY_TO_CREDS = "8201a18200581c0101010101010101010101010101010101010101010101010101010100"
CREDENTIAL_HASH = "01010101010101010101010101010101010101010101010101010101"
CREDENTIAL_HASH2 = "00010101010101010101010101010101010101010101010101010101"
CREDENTIAL_HASH3 = "ff010101010101010101010101010101010101010101010101010101"


def new_default_cert_reserve():
    """Creates a default MIR to stake credentials certificate with reserve pot for testing."""
    reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
    return MirToStakeCredsCert.from_cbor(reader)


def new_default_cert_treasury():
    """Creates a default MIR to stake credentials certificate with treasury pot for testing."""
    reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_CREDS)
    return MirToStakeCredsCert.from_cbor(reader)


class TestMirToStakeCredsCertNew:
    """Tests for MirToStakeCredsCert.new() factory method."""

    def test_new_creates_valid_certificate_with_reserve(self):
        """Test creating a new MIR to stake credentials certificate with reserve."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)

        assert cert is not None
        assert cert.pot == MirCertPotType.RESERVE
        assert len(cert) == 0

    def test_new_creates_valid_certificate_with_treasury(self):
        """Test creating a new MIR to stake credentials certificate with treasury."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)

        assert cert is not None
        assert cert.pot == MirCertPotType.TREASURY
        assert len(cert) == 0

    def test_new_with_invalid_pot_type_raises_error(self):
        """Test that creating with invalid pot type raises error."""
        with pytest.raises((CardanoError, ValueError, AttributeError)):
            MirToStakeCredsCert.new(999)


class TestMirToStakeCredsCertFromCbor:
    """Tests for MirToStakeCredsCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate_reserve(self):
        """Test deserializing a certificate with reserve pot from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        cert = MirToStakeCredsCert.from_cbor(reader)

        assert cert is not None
        assert cert.pot == MirCertPotType.RESERVE
        assert len(cert) == 1

    def test_from_cbor_deserializes_certificate_treasury(self):
        """Test deserializing a certificate with treasury pot from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_CREDS)
        cert = MirToStakeCredsCert.from_cbor(reader)

        assert cert is not None
        assert cert.pot == MirCertPotType.TREASURY
        assert len(cert) == 1

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            MirToStakeCredsCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MirToStakeCredsCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MirToStakeCredsCert.from_cbor(reader)

    def test_from_cbor_with_invalid_pot_type_raises_error(self):
        """Test that invalid pot type in CBOR raises error."""
        reader = CborReader.from_hex("820900")
        with pytest.raises(CardanoError):
            MirToStakeCredsCert.from_cbor(reader)

    def test_from_cbor_with_invalid_creds_raises_error(self):
        """Test that invalid credentials in CBOR raises error."""
        reader = CborReader.from_hex("8200ef")
        with pytest.raises(CardanoError):
            MirToStakeCredsCert.from_cbor(reader)


class TestMirToStakeCredsCertToCbor:
    """Tests for MirToStakeCredsCert.to_cbor() method."""

    def test_to_cbor_serializes_certificate_reserve(self):
        """Test serializing a certificate with reserve to CBOR."""
        cert = new_default_cert_reserve()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR_USE_RESERVES_TO_CREDS

    def test_to_cbor_serializes_certificate_treasury(self):
        """Test serializing a certificate with treasury to CBOR."""
        cert = new_default_cert_treasury()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR_USE_TREASURY_TO_CREDS

    def test_to_cbor_roundtrip_reserve(self):
        """Test that serialization and deserialization produce same result for reserve."""
        cert1 = new_default_cert_reserve()
        writer = CborWriter()
        cert1.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToStakeCredsCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert len(cert1) == len(cert2)

    def test_to_cbor_roundtrip_treasury(self):
        """Test that serialization and deserialization produce same result for treasury."""
        cert1 = new_default_cert_treasury()
        writer = CborWriter()
        cert1.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToStakeCredsCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert len(cert1) == len(cert2)

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, AttributeError)):
            cert.to_cbor(None)


class TestMirToStakeCredsCertPotProperty:
    """Tests for MirToStakeCredsCert.pot property."""

    def test_get_pot_returns_reserve(self):
        """Test getting the reserve pot from certificate."""
        cert = new_default_cert_reserve()
        pot = cert.pot

        assert pot == MirCertPotType.RESERVE

    def test_get_pot_returns_treasury(self):
        """Test getting the treasury pot from certificate."""
        cert = new_default_cert_treasury()
        pot = cert.pot

        assert pot == MirCertPotType.TREASURY

    def test_set_pot_updates_to_reserve(self):
        """Test setting pot to reserve."""
        cert = new_default_cert_treasury()
        cert.pot = MirCertPotType.RESERVE

        assert cert.pot == MirCertPotType.RESERVE

    def test_set_pot_updates_to_treasury(self):
        """Test setting pot to treasury."""
        cert = new_default_cert_reserve()
        cert.pot = MirCertPotType.TREASURY

        assert cert.pot == MirCertPotType.TREASURY

    def test_set_pot_with_invalid_type_raises_error(self):
        """Test that setting invalid pot type raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, ValueError, AttributeError)):
            cert.pot = 999

    def test_set_pot_with_none_raises_error(self):
        """Test that setting None pot raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, AttributeError)):
            cert.pot = None


class TestMirToStakeCredsCertInsert:
    """Tests for MirToStakeCredsCert.insert() method."""

    def test_insert_adds_credential_mapping(self):
        """Test inserting a credential-to-amount mapping."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)

        assert len(cert) == 0
        cert.insert(cred, 100)
        assert len(cert) == 1

    def test_insert_multiple_credentials(self):
        """Test inserting multiple credential mappings."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)

        cert.insert(cred1, 100)
        cert.insert(cred2, 200)

        assert len(cert) == 2

    def test_insert_with_zero_amount(self):
        """Test inserting credential with zero amount."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)

        cert.insert(cred, 0)
        assert len(cert) == 1

    def test_insert_with_large_amount(self):
        """Test inserting credential with large amount."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        large_amount = 45000000000000000

        cert.insert(cred, large_amount)
        assert len(cert) == 1

    def test_insert_with_none_credential_raises_error(self):
        """Test that inserting None credential raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        with pytest.raises((CardanoError, AttributeError)):
            cert.insert(None, 100)

    def test_insert_with_negative_amount_raises_error(self):
        """Test that inserting negative amount raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        with pytest.raises((CardanoError, OverflowError, ValueError)):
            cert.insert(cred, -1)

    def test_insert_keeps_credentials_sorted(self):
        """Test that credentials are kept sorted on insertion."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)
        cred3 = Credential.from_key_hash(CREDENTIAL_HASH3)

        cert.insert(cred1, 100)
        cert.insert(cred2, 200)
        cert.insert(cred3, 300)

        key0, val0 = cert.get_key_value_at(0)
        key1, val1 = cert.get_key_value_at(1)
        key2, val2 = cert.get_key_value_at(2)

        assert key0.hash_hex == CREDENTIAL_HASH2
        assert val0 == 200
        assert key1.hash_hex == CREDENTIAL_HASH
        assert val1 == 100
        assert key2.hash_hex == CREDENTIAL_HASH3
        assert val2 == 300


class TestMirToStakeCredsCertGetKeyAt:
    """Tests for MirToStakeCredsCert.get_key_at() method."""

    def test_get_key_at_returns_credential(self):
        """Test retrieving credential at index."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        retrieved = cert.get_key_at(0)
        assert retrieved is not None
        assert retrieved.hash_hex == CREDENTIAL_HASH

    def test_get_key_at_with_invalid_index_raises_error(self):
        """Test that retrieving with invalid index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises(CardanoError):
            cert.get_key_at(1)

    def test_get_key_at_with_negative_index_raises_error(self):
        """Test that retrieving with negative index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises((CardanoError, OverflowError)):
            cert.get_key_at(-1)

    def test_get_key_at_on_empty_cert_raises_error(self):
        """Test that retrieving from empty certificate raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        with pytest.raises(CardanoError):
            cert.get_key_at(0)


class TestMirToStakeCredsCertGetValueAt:
    """Tests for MirToStakeCredsCert.get_value_at() method."""

    def test_get_value_at_returns_amount(self):
        """Test retrieving amount at index."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        retrieved = cert.get_value_at(0)
        assert retrieved == 100

    def test_get_value_at_with_invalid_index_raises_error(self):
        """Test that retrieving with invalid index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises(CardanoError):
            cert.get_value_at(1)

    def test_get_value_at_with_negative_index_raises_error(self):
        """Test that retrieving with negative index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises((CardanoError, OverflowError)):
            cert.get_value_at(-1)

    def test_get_value_at_on_empty_cert_raises_error(self):
        """Test that retrieving from empty certificate raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        with pytest.raises(CardanoError):
            cert.get_value_at(0)


class TestMirToStakeCredsCertGetKeyValueAt:
    """Tests for MirToStakeCredsCert.get_key_value_at() method."""

    def test_get_key_value_at_returns_both(self):
        """Test retrieving both credential and amount at index."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        key, val = cert.get_key_value_at(0)
        assert key is not None
        assert key.hash_hex == CREDENTIAL_HASH
        assert val == 100

    def test_get_key_value_at_with_invalid_index_raises_error(self):
        """Test that retrieving with invalid index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises(CardanoError):
            cert.get_key_value_at(1)

    def test_get_key_value_at_with_negative_index_raises_error(self):
        """Test that retrieving with negative index raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        with pytest.raises((CardanoError, OverflowError)):
            cert.get_key_value_at(-1)

    def test_get_key_value_at_on_empty_cert_raises_error(self):
        """Test that retrieving from empty certificate raises error."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        with pytest.raises(CardanoError):
            cert.get_key_value_at(0)


class TestMirToStakeCredsCertLen:
    """Tests for MirToStakeCredsCert.__len__() method."""

    def test_len_returns_zero_for_empty_cert(self):
        """Test that length is zero for empty certificate."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        assert len(cert) == 0

    def test_len_returns_correct_count(self):
        """Test that length returns correct count after insertions."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)

        cert.insert(cred1, 100)
        assert len(cert) == 1

        cert.insert(cred2, 200)
        assert len(cert) == 2

    def test_len_after_deserialization(self):
        """Test that length is correct after deserialization."""
        cert = new_default_cert_reserve()
        assert len(cert) == 1


class TestMirToStakeCredsCertIter:
    """Tests for MirToStakeCredsCert.__iter__() method."""

    def test_iter_yields_all_mappings(self):
        """Test that iteration yields all credential-to-amount mappings."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)

        cert.insert(cred1, 100)
        cert.insert(cred2, 200)

        mappings = list(cert)
        assert len(mappings) == 2

    def test_iter_on_empty_cert(self):
        """Test iteration on empty certificate."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        mappings = list(cert)
        assert len(mappings) == 0

    def test_iter_returns_tuples(self):
        """Test that iteration returns tuples of (Credential, int)."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred = Credential.from_key_hash(CREDENTIAL_HASH)
        cert.insert(cred, 100)

        for key, val in cert:
            assert isinstance(key, Credential)
            assert isinstance(val, int)
            assert key.hash_hex == CREDENTIAL_HASH
            assert val == 100


class TestMirToStakeCredsCertToCip116Json:
    """Tests for MirToStakeCredsCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_treasury_correctly(self):
        """Test serializing certificate with treasury to CIP-116 JSON."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)
        cred3 = Credential.from_key_hash(CREDENTIAL_HASH3)

        cert.insert(cred1, 100)
        cert.insert(cred2, 200)
        cert.insert(cred3, 300)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"to_stake_creds","pot":"treasury","rewards":[{"key":{"tag":"pubkey_hash","value":"00010101010101010101010101010101010101010101010101010101"},"value":"200"},{"key":{"tag":"pubkey_hash","value":"01010101010101010101010101010101010101010101010101010101"},"value":"100"},{"key":{"tag":"pubkey_hash","value":"ff010101010101010101010101010101010101010101010101010101"},"value":"300"}]}'
        assert result == expected

    def test_to_cip116_json_serializes_reserves_correctly(self):
        """Test serializing certificate with reserves to CIP-116 JSON."""
        cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        cred1 = Credential.from_key_hash(CREDENTIAL_HASH)
        cred2 = Credential.from_key_hash(CREDENTIAL_HASH2)
        cred3 = Credential.from_key_hash(CREDENTIAL_HASH3)

        cert.insert(cred1, 100)
        cert.insert(cred2, 200)
        cert.insert(cred3, 300)

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"to_stake_creds","pot":"reserves","rewards":[{"key":{"tag":"pubkey_hash","value":"00010101010101010101010101010101010101010101010101010101"},"value":"200"},{"key":{"tag":"pubkey_hash","value":"01010101010101010101010101010101010101010101010101010101"},"value":"100"},{"key":{"tag":"pubkey_hash","value":"ff010101010101010101010101010101010101010101010101010101"},"value":"300"}]}'
        assert result == expected

    def test_to_cip116_json_includes_tag(self):
        """Test that JSON includes 'to_stake_creds' tag."""
        cert = new_default_cert_treasury()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_stake_creds"' in result

    def test_to_cip116_json_includes_pot(self):
        """Test that JSON includes pot field."""
        cert = new_default_cert_reserve()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"pot":"reserves"' in result

    def test_to_cip116_json_includes_rewards(self):
        """Test that JSON includes rewards field."""
        cert = new_default_cert_treasury()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"rewards":[' in result

    def test_to_cip116_json_with_none_writer_raises_error(self):
        """Test that None writer raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, TypeError)):
            cert.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that invalid writer type raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises(TypeError):
            cert.to_cip116_json("not a writer")


class TestMirToStakeCredsCertLifecycle:
    """Tests for certificate lifecycle management."""

    def test_certificate_can_be_created_and_destroyed(self):
        """Test that certificate can be properly managed."""
        cert = new_default_cert_reserve()
        assert cert is not None
        del cert

    def test_context_manager_support(self):
        """Test using certificate as context manager."""
        with new_default_cert_reserve() as cert:
            assert cert is not None
            assert cert.pot == MirCertPotType.RESERVE
            assert len(cert) == 1

    def test_repr_returns_string(self):
        """Test that repr returns a string representation."""
        cert = new_default_cert_reserve()
        result = repr(cert)

        assert isinstance(result, str)
        assert "MirToStakeCredsCert" in result
        assert "RESERVE" in result

    def test_repr_includes_pot_and_size(self):
        """Test that repr includes pot and size information."""
        cert = new_default_cert_treasury()
        result = repr(cert)

        assert "TREASURY" in result
        assert "size=1" in result


class TestMirToStakeCredsCertEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_get_pot_calls(self):
        """Test that multiple pot retrievals work correctly."""
        cert = new_default_cert_reserve()
        pot1 = cert.pot
        pot2 = cert.pot

        assert pot1 == pot2

    def test_set_then_get_pot(self):
        """Test setting and getting pot in sequence."""
        cert = new_default_cert_reserve()
        original_pot = cert.pot

        cert.pot = MirCertPotType.TREASURY
        retrieved = cert.pot

        assert retrieved != original_pot
        assert retrieved == MirCertPotType.TREASURY

    def test_serialize_after_pot_change(self):
        """Test serialization after changing pot."""
        cert = new_default_cert_reserve()
        cert.pot = MirCertPotType.TREASURY

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result == CBOR_USE_TREASURY_TO_CREDS

    def test_roundtrip_after_modifications(self):
        """Test roundtrip after modifying certificate."""
        cert1 = new_default_cert_reserve()
        cert1.pot = MirCertPotType.TREASURY

        writer = CborWriter()
        cert1.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToStakeCredsCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert len(cert1) == len(cert2)

    def test_roundtrip_with_both_pot_types(self):
        """Test roundtrip with both pot types."""
        for pot_type in [MirCertPotType.RESERVE, MirCertPotType.TREASURY]:
            cert1 = MirToStakeCredsCert.new(pot_type)
            cred = Credential.from_key_hash(CREDENTIAL_HASH)
            cert1.insert(cred, 100)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = MirToStakeCredsCert.from_cbor(reader)

            assert cert1.pot == cert2.pot
            assert len(cert1) == len(cert2)

    def test_json_serialization_after_modification(self):
        """Test JSON serialization after modifying certificate."""
        cert = new_default_cert_reserve()
        cert.pot = MirCertPotType.TREASURY

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"pot":"treasury"' in result

    def test_multiple_insertions_and_retrievals(self):
        """Test multiple insertions and retrievals work correctly."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        credentials = [CREDENTIAL_HASH, CREDENTIAL_HASH2, CREDENTIAL_HASH3]
        amounts = [100, 200, 300]

        for cred_hash, amount in zip(credentials, amounts):
            cred = Credential.from_key_hash(cred_hash)
            cert.insert(cred, amount)

        assert len(cert) == 3

        for i in range(len(cert)):
            key, val = cert.get_key_value_at(i)
            assert key is not None
            assert val in amounts

    def test_empty_certificate_serialization(self):
        """Test serializing an empty certificate."""
        cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None

        reader = CborReader.from_hex(result)
        cert2 = MirToStakeCredsCert.from_cbor(reader)

        assert cert.pot == cert2.pot
        assert len(cert) == len(cert2) == 0
