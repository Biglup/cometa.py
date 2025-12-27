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
    MirCert,
    MirToPotCert,
    MirToStakeCredsCert,
    MirCertType,
    MirCertPotType,
    Credential,
    CredentialType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR_USE_RESERVES_TO_POT = "820682001a000f4240"
CBOR_USE_TREASURY_TO_POT = "820682011a000f4240"
CBOR_USE_RESERVES_TO_CREDS = "82068200a18200581c0101010101010101010101010101010101010101010101010101010100"
CBOR_USE_TREASURY_TO_CREDS = "82068201a18200581c0101010101010101010101010101010101010101010101010101010100"
CBOR_INNER_TREASURY_TO_CREDS = "8201a18200581c0101010101010101010101010101010101010101010101010101010100"
CREDENTIAL_HASH = "01010101010101010101010101010101010101010101010101010101"


def new_default_mir_to_pot_cert():
    """Creates a default MIR to pot certificate for testing."""
    return MirToPotCert.new(MirCertPotType.RESERVE, 1000000)


def new_default_mir_to_stake_creds_cert():
    """Creates a default MIR to stake credentials certificate for testing."""
    reader = CborReader.from_hex(CBOR_INNER_TREASURY_TO_CREDS)
    return MirToStakeCredsCert.from_cbor(reader)


class TestMirCertNewToOtherPot:
    """Tests for MirCert.new_to_other_pot() factory method."""

    def test_new_to_other_pot_creates_valid_certificate(self):
        """Test creating a MIR certificate for pot transfer."""
        pot_cert = new_default_mir_to_pot_cert()
        mir_cert = MirCert.new_to_other_pot(pot_cert)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_POT

    def test_new_to_other_pot_with_reserve(self):
        """Test creating certificate with reserve pot."""
        pot_cert = MirToPotCert.new(MirCertPotType.RESERVE, 1000000000)
        mir_cert = MirCert.new_to_other_pot(pot_cert)

        assert mir_cert is not None
        retrieved_pot_cert = mir_cert.as_to_other_pot()
        assert retrieved_pot_cert.pot == MirCertPotType.RESERVE
        assert retrieved_pot_cert.amount == 1000000000

    def test_new_to_other_pot_with_treasury(self):
        """Test creating certificate with treasury pot."""
        pot_cert = MirToPotCert.new(MirCertPotType.TREASURY, 5000000)
        mir_cert = MirCert.new_to_other_pot(pot_cert)

        assert mir_cert is not None
        retrieved_pot_cert = mir_cert.as_to_other_pot()
        assert retrieved_pot_cert.pot == MirCertPotType.TREASURY
        assert retrieved_pot_cert.amount == 5000000

    def test_new_to_other_pot_with_none_raises_error(self):
        """Test that creating with None raises error."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            MirCert.new_to_other_pot(None)


class TestMirCertNewToStakeCreds:
    """Tests for MirCert.new_to_stake_creds() factory method."""

    def test_new_to_stake_creds_creates_valid_certificate(self):
        """Test creating a MIR certificate for stake credentials transfer."""
        creds_cert = new_default_mir_to_stake_creds_cert()
        mir_cert = MirCert.new_to_stake_creds(creds_cert)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_STAKE_CREDS

    def test_new_to_stake_creds_with_reserve(self):
        """Test creating certificate with reserve pot."""
        creds_cert = MirToStakeCredsCert.new(MirCertPotType.RESERVE)
        credential = Credential.from_hex(CREDENTIAL_HASH, CredentialType.KEY_HASH)
        creds_cert.insert(credential, 100000)
        mir_cert = MirCert.new_to_stake_creds(creds_cert)

        assert mir_cert is not None
        retrieved_creds_cert = mir_cert.as_to_stake_creds()
        assert retrieved_creds_cert.pot == MirCertPotType.RESERVE
        assert len(retrieved_creds_cert) == 1

    def test_new_to_stake_creds_with_treasury(self):
        """Test creating certificate with treasury pot."""
        creds_cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        credential = Credential.from_hex(CREDENTIAL_HASH, CredentialType.KEY_HASH)
        creds_cert.insert(credential, 200000)
        mir_cert = MirCert.new_to_stake_creds(creds_cert)

        assert mir_cert is not None
        retrieved_creds_cert = mir_cert.as_to_stake_creds()
        assert retrieved_creds_cert.pot == MirCertPotType.TREASURY

    def test_new_to_stake_creds_with_none_raises_error(self):
        """Test that creating with None raises error."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            MirCert.new_to_stake_creds(None)


class TestMirCertFromCbor:
    """Tests for MirCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_to_pot_reserve(self):
        """Test deserializing a to-pot certificate with reserve from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_POT

    def test_from_cbor_deserializes_to_pot_treasury(self):
        """Test deserializing a to-pot certificate with treasury from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_POT

    def test_from_cbor_deserializes_to_stake_creds_reserve(self):
        """Test deserializing a to-stake-creds certificate with reserve from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_STAKE_CREDS

    def test_from_cbor_deserializes_to_stake_creds_treasury(self):
        """Test deserializing a to-stake-creds certificate with treasury from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert is not None
        assert mir_cert.cert_type == MirCertType.TO_STAKE_CREDS

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_wrong_cert_type_raises_error(self):
        """Test that wrong certificate type raises error."""
        reader = CborReader.from_hex("820900")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_raises_error(self):
        """Test that invalid array structure raises error."""
        reader = CborReader.from_hex("820600")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_invalid_pot_type_raises_error(self):
        """Test that invalid pot type raises error."""
        reader = CborReader.from_hex("8206820909")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_invalid_to_pot_data_raises_error(self):
        """Test that invalid to-pot data raises error."""
        reader = CborReader.from_hex("82068200")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_invalid_to_creds_data_raises_error(self):
        """Test that invalid to-creds data raises error."""
        reader = CborReader.from_hex("8206820182")
        with pytest.raises(CardanoError):
            MirCert.from_cbor(reader)

    def test_from_cbor_with_none_reader_raises_error(self):
        """Test that None reader raises error."""
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            MirCert.from_cbor(None)


class TestMirCertToCbor:
    """Tests for MirCert.to_cbor() method."""

    def test_to_cbor_serializes_to_pot_certificate(self):
        """Test serializing a to-pot certificate to CBOR."""
        pot_cert = MirToPotCert.new(MirCertPotType.TREASURY, 1000000)
        mir_cert = MirCert.new_to_other_pot(pot_cert)
        writer = CborWriter()

        mir_cert.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR_USE_TREASURY_TO_POT

    def test_to_cbor_serializes_to_stake_creds_certificate(self):
        """Test serializing a to-stake-creds certificate to CBOR."""
        creds_cert = MirToStakeCredsCert.new(MirCertPotType.TREASURY)
        credential = Credential.from_hex(CREDENTIAL_HASH, CredentialType.KEY_HASH)
        creds_cert.insert(credential, 0)
        mir_cert = MirCert.new_to_stake_creds(creds_cert)
        writer = CborWriter()

        mir_cert.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR_USE_TREASURY_TO_CREDS

    def test_to_cbor_round_trip_to_pot(self):
        """Test CBOR serialization round-trip for to-pot certificate."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        original_cert = MirCert.from_cbor(reader)

        writer = CborWriter()
        original_cert.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized_cert = MirCert.from_cbor(reader2)

        assert deserialized_cert.cert_type == original_cert.cert_type

    def test_to_cbor_round_trip_to_creds(self):
        """Test CBOR serialization round-trip for to-creds certificate."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        original_cert = MirCert.from_cbor(reader)

        writer = CborWriter()
        original_cert.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized_cert = MirCert.from_cbor(reader2)

        assert deserialized_cert.cert_type == original_cert.cert_type

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that None writer raises error."""
        pot_cert = new_default_mir_to_pot_cert()
        mir_cert = MirCert.new_to_other_pot(pot_cert)

        with pytest.raises((CardanoError, AttributeError, TypeError)):
            mir_cert.to_cbor(None)


class TestMirCertCertType:
    """Tests for MirCert.cert_type property."""

    def test_cert_type_returns_to_pot_for_pot_certificate(self):
        """Test that cert_type returns TO_POT for pot certificates."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert.cert_type == MirCertType.TO_POT

    def test_cert_type_returns_to_stake_creds_for_creds_certificate(self):
        """Test that cert_type returns TO_STAKE_CREDS for creds certificates."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        assert mir_cert.cert_type == MirCertType.TO_STAKE_CREDS


class TestMirCertAsToOtherPot:
    """Tests for MirCert.as_to_other_pot() method."""

    def test_as_to_other_pot_returns_pot_certificate(self):
        """Test retrieving certificate as MirToPotCert."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        pot_cert = mir_cert.as_to_other_pot()

        assert pot_cert is not None
        assert pot_cert.pot == MirCertPotType.RESERVE
        assert pot_cert.amount == 1000000

    def test_as_to_other_pot_with_treasury_pot(self):
        """Test retrieving pot certificate with treasury."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        pot_cert = mir_cert.as_to_other_pot()

        assert pot_cert is not None
        assert pot_cert.pot == MirCertPotType.TREASURY

    def test_as_to_other_pot_on_stake_creds_cert_raises_error(self):
        """Test that calling as_to_other_pot on stake creds cert raises error."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        with pytest.raises(CardanoError):
            mir_cert.as_to_other_pot()


class TestMirCertAsToStakeCreds:
    """Tests for MirCert.as_to_stake_creds() method."""

    def test_as_to_stake_creds_returns_creds_certificate(self):
        """Test retrieving certificate as MirToStakeCredsCert."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        creds_cert = mir_cert.as_to_stake_creds()

        assert creds_cert is not None
        assert creds_cert.pot == MirCertPotType.RESERVE
        assert len(creds_cert) == 1

    def test_as_to_stake_creds_with_treasury_pot(self):
        """Test retrieving creds certificate with treasury."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        creds_cert = mir_cert.as_to_stake_creds()

        assert creds_cert is not None
        assert creds_cert.pot == MirCertPotType.TREASURY

    def test_as_to_stake_creds_on_pot_cert_raises_error(self):
        """Test that calling as_to_stake_creds on pot cert raises error."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        with pytest.raises(CardanoError):
            mir_cert.as_to_stake_creds()


class TestMirCertToCip116Json:
    """Tests for MirCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_to_pot_reserve(self):
        """Test serializing to-pot certificate with reserve to CIP-116 JSON."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)
        writer = JsonWriter()

        mir_cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_other_pot"' in result
        assert '"pot":"reserves"' in result
        assert '"amount":"1000000"' in result

    def test_to_cip116_json_serializes_to_pot_treasury(self):
        """Test serializing to-pot certificate with treasury to CIP-116 JSON."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_POT)
        mir_cert = MirCert.from_cbor(reader)
        writer = JsonWriter()

        mir_cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_other_pot"' in result
        assert '"pot":"treasury"' in result
        assert '"amount":"1000000"' in result

    def test_to_cip116_json_serializes_to_stake_creds_reserve(self):
        """Test serializing to-stake-creds certificate with reserve to CIP-116 JSON."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)
        writer = JsonWriter()

        mir_cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_stake_creds"' in result
        assert '"pot":"reserves"' in result
        assert '"rewards"' in result

    def test_to_cip116_json_serializes_to_stake_creds_treasury(self):
        """Test serializing to-stake-creds certificate with treasury to CIP-116 JSON."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)
        writer = JsonWriter()

        mir_cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_stake_creds"' in result
        assert '"pot":"treasury"' in result
        assert '"rewards"' in result

    def test_to_cip116_json_with_none_writer_raises_error(self):
        """Test that None writer raises error."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        with pytest.raises((CardanoError, TypeError)):
            mir_cert.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that invalid writer type raises error."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        with pytest.raises(TypeError):
            mir_cert.to_cip116_json("not a writer")


class TestMirCertRepr:
    """Tests for MirCert.__repr__() method."""

    def test_repr_includes_cert_type_to_pot(self):
        """Test that __repr__ includes the certificate type for to-pot cert."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        repr_str = repr(mir_cert)

        assert "MirCert" in repr_str
        assert "TO_POT" in repr_str

    def test_repr_includes_cert_type_to_stake_creds(self):
        """Test that __repr__ includes the certificate type for to-stake-creds cert."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_CREDS)
        mir_cert = MirCert.from_cbor(reader)

        repr_str = repr(mir_cert)

        assert "MirCert" in repr_str
        assert "TO_STAKE_CREDS" in repr_str


class TestMirCertContextManager:
    """Tests for MirCert context manager protocol."""

    def test_context_manager_enter_exit(self):
        """Test that MirCert can be used as a context manager."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        mir_cert = MirCert.from_cbor(reader)

        with mir_cert as cert:
            assert cert is not None
            assert cert.cert_type == MirCertType.TO_POT

    def test_context_manager_with_operations(self):
        """Test performing operations within context manager."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)

        with MirCert.from_cbor(reader) as mir_cert:
            pot_cert = mir_cert.as_to_other_pot()
            assert pot_cert.amount == 1000000
