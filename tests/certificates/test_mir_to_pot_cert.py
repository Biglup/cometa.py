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
    MirToPotCert,
    MirCertPotType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR_USE_RESERVES_TO_POT = "82001a000f4240"
CBOR_USE_TREASURY_TO_POT = "82011a000f4240"
AMOUNT = 1000000


def new_default_cert_reserve():
    """Creates a default MIR to pot certificate with reserve pot for testing."""
    reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
    return MirToPotCert.from_cbor(reader)


def new_default_cert_treasury():
    """Creates a default MIR to pot certificate with treasury pot for testing."""
    reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_POT)
    return MirToPotCert.from_cbor(reader)


class TestMirToPotCertNew:
    """Tests for MirToPotCert.new() factory method."""

    def test_new_creates_valid_certificate_with_reserve(self):
        """Test creating a new MIR to pot certificate with reserve."""
        cert = MirToPotCert.new(MirCertPotType.RESERVE, AMOUNT)

        assert cert is not None
        assert cert.pot == MirCertPotType.RESERVE
        assert cert.amount == AMOUNT

    def test_new_creates_valid_certificate_with_treasury(self):
        """Test creating a new MIR to pot certificate with treasury."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, AMOUNT)

        assert cert is not None
        assert cert.pot == MirCertPotType.TREASURY
        assert cert.amount == AMOUNT

    def test_new_with_zero_amount(self):
        """Test creating certificate with zero amount."""
        cert = MirToPotCert.new(MirCertPotType.RESERVE, 0)

        assert cert is not None
        assert cert.amount == 0

    def test_new_with_large_amount(self):
        """Test creating certificate with large amount."""
        large_amount = 45000000000000000
        cert = MirToPotCert.new(MirCertPotType.TREASURY, large_amount)

        assert cert is not None
        assert cert.amount == large_amount

    def test_new_with_invalid_pot_type_raises_error(self):
        """Test that creating with invalid pot type raises error."""
        with pytest.raises((CardanoError, ValueError, AttributeError)):
            MirToPotCert.new(999, AMOUNT)

    def test_new_with_negative_amount_raises_error(self):
        """Test that creating with negative amount raises error."""
        with pytest.raises((CardanoError, OverflowError, ValueError)):
            MirToPotCert.new(MirCertPotType.RESERVE, -1)


class TestMirToPotCertFromCbor:
    """Tests for MirToPotCert.from_cbor() factory method."""

    def test_from_cbor_deserializes_certificate_reserve(self):
        """Test deserializing a certificate with reserve pot from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_RESERVES_TO_POT)
        cert = MirToPotCert.from_cbor(reader)

        assert cert is not None
        assert cert.pot == MirCertPotType.RESERVE
        assert cert.amount == AMOUNT

    def test_from_cbor_deserializes_certificate_treasury(self):
        """Test deserializing a certificate with treasury pot from CBOR."""
        reader = CborReader.from_hex(CBOR_USE_TREASURY_TO_POT)
        cert = MirToPotCert.from_cbor(reader)

        assert cert is not None
        assert cert.pot == MirCertPotType.TREASURY
        assert cert.amount == AMOUNT

    def test_from_cbor_with_none_raises_error(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            MirToPotCert.from_cbor(None)

    def test_from_cbor_with_invalid_data_raises_error(self):
        """Test that invalid CBOR data raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MirToPotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_array_type_raises_error(self):
        """Test that non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            MirToPotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_pot_type_raises_error(self):
        """Test that invalid pot type in CBOR raises error."""
        reader = CborReader.from_hex("820900")
        with pytest.raises(CardanoError):
            MirToPotCert.from_cbor(reader)

    def test_from_cbor_with_invalid_amount_raises_error(self):
        """Test that invalid amount in CBOR raises error."""
        reader = CborReader.from_hex("8200ef")
        with pytest.raises(CardanoError):
            MirToPotCert.from_cbor(reader)


class TestMirToPotCertToCbor:
    """Tests for MirToPotCert.to_cbor() method."""

    def test_to_cbor_serializes_certificate_reserve(self):
        """Test serializing a certificate with reserve to CBOR."""
        cert = new_default_cert_reserve()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR_USE_RESERVES_TO_POT

    def test_to_cbor_serializes_certificate_treasury(self):
        """Test serializing a certificate with treasury to CBOR."""
        cert = new_default_cert_treasury()
        writer = CborWriter()
        cert.to_cbor(writer)

        result = writer.to_hex()
        assert result == CBOR_USE_TREASURY_TO_POT

    def test_to_cbor_roundtrip_reserve(self):
        """Test that serialization and deserialization produce same result for reserve."""
        cert1 = new_default_cert_reserve()
        writer = CborWriter()
        cert1.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToPotCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert cert1.amount == cert2.amount

    def test_to_cbor_roundtrip_treasury(self):
        """Test that serialization and deserialization produce same result for treasury."""
        cert1 = new_default_cert_treasury()
        writer = CborWriter()
        cert1.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToPotCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert cert1.amount == cert2.amount

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that serializing with None writer raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, AttributeError)):
            cert.to_cbor(None)


class TestMirToPotCertPotProperty:
    """Tests for MirToPotCert.pot property."""

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


class TestMirToPotCertAmountProperty:
    """Tests for MirToPotCert.amount property."""

    def test_get_amount_returns_correct_value(self):
        """Test getting the amount from certificate."""
        cert = new_default_cert_reserve()
        amount = cert.amount

        assert amount == AMOUNT

    def test_set_amount_updates_amount(self):
        """Test setting a new amount."""
        cert = new_default_cert_reserve()
        new_amount = 2000000

        cert.amount = new_amount
        assert cert.amount == new_amount

    def test_set_amount_to_zero(self):
        """Test setting amount to zero."""
        cert = new_default_cert_reserve()
        cert.amount = 0

        assert cert.amount == 0

    def test_set_amount_to_large_value(self):
        """Test setting amount to large value."""
        cert = new_default_cert_reserve()
        large_amount = 45000000000000000
        cert.amount = large_amount

        assert cert.amount == large_amount

    def test_set_amount_with_negative_raises_error(self):
        """Test that setting negative amount raises error."""
        cert = new_default_cert_reserve()
        with pytest.raises((CardanoError, OverflowError, ValueError)):
            cert.amount = -1

    def test_multiple_amount_changes(self):
        """Test changing amount multiple times."""
        cert = new_default_cert_reserve()
        amounts = [100, 1000, 10000, 100000]

        for amt in amounts:
            cert.amount = amt
            assert cert.amount == amt


class TestMirToPotCertToCip116Json:
    """Tests for MirToPotCert.to_cip116_json() method."""

    def test_to_cip116_json_serializes_treasury_correctly(self):
        """Test serializing certificate with treasury to CIP-116 JSON."""
        cert = MirToPotCert.new(MirCertPotType.TREASURY, AMOUNT)
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"to_other_pot","pot":"treasury","amount":"1000000"}'
        assert result == expected

    def test_to_cip116_json_serializes_reserves_correctly(self):
        """Test serializing certificate with reserves to CIP-116 JSON."""
        cert = MirToPotCert.new(MirCertPotType.RESERVE, AMOUNT)
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        expected = '{"tag":"to_other_pot","pot":"reserves","amount":"1000000"}'
        assert result == expected

    def test_to_cip116_json_includes_tag(self):
        """Test that JSON includes 'to_other_pot' tag."""
        cert = new_default_cert_treasury()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"tag":"to_other_pot"' in result

    def test_to_cip116_json_includes_pot(self):
        """Test that JSON includes pot field."""
        cert = new_default_cert_reserve()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"pot":"reserves"' in result

    def test_to_cip116_json_includes_amount(self):
        """Test that JSON includes amount field."""
        cert = new_default_cert_treasury()
        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"amount":"1000000"' in result

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


class TestMirToPotCertLifecycle:
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
            assert cert.amount == AMOUNT

    def test_repr_returns_string(self):
        """Test that repr returns a string representation."""
        cert = new_default_cert_reserve()
        result = repr(cert)

        assert isinstance(result, str)
        assert "MirToPotCert" in result
        assert "RESERVE" in result
        assert str(AMOUNT) in result

    def test_repr_includes_pot_and_amount(self):
        """Test that repr includes pot and amount information."""
        cert = new_default_cert_treasury()
        result = repr(cert)

        assert "TREASURY" in result
        assert str(AMOUNT) in result


class TestMirToPotCertEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_get_pot_calls(self):
        """Test that multiple pot retrievals work correctly."""
        cert = new_default_cert_reserve()
        pot1 = cert.pot
        pot2 = cert.pot

        assert pot1 == pot2

    def test_multiple_get_amount_calls(self):
        """Test that multiple amount retrievals work correctly."""
        cert = new_default_cert_reserve()
        amount1 = cert.amount
        amount2 = cert.amount

        assert amount1 == amount2

    def test_set_then_get_pot(self):
        """Test setting and getting pot in sequence."""
        cert = new_default_cert_reserve()
        original_pot = cert.pot

        cert.pot = MirCertPotType.TREASURY
        retrieved = cert.pot

        assert retrieved != original_pot
        assert retrieved == MirCertPotType.TREASURY

    def test_set_then_get_amount(self):
        """Test setting and getting amount in sequence."""
        cert = new_default_cert_reserve()
        original_amount = cert.amount

        new_amount = 5000000
        cert.amount = new_amount
        retrieved = cert.amount

        assert retrieved != original_amount
        assert retrieved == new_amount

    def test_serialize_after_pot_change(self):
        """Test serialization after changing pot."""
        cert = new_default_cert_reserve()
        cert.pot = MirCertPotType.TREASURY

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result == CBOR_USE_TREASURY_TO_POT

    def test_serialize_after_amount_change(self):
        """Test serialization after changing amount."""
        cert = new_default_cert_reserve()
        cert.amount = 2000000

        writer = CborWriter()
        cert.to_cbor(writer)
        result = writer.to_hex()

        assert result is not None
        assert result != CBOR_USE_RESERVES_TO_POT

    def test_roundtrip_after_modifications(self):
        """Test roundtrip after modifying certificate."""
        cert1 = new_default_cert_reserve()
        cert1.pot = MirCertPotType.TREASURY
        cert1.amount = 3000000

        writer = CborWriter()
        cert1.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        cert2 = MirToPotCert.from_cbor(reader)

        assert cert1.pot == cert2.pot
        assert cert1.amount == cert2.amount

    def test_roundtrip_with_both_pot_types(self):
        """Test roundtrip with both pot types."""
        for pot_type in [MirCertPotType.RESERVE, MirCertPotType.TREASURY]:
            cert1 = MirToPotCert.new(pot_type, AMOUNT)

            writer = CborWriter()
            cert1.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            cert2 = MirToPotCert.from_cbor(reader)

            assert cert1.pot == cert2.pot
            assert cert1.amount == cert2.amount

    def test_json_serialization_after_modification(self):
        """Test JSON serialization after modifying certificate."""
        cert = new_default_cert_reserve()
        cert.pot = MirCertPotType.TREASURY
        cert.amount = 7500000

        writer = JsonWriter()
        cert.to_cip116_json(writer)
        result = writer.encode()

        assert '"pot":"treasury"' in result
        assert '"amount":"7500000"' in result
