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
    CertificateSet,
    Certificate,
    StakeRegistrationCert,
    StakeDeregistrationCert,
    Credential,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "d901028483078200581c000000000000000000000000000000000000000000000000000000000083088200581c0000000000000000000000000000000000000000000000000000000000830f8200581c00000000000000000000000000000000000000000000000000000000f683028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
CBOR_WITHOUT_TAG = "8483078200581c000000000000000000000000000000000000000000000000000000000083088200581c0000000000000000000000000000000000000000000000000000000000830f8200581c00000000000000000000000000000000000000000000000000000000f683028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
CERTIFICATE1_CBOR = "83078200581c0000000000000000000000000000000000000000000000000000000000"
CERTIFICATE2_CBOR = "83088200581c0000000000000000000000000000000000000000000000000000000000"
CERTIFICATE3_CBOR = "830f8200581c00000000000000000000000000000000000000000000000000000000f6"
CERTIFICATE4_CBOR = "83028200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
EMPTY_SET_CBOR = "d9010280"


def new_default_certificate(cbor_hex: str) -> Certificate:
    """Creates a certificate from CBOR hex string."""
    reader = CborReader.from_hex(cbor_hex)
    return Certificate.from_cbor(reader)


def new_default_credential():
    """Creates a default credential for testing."""
    cbor_hex = "8200581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f"
    reader = CborReader.from_hex(cbor_hex)
    return Credential.from_cbor(reader)


class TestCertificateSetNew:
    """Tests for CertificateSet.new() factory method."""

    def test_new_creates_empty_set(self):
        """Test creating a new empty certificate set."""
        cert_set = CertificateSet.new()
        assert cert_set is not None
        assert len(cert_set) == 0

    def test_new_set_can_be_used_with_context_manager(self):
        """Test that new set can be used with context manager."""
        with CertificateSet.new() as cert_set:
            assert cert_set is not None
            assert len(cert_set) == 0

    def test_new_set_has_correct_repr(self):
        """Test that new set has correct string representation."""
        cert_set = CertificateSet.new()
        assert repr(cert_set) == "CertificateSet(len=0)"


class TestCertificateSetFromCbor:
    """Tests for CertificateSet.from_cbor() factory method."""

    def test_from_cbor_deserializes_empty_set(self):
        """Test deserializing an empty certificate set from CBOR."""
        reader = CborReader.from_hex(EMPTY_SET_CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        assert cert_set is not None
        assert len(cert_set) == 0

    def test_from_cbor_deserializes_set_with_certificates(self):
        """Test deserializing a certificate set with multiple certificates."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        assert cert_set is not None
        assert len(cert_set) == 4

    def test_from_cbor_without_tag(self):
        """Test deserializing CBOR without tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        cert_set = CertificateSet.from_cbor(reader)
        assert cert_set is not None
        assert len(cert_set) == 4

    def test_from_cbor_certificates_match_expected(self):
        """Test that deserialized certificates match expected values."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        certificates = [CERTIFICATE1_CBOR, CERTIFICATE2_CBOR, CERTIFICATE3_CBOR, CERTIFICATE4_CBOR]

        for i, expected_cbor in enumerate(certificates):
            cert = cert_set[i]
            writer = CborWriter()
            cert.to_cbor(writer)
            actual_cbor = writer.to_hex()
            assert actual_cbor == expected_cbor

    def test_from_cbor_with_none_reader_raises_error(self):
        """Test that from_cbor with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            CertificateSet.from_cbor(None)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that from_cbor with invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            CertificateSet.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test that from_cbor with non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            CertificateSet.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test that from_cbor with invalid elements raises error."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            CertificateSet.from_cbor(reader)

    def test_from_cbor_with_missing_end_array_raises_error(self):
        """Test that from_cbor with missing end array raises error."""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            CertificateSet.from_cbor(reader)


class TestCertificateSetFromList:
    """Tests for CertificateSet.from_list() factory method."""

    def test_from_list_creates_set_from_certificates(self):
        """Test creating a set from a list of certificates."""
        certs = [
            new_default_certificate(CERTIFICATE1_CBOR),
            new_default_certificate(CERTIFICATE2_CBOR)
        ]
        cert_set = CertificateSet.from_list(certs)
        assert cert_set is not None
        assert len(cert_set) == 2

    def test_from_list_with_empty_list(self):
        """Test creating a set from an empty list."""
        cert_set = CertificateSet.from_list([])
        assert cert_set is not None
        assert len(cert_set) == 0

    def test_from_list_with_specific_cert_types(self):
        """Test creating a set from specific certificate types."""
        credential = new_default_credential()
        certs = [
            StakeRegistrationCert.new(credential),
            StakeDeregistrationCert.new(credential)
        ]
        cert_set = CertificateSet.from_list(certs)
        assert cert_set is not None
        assert len(cert_set) == 2

    def test_from_list_with_mixed_cert_types(self):
        """Test creating a set from mixed certificate types."""
        cert1 = new_default_certificate(CERTIFICATE1_CBOR)
        credential = new_default_credential()
        cert2 = StakeRegistrationCert.new(credential)

        cert_set = CertificateSet.from_list([cert1, cert2])
        assert cert_set is not None
        assert len(cert_set) == 2


class TestCertificateSetToCbor:
    """Tests for CertificateSet.to_cbor() method."""

    def test_to_cbor_serializes_empty_set(self):
        """Test serializing an empty certificate set to CBOR."""
        cert_set = CertificateSet.new()
        writer = CborWriter()
        cert_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == EMPTY_SET_CBOR

    def test_to_cbor_serializes_set_with_certificates(self):
        """Test serializing a certificate set with certificates to CBOR."""
        cert_set = CertificateSet.new()
        certificates = [CERTIFICATE1_CBOR, CERTIFICATE2_CBOR, CERTIFICATE3_CBOR, CERTIFICATE4_CBOR]

        for cert_cbor in certificates:
            cert = new_default_certificate(cert_cbor)
            cert_set.add(cert)

        writer = CborWriter()
        cert_set.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_to_cbor_roundtrip(self):
        """Test that CBOR serialization roundtrip preserves data."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        writer = CborWriter()
        cert_set.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_to_cbor_roundtrip_without_tag(self):
        """Test CBOR roundtrip with data that originally had no tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        cert_set = CertificateSet.from_cbor(reader)

        writer = CborWriter()
        cert_set.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex == CBOR

    def test_to_cbor_with_none_writer_raises_error(self):
        """Test that to_cbor with None writer raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises((CardanoError, AttributeError)):
            cert_set.to_cbor(None)


class TestCertificateSetGet:
    """Tests for CertificateSet.get() method."""

    def test_get_retrieves_certificate_at_index(self):
        """Test retrieving a certificate at a specific index."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        cert = cert_set.get(0)
        assert cert is not None

    def test_get_all_certificates(self):
        """Test retrieving all certificates by index."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        for i in range(len(cert_set)):
            cert = cert_set.get(i)
            assert cert is not None

    def test_get_certificates_match_cbor(self):
        """Test that retrieved certificates match expected CBOR."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        certificates = [CERTIFICATE1_CBOR, CERTIFICATE2_CBOR, CERTIFICATE3_CBOR, CERTIFICATE4_CBOR]

        for i, expected_cbor in enumerate(certificates):
            cert = cert_set.get(i)
            writer = CborWriter()
            cert.to_cbor(writer)
            actual_cbor = writer.to_hex()
            assert actual_cbor == expected_cbor

    def test_get_out_of_bounds_raises_error(self):
        """Test that get with out of bounds index raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises(CardanoError):
            cert_set.get(0)

    def test_get_with_large_index_raises_error(self):
        """Test that get with large index raises error."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        with pytest.raises(CardanoError):
            cert_set.get(100)


class TestCertificateSetAdd:
    """Tests for CertificateSet.add() method."""

    def test_add_certificate_to_empty_set(self):
        """Test adding a certificate to an empty set."""
        cert_set = CertificateSet.new()
        cert = new_default_certificate(CERTIFICATE1_CBOR)

        cert_set.add(cert)
        assert len(cert_set) == 1

    def test_add_multiple_certificates(self):
        """Test adding multiple certificates to a set."""
        cert_set = CertificateSet.new()
        certificates = [CERTIFICATE1_CBOR, CERTIFICATE2_CBOR, CERTIFICATE3_CBOR, CERTIFICATE4_CBOR]

        for cert_cbor in certificates:
            cert = new_default_certificate(cert_cbor)
            cert_set.add(cert)

        assert len(cert_set) == 4

    def test_add_specific_cert_type(self):
        """Test adding a specific certificate type."""
        cert_set = CertificateSet.new()
        credential = new_default_credential()
        cert = StakeRegistrationCert.new(credential)

        cert_set.add(cert)
        assert len(cert_set) == 1

    def test_add_mixed_cert_types(self):
        """Test adding mixed certificate types."""
        cert_set = CertificateSet.new()
        credential = new_default_credential()

        cert_set.add(StakeRegistrationCert.new(credential))
        cert_set.add(StakeDeregistrationCert.new(credential))

        assert len(cert_set) == 2

    def test_add_with_none_raises_error(self):
        """Test that add with None raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises((CardanoError, AttributeError, TypeError)):
            cert_set.add(None)


class TestCertificateSetLen:
    """Tests for CertificateSet.__len__() method."""

    def test_len_of_empty_set(self):
        """Test length of empty set."""
        cert_set = CertificateSet.new()
        assert len(cert_set) == 0

    def test_len_of_set_with_certificates(self):
        """Test length of set with certificates."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        assert len(cert_set) == 4

    def test_len_after_adding_certificates(self):
        """Test length after adding certificates."""
        cert_set = CertificateSet.new()
        assert len(cert_set) == 0

        cert = new_default_certificate(CERTIFICATE1_CBOR)
        cert_set.add(cert)
        assert len(cert_set) == 1

        cert2 = new_default_certificate(CERTIFICATE2_CBOR)
        cert_set.add(cert2)
        assert len(cert_set) == 2


class TestCertificateSetIter:
    """Tests for CertificateSet.__iter__() method."""

    def test_iter_over_empty_set(self):
        """Test iterating over empty set."""
        cert_set = CertificateSet.new()
        certs = list(cert_set)
        assert len(certs) == 0

    def test_iter_over_set_with_certificates(self):
        """Test iterating over set with certificates."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        certs = list(cert_set)
        assert len(certs) == 4
        for cert in certs:
            assert cert is not None

    def test_iter_certificates_match_get(self):
        """Test that iterated certificates match get() results."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        for i, cert in enumerate(cert_set):
            expected_cert = cert_set.get(i)
            writer1 = CborWriter()
            writer2 = CborWriter()
            cert.to_cbor(writer1)
            expected_cert.to_cbor(writer2)
            assert writer1.to_hex() == writer2.to_hex()

    def test_iter_in_for_loop(self):
        """Test using iterator in a for loop."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        count = 0
        for cert in cert_set:
            assert cert is not None
            count += 1
        assert count == 4


class TestCertificateSetGetItem:
    """Tests for CertificateSet.__getitem__() method."""

    def test_getitem_positive_index(self):
        """Test accessing certificate with positive index."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        cert = cert_set[0]
        assert cert is not None

    def test_getitem_all_indices(self):
        """Test accessing all certificates by index."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        for i in range(len(cert_set)):
            cert = cert_set[i]
            assert cert is not None

    def test_getitem_negative_index(self):
        """Test accessing certificate with negative index."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        cert = cert_set[-1]
        assert cert is not None

        writer = CborWriter()
        cert.to_cbor(writer)
        assert writer.to_hex() == CERTIFICATE4_CBOR

    def test_getitem_negative_indices(self):
        """Test accessing certificates with negative indices."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        cert_first = cert_set[0]
        cert_last_negative = cert_set[-4]

        writer1 = CborWriter()
        writer2 = CborWriter()
        cert_first.to_cbor(writer1)
        cert_last_negative.to_cbor(writer2)

        assert writer1.to_hex() == writer2.to_hex()

    def test_getitem_out_of_bounds_raises_error(self):
        """Test that getitem with out of bounds index raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises(IndexError):
            _ = cert_set[0]

    def test_getitem_large_negative_index_raises_error(self):
        """Test that getitem with large negative index raises error."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        with pytest.raises(IndexError):
            _ = cert_set[-10]

    def test_getitem_large_positive_index_raises_error(self):
        """Test that getitem with large positive index raises error."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        with pytest.raises(IndexError):
            _ = cert_set[100]


class TestCertificateSetContains:
    """Tests for CertificateSet.__contains__() method."""

    def test_contains_with_iteration(self):
        """Test that we can iterate over certificates in the set."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        count = 0
        for cert in cert_set:
            assert cert is not None
            count += 1
        assert count == 4

    def test_contains_certificate_cbor_match(self):
        """Test that certificates can be accessed and serialized."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)

        cert = cert_set[0]
        writer = CborWriter()
        cert.to_cbor(writer)
        assert writer.to_hex() == CERTIFICATE1_CBOR

    def test_contains_after_adding_certificate(self):
        """Test that certificates are accessible after adding."""
        cert_set = CertificateSet.new()
        assert len(cert_set) == 0

        cert = new_default_certificate(CERTIFICATE1_CBOR)
        cert_set.add(cert)
        assert len(cert_set) == 1

        retrieved = cert_set[0]
        assert retrieved is not None

    def test_contains_with_non_certificate_object(self):
        """Test contains with non-certificate object."""
        cert_set = CertificateSet.new()
        assert "not a certificate" not in cert_set
        assert 123 not in cert_set
        assert None not in cert_set


class TestCertificateSetIsDisjoint:
    """Tests for CertificateSet.isdisjoint() method."""

    def test_isdisjoint_with_empty_sets(self):
        """Test isdisjoint with empty sets."""
        cert_set1 = CertificateSet.new()
        cert_set2 = CertificateSet.new()
        assert cert_set1.isdisjoint(cert_set2)

    def test_isdisjoint_with_one_empty_set(self):
        """Test isdisjoint with one empty set."""
        reader = CborReader.from_hex(CBOR)
        cert_set1 = CertificateSet.from_cbor(reader)
        cert_set2 = CertificateSet.new()
        assert cert_set1.isdisjoint(cert_set2)

    def test_isdisjoint_with_different_certificate_sets(self):
        """Test isdisjoint with sets containing different certificates."""
        cert_set1 = CertificateSet.new()
        cert_set2 = CertificateSet.new()

        cert_set1.add(new_default_certificate(CERTIFICATE1_CBOR))
        cert_set2.add(new_default_certificate(CERTIFICATE2_CBOR))

        result = cert_set1.isdisjoint(cert_set2)
        assert isinstance(result, bool)

    def test_isdisjoint_with_list(self):
        """Test isdisjoint with a list."""
        cert_set = CertificateSet.new()
        cert = new_default_certificate(CERTIFICATE1_CBOR)
        cert_set.add(cert)

        other_list = [new_default_certificate(CERTIFICATE2_CBOR)]
        result = cert_set.isdisjoint(other_list)
        assert isinstance(result, bool)

    def test_isdisjoint_with_empty_list(self):
        """Test isdisjoint with an empty list."""
        cert_set = CertificateSet.new()
        cert_set.add(new_default_certificate(CERTIFICATE1_CBOR))

        assert cert_set.isdisjoint([])


class TestCertificateSetToCip116Json:
    """Tests for CertificateSet.to_cip116_json() method."""

    def test_to_cip116_json_empty_set(self):
        """Test serializing empty set to CIP-116 JSON."""
        cert_set = CertificateSet.new()
        writer = JsonWriter(JsonFormat.COMPACT)
        cert_set.to_cip116_json(writer)

        json_str = writer.encode()
        assert json_str == "[]"

    def test_to_cip116_json_with_certificates(self):
        """Test serializing set with certificates to CIP-116 JSON."""
        cert_set = CertificateSet.new()

        cert1 = new_default_certificate(CERTIFICATE1_CBOR)
        cert2 = new_default_certificate(CERTIFICATE2_CBOR)

        cert_set.add(cert1)
        cert_set.add(cert2)

        writer = JsonWriter(JsonFormat.COMPACT)
        cert_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert json_str.startswith("[")
        assert json_str.endswith("]")
        assert "registration" in json_str or "unregistration" in json_str

    def test_to_cip116_json_with_none_writer_raises_error(self):
        """Test that to_cip116_json with None writer raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            cert_set.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that to_cip116_json with invalid writer raises error."""
        cert_set = CertificateSet.new()
        with pytest.raises(TypeError):
            cert_set.to_cip116_json("not a writer")


class TestCertificateSetRepr:
    """Tests for CertificateSet.__repr__() method."""

    def test_repr_empty_set(self):
        """Test repr of empty set."""
        cert_set = CertificateSet.new()
        assert repr(cert_set) == "CertificateSet(len=0)"

    def test_repr_set_with_certificates(self):
        """Test repr of set with certificates."""
        reader = CborReader.from_hex(CBOR)
        cert_set = CertificateSet.from_cbor(reader)
        assert repr(cert_set) == "CertificateSet(len=4)"

    def test_repr_after_adding_certificates(self):
        """Test repr after adding certificates."""
        cert_set = CertificateSet.new()
        assert repr(cert_set) == "CertificateSet(len=0)"

        cert = new_default_certificate(CERTIFICATE1_CBOR)
        cert_set.add(cert)
        assert repr(cert_set) == "CertificateSet(len=1)"


class TestCertificateSetContextManager:
    """Tests for CertificateSet context manager protocol."""

    def test_context_manager_enter_exit(self):
        """Test using certificate set as context manager."""
        with CertificateSet.new() as cert_set:
            assert cert_set is not None
            cert = new_default_certificate(CERTIFICATE1_CBOR)
            cert_set.add(cert)
            assert len(cert_set) == 1

    def test_context_manager_with_operations(self):
        """Test context manager with various operations."""
        with CertificateSet.new() as cert_set:
            certificates = [CERTIFICATE1_CBOR, CERTIFICATE2_CBOR]
            for cert_cbor in certificates:
                cert = new_default_certificate(cert_cbor)
                cert_set.add(cert)

            assert len(cert_set) == 2
            assert cert_set[0] is not None

    def test_context_manager_exit_does_not_invalidate(self):
        """Test that exiting context manager doesn't invalidate object."""
        cert_set = None
        with CertificateSet.new() as cs:
            cert_set = cs
            cert = new_default_certificate(CERTIFICATE1_CBOR)
            cert_set.add(cert)

        assert len(cert_set) == 1
