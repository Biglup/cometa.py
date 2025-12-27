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
from cometa.common.protocol_version import ProtocolVersion
from cometa import CborWriter
from cometa import CborReader
from cometa import JsonWriter
from cometa.errors import CardanoError


class TestProtocolVersionNew:
    """Tests for ProtocolVersion.new() factory method."""

    def test_can_create_protocol_version(self):
        """Test creating a new ProtocolVersion with valid arguments."""
        pv = ProtocolVersion.new(1, 3)
        assert pv is not None
        assert pv.major == 1
        assert pv.minor == 3
        assert pv.refcount >= 1

    def test_can_create_with_zero_values(self):
        """Test creating a ProtocolVersion with zero values."""
        pv = ProtocolVersion.new(0, 0)
        assert pv.major == 0
        assert pv.minor == 0

    def test_can_create_with_large_values(self):
        """Test creating a ProtocolVersion with large values."""
        pv = ProtocolVersion.new(123456789, 987654321)
        assert pv.major == 123456789
        assert pv.minor == 987654321


class TestProtocolVersionFromCbor:
    """Tests for ProtocolVersion.from_cbor() factory method."""

    def test_can_deserialize_protocol_version(self):
        """Test deserializing a ProtocolVersion from CBOR."""
        cbor_hex = "820103"
        reader = CborReader.from_hex(cbor_hex)
        pv = ProtocolVersion.from_cbor(reader)

        assert pv is not None
        assert pv.major == 1
        assert pv.minor == 3

    def test_error_if_cbor_array_size_invalid(self):
        """Test error when CBOR array has wrong size."""
        cbor_hex = "81"
        reader = CborReader.from_hex(cbor_hex)

        with pytest.raises(CardanoError):
            ProtocolVersion.from_cbor(reader)

    def test_error_if_first_element_not_uint(self):
        """Test error when first element in CBOR is not uint."""
        cbor_hex = "82ff"
        reader = CborReader.from_hex(cbor_hex)

        with pytest.raises(CardanoError):
            ProtocolVersion.from_cbor(reader)

    def test_error_if_second_element_not_uint(self):
        """Test error when second element in CBOR is not uint."""
        cbor_hex = "8200ff"
        reader = CborReader.from_hex(cbor_hex)

        with pytest.raises(CardanoError):
            ProtocolVersion.from_cbor(reader)


class TestProtocolVersionProperties:
    """Tests for ProtocolVersion property getters and setters."""

    def test_get_major(self):
        """Test getting the major version number."""
        pv = ProtocolVersion.new(1, 3)
        assert pv.major == 1

    def test_get_minor(self):
        """Test getting the minor version number."""
        pv = ProtocolVersion.new(1, 3)
        assert pv.minor == 3

    def test_set_major(self):
        """Test setting the major version number."""
        pv = ProtocolVersion.new(1, 3)
        pv.major = 123456789
        assert pv.major == 123456789

    def test_set_minor(self):
        """Test setting the minor version number."""
        pv = ProtocolVersion.new(1, 3)
        pv.minor = 987654321
        assert pv.minor == 987654321


class TestProtocolVersionSerialization:
    """Tests for ProtocolVersion serialization methods."""

    def test_can_serialize_to_cbor(self):
        """Test serializing ProtocolVersion to CBOR."""
        pv = ProtocolVersion.new(1, 3)
        writer = CborWriter()

        pv.to_cbor(writer)
        cbor_hex = writer.encode().hex()

        assert cbor_hex == "820103"

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        original = ProtocolVersion.new(8, 0)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        decoded = ProtocolVersion.from_cbor(reader)

        assert original == decoded
        assert original.major == decoded.major
        assert original.minor == decoded.minor

    def test_can_serialize_to_cip116_json(self):
        """Test serializing ProtocolVersion to CIP-116 JSON."""
        pv = ProtocolVersion.new(8, 0)
        writer = JsonWriter()

        pv.to_json(writer)
        json_str = writer.encode()

        assert '"major":8' in json_str.replace(" ", "")
        assert '"minor":0' in json_str.replace(" ", "")

    def test_can_serialize_to_cip116_json_with_different_values(self):
        """Test serializing ProtocolVersion with different values to JSON."""
        pv = ProtocolVersion.new(8, 2)
        writer = JsonWriter()

        pv.to_json(writer)
        json_str = writer.encode()

        assert '"major":8' in json_str.replace(" ", "")
        assert '"minor":2' in json_str.replace(" ", "")


class TestProtocolVersionInternalState:
    """Tests for ProtocolVersion internal state management."""

    def test_refcount(self):
        """Test getting the reference count."""
        pv = ProtocolVersion.new(1, 3)
        assert pv.refcount >= 1

    def test_last_error_getter(self):
        """Test getting the last error message."""
        pv = ProtocolVersion.new(1, 3)
        error_msg = pv.last_error
        assert isinstance(error_msg, str)

    def test_last_error_setter(self):
        """Test setting the last error message."""
        pv = ProtocolVersion.new(1, 3)
        test_message = "This is a test message"
        pv.last_error = test_message
        assert pv.last_error == test_message


class TestProtocolVersionMagicMethods:
    """Tests for ProtocolVersion magic methods."""

    def test_equality_same_values(self):
        """Test equality comparison with same values."""
        pv1 = ProtocolVersion.new(8, 0)
        pv2 = ProtocolVersion.new(8, 0)
        assert pv1 == pv2

    def test_equality_different_major(self):
        """Test equality comparison with different major version."""
        pv1 = ProtocolVersion.new(8, 0)
        pv2 = ProtocolVersion.new(9, 0)
        assert pv1 != pv2

    def test_equality_different_minor(self):
        """Test equality comparison with different minor version."""
        pv1 = ProtocolVersion.new(8, 0)
        pv2 = ProtocolVersion.new(8, 1)
        assert pv1 != pv2

    def test_equality_with_non_protocol_version(self):
        """Test equality comparison with non-ProtocolVersion object."""
        pv = ProtocolVersion.new(8, 0)
        assert pv != "not a protocol version"
        assert pv != 42
        assert pv != None

    def test_repr(self):
        """Test string representation."""
        pv = ProtocolVersion.new(8, 0)
        assert repr(pv) == "<ProtocolVersion major=8 minor=0>"

    def test_repr_with_different_values(self):
        """Test string representation with different values."""
        pv = ProtocolVersion.new(1, 3)
        assert repr(pv) == "<ProtocolVersion major=1 minor=3>"

    def test_context_manager(self):
        """Test usage as a context manager."""
        with ProtocolVersion.new(1, 1) as pv:
            assert pv.major == 1
            assert pv.minor == 1

    def test_context_manager_exit(self):
        """Test context manager exit behavior."""
        pv = ProtocolVersion.new(1, 1)
        with pv:
            pass
        assert pv.major == 1


class TestProtocolVersionEdgeCases:
    """Tests for ProtocolVersion edge cases and error conditions."""

    def test_init_with_null_pointer_raises_error(self):
        """Test that initializing with NULL pointer raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            ProtocolVersion(ffi.NULL)

    def test_can_modify_version_after_creation(self):
        """Test modifying version numbers after creation."""
        pv = ProtocolVersion.new(1, 0)
        pv.major = 9
        pv.minor = 2
        assert pv.major == 9
        assert pv.minor == 2

    def test_multiple_modifications(self):
        """Test multiple modifications to version numbers."""
        pv = ProtocolVersion.new(1, 0)

        pv.major = 2
        assert pv.major == 2

        pv.major = 3
        assert pv.major == 3

        pv.minor = 1
        assert pv.minor == 1

        pv.minor = 2
        assert pv.minor == 2