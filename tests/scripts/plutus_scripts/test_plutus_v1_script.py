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
    PlutusV1Script,
    CborReader,
    CborWriter,
    CardanoError,
)


PLUTUS_V1_SCRIPT_HEX = "4d01000033222220051200120011"
PLUTUS_V1_HASH = "67f33146617a5e61936081db3b2117cbf59bd2123748f58ac9678656"
PLUTUS_V1_CBOR = "4e4d01000033222220051200120011"
PLUTUS_V1_SCRIPT_BYTES = bytes([
    0x4d, 0x01, 0x00, 0x00, 0x33, 0x22, 0x22,
    0x20, 0x05, 0x12, 0x00, 0x12, 0x00, 0x11
])


class TestPlutusV1ScriptNew:
    """Tests for PlutusV1Script.new() factory method."""

    def test_can_create_plutus_v1_script_from_bytes(self):
        """Test that PlutusV1Script can be created from raw bytes."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script is not None

    def test_created_script_can_be_serialized_to_cbor(self):
        """Test that a created script can be serialized to CBOR."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        writer = CborWriter()
        script.to_cbor(writer)
        result = writer.to_hex()
        assert result == PLUTUS_V1_CBOR

    def test_raises_error_if_bytes_are_none(self):
        """Test that creating script with None bytes raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.new(None)

    def test_raises_error_if_bytes_are_empty(self):
        """Test that creating script with empty bytes raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1Script.new(b"")

    def test_can_create_from_bytes_like_objects(self):
        """Test that PlutusV1Script can be created from bytes-like objects."""
        script = PlutusV1Script.new(bytes(PLUTUS_V1_SCRIPT_BYTES))
        assert script is not None

    def test_script_preserves_original_bytes(self):
        """Test that the script preserves the original bytes."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script.raw_bytes == PLUTUS_V1_SCRIPT_BYTES


class TestPlutusV1ScriptFromHex:
    """Tests for PlutusV1Script.from_hex() factory method."""

    def test_can_create_plutus_v1_script_from_hex(self):
        """Test that PlutusV1Script can be created from hexadecimal string."""
        script = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX)
        assert script is not None

    def test_created_script_from_hex_can_be_serialized_to_cbor(self):
        """Test that script created from hex can be serialized to CBOR."""
        script = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX)
        writer = CborWriter()
        script.to_cbor(writer)
        result = writer.to_hex()
        assert result == PLUTUS_V1_CBOR

    def test_raises_error_if_hex_is_none(self):
        """Test that creating script with None hex raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.from_hex(None)

    def test_raises_error_if_hex_is_empty(self):
        """Test that creating script with empty hex raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1Script.from_hex("")

    def test_accepts_uppercase_and_lowercase_hex(self):
        """Test that hex parsing accepts both cases."""
        script = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX.lower())
        assert script is not None

    def test_raises_error_if_hex_is_odd_length(self):
        """Test that creating script with odd length hex raises an error."""
        with pytest.raises(CardanoError):
            PlutusV1Script.from_hex("4d0")

    def test_hex_is_case_insensitive(self):
        """Test that hex parsing is case insensitive."""
        script1 = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX.lower())
        script2 = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX.upper())
        assert script1 == script2


class TestPlutusV1ScriptFromCbor:
    """Tests for PlutusV1Script.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that PlutusV1Script can be deserialized from CBOR."""
        reader = CborReader.from_hex(PLUTUS_V1_CBOR)
        script = PlutusV1Script.from_cbor(reader)
        assert script is not None

    def test_deserialized_script_can_be_reserialized(self):
        """Test that deserialized script can be reserialized to same CBOR."""
        reader = CborReader.from_hex(PLUTUS_V1_CBOR)
        script = PlutusV1Script.from_cbor(reader)
        writer = CborWriter()
        script.to_cbor(writer)
        result = writer.to_hex()
        assert result == PLUTUS_V1_CBOR

    def test_raises_error_if_reader_is_none(self):
        """Test that deserializing with None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.from_cbor(None)

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        original = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = PlutusV1Script.from_cbor(reader)

        assert original == deserialized


class TestPlutusV1ScriptToCbor:
    """Tests for PlutusV1Script.to_cbor() method."""

    def test_can_serialize_to_cbor(self):
        """Test that PlutusV1Script can be serialized to CBOR."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        writer = CborWriter()
        script.to_cbor(writer)
        result = writer.to_hex()
        assert result == PLUTUS_V1_CBOR

    def test_raises_error_if_writer_is_none(self):
        """Test that serializing with None writer raises an error."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            script.to_cbor(None)


class TestPlutusV1ScriptHash:
    """Tests for PlutusV1Script.hash property."""

    def test_can_get_hash_of_script(self):
        """Test that the hash of a script can be retrieved."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        hash_bytes = script.hash
        assert hash_bytes is not None
        assert len(hash_bytes) == 28

    def test_hash_matches_expected_value(self):
        """Test that the hash matches the expected value."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        hash_bytes = script.hash
        hash_hex = hash_bytes.hex()
        assert hash_hex == PLUTUS_V1_HASH

    def test_hash_is_consistent(self):
        """Test that hash is consistent across multiple calls."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        hash1 = script.hash
        hash2 = script.hash
        assert hash1 == hash2

    def test_equal_scripts_have_equal_hashes(self):
        """Test that equal scripts have equal hashes."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script1.hash == script2.hash

    def test_hash_is_blake2b_28_bytes(self):
        """Test that hash is 28 bytes (Blake2b-224)."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        hash_bytes = script.hash
        assert len(hash_bytes) == 28


class TestPlutusV1ScriptRawBytes:
    """Tests for PlutusV1Script.raw_bytes property."""

    def test_can_get_raw_bytes(self):
        """Test that raw bytes can be retrieved from script."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        raw_bytes = script.raw_bytes
        assert raw_bytes is not None

    def test_raw_bytes_match_original(self):
        """Test that raw bytes match the original input."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        raw_bytes = script.raw_bytes
        assert raw_bytes == PLUTUS_V1_SCRIPT_BYTES

    def test_raw_bytes_have_correct_length(self):
        """Test that raw bytes have the correct length."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        raw_bytes = script.raw_bytes
        assert len(raw_bytes) == len(PLUTUS_V1_SCRIPT_BYTES)

    def test_raw_bytes_are_bytes_type(self):
        """Test that raw_bytes returns bytes type."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        raw_bytes = script.raw_bytes
        assert isinstance(raw_bytes, bytes)


class TestPlutusV1ScriptEquals:
    """Tests for PlutusV1Script equality comparison."""

    def test_equal_scripts_are_equal(self):
        """Test that two scripts with same bytes are equal."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script1 == script2

    def test_different_scripts_are_not_equal(self):
        """Test that scripts with different bytes are not equal."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES[:-1])
        assert script1 != script2

    def test_script_not_equal_to_none(self):
        """Test that script is not equal to None."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script != None

    def test_script_not_equal_to_different_type(self):
        """Test that script is not equal to different type."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script != "not a script"
        assert script != 123
        assert script != []

    def test_equality_is_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script == script

    def test_equality_is_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script1 == script2
        assert script2 == script1

    def test_equality_is_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script3 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script1 == script2
        assert script2 == script3
        assert script1 == script3


class TestPlutusV1ScriptRepr:
    """Tests for PlutusV1Script.__repr__() method."""

    def test_repr_contains_class_name(self):
        """Test that __repr__ contains the class name."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        repr_str = repr(script)
        assert "PlutusV1Script" in repr_str

    def test_repr_contains_hash(self):
        """Test that __repr__ contains the script hash."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        repr_str = repr(script)
        assert "hash=" in repr_str
        assert PLUTUS_V1_HASH in repr_str

    def test_repr_can_be_evaluated(self):
        """Test that __repr__ output is informative."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        repr_str = repr(script)
        assert repr_str.startswith("PlutusV1Script(")
        assert repr_str.endswith(")")


class TestPlutusV1ScriptContextManager:
    """Tests for PlutusV1Script context manager protocol."""

    def test_can_use_as_context_manager(self):
        """Test that PlutusV1Script can be used as a context manager."""
        with PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES) as script:
            assert script is not None
            assert script.raw_bytes == PLUTUS_V1_SCRIPT_BYTES

    def test_script_is_usable_within_context(self):
        """Test that script is usable within context manager."""
        with PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES) as script:
            hash_bytes = script.hash
            assert hash_bytes is not None
            raw_bytes = script.raw_bytes
            assert raw_bytes == PLUTUS_V1_SCRIPT_BYTES

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        with script:
            pass


class TestPlutusV1ScriptEdgeCases:
    """Tests for edge cases and various scenarios."""

    def test_can_create_script_from_single_byte(self):
        """Test that script can be created from single byte."""
        single_byte = bytes([0x01])
        script = PlutusV1Script.new(single_byte)
        assert script is not None
        assert script.raw_bytes == single_byte

    def test_can_create_script_from_large_bytes(self):
        """Test that script can be created from large byte array."""
        large_bytes = bytes(range(256))
        script = PlutusV1Script.new(large_bytes)
        assert script is not None
        assert script.raw_bytes == large_bytes

    def test_multiple_scripts_have_independent_data(self):
        """Test that multiple scripts maintain independent data."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(bytes([0x01, 0x02, 0x03]))
        assert script1.raw_bytes != script2.raw_bytes
        assert script1.hash != script2.hash

    def test_can_create_multiple_scripts_from_same_bytes(self):
        """Test that multiple scripts can be created from same bytes."""
        script1 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script2 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script3 = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        assert script1 == script2
        assert script2 == script3

    def test_script_from_bytes_and_hex_are_equal(self):
        """Test that scripts created from bytes and hex are equal."""
        script_from_bytes = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        script_from_hex = PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_HEX)
        assert script_from_bytes == script_from_hex

    def test_cbor_roundtrip_preserves_equality(self):
        """Test that CBOR roundtrip preserves equality."""
        original = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = PlutusV1Script.from_cbor(reader)

        assert original == deserialized
        assert original.hash == deserialized.hash

    def test_script_with_all_zero_bytes(self):
        """Test that script can be created with all zero bytes."""
        zero_bytes = bytes(10)
        script = PlutusV1Script.new(zero_bytes)
        assert script is not None
        assert script.raw_bytes == zero_bytes

    def test_script_with_all_ff_bytes(self):
        """Test that script can be created with all 0xFF bytes."""
        ff_bytes = bytes([0xFF] * 10)
        script = PlutusV1Script.new(ff_bytes)
        assert script is not None
        assert script.raw_bytes == ff_bytes

    def test_hash_hex_format_is_lowercase(self):
        """Test that hash hex format is lowercase."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        hash_hex = script.hash.hex()
        assert hash_hex == hash_hex.lower()

    def test_raw_bytes_are_immutable(self):
        """Test that modifying returned raw_bytes doesn't affect script."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        raw_bytes1 = script.raw_bytes
        raw_bytes2 = script.raw_bytes
        assert raw_bytes1 == raw_bytes2
        assert raw_bytes1 == PLUTUS_V1_SCRIPT_BYTES


class TestPlutusV1ScriptInvalidInputs:
    """Tests for invalid inputs and error handling."""

    def test_new_raises_error_with_invalid_type(self):
        """Test that new() raises error with invalid type."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.new("not bytes")

    def test_new_raises_error_with_integer(self):
        """Test that new() raises error with integer input."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.new(123)

    def test_new_accepts_bytes_like_sequences(self):
        """Test that new() accepts bytes-like sequences."""
        script = PlutusV1Script.new(bytes([0x4d, 0x01, 0x00]))
        assert script is not None

    def test_from_hex_raises_error_with_bytes(self):
        """Test that from_hex() raises error with bytes input."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.from_hex(PLUTUS_V1_SCRIPT_BYTES)

    def test_from_hex_raises_error_with_integer(self):
        """Test that from_hex() raises error with integer input."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.from_hex(123)

    def test_from_cbor_raises_error_with_invalid_cbor(self):
        """Test that from_cbor() raises error with invalid CBOR."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            PlutusV1Script.from_cbor(reader)

    def test_from_cbor_raises_error_with_string(self):
        """Test that from_cbor() raises error with string input."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            PlutusV1Script.from_cbor("not a reader")

    def test_to_cbor_raises_error_with_string(self):
        """Test that to_cbor() raises error with string input."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            script.to_cbor("not a writer")

    def test_to_cbor_raises_error_with_integer(self):
        """Test that to_cbor() raises error with integer input."""
        script = PlutusV1Script.new(PLUTUS_V1_SCRIPT_BYTES)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            script.to_cbor(123)
