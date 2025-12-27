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
    Credential,
    CredentialType,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


KEY_HASH_HEX = "00000000000000000000000000000000000000000000000000000000"
KEY_HASH_HEX_2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
INVALID_KEY_HASH_HEX = "000000000000000000000000000000000000000000000000"
KEY_HASH_CREDENTIAL_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"


class TestCredential:
    """Tests for the Credential class."""

    def test_from_hash_creates_key_hash_credential(self):
        """Test creating a key hash credential from a Blake2bHash."""
        hash_value = Blake2bHash.from_hex(KEY_HASH_HEX)
        cred = Credential.from_hash(hash_value, CredentialType.KEY_HASH)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_hash_creates_script_hash_credential(self):
        """Test creating a script hash credential from a Blake2bHash."""
        hash_value = Blake2bHash.from_hex(KEY_HASH_HEX)
        cred = Credential.from_hash(hash_value, CredentialType.SCRIPT_HASH)

        assert cred is not None
        assert cred.type == CredentialType.SCRIPT_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_hash_with_invalid_hash_raises_error(self):
        """Test that creating a credential with invalid hash size raises error."""
        hash_value = Blake2bHash.from_hex(INVALID_KEY_HASH_HEX)
        with pytest.raises(CardanoError):
            Credential.from_hash(hash_value, CredentialType.KEY_HASH)

    def test_from_key_hash_with_hex_string(self):
        """Test creating key hash credential from hex string."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_key_hash_with_bytes(self):
        """Test creating key hash credential from bytes."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        cred = Credential.from_key_hash(hash_bytes)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_key_hash_with_blake2b_hash(self):
        """Test creating key hash credential from Blake2bHash."""
        hash_value = Blake2bHash.from_hex(KEY_HASH_HEX)
        cred = Credential.from_key_hash(hash_value)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_script_hash_with_hex_string(self):
        """Test creating script hash credential from hex string."""
        cred = Credential.from_script_hash(KEY_HASH_HEX)

        assert cred is not None
        assert cred.type == CredentialType.SCRIPT_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_script_hash_with_bytes(self):
        """Test creating script hash credential from bytes."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        cred = Credential.from_script_hash(hash_bytes)

        assert cred is not None
        assert cred.type == CredentialType.SCRIPT_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_script_hash_with_blake2b_hash(self):
        """Test creating script hash credential from Blake2bHash."""
        hash_value = Blake2bHash.from_hex(KEY_HASH_HEX)
        cred = Credential.from_script_hash(hash_value)

        assert cred is not None
        assert cred.type == CredentialType.SCRIPT_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_hex_creates_credential(self):
        """Test creating credential from hexadecimal string."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_hex_with_invalid_hex_raises_error(self):
        """Test that invalid hex string raises error."""
        with pytest.raises(CardanoError):
            Credential.from_hex(INVALID_KEY_HASH_HEX, CredentialType.KEY_HASH)

    def test_from_hex_with_invalid_hex_characters_raises_error(self):
        """Test that invalid hex characters raise error."""
        with pytest.raises(CardanoError):
            Credential.from_hex("ZZZZZZ", CredentialType.KEY_HASH)

    def test_from_bytes_creates_credential(self):
        """Test creating credential from raw bytes."""
        hash_bytes = bytes.fromhex(KEY_HASH_HEX)
        cred = Credential.from_bytes(hash_bytes, CredentialType.KEY_HASH)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_bytes_with_bytearray(self):
        """Test creating credential from bytearray."""
        hash_bytes = bytearray.fromhex(KEY_HASH_HEX)
        cred = Credential.from_bytes(hash_bytes, CredentialType.KEY_HASH)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_bytes_with_invalid_size_raises_error(self):
        """Test that invalid byte size raises error."""
        hash_bytes = bytes.fromhex(INVALID_KEY_HASH_HEX)
        with pytest.raises(CardanoError):
            Credential.from_bytes(hash_bytes, CredentialType.KEY_HASH)

    def test_to_cbor_serialization(self):
        """Test serializing credential to CBOR."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        writer = CborWriter()
        cred.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == KEY_HASH_CREDENTIAL_CBOR

    def test_from_cbor_deserialization(self):
        """Test deserializing credential from CBOR."""
        reader = CborReader.from_hex(KEY_HASH_CREDENTIAL_CBOR)
        cred = Credential.from_cbor(reader)

        assert cred is not None
        assert cred.type == CredentialType.KEY_HASH
        assert cred.hash_hex == KEY_HASH_HEX

    def test_from_cbor_with_invalid_array_size_raises_error(self):
        """Test that invalid CBOR array size raises error."""
        invalid_cbor = "8100581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Credential.from_cbor(reader)

    def test_from_cbor_with_invalid_credential_type_raises_error(self):
        """Test that invalid credential type in CBOR raises error."""
        invalid_cbor = "8203581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Credential.from_cbor(reader)

    def test_from_cbor_with_invalid_byte_string_size_raises_error(self):
        """Test that invalid byte string size in CBOR raises error."""
        invalid_cbor = "8200581b0000000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Credential.from_cbor(reader)

    def test_cbor_round_trip(self):
        """Test that CBOR serialization and deserialization are inverses."""
        original = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        writer = CborWriter()
        original.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized = Credential.from_cbor(reader)

        assert deserialized.type == original.type
        assert deserialized.hash_hex == original.hash_hex

    def test_type_property_getter(self):
        """Test getting credential type."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        assert cred.type == CredentialType.KEY_HASH

    def test_type_property_setter(self):
        """Test setting credential type."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        cred.type = CredentialType.SCRIPT_HASH

        assert cred.type == CredentialType.SCRIPT_HASH

    def test_type_property_setter_with_invalid_type_raises_error(self):
        """Test that setting invalid type raises error."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)

        with pytest.raises(CardanoError):
            cred.type = 3

    def test_hash_property_getter(self):
        """Test getting credential hash."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        hash_value = cred.hash

        assert hash_value is not None
        assert isinstance(hash_value, Blake2bHash)
        assert hash_value.to_hex() == KEY_HASH_HEX

    def test_hash_property_setter(self):
        """Test setting credential hash."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        new_hash = Blake2bHash.from_hex(KEY_HASH_HEX_2)

        cred.hash = new_hash

        assert cred.hash_hex == KEY_HASH_HEX_2

    def test_hash_property_setter_with_invalid_size_raises_error(self):
        """Test that setting hash with invalid size raises error."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        invalid_hash = Blake2bHash.from_hex(INVALID_KEY_HASH_HEX)

        with pytest.raises(CardanoError):
            cred.hash = invalid_hash

    def test_hash_bytes_property(self):
        """Test getting hash as raw bytes."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        hash_bytes = cred.hash_bytes

        assert hash_bytes == bytes.fromhex(KEY_HASH_HEX)

    def test_hash_hex_property(self):
        """Test getting hash as hexadecimal string."""
        cred = Credential.from_hex(KEY_HASH_HEX, CredentialType.KEY_HASH)
        hash_hex = cred.hash_hex

        assert hash_hex == KEY_HASH_HEX

    def test_is_key_hash_property(self):
        """Test checking if credential is key hash type."""
        key_cred = Credential.from_key_hash(KEY_HASH_HEX)
        script_cred = Credential.from_script_hash(KEY_HASH_HEX)

        assert key_cred.is_key_hash is True
        assert script_cred.is_key_hash is False

    def test_is_script_hash_property(self):
        """Test checking if credential is script hash type."""
        key_cred = Credential.from_key_hash(KEY_HASH_HEX)
        script_cred = Credential.from_script_hash(KEY_HASH_HEX)

        assert key_cred.is_script_hash is False
        assert script_cred.is_script_hash is True

    def test_to_cip116_json_key_hash(self):
        """Test converting key hash credential to CIP-116 JSON."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        writer = JsonWriter()

        cred.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"pubkey_hash"' in json_str
        assert f'"value":"{KEY_HASH_HEX}"' in json_str

    def test_to_cip116_json_script_hash(self):
        """Test converting script hash credential to CIP-116 JSON."""
        cred = Credential.from_script_hash(KEY_HASH_HEX)
        writer = JsonWriter()

        cred.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"script_hash"' in json_str
        assert f'"value":"{KEY_HASH_HEX}"' in json_str

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that passing invalid writer to to_cip116_json raises error."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)

        with pytest.raises(TypeError):
            cred.to_cip116_json("not a writer")

    def test_compare_equal_credentials(self):
        """Test comparing equal credentials."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)

        assert cred1.compare(cred2) == 0

    def test_compare_different_hashes(self):
        """Test comparing credentials with different hashes."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred1.compare(cred2) < 0
        assert cred2.compare(cred1) > 0

    def test_compare_different_types(self):
        """Test comparing credentials with different types."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_script_hash(KEY_HASH_HEX)

        assert cred1.compare(cred2) < 0
        assert cred2.compare(cred1) > 0

    def test_equality_operator(self):
        """Test equality operator."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)

        assert cred1 == cred2

    def test_equality_operator_different_hashes(self):
        """Test equality operator with different hashes."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred1 != cred2

    def test_equality_operator_different_types(self):
        """Test equality operator with different types."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_script_hash(KEY_HASH_HEX)

        assert cred1 != cred2

    def test_equality_operator_with_non_credential(self):
        """Test equality operator with non-Credential object."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)

        assert cred != "not a credential"
        assert cred != 123
        assert cred != None

    def test_hash_method(self):
        """Test that credentials are hashable."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)
        cred3 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert hash(cred1) == hash(cred2)
        assert hash(cred1) != hash(cred3)

    def test_credentials_in_set(self):
        """Test using credentials in a set."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)
        cred3 = Credential.from_key_hash(KEY_HASH_HEX_2)

        cred_set = {cred1, cred2, cred3}
        assert len(cred_set) == 2

    def test_credentials_as_dict_keys(self):
        """Test using credentials as dictionary keys."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)

        cred_dict = {cred1: "first", cred2: "second"}
        assert cred_dict[cred1] == "first"
        assert cred_dict[cred2] == "second"

    def test_less_than_operator(self):
        """Test less than operator."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred1 < cred2
        assert not cred2 < cred1

    def test_less_than_or_equal_operator(self):
        """Test less than or equal operator."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)
        cred3 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred1 <= cred2
        assert cred1 <= cred3
        assert not cred3 <= cred1

    def test_greater_than_operator(self):
        """Test greater than operator."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred2 > cred1
        assert not cred1 > cred2

    def test_greater_than_or_equal_operator(self):
        """Test greater than or equal operator."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)
        cred3 = Credential.from_key_hash(KEY_HASH_HEX_2)

        assert cred1 >= cred2
        assert cred3 >= cred1
        assert not cred1 >= cred3

    def test_repr(self):
        """Test __repr__ method."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        repr_str = repr(cred)

        assert "Credential" in repr_str
        assert "KEY_HASH" in repr_str
        assert KEY_HASH_HEX in repr_str

    def test_str(self):
        """Test __str__ method."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        str_repr = str(cred)

        assert "key_hash:" in str_repr
        assert KEY_HASH_HEX in str_repr

    def test_str_script_hash(self):
        """Test __str__ method for script hash."""
        cred = Credential.from_script_hash(KEY_HASH_HEX)
        str_repr = str(cred)

        assert "script_hash:" in str_repr
        assert KEY_HASH_HEX in str_repr

    def test_context_manager(self):
        """Test using credential as context manager."""
        with Credential.from_key_hash(KEY_HASH_HEX) as cred:
            assert cred is not None
            assert cred.type == CredentialType.KEY_HASH

    def test_credential_lifecycle(self):
        """Test credential creation and cleanup."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        hash_hex = cred.hash_hex
        del cred

        new_cred = Credential.from_key_hash(hash_hex)
        assert new_cred.hash_hex == hash_hex

    def test_multiple_credentials_same_hash(self):
        """Test creating multiple credentials with same hash."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX)

        assert cred1 == cred2
        assert cred1 is not cred2

    def test_credential_type_change_preserves_hash(self):
        """Test that changing type preserves hash value."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        original_hash = cred.hash_hex

        cred.type = CredentialType.SCRIPT_HASH

        assert cred.hash_hex == original_hash
        assert cred.type == CredentialType.SCRIPT_HASH

    def test_credential_hash_bytes_length(self):
        """Test that hash_bytes has correct length."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        hash_bytes = cred.hash_bytes

        assert len(hash_bytes) == 28

    def test_credential_properties_are_consistent(self):
        """Test that different hash properties are consistent."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)

        hash_obj = cred.hash
        hash_bytes = cred.hash_bytes
        hash_hex = cred.hash_hex

        assert hash_obj.to_hex() == hash_hex
        assert hash_obj.to_bytes() == hash_bytes
        assert hash_bytes == bytes.fromhex(hash_hex)

    def test_sorting_credentials(self):
        """Test sorting a list of credentials."""
        cred1 = Credential.from_key_hash(KEY_HASH_HEX)
        cred2 = Credential.from_key_hash(KEY_HASH_HEX_2)
        cred3 = Credential.from_script_hash(KEY_HASH_HEX)

        credentials = [cred2, cred3, cred1]
        sorted_creds = sorted(credentials)

        assert sorted_creds[0] == cred1
        assert sorted_creds[1] == cred2
        assert sorted_creds[2] == cred3

    def test_credential_immutability_through_hash_object(self):
        """Test that modifying returned hash doesn't affect credential."""
        cred = Credential.from_key_hash(KEY_HASH_HEX)
        original_hex = cred.hash_hex

        hash_obj = cred.hash
        del hash_obj

        assert cred.hash_hex == original_hex
