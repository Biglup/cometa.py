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
    DRep,
    DRepType,
    Credential,
    CredentialType,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


DREP_KEY_HASH_CBOR = "8200581c00000000000000000000000000000000000000000000000000000000"
DREP_SCRIPT_HASH_CBOR = "8201581c00000000000000000000000000000000000000000000000000000000"
DREP_ABSTAIN_CBOR = "8102"
DREP_NO_CONFIDENCE_CBOR = "8103"
DREP_CRED_HASH = "00000000000000000000000000000000000000000000000000000000"
DREP_CIP105_KEY_HASH = "drep19we4mh7zaxqmyasqgpr7h7hcuq5m6dwpx99j4mrcd3e4ufxuc8n"
DREP_CIP105_SCRIPT_HASH = "drep_script1rxdd99vu338y659qfg8nmpemdyhlsmaudgv4m4zdz7m5vz8uzt6"
DREP_CIP129_KEY_HASH = "drep1yg4mxhwlct5crvnkqpqy06l6lrszn0f4cyc5k2hv0pk8xhsvluu37"
DREP_CIP129_SCRIPT_HASH = "drep1yvve4554njxyun2s5p9q70v88d5jl7r0h34pjhw5f5tmw3sjtrutp"
DREP_SCRIPT_HASH = "199ad2959c8c4e4d50a04a0f3d873b692ff86fbc6a195dd44d17b746"
DREP_KEY_HASH = "2bb35ddfc2e981b276004047ebfaf8e029bd35c1314b2aec786c735e"


class TestDRepNew:
    """Tests for DRep.new() factory method."""

    def test_can_create_drep_with_abstain(self):
        """Test that DRep can be created with ABSTAIN type."""
        drep = DRep.new(DRepType.ABSTAIN)
        assert drep is not None
        assert drep.drep_type == DRepType.ABSTAIN

    def test_can_create_drep_with_no_confidence(self):
        """Test that DRep can be created with NO_CONFIDENCE type."""
        drep = DRep.new(DRepType.NO_CONFIDENCE)
        assert drep is not None
        assert drep.drep_type == DRepType.NO_CONFIDENCE

    def test_can_create_drep_with_key_hash(self):
        """Test that DRep can be created with KEY_HASH type."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)
        assert drep is not None
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential is not None

    def test_can_create_drep_with_script_hash(self):
        """Test that DRep can be created with SCRIPT_HASH type."""
        credential = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential)
        assert drep is not None
        assert drep.drep_type == DRepType.SCRIPT_HASH
        assert drep.credential is not None

    def test_raises_error_for_key_hash_without_credential(self):
        """Test that KEY_HASH type without credential raises an error."""
        with pytest.raises(CardanoError):
            DRep.new(DRepType.KEY_HASH, None)

    def test_raises_error_for_script_hash_without_credential(self):
        """Test that SCRIPT_HASH type without credential raises an error."""
        with pytest.raises(CardanoError):
            DRep.new(DRepType.SCRIPT_HASH, None)

    def test_raises_error_for_abstain_with_credential(self):
        """Test that ABSTAIN type with credential raises an error."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        with pytest.raises(CardanoError):
            DRep.new(DRepType.ABSTAIN, credential)

    def test_raises_error_for_no_confidence_with_credential(self):
        """Test that NO_CONFIDENCE type with credential raises an error."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        with pytest.raises(CardanoError):
            DRep.new(DRepType.NO_CONFIDENCE, credential)


class TestDRepAbstainNoConfidence:
    """Tests for DRep.abstain() and DRep.no_confidence() factory methods."""

    def test_can_create_abstain_drep(self):
        """Test that abstain() creates a DRep with ABSTAIN type."""
        drep = DRep.abstain()
        assert drep is not None
        assert drep.drep_type == DRepType.ABSTAIN
        assert drep.credential is None

    def test_can_create_no_confidence_drep(self):
        """Test that no_confidence() creates a DRep with NO_CONFIDENCE type."""
        drep = DRep.no_confidence()
        assert drep is not None
        assert drep.drep_type == DRepType.NO_CONFIDENCE
        assert drep.credential is None


class TestDRepFromString:
    """Tests for DRep.from_string() factory method."""

    def test_can_create_from_cip105_key_hash(self):
        """Test that DRep can be created from CIP-105 key hash string."""
        drep = DRep.from_string(DREP_CIP105_KEY_HASH)
        assert drep is not None
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential is not None

    def test_can_create_from_cip105_script_hash(self):
        """Test that DRep can be created from CIP-105 script hash string."""
        drep = DRep.from_string(DREP_CIP105_SCRIPT_HASH)
        assert drep is not None
        assert drep.drep_type == DRepType.SCRIPT_HASH
        assert drep.credential is not None

    def test_can_create_from_cip129_key_hash(self):
        """Test that DRep can be created from CIP-129 key hash string."""
        drep = DRep.from_string(DREP_CIP129_KEY_HASH)
        assert drep is not None
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential is not None

    def test_can_create_from_cip129_script_hash(self):
        """Test that DRep can be created from CIP-129 script hash string."""
        drep = DRep.from_string(DREP_CIP129_SCRIPT_HASH)
        assert drep is not None
        assert drep.drep_type == DRepType.SCRIPT_HASH
        assert drep.credential is not None

    def test_raises_error_for_empty_string(self):
        """Test that empty string raises an error."""
        with pytest.raises(CardanoError):
            DRep.from_string("")

    def test_raises_error_for_invalid_bech32(self):
        """Test that invalid bech32 string raises an error."""
        with pytest.raises(CardanoError):
            DRep.from_string("invalid")

    def test_raises_error_for_invalid_prefix(self):
        """Test that invalid prefix raises an error."""
        with pytest.raises(CardanoError):
            DRep.from_string(
                "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh"
            )

    def test_raises_error_for_invalid_hash_size(self):
        """Test that invalid hash size raises an error."""
        with pytest.raises(CardanoError):
            DRep.from_string("drep1478q9x7ntsf3fv4wc7rvwdgw2uk75x")


class TestDRepFromCbor:
    """Tests for CBOR deserialization."""

    def test_can_deserialize_abstain_from_cbor(self):
        """Test that ABSTAIN DRep can be deserialized from CBOR."""
        reader = CborReader.from_hex(DREP_ABSTAIN_CBOR)
        drep = DRep.from_cbor(reader)
        assert drep is not None
        assert drep.drep_type == DRepType.ABSTAIN

    def test_can_deserialize_no_confidence_from_cbor(self):
        """Test that NO_CONFIDENCE DRep can be deserialized from CBOR."""
        reader = CborReader.from_hex(DREP_NO_CONFIDENCE_CBOR)
        drep = DRep.from_cbor(reader)
        assert drep is not None
        assert drep.drep_type == DRepType.NO_CONFIDENCE

    def test_can_deserialize_key_hash_from_cbor(self):
        """Test that KEY_HASH DRep can be deserialized from CBOR."""
        reader = CborReader.from_hex(DREP_KEY_HASH_CBOR)
        drep = DRep.from_cbor(reader)
        assert drep is not None
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential is not None

    def test_can_deserialize_script_hash_from_cbor(self):
        """Test that SCRIPT_HASH DRep can be deserialized from CBOR."""
        reader = CborReader.from_hex(DREP_SCRIPT_HASH_CBOR)
        drep = DRep.from_cbor(reader)
        assert drep is not None
        assert drep.drep_type == DRepType.SCRIPT_HASH
        assert drep.credential is not None

    def test_raises_error_with_invalid_reader(self):
        """Test that invalid reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            DRep.from_cbor(None)

    def test_raises_error_with_invalid_cbor(self):
        """Test that invalid CBOR raises an error."""
        reader = CborReader.from_hex("8109")
        with pytest.raises(CardanoError):
            DRep.from_cbor(reader)

    def test_raises_error_with_incomplete_cbor(self):
        """Test that incomplete CBOR raises an error."""
        reader = CborReader.from_hex("8100")
        with pytest.raises(CardanoError):
            DRep.from_cbor(reader)


class TestDRepToCbor:
    """Tests for CBOR serialization."""

    def test_can_serialize_abstain_to_cbor(self):
        """Test that ABSTAIN DRep can be serialized to CBOR."""
        drep = DRep.abstain()
        writer = CborWriter()
        drep.to_cbor(writer)
        result = writer.to_hex()
        assert result == DREP_ABSTAIN_CBOR

    def test_can_serialize_no_confidence_to_cbor(self):
        """Test that NO_CONFIDENCE DRep can be serialized to CBOR."""
        drep = DRep.no_confidence()
        writer = CborWriter()
        drep.to_cbor(writer)
        result = writer.to_hex()
        assert result == DREP_NO_CONFIDENCE_CBOR

    def test_can_serialize_key_hash_to_cbor(self):
        """Test that KEY_HASH DRep can be serialized to CBOR."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)
        writer = CborWriter()
        drep.to_cbor(writer)
        result = writer.to_hex()
        assert result == DREP_KEY_HASH_CBOR

    def test_can_serialize_script_hash_to_cbor(self):
        """Test that SCRIPT_HASH DRep can be serialized to CBOR."""
        credential = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential)
        writer = CborWriter()
        drep.to_cbor(writer)
        result = writer.to_hex()
        assert result == DREP_SCRIPT_HASH_CBOR

    def test_roundtrip_cbor_serialization_abstain(self):
        """Test CBOR serialization/deserialization roundtrip for ABSTAIN."""
        original = DRep.abstain()
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = DRep.from_cbor(reader)

        assert deserialized.drep_type == original.drep_type

    def test_roundtrip_cbor_serialization_key_hash(self):
        """Test CBOR serialization/deserialization roundtrip for KEY_HASH."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        original = DRep.new(DRepType.KEY_HASH, credential)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = DRep.from_cbor(reader)

        assert deserialized.drep_type == original.drep_type
        assert deserialized.credential is not None

    def test_raises_error_with_invalid_writer(self):
        """Test that invalid writer raises an error."""
        drep = DRep.abstain()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            drep.to_cbor(None)


class TestDRepProperties:
    """Tests for DRep properties (drep_type, credential)."""

    def test_get_drep_type_abstain(self):
        """Test that drep_type property returns ABSTAIN."""
        drep = DRep.abstain()
        assert drep.drep_type == DRepType.ABSTAIN

    def test_get_drep_type_no_confidence(self):
        """Test that drep_type property returns NO_CONFIDENCE."""
        drep = DRep.no_confidence()
        assert drep.drep_type == DRepType.NO_CONFIDENCE

    def test_get_drep_type_key_hash(self):
        """Test that drep_type property returns KEY_HASH."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)
        assert drep.drep_type == DRepType.KEY_HASH

    def test_get_drep_type_script_hash(self):
        """Test that drep_type property returns SCRIPT_HASH."""
        credential = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential)
        assert drep.drep_type == DRepType.SCRIPT_HASH

    def test_set_drep_type_from_abstain_to_key_hash(self):
        """Test that drep_type can be changed from ABSTAIN to KEY_HASH."""
        drep = DRep.abstain()
        drep.drep_type = DRepType.KEY_HASH
        assert drep.drep_type == DRepType.KEY_HASH

    def test_get_credential_for_key_hash(self):
        """Test that credential property returns credential for KEY_HASH."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)
        retrieved = drep.credential
        assert retrieved is not None
        assert retrieved.hash_hex == DREP_CRED_HASH

    def test_get_credential_for_script_hash(self):
        """Test that credential property returns credential for SCRIPT_HASH."""
        credential = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential)
        retrieved = drep.credential
        assert retrieved is not None
        assert retrieved.hash_hex == DREP_CRED_HASH

    def test_get_credential_for_abstain_returns_none(self):
        """Test that credential property returns None for ABSTAIN."""
        drep = DRep.abstain()
        assert drep.credential is None

    def test_get_credential_for_no_confidence_returns_none(self):
        """Test that credential property returns None for NO_CONFIDENCE."""
        drep = DRep.no_confidence()
        assert drep.credential is None

    def test_set_credential_for_key_hash(self):
        """Test that credential property can be set for KEY_HASH."""
        credential1 = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential1)

        credential2 = Credential.from_key_hash(DREP_KEY_HASH)
        drep.credential = credential2

        retrieved = drep.credential
        assert retrieved is not None
        assert retrieved.hash_hex == DREP_KEY_HASH

    def test_set_credential_for_script_hash(self):
        """Test that credential property can be set for SCRIPT_HASH."""
        credential1 = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential1)

        credential2 = Credential.from_script_hash(DREP_SCRIPT_HASH)
        drep.credential = credential2

        retrieved = drep.credential
        assert retrieved is not None
        assert retrieved.hash_hex == DREP_SCRIPT_HASH

    def test_set_credential_raises_error_for_abstain(self):
        """Test that setting credential for ABSTAIN raises an error."""
        drep = DRep.abstain()
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        with pytest.raises(CardanoError):
            drep.credential = credential

    def test_set_credential_raises_error_for_no_confidence(self):
        """Test that setting credential for NO_CONFIDENCE raises an error."""
        drep = DRep.no_confidence()
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        with pytest.raises(CardanoError):
            drep.credential = credential


class TestDRepToString:
    """Tests for string representation (to_cip129_string, __str__)."""

    def test_can_convert_key_hash_to_string(self):
        """Test that KEY_HASH DRep can be converted to CIP-129 string."""
        drep = DRep.from_string(DREP_CIP129_KEY_HASH)
        result = drep.to_cip129_string()
        assert result == DREP_CIP129_KEY_HASH

    def test_can_convert_script_hash_to_string(self):
        """Test that SCRIPT_HASH DRep can be converted to CIP-129 string."""
        drep = DRep.from_string(DREP_CIP129_SCRIPT_HASH)
        result = drep.to_cip129_string()
        assert result == DREP_CIP129_SCRIPT_HASH

    def test_str_returns_cip129_string(self):
        """Test that __str__ returns CIP-129 string."""
        drep = DRep.from_string(DREP_CIP129_KEY_HASH)
        assert str(drep) == DREP_CIP129_KEY_HASH

    def test_abstain_to_string_returns_empty(self):
        """Test that ABSTAIN DRep to_string returns empty string."""
        drep = DRep.abstain()
        result = drep.to_cip129_string()
        assert result == ""

    def test_no_confidence_to_string_returns_empty(self):
        """Test that NO_CONFIDENCE DRep to_string returns empty string."""
        drep = DRep.no_confidence()
        result = drep.to_cip129_string()
        assert result == ""


class TestDRepToJson:
    """Tests for JSON serialization (to_cip116_json)."""

    def test_can_convert_key_hash_to_json(self):
        """Test that KEY_HASH DRep can be converted to CIP-116 JSON."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)
        writer = JsonWriter()
        drep.to_cip116_json(writer)
        json_str = writer.encode()
        assert "pubkey_hash" in json_str
        assert DREP_CRED_HASH in json_str

    def test_can_convert_script_hash_to_json(self):
        """Test that SCRIPT_HASH DRep can be converted to CIP-116 JSON."""
        credential = Credential.from_script_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, credential)
        writer = JsonWriter()
        drep.to_cip116_json(writer)
        json_str = writer.encode()
        assert "script_hash" in json_str
        assert DREP_CRED_HASH in json_str

    def test_can_convert_abstain_to_json(self):
        """Test that ABSTAIN DRep can be converted to CIP-116 JSON."""
        drep = DRep.abstain()
        writer = JsonWriter()
        drep.to_cip116_json(writer)
        json_str = writer.encode()
        assert "always_abstain" in json_str

    def test_can_convert_no_confidence_to_json(self):
        """Test that NO_CONFIDENCE DRep can be converted to CIP-116 JSON."""
        drep = DRep.no_confidence()
        writer = JsonWriter()
        drep.to_cip116_json(writer)
        json_str = writer.encode()
        assert "always_no_confidence" in json_str

    def test_raises_error_with_invalid_writer(self):
        """Test that invalid writer raises an error."""
        drep = DRep.abstain()
        with pytest.raises((CardanoError, TypeError)):
            drep.to_cip116_json(None)

    def test_raises_error_with_wrong_writer_type(self):
        """Test that wrong writer type raises an error."""
        drep = DRep.abstain()
        with pytest.raises((CardanoError, TypeError)):
            drep.to_cip116_json("not a writer")


class TestDRepMagicMethods:
    """Tests for magic methods (__eq__, __hash__, __repr__, __str__)."""

    def test_equality_for_abstain(self):
        """Test that two ABSTAIN DReps are equal."""
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()
        assert drep1 == drep2

    def test_equality_for_no_confidence(self):
        """Test that two NO_CONFIDENCE DReps are equal."""
        drep1 = DRep.no_confidence()
        drep2 = DRep.no_confidence()
        assert drep1 == drep2

    def test_equality_for_key_hash_with_same_credential(self):
        """Test that KEY_HASH DReps with same credential are equal."""
        credential1 = Credential.from_key_hash(DREP_CRED_HASH)
        credential2 = Credential.from_key_hash(DREP_CRED_HASH)
        drep1 = DRep.new(DRepType.KEY_HASH, credential1)
        drep2 = DRep.new(DRepType.KEY_HASH, credential2)
        assert drep1 == drep2

    def test_inequality_for_different_types(self):
        """Test that DReps with different types are not equal."""
        drep1 = DRep.abstain()
        drep2 = DRep.no_confidence()
        assert drep1 != drep2

    def test_inequality_for_key_hash_with_different_credentials(self):
        """Test that KEY_HASH DReps with different credentials are not equal."""
        credential1 = Credential.from_key_hash(DREP_CRED_HASH)
        credential2 = Credential.from_key_hash(DREP_KEY_HASH)
        drep1 = DRep.new(DRepType.KEY_HASH, credential1)
        drep2 = DRep.new(DRepType.KEY_HASH, credential2)
        assert drep1 != drep2

    def test_inequality_with_non_drep_object(self):
        """Test that DRep is not equal to non-DRep objects."""
        drep = DRep.abstain()
        assert drep != "not a DRep"
        assert drep != 123
        assert drep != None

    def test_hash_consistency(self):
        """Test that hash is consistent for the same object."""
        drep = DRep.abstain()
        hash1 = hash(drep)
        hash2 = hash(drep)
        assert hash1 == hash2

    def test_hash_equality_for_equal_dreps(self):
        """Test that equal DReps have the same hash."""
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()
        assert hash(drep1) == hash(drep2)

    def test_can_use_in_set(self):
        """Test that DReps can be used in a set."""
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()
        drep3 = DRep.no_confidence()

        drep_set = {drep1, drep2, drep3}
        assert len(drep_set) == 2

    def test_can_use_as_dict_key(self):
        """Test that DReps can be used as dictionary keys."""
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()

        drep_dict = {drep1: "value1"}
        drep_dict[drep2] = "value2"

        assert len(drep_dict) == 1
        assert drep_dict[drep1] == "value2"

    def test_repr_contains_type(self):
        """Test that __repr__ contains the DRep type."""
        drep = DRep.abstain()
        repr_str = repr(drep)
        assert "DRep" in repr_str
        assert "ABSTAIN" in repr_str


class TestDRepContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that DRep can be used as a context manager."""
        with DRep.abstain() as drep:
            assert drep is not None
            assert drep.drep_type == DRepType.ABSTAIN

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        drep = DRep.abstain()
        with drep:
            pass


class TestDRepEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_property_updates(self):
        """Test that multiple property updates work correctly."""
        credential1 = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential1)

        credential2 = Credential.from_key_hash(DREP_KEY_HASH)
        drep.credential = credential2

        credential3 = Credential.from_key_hash(DREP_CRED_HASH)
        drep.credential = credential3

        retrieved = drep.credential
        assert retrieved is not None
        assert retrieved.hash_hex == DREP_CRED_HASH

    def test_create_modify_serialize_deserialize(self):
        """Test complete workflow: create, modify, serialize, deserialize."""
        credential1 = Credential.from_key_hash(DREP_CRED_HASH)
        original = DRep.new(DRepType.KEY_HASH, credential1)

        credential2 = Credential.from_key_hash(DREP_KEY_HASH)
        original.credential = credential2

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = DRep.from_cbor(reader)

        assert deserialized.drep_type == DRepType.KEY_HASH
        assert deserialized.credential is not None

    def test_json_and_cbor_serialization_consistency(self):
        """Test that both JSON and CBOR serialization work on same object."""
        credential = Credential.from_key_hash(DREP_CRED_HASH)
        drep = DRep.new(DRepType.KEY_HASH, credential)

        cbor_writer = CborWriter()
        drep.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        drep.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert "pubkey_hash" in json_str
        assert DREP_CRED_HASH in json_str

    def test_roundtrip_from_string_to_string(self):
        """Test that string parsing and serialization roundtrip works."""
        original_str = DREP_CIP129_KEY_HASH
        drep = DRep.from_string(original_str)
        result_str = drep.to_cip129_string()
        assert result_str == original_str

    def test_cip105_and_cip129_compatibility(self):
        """Test that CIP-105 input produces CIP-129 output."""
        drep = DRep.from_string(DREP_CIP105_KEY_HASH)
        result = drep.to_cip129_string()
        assert result.startswith("drep1")

    def test_different_credential_types(self):
        """Test that KEY_HASH and SCRIPT_HASH are properly distinguished."""
        key_cred = Credential.from_key_hash(DREP_CRED_HASH)
        script_cred = Credential.from_script_hash(DREP_CRED_HASH)

        key_drep = DRep.new(DRepType.KEY_HASH, key_cred)
        script_drep = DRep.new(DRepType.SCRIPT_HASH, script_cred)

        assert key_drep.drep_type == DRepType.KEY_HASH
        assert script_drep.drep_type == DRepType.SCRIPT_HASH
        assert key_drep != script_drep
