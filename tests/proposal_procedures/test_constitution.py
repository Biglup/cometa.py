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
    Constitution,
    Anchor,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError
)


CBOR = "82827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"
CBOR_WITH_SCRIPT_HASH = "82827668747470733a2f2f7777772e736f6d6575726c2e696f5820000000000000000000000000000000000000000000000000000000000000000058200000000000000000000000000000000000000000000000000000000000000000"
ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
DATA_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
ANCHOR_URL = "https://www.someurl.io"
ANCHOR_HASH = "2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"
SCRIPT_HASH = "1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"


def create_default_anchor() -> Anchor:
    """Helper function to create a default anchor from CBOR."""
    reader = CborReader.from_hex(ANCHOR_CBOR)
    return Anchor.from_cbor(reader)


def create_anchor_with_url_and_hash(url: str, hash_hex: str) -> Anchor:
    """Helper function to create an anchor with specific URL and hash."""
    anchor_hash = Blake2bHash.from_hex(hash_hex)
    return Anchor.new(url, anchor_hash)


def create_default_constitution() -> Constitution:
    """Helper function to create a default constitution from CBOR."""
    reader = CborReader.from_hex(CBOR)
    return Constitution.from_cbor(reader)


def create_constitution_with_script_hash() -> Constitution:
    """Helper function to create a constitution with script hash from CBOR."""
    reader = CborReader.from_hex(CBOR_WITH_SCRIPT_HASH)
    return Constitution.from_cbor(reader)


class TestConstitution:
    """Tests for the Constitution class."""

    def test_new_creates_constitution_without_script_hash(self):
        """Test creating a new constitution without script hash."""
        anchor = create_default_anchor()
        constitution = Constitution.new(anchor)

        assert constitution is not None
        assert constitution.anchor is not None

    def test_new_creates_constitution_with_script_hash(self):
        """Test creating a new constitution with script hash."""
        anchor = create_default_anchor()
        script_hash = Blake2bHash.from_hex(DATA_HASH)
        constitution = Constitution.new(anchor, script_hash)

        assert constitution is not None
        assert constitution.anchor is not None
        assert constitution.script_hash is not None

    def test_new_raises_error_with_null_anchor(self):
        """Test that creating constitution with null anchor raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Constitution.new(None)

    def test_from_cbor_deserializes_constitution(self):
        """Test deserializing a constitution from CBOR."""
        reader = CborReader.from_hex(CBOR)
        constitution = Constitution.from_cbor(reader)

        assert constitution is not None
        assert constitution.anchor is not None

    def test_from_cbor_deserializes_constitution_with_script_hash(self):
        """Test deserializing a constitution with script hash from CBOR."""
        reader = CborReader.from_hex(CBOR_WITH_SCRIPT_HASH)
        constitution = Constitution.from_cbor(reader)

        assert constitution is not None
        assert constitution.anchor is not None
        assert constitution.script_hash is not None

    def test_from_cbor_raises_error_with_null_reader(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Constitution.from_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_not_array(self):
        """Test that deserializing invalid CBOR (not an array) raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            Constitution.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_array_size(self):
        """Test that deserializing invalid CBOR (wrong array size) raises error."""
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            Constitution.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_anchor(self):
        """Test that deserializing invalid anchor raises error."""
        reader = CborReader.from_hex("82ef")

        with pytest.raises(CardanoError):
            Constitution.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_script_hash(self):
        """Test that deserializing invalid script hash raises error."""
        invalid_cbor = "82827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000ef"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Constitution.from_cbor(reader)

    def test_to_cbor_serializes_constitution(self):
        """Test serializing a constitution to CBOR."""
        constitution = create_default_constitution()
        writer = CborWriter()
        constitution.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_serializes_constitution_with_script_hash(self):
        """Test serializing a constitution with script hash to CBOR."""
        constitution = create_constitution_with_script_hash()
        writer = CborWriter()
        constitution.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_WITH_SCRIPT_HASH

    def test_to_cbor_raises_error_with_null_writer(self):
        """Test that serializing with null writer raises error."""
        constitution = create_default_constitution()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            constitution.to_cbor(None)

    def test_get_anchor_returns_anchor(self):
        """Test getting the anchor from a constitution."""
        constitution = create_default_constitution()
        anchor = constitution.anchor

        assert anchor is not None

    def test_set_anchor_updates_anchor(self):
        """Test setting the anchor on a constitution."""
        constitution = create_default_constitution()
        new_anchor = create_default_anchor()

        constitution.anchor = new_anchor

        retrieved_anchor = constitution.anchor
        assert retrieved_anchor is not None

    def test_set_anchor_raises_error_with_null_anchor(self):
        """Test that setting null anchor raises error."""
        constitution = create_default_constitution()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            constitution.anchor = None

    def test_get_script_hash_returns_none_when_not_set(self):
        """Test getting script hash returns None when not set."""
        constitution = create_default_constitution()
        script_hash = constitution.script_hash

        assert script_hash is None

    def test_get_script_hash_returns_hash_when_set(self):
        """Test getting script hash returns hash when set."""
        constitution = create_constitution_with_script_hash()
        script_hash = constitution.script_hash

        assert script_hash is not None

    def test_set_script_hash_updates_hash(self):
        """Test setting the script hash on a constitution."""
        constitution = create_default_constitution()
        script_hash = Blake2bHash.from_hex(DATA_HASH)

        constitution.script_hash = script_hash

        retrieved_hash = constitution.script_hash
        assert retrieved_hash is not None

    def test_set_script_hash_can_be_set_to_none(self):
        """Test that script hash can be set to None."""
        constitution = create_constitution_with_script_hash()

        constitution.script_hash = None

        script_hash = constitution.script_hash
        assert script_hash is None

    def test_to_cip116_json_with_anchor_and_script_hash(self):
        """Test serializing constitution with both anchor and script hash to CIP-116 JSON."""
        anchor_hash = Blake2bHash.from_hex(ANCHOR_HASH)
        anchor = Anchor.new(ANCHOR_URL, anchor_hash)
        script_hash = Blake2bHash.from_hex(SCRIPT_HASH)
        constitution = Constitution.new(anchor, script_hash)

        writer = JsonWriter(JsonFormat.COMPACT)
        constitution.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"anchor":{"url":"https://example.com","data_hash":"2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"},"script_hash":"1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"}'
        assert ANCHOR_URL in json_str
        assert ANCHOR_HASH in json_str
        assert SCRIPT_HASH in json_str
        assert "anchor" in json_str
        assert "script_hash" in json_str

    def test_to_cip116_json_with_anchor_only(self):
        """Test serializing constitution with only anchor to CIP-116 JSON."""
        anchor_hash = Blake2bHash.from_hex(ANCHOR_HASH)
        anchor = Anchor.new(ANCHOR_URL, anchor_hash)
        constitution = Constitution.new(anchor, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        constitution.to_cip116_json(writer)
        json_str = writer.encode()

        assert ANCHOR_URL in json_str
        assert ANCHOR_HASH in json_str
        assert "anchor" in json_str
        assert "script_hash" not in json_str

    def test_to_cip116_json_raises_error_with_null_writer(self):
        """Test that serializing to JSON with null writer raises error."""
        constitution = create_default_constitution()

        with pytest.raises((CardanoError, TypeError)):
            constitution.to_cip116_json(None)

    def test_repr_returns_string_representation(self):
        """Test that __repr__ returns a string representation."""
        constitution = create_default_constitution()
        repr_str = repr(constitution)

        assert "Constitution" in repr_str
        assert "url=" in repr_str

    def test_context_manager_enter_returns_self(self):
        """Test that __enter__ returns self for context manager."""
        constitution = create_default_constitution()

        with constitution as ctx:
            assert ctx is constitution

    def test_context_manager_exit_completes(self):
        """Test that __exit__ completes without error."""
        constitution = create_default_constitution()

        with constitution:
            pass

    def test_cbor_roundtrip_without_script_hash(self):
        """Test CBOR serialization roundtrip without script hash."""
        original = create_default_constitution()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = Constitution.from_cbor(reader)

        assert restored is not None
        assert restored.anchor is not None
        assert restored.script_hash is None

    def test_cbor_roundtrip_with_script_hash(self):
        """Test CBOR serialization roundtrip with script hash."""
        original = create_constitution_with_script_hash()
        writer = CborWriter()
        original.to_cbor(writer)

        cbor_hex = writer.to_hex()
        reader = CborReader.from_hex(cbor_hex)
        restored = Constitution.from_cbor(reader)

        assert restored is not None
        assert restored.anchor is not None
        assert restored.script_hash is not None

    def test_anchor_property_getter_does_not_return_null(self):
        """Test that anchor property getter never returns null for valid constitution."""
        constitution = create_default_constitution()
        anchor = constitution.anchor

        assert anchor is not None

    def test_script_hash_property_update(self):
        """Test updating script hash property multiple times."""
        constitution = create_default_constitution()

        hash1 = Blake2bHash.from_hex(DATA_HASH)
        constitution.script_hash = hash1
        assert constitution.script_hash is not None

        constitution.script_hash = None
        assert constitution.script_hash is None

        hash2 = Blake2bHash.from_hex(SCRIPT_HASH)
        constitution.script_hash = hash2
        assert constitution.script_hash is not None

    def test_anchor_property_update(self):
        """Test updating anchor property."""
        constitution = create_default_constitution()
        original_anchor = constitution.anchor

        new_anchor = create_anchor_with_url_and_hash(ANCHOR_URL, ANCHOR_HASH)
        constitution.anchor = new_anchor

        updated_anchor = constitution.anchor
        assert updated_anchor is not None

    def test_new_constitution_has_correct_initial_state(self):
        """Test that a newly created constitution has the correct initial state."""
        anchor = create_default_anchor()
        constitution = Constitution.new(anchor)

        assert constitution.anchor is not None
        assert constitution.script_hash is None

    def test_constitution_with_script_hash_has_correct_state(self):
        """Test that a constitution created with script hash has correct state."""
        anchor = create_default_anchor()
        script_hash = Blake2bHash.from_hex(DATA_HASH)
        constitution = Constitution.new(anchor, script_hash)

        assert constitution.anchor is not None
        assert constitution.script_hash is not None
