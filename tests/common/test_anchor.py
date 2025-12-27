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
    Anchor,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000"
HASH_HEX_2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
INVALID_HASH_HEX = "000000000000000000000000000000000000000000000000"
ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
URL = "https://www.someurl.io"
URL_2 = "https://www.someotherurl.io"


class TestAnchor:
    """Tests for the Anchor class."""

    def test_new_creates_anchor_with_url_and_hash(self):
        """Test creating an anchor with URL and Blake2bHash."""
        hash_value = Blake2bHash.from_hex(HASH_HEX)
        anchor = Anchor.new(URL, hash_value)

        assert anchor is not None
        assert anchor.url == URL
        assert anchor.hash_hex == HASH_HEX

    def test_new_with_invalid_hash_size_raises_error(self):
        """Test that creating anchor with invalid hash size raises error."""
        hash_value = Blake2bHash.from_hex(INVALID_HASH_HEX)
        with pytest.raises(CardanoError):
            Anchor.new(URL, hash_value)

    def test_from_hash_hex_creates_anchor(self):
        """Test creating anchor from URL and hexadecimal hash string."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor is not None
        assert anchor.url == URL
        assert anchor.hash_hex == HASH_HEX

    def test_from_hash_hex_with_empty_url_raises_error(self):
        """Test that empty URL raises error."""
        with pytest.raises(CardanoError):
            Anchor.from_hash_hex("", HASH_HEX)

    def test_from_hash_hex_with_invalid_hash_raises_error(self):
        """Test that invalid hash hex raises error."""
        with pytest.raises(CardanoError):
            Anchor.from_hash_hex(URL, INVALID_HASH_HEX)

    def test_from_hash_hex_with_empty_hash_raises_error(self):
        """Test that empty hash string raises error."""
        with pytest.raises(CardanoError):
            Anchor.from_hash_hex(URL, "")

    def test_from_hash_bytes_creates_anchor(self):
        """Test creating anchor from URL and raw hash bytes."""
        hash_bytes = bytes.fromhex(HASH_HEX)
        anchor = Anchor.from_hash_bytes(URL, hash_bytes)

        assert anchor is not None
        assert anchor.url == URL
        assert anchor.hash_hex == HASH_HEX
        assert anchor.hash_bytes == hash_bytes

    def test_from_hash_bytes_with_bytearray(self):
        """Test creating anchor from URL and bytearray."""
        hash_bytes = bytearray.fromhex(HASH_HEX)
        anchor = Anchor.from_hash_bytes(URL, hash_bytes)

        assert anchor is not None
        assert anchor.url == URL
        assert anchor.hash_hex == HASH_HEX

    def test_from_hash_bytes_with_invalid_size_raises_error(self):
        """Test that invalid hash bytes size raises error."""
        hash_bytes = bytes.fromhex(INVALID_HASH_HEX)
        with pytest.raises(CardanoError):
            Anchor.from_hash_bytes(URL, hash_bytes)

    def test_to_cbor_serialization(self):
        """Test serializing anchor to CBOR."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        writer = CborWriter()
        anchor.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == ANCHOR_CBOR

    def test_from_cbor_deserialization(self):
        """Test deserializing anchor from CBOR."""
        reader = CborReader.from_hex(ANCHOR_CBOR)
        anchor = Anchor.from_cbor(reader)

        assert anchor is not None
        assert anchor.url == URL
        assert anchor.hash_hex == HASH_HEX

    def test_from_cbor_with_invalid_array_size_raises_error(self):
        """Test that invalid CBOR array size raises error."""
        invalid_cbor = "81"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Anchor.from_cbor(reader)

    def test_from_cbor_with_invalid_first_element_raises_error(self):
        """Test that invalid first element (non-text) in CBOR raises error."""
        invalid_cbor = "822d"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Anchor.from_cbor(reader)

    def test_from_cbor_with_invalid_second_element_raises_error(self):
        """Test that invalid second element (non-byte string) in CBOR raises error."""
        invalid_cbor = "8268747470733a2f2f7777772e736f6d6575726c2e696f582d"
        reader = CborReader.from_hex(invalid_cbor)

        with pytest.raises(CardanoError):
            Anchor.from_cbor(reader)

    def test_cbor_round_trip(self):
        """Test that CBOR serialization and deserialization are inverses."""
        original = Anchor.from_hash_hex(URL, HASH_HEX)
        writer = CborWriter()
        original.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized = Anchor.from_cbor(reader)

        assert deserialized.url == original.url
        assert deserialized.hash_hex == original.hash_hex

    def test_url_property_getter(self):
        """Test getting anchor URL."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        assert anchor.url == URL

    def test_url_property_setter(self):
        """Test setting anchor URL."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor.url = URL_2

        assert anchor.url == URL_2

    def test_url_property_setter_with_empty_url_raises_error(self):
        """Test that setting empty URL raises error."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        with pytest.raises(CardanoError):
            anchor.url = ""

    def test_hash_property_getter(self):
        """Test getting anchor hash."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        hash_value = anchor.hash

        assert hash_value is not None
        assert isinstance(hash_value, Blake2bHash)
        assert hash_value.to_hex() == HASH_HEX

    def test_hash_property_setter(self):
        """Test setting anchor hash."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        new_hash = Blake2bHash.from_hex(HASH_HEX_2)

        anchor.hash = new_hash

        assert anchor.hash_hex == HASH_HEX_2

    def test_hash_property_setter_with_invalid_size_raises_error(self):
        """Test that setting hash with invalid size raises error."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        invalid_hash = Blake2bHash.from_hex(INVALID_HASH_HEX)

        with pytest.raises(CardanoError):
            anchor.hash = invalid_hash

    def test_hash_hex_property(self):
        """Test getting hash as hexadecimal string."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        hash_hex = anchor.hash_hex

        assert hash_hex == HASH_HEX

    def test_hash_bytes_property(self):
        """Test getting hash as raw bytes."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        hash_bytes = anchor.hash_bytes

        assert hash_bytes == bytes.fromhex(HASH_HEX)

    def test_to_cip116_json(self):
        """Test converting anchor to CIP-116 JSON."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        writer = JsonWriter()

        anchor.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"url":"https://www.someurl.io"' in json_str
        assert f'"data_hash":"{HASH_HEX}"' in json_str

    def test_to_cip116_json_with_different_url_and_hash(self):
        """Test converting anchor with different values to CIP-116 JSON."""
        test_url = "https://example.com/metadata.json"
        test_hash = "2a3f9a878b3b9ac18a65c16ed1c92c37fd4f5a16e629580a23330f6e0f6e0f6e"
        anchor = Anchor.from_hash_hex(test_url, test_hash)
        writer = JsonWriter()

        anchor.to_cip116_json(writer)
        json_str = writer.encode()

        assert f'"url":"{test_url}"' in json_str
        assert f'"data_hash":"{test_hash}"' in json_str

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that passing invalid writer to to_cip116_json raises error."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        with pytest.raises(TypeError):
            anchor.to_cip116_json("not a writer")

    def test_equality_operator_same_values(self):
        """Test equality operator with same URL and hash."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor1 == anchor2

    def test_equality_operator_different_urls(self):
        """Test equality operator with different URLs."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL_2, HASH_HEX)

        assert anchor1 != anchor2

    def test_equality_operator_different_hashes(self):
        """Test equality operator with different hashes."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX_2)

        assert anchor1 != anchor2

    def test_equality_operator_with_non_anchor(self):
        """Test equality operator with non-Anchor object."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor != "not an anchor"
        assert anchor != 123
        assert anchor != None

    def test_hash_method(self):
        """Test that anchors are hashable."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor3 = Anchor.from_hash_hex(URL_2, HASH_HEX)

        assert hash(anchor1) == hash(anchor2)
        assert hash(anchor1) != hash(anchor3)

    def test_anchors_in_set(self):
        """Test using anchors in a set."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor3 = Anchor.from_hash_hex(URL_2, HASH_HEX)

        anchor_set = {anchor1, anchor2, anchor3}
        assert len(anchor_set) == 2

    def test_anchors_as_dict_keys(self):
        """Test using anchors as dictionary keys."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL_2, HASH_HEX)

        anchor_dict = {anchor1: "first", anchor2: "second"}
        assert anchor_dict[anchor1] == "first"
        assert anchor_dict[anchor2] == "second"

    def test_repr(self):
        """Test __repr__ method."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        repr_str = repr(anchor)

        assert "Anchor" in repr_str
        assert URL in repr_str

    def test_str(self):
        """Test __str__ method."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        str_repr = str(anchor)

        assert URL in str_repr
        assert HASH_HEX[:16] in str_repr

    def test_context_manager(self):
        """Test using anchor as context manager."""
        with Anchor.from_hash_hex(URL, HASH_HEX) as anchor:
            assert anchor is not None
            assert anchor.url == URL

    def test_anchor_lifecycle(self):
        """Test anchor creation and cleanup."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        url = anchor.url
        del anchor

        new_anchor = Anchor.from_hash_hex(url, HASH_HEX)
        assert new_anchor.url == url

    def test_multiple_anchors_same_values(self):
        """Test creating multiple anchors with same values."""
        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor1 == anchor2
        assert anchor1 is not anchor2

    def test_url_change_preserves_hash(self):
        """Test that changing URL preserves hash value."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        original_hash = anchor.hash_hex

        anchor.url = URL_2

        assert anchor.hash_hex == original_hash
        assert anchor.url == URL_2

    def test_hash_change_preserves_url(self):
        """Test that changing hash preserves URL value."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        original_url = anchor.url

        new_hash = Blake2bHash.from_hex(HASH_HEX_2)
        anchor.hash = new_hash

        assert anchor.url == original_url
        assert anchor.hash_hex == HASH_HEX_2

    def test_hash_bytes_length(self):
        """Test that hash_bytes has correct length."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        hash_bytes = anchor.hash_bytes

        assert len(hash_bytes) == 32

    def test_anchor_properties_are_consistent(self):
        """Test that different hash properties are consistent."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        hash_obj = anchor.hash
        hash_bytes = anchor.hash_bytes
        hash_hex = anchor.hash_hex

        assert hash_obj.to_hex() == hash_hex
        assert hash_obj.to_bytes() == hash_bytes
        assert hash_bytes == bytes.fromhex(hash_hex)

    def test_anchor_immutability_through_hash_object(self):
        """Test that modifying returned hash doesn't affect anchor."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        original_hex = anchor.hash_hex

        hash_obj = anchor.hash
        del hash_obj

        assert anchor.hash_hex == original_hex

    def test_anchor_with_various_url_formats(self):
        """Test anchor with different URL formats."""
        urls = [
            "https://example.com",
            "https://example.com/path",
            "https://example.com/path/to/file.json",
            "http://example.org",
            "https://subdomain.example.com:8080/path?query=value",
        ]

        for test_url in urls:
            anchor = Anchor.from_hash_hex(test_url, HASH_HEX)
            assert anchor.url == test_url
            assert anchor.hash_hex == HASH_HEX

    def test_anchor_with_long_url(self):
        """Test anchor with very long URL raises error due to size limit."""
        long_url = "https://example.com/" + "a" * 1000
        with pytest.raises(CardanoError):
            Anchor.from_hash_hex(long_url, HASH_HEX)

    def test_anchor_all_zeros_hash(self):
        """Test anchor with all zeros hash."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor.hash_hex == HASH_HEX
        assert anchor.hash_bytes == bytes(32)

    def test_anchor_all_ones_hash(self):
        """Test anchor with all ones hash."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX_2)

        assert anchor.hash_hex == HASH_HEX_2
        assert anchor.hash_bytes == bytes([0xff] * 32)

    def test_from_hash_bytes_and_from_hash_hex_equivalence(self):
        """Test that from_hash_bytes and from_hash_hex produce equivalent anchors."""
        hash_bytes = bytes.fromhex(HASH_HEX)

        anchor1 = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor2 = Anchor.from_hash_bytes(URL, hash_bytes)

        assert anchor1 == anchor2
        assert anchor1.url == anchor2.url
        assert anchor1.hash_hex == anchor2.hash_hex
        assert anchor1.hash_bytes == anchor2.hash_bytes

    def test_new_and_from_hash_hex_equivalence(self):
        """Test that new and from_hash_hex produce equivalent anchors."""
        hash_value = Blake2bHash.from_hex(HASH_HEX)

        anchor1 = Anchor.new(URL, hash_value)
        anchor2 = Anchor.from_hash_hex(URL, HASH_HEX)

        assert anchor1 == anchor2
        assert anchor1.url == anchor2.url
        assert anchor1.hash_hex == anchor2.hash_hex

    def test_multiple_cbor_serializations_are_consistent(self):
        """Test that multiple CBOR serializations produce same result."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        writer1 = CborWriter()
        anchor.to_cbor(writer1)
        cbor1 = writer1.to_hex()

        writer2 = CborWriter()
        anchor.to_cbor(writer2)
        cbor2 = writer2.to_hex()

        assert cbor1 == cbor2

    def test_multiple_json_serializations_are_consistent(self):
        """Test that multiple JSON serializations produce same result."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        writer1 = JsonWriter()
        anchor.to_cip116_json(writer1)
        json1 = writer1.encode()

        writer2 = JsonWriter()
        anchor.to_cip116_json(writer2)
        json2 = writer2.encode()

        assert json1 == json2

    def test_anchor_str_truncates_hash(self):
        """Test that __str__ truncates hash for readability."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        str_repr = str(anchor)

        assert "..." in str_repr

    def test_anchor_with_unicode_url(self):
        """Test anchor with URL containing unicode characters."""
        unicode_url = "https://example.com/ñoño"
        anchor = Anchor.from_hash_hex(unicode_url, HASH_HEX)

        assert anchor.url == unicode_url
        assert anchor.hash_hex == HASH_HEX

    def test_setting_url_multiple_times(self):
        """Test setting URL multiple times."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        anchor.url = URL_2
        assert anchor.url == URL_2

        anchor.url = URL
        assert anchor.url == URL

        anchor.url = "https://third.com"
        assert anchor.url == "https://third.com"

    def test_setting_hash_multiple_times(self):
        """Test setting hash multiple times."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)

        hash2 = Blake2bHash.from_hex(HASH_HEX_2)
        anchor.hash = hash2
        assert anchor.hash_hex == HASH_HEX_2

        hash1 = Blake2bHash.from_hex(HASH_HEX)
        anchor.hash = hash1
        assert anchor.hash_hex == HASH_HEX

    def test_cbor_deserialization_after_url_change(self):
        """Test that CBOR serialization reflects URL changes."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        anchor.url = URL_2

        writer = CborWriter()
        anchor.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized = Anchor.from_cbor(reader)

        assert deserialized.url == URL_2

    def test_cbor_deserialization_after_hash_change(self):
        """Test that CBOR serialization reflects hash changes."""
        anchor = Anchor.from_hash_hex(URL, HASH_HEX)
        new_hash = Blake2bHash.from_hex(HASH_HEX_2)
        anchor.hash = new_hash

        writer = CborWriter()
        anchor.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        deserialized = Anchor.from_cbor(reader)

        assert deserialized.hash_hex == HASH_HEX_2
