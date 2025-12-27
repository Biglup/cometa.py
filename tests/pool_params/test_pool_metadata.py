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
    PoolMetadata,
    Blake2bHash,
    CborWriter,
    CborReader,
    JsonWriter,
    JsonFormat,
    CardanoError,
)


CBOR = "827368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5"
URL = "https://example.com"
HASH = "0f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5"


class TestPoolMetadata:
    """Tests for PoolMetadata class."""

    def test_new_creates_pool_metadata(self):
        """Test creating pool metadata with URL and hash."""
        hash_obj = Blake2bHash.from_hex(HASH)
        metadata = PoolMetadata.new(URL, hash_obj)
        assert metadata is not None
        assert metadata.url == URL

    def test_new_with_null_url_raises_error(self):
        """Test that None URL raises error."""
        hash_obj = Blake2bHash.from_hex(HASH)
        with pytest.raises(AttributeError):
            PoolMetadata.new(None, hash_obj)

    def test_new_with_null_hash_raises_error(self):
        """Test that None hash raises error."""
        with pytest.raises(AttributeError):
            PoolMetadata.new(URL, None)

    def test_new_with_url_bigger_than_128_raises_error(self):
        """Test that URL longer than 128 chars raises error."""
        hash_obj = Blake2bHash.from_hex(HASH)
        long_url = "https://example.com/" + "x" * 120
        with pytest.raises(CardanoError):
            PoolMetadata.new(long_url, hash_obj)

    def test_from_hash_hex_creates_pool_metadata(self):
        """Test creating pool metadata from URL and hex hash."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        assert metadata is not None
        assert metadata.url == URL
        assert metadata.hash.to_hex() == HASH

    def test_from_hash_hex_with_null_url_raises_error(self):
        """Test that None URL raises error."""
        with pytest.raises(AttributeError):
            PoolMetadata.from_hash_hex(None, HASH)

    def test_from_hash_hex_with_null_hash_raises_error(self):
        """Test that None hash raises error."""
        with pytest.raises(AttributeError):
            PoolMetadata.from_hash_hex(URL, None)

    def test_from_hash_hex_with_invalid_hash_length_raises_error(self):
        """Test that hash with wrong length raises error."""
        with pytest.raises(CardanoError):
            PoolMetadata.from_hash_hex(URL, HASH[:63])

    def test_to_cbor_serializes_pool_metadata(self):
        """Test serializing pool metadata to CBOR."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        writer = CborWriter()
        metadata.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that None writer raises error."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        with pytest.raises(AttributeError):
            metadata.to_cbor(None)

    def test_from_cbor_deserializes_pool_metadata(self):
        """Test deserializing pool metadata from CBOR."""
        reader = CborReader.from_hex(CBOR)
        metadata = PoolMetadata.from_cbor(reader)
        assert metadata is not None
        assert metadata.url == URL
        assert metadata.hash.to_hex() == HASH

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that None reader raises error."""
        with pytest.raises(AttributeError):
            PoolMetadata.from_cbor(None)

    def test_from_cbor_with_invalid_array_size_raises_error(self):
        """Test that invalid CBOR array size raises error."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            PoolMetadata.from_cbor(reader)

    def test_from_cbor_with_invalid_url_type_raises_error(self):
        """Test that invalid URL type in CBOR raises error."""
        invalid_cbor = "82ef7368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            PoolMetadata.from_cbor(reader)

    def test_from_cbor_with_invalid_hash_type_raises_error(self):
        """Test that invalid hash type in CBOR raises error."""
        invalid_cbor = "827368747470733a2f2f6578616d706c652e636f6def"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            PoolMetadata.from_cbor(reader)

    def test_get_url_returns_url(self):
        """Test getting URL from pool metadata."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        assert metadata.url == URL

    def test_set_url_updates_url(self):
        """Test setting URL on pool metadata."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        new_url = "https://example.com/this-is-a-long-url"
        metadata.url = new_url
        assert metadata.url == new_url

    def test_set_url_with_null_raises_error(self):
        """Test that setting None URL raises error."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        with pytest.raises(AttributeError):
            metadata.url = None

    def test_set_url_bigger_than_128_raises_error(self):
        """Test that URL longer than 128 chars raises error."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        long_url = "https://example.com/" + "x" * 120
        with pytest.raises(CardanoError):
            metadata.url = long_url

    def test_get_hash_returns_hash(self):
        """Test getting hash from pool metadata."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        hash_obj = metadata.hash
        assert hash_obj is not None
        assert hash_obj.to_hex() == HASH

    def test_set_hash_updates_hash(self):
        """Test setting hash on pool metadata."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        new_hash = Blake2bHash.from_hex(HASH)
        metadata.hash = new_hash
        assert metadata.hash.to_hex() == HASH

    def test_set_hash_with_null_raises_error(self):
        """Test that setting None hash raises error."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        with pytest.raises(AttributeError):
            metadata.hash = None

    def test_to_cip116_json_converts_to_json(self):
        """Test converting pool metadata to CIP-116 JSON."""
        url = "https://example.com/foo.json"
        hash_hex = "0000000000000000000000000000000000000000000000000000000000000000"
        hash_obj = Blake2bHash.from_hex(hash_hex)
        metadata = PoolMetadata.new(url, hash_obj)

        writer = JsonWriter(JsonFormat.COMPACT)
        metadata.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"url":"https://example.com/foo.json","hash":"0000000000000000000000000000000000000000000000000000000000000000"}'
        assert json_str == expected

    def test_to_cip116_json_with_null_writer_raises_error(self):
        """Test that None writer raises error."""
        hash_obj = Blake2bHash.from_hex(HASH)
        metadata = PoolMetadata.new(URL, hash_obj)
        with pytest.raises((CardanoError, TypeError)):
            metadata.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_type_raises_error(self):
        """Test that invalid writer type raises error."""
        hash_obj = Blake2bHash.from_hex(HASH)
        metadata = PoolMetadata.new(URL, hash_obj)
        with pytest.raises(TypeError):
            metadata.to_cip116_json("not a writer")

    def test_repr(self):
        """Test pool metadata repr."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        repr_str = repr(metadata)
        assert "PoolMetadata" in repr_str
        assert URL in repr_str
        assert HASH in repr_str

    def test_str(self):
        """Test pool metadata str."""
        metadata = PoolMetadata.from_hash_hex(URL, HASH)
        assert str(metadata) == URL

    def test_context_manager(self):
        """Test pool metadata as context manager."""
        with PoolMetadata.from_hash_hex(URL, HASH) as metadata:
            assert metadata is not None
            assert metadata.url == URL

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization roundtrip."""
        original = PoolMetadata.from_hash_hex(URL, HASH)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        restored = PoolMetadata.from_cbor(reader)

        assert restored.url == original.url
        assert restored.hash.to_hex() == original.hash.to_hex()

    def test_multiple_metadata_objects(self):
        """Test creating multiple independent pool metadata objects."""
        url1 = "https://pool1.example.com"
        url2 = "https://pool2.example.com"
        hash1 = "1" * 64
        hash2 = "2" * 64

        metadata1 = PoolMetadata.from_hash_hex(url1, hash1)
        metadata2 = PoolMetadata.from_hash_hex(url2, hash2)

        assert metadata1.url == url1
        assert metadata2.url == url2
        assert metadata1.hash.to_hex() == hash1
        assert metadata2.hash.to_hex() == hash2

    def test_url_edge_cases(self):
        """Test URL edge cases."""
        hash_obj = Blake2bHash.from_hex(HASH)

        short_url = "https://a.b"
        metadata = PoolMetadata.new(short_url, hash_obj)
        assert metadata.url == short_url

        max_url = "https://" + "x" * 120
        metadata = PoolMetadata.new(max_url, hash_obj)
        assert metadata.url == max_url

    def test_hash_independence(self):
        """Test that hash object is independent after creation."""
        hash_obj = Blake2bHash.from_hex(HASH)
        metadata = PoolMetadata.new(URL, hash_obj)

        retrieved_hash1 = metadata.hash
        retrieved_hash2 = metadata.hash

        assert retrieved_hash1.to_hex() == retrieved_hash2.to_hex()
