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
from cometa import crc32


class TestCrc32:
    """Tests for the crc32 function."""

    def test_empty_data(self):
        """Test CRC32 computation with empty data."""
        result = crc32(b"")
        assert result == 0

    def test_quick_brown_fox(self):
        """Test CRC32 computation with 'quick brown fox' test vector."""
        data = b"The quick brown fox jumps over the lazy dog"
        result = crc32(data)
        assert result == 0x414FA339

    def test_various_crc_algorithms(self):
        """Test CRC32 computation with 'various CRC algorithms' test vector."""
        data = b"various CRC algorithms input data"
        result = crc32(data)
        assert result == 0x9BD366AE

    def test_febooti_test_vector(self):
        """Test CRC32 computation with test vector from febooti.com."""
        data = b"Test vector from febooti.com"
        result = crc32(data)
        assert result == 0x0C877F61

    def test_hello_world(self):
        """Test CRC32 computation with 'Hello, world!' string."""
        data = b"Hello, world!"
        result = crc32(data)
        assert result == 3957769958

    def test_deterministic(self):
        """Test that CRC32 produces consistent results for the same input."""
        data = b"Test data for deterministic check"
        result1 = crc32(data)
        result2 = crc32(data)
        assert result1 == result2

    def test_different_inputs_different_results(self):
        """Test that different inputs produce different CRC32 checksums."""
        result1 = crc32(b"data1")
        result2 = crc32(b"data2")
        assert result1 != result2

    def test_return_type(self):
        """Test that CRC32 returns an integer."""
        result = crc32(b"test data")
        assert isinstance(result, int)

    def test_return_value_range(self):
        """Test that CRC32 returns a 32-bit unsigned integer."""
        result = crc32(b"test data")
        assert 0 <= result <= 0xFFFFFFFF

    def test_bytes_input(self):
        """Test CRC32 with bytes input."""
        data = bytes([0x00, 0x01, 0x02, 0x03, 0x04])
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_bytearray_input(self):
        """Test CRC32 with bytearray input."""
        data = bytearray([0x00, 0x01, 0x02, 0x03, 0x04])
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_bytes_and_bytearray_same_result(self):
        """Test that bytes and bytearray with same content produce same CRC32."""
        data_bytes = bytes([0x01, 0x02, 0x03])
        data_bytearray = bytearray([0x01, 0x02, 0x03])
        result1 = crc32(data_bytes)
        result2 = crc32(data_bytearray)
        assert result1 == result2

    def test_single_byte(self):
        """Test CRC32 with single byte input."""
        result = crc32(b"\x00")
        assert isinstance(result, int)
        assert result > 0

    def test_large_data(self):
        """Test CRC32 with large data input."""
        data = b"A" * 10000
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_binary_data(self):
        """Test CRC32 with binary data containing all byte values."""
        data = bytes(range(256))
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_null_bytes(self):
        """Test CRC32 with null bytes."""
        data = b"\x00\x00\x00\x00"
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_utf8_encoded_string(self):
        """Test CRC32 with UTF-8 encoded string."""
        data = "Hello, 世界!".encode('utf-8')
        result = crc32(data)
        assert isinstance(result, int)
        assert result >= 0

    def test_sensitivity_to_byte_order(self):
        """Test that CRC32 is sensitive to byte order."""
        result1 = crc32(b"\x01\x02")
        result2 = crc32(b"\x02\x01")
        assert result1 != result2

    def test_sensitivity_to_length(self):
        """Test that CRC32 is sensitive to data length."""
        result1 = crc32(b"test")
        result2 = crc32(b"test\x00")
        assert result1 != result2
