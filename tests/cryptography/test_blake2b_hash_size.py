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

# pylint: disable=no-self-use

import pytest
from cometa import Blake2bHashSize


class TestBlake2bHashSize:
    """Tests for the Blake2bHashSize enum."""

    def test_blake2b_hash_size_values(self):
        """Test that Blake2bHashSize enum values are correct."""
        assert Blake2bHashSize.HASH_224 == 28
        assert Blake2bHashSize.HASH_256 == 32
        assert Blake2bHashSize.HASH_512 == 64

    def test_blake2b_hash_size_from_int(self):
        """Test creating Blake2bHashSize from integer values."""
        assert Blake2bHashSize(28) == Blake2bHashSize.HASH_224
        assert Blake2bHashSize(32) == Blake2bHashSize.HASH_256
        assert Blake2bHashSize(64) == Blake2bHashSize.HASH_512

    def test_blake2b_hash_size_comparison(self):
        """Test comparison between Blake2bHashSize values."""
        assert Blake2bHashSize.HASH_224 != Blake2bHashSize.HASH_256
        assert Blake2bHashSize.HASH_224 == Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_256 != Blake2bHashSize.HASH_512
        assert Blake2bHashSize.HASH_512 == Blake2bHashSize.HASH_512

    def test_blake2b_hash_size_names(self):
        """Test that Blake2bHashSize enum has correct names."""
        assert Blake2bHashSize.HASH_224.name == "HASH_224"
        assert Blake2bHashSize.HASH_256.name == "HASH_256"
        assert Blake2bHashSize.HASH_512.name == "HASH_512"

    def test_blake2b_hash_size_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            Blake2bHashSize(16)
        with pytest.raises(ValueError):
            Blake2bHashSize(0)
        with pytest.raises(ValueError):
            Blake2bHashSize(100)
        with pytest.raises(ValueError):
            Blake2bHashSize(-1)

    def test_blake2b_hash_size_is_int_enum(self):
        """Test that Blake2bHashSize values can be used as integers."""
        assert isinstance(Blake2bHashSize.HASH_224, int)
        assert isinstance(Blake2bHashSize.HASH_256, int)
        assert isinstance(Blake2bHashSize.HASH_512, int)
        assert Blake2bHashSize.HASH_224 + 4 == 32
        assert Blake2bHashSize.HASH_256 * 2 == 64
        assert Blake2bHashSize.HASH_512 // 2 == 32

    def test_blake2b_hash_size_iteration(self):
        """Test iteration over Blake2bHashSize enum."""
        values = list(Blake2bHashSize)
        assert len(values) == 3
        assert Blake2bHashSize.HASH_224 in values
        assert Blake2bHashSize.HASH_256 in values
        assert Blake2bHashSize.HASH_512 in values

    def test_blake2b_hash_size_membership(self):
        """Test membership testing with Blake2bHashSize."""
        assert 28 in Blake2bHashSize.__members__.values()
        assert 32 in Blake2bHashSize.__members__.values()
        assert 64 in Blake2bHashSize.__members__.values()
        assert "HASH_224" in Blake2bHashSize.__members__
        assert "HASH_256" in Blake2bHashSize.__members__
        assert "HASH_512" in Blake2bHashSize.__members__

    def test_blake2b_hash_size_string_representation(self):
        """Test string representation of Blake2bHashSize values."""
        assert str(Blake2bHashSize.HASH_224) == "Blake2bHashSize.HASH_224"
        assert str(Blake2bHashSize.HASH_256) == "Blake2bHashSize.HASH_256"
        assert str(Blake2bHashSize.HASH_512) == "Blake2bHashSize.HASH_512"

    def test_blake2b_hash_size_repr(self):
        """Test repr of Blake2bHashSize values."""
        assert repr(Blake2bHashSize.HASH_224) == "<Blake2bHashSize.HASH_224: 28>"
        assert repr(Blake2bHashSize.HASH_256) == "<Blake2bHashSize.HASH_256: 32>"
        assert repr(Blake2bHashSize.HASH_512) == "<Blake2bHashSize.HASH_512: 64>"

    def test_blake2b_hash_size_bool_conversion(self):
        """Test boolean conversion of Blake2bHashSize values."""
        assert bool(Blake2bHashSize.HASH_224) is True
        assert bool(Blake2bHashSize.HASH_256) is True
        assert bool(Blake2bHashSize.HASH_512) is True

    def test_blake2b_hash_size_arithmetic(self):
        """Test arithmetic operations with Blake2bHashSize values."""
        assert Blake2bHashSize.HASH_224 + Blake2bHashSize.HASH_224 == 56
        assert Blake2bHashSize.HASH_256 * 2 == 64
        assert Blake2bHashSize.HASH_512 - Blake2bHashSize.HASH_256 == 32
        assert Blake2bHashSize.HASH_512 // Blake2bHashSize.HASH_256 == 2

    def test_blake2b_hash_size_hash(self):
        """Test that Blake2bHashSize values are hashable."""
        hash_size_set = {
            Blake2bHashSize.HASH_224,
            Blake2bHashSize.HASH_256,
            Blake2bHashSize.HASH_512
        }
        assert len(hash_size_set) == 3
        assert Blake2bHashSize.HASH_224 in hash_size_set
        assert Blake2bHashSize.HASH_256 in hash_size_set
        assert Blake2bHashSize.HASH_512 in hash_size_set

    def test_blake2b_hash_size_as_dict_key(self):
        """Test using Blake2bHashSize as dictionary key."""
        hash_size_dict = {
            Blake2bHashSize.HASH_224: "224-bit",
            Blake2bHashSize.HASH_256: "256-bit",
            Blake2bHashSize.HASH_512: "512-bit"
        }
        assert hash_size_dict[Blake2bHashSize.HASH_224] == "224-bit"
        assert hash_size_dict[Blake2bHashSize.HASH_256] == "256-bit"
        assert hash_size_dict[Blake2bHashSize.HASH_512] == "512-bit"

    def test_blake2b_hash_size_ordering(self):
        """Test ordering comparison between Blake2bHashSize values."""
        assert Blake2bHashSize.HASH_224 < Blake2bHashSize.HASH_256
        assert Blake2bHashSize.HASH_256 < Blake2bHashSize.HASH_512
        assert Blake2bHashSize.HASH_512 > Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_256 > Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_224 <= Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_512 >= Blake2bHashSize.HASH_512


class TestBlake2bHashSizeEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert Blake2bHashSize.HASH_224 == Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_224 != Blake2bHashSize.HASH_256
        assert Blake2bHashSize.HASH_512 == Blake2bHashSize.HASH_512

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        hs1 = Blake2bHashSize.HASH_224
        hs2 = Blake2bHashSize.HASH_224
        assert hs1 is hs2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(Blake2bHashSize.HASH_224) == 28
        assert int(Blake2bHashSize.HASH_256) == 32
        assert int(Blake2bHashSize.HASH_512) == 64

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_values = list(Blake2bHashSize)
        assert len(all_values) == 3

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert Blake2bHashSize.HASH_224 in Blake2bHashSize
        assert Blake2bHashSize.HASH_256 in Blake2bHashSize
        assert Blake2bHashSize.HASH_512 in Blake2bHashSize

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert Blake2bHashSize.HASH_224.name == "HASH_224"
        assert Blake2bHashSize.HASH_256.name == "HASH_256"
        assert Blake2bHashSize.HASH_512.name == "HASH_512"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert Blake2bHashSize.HASH_224.value == 28
        assert Blake2bHashSize.HASH_256.value == 32
        assert Blake2bHashSize.HASH_512.value == 64

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert Blake2bHashSize(28) == Blake2bHashSize.HASH_224
        assert Blake2bHashSize(32) == Blake2bHashSize.HASH_256
        assert Blake2bHashSize(64) == Blake2bHashSize.HASH_512

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            Blake2bHashSize(100)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            Blake2bHashSize(-1)

    def test_invalid_value_zero(self):
        """Test that value 0 raises ValueError."""
        with pytest.raises(ValueError):
            Blake2bHashSize(0)

    def test_invalid_value_between_sizes(self):
        """Test that values between valid sizes raise ValueError."""
        with pytest.raises(ValueError):
            Blake2bHashSize(30)
        with pytest.raises(ValueError):
            Blake2bHashSize(50)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(Blake2bHashSize.HASH_224) == "Blake2bHashSize.HASH_224"
        assert repr(Blake2bHashSize.HASH_256) == "<Blake2bHashSize.HASH_256: 32>"


class TestBlake2bHashSizeBytes:
    """Tests for byte size semantics of Blake2bHashSize."""

    def test_hash_224_byte_size(self):
        """Test that HASH_224 represents 28 bytes (224 bits)."""
        assert Blake2bHashSize.HASH_224 == 28
        assert Blake2bHashSize.HASH_224 * 8 == 224

    def test_hash_256_byte_size(self):
        """Test that HASH_256 represents 32 bytes (256 bits)."""
        assert Blake2bHashSize.HASH_256 == 32
        assert Blake2bHashSize.HASH_256 * 8 == 256

    def test_hash_512_byte_size(self):
        """Test that HASH_512 represents 64 bytes (512 bits)."""
        assert Blake2bHashSize.HASH_512 == 64
        assert Blake2bHashSize.HASH_512 * 8 == 512

    def test_bit_conversion(self):
        """Test converting byte sizes to bit sizes."""
        assert Blake2bHashSize.HASH_224 * 8 == 224
        assert Blake2bHashSize.HASH_256 * 8 == 256
        assert Blake2bHashSize.HASH_512 * 8 == 512

    def test_size_relationships(self):
        """Test size relationships between hash types."""
        assert Blake2bHashSize.HASH_256 > Blake2bHashSize.HASH_224
        assert Blake2bHashSize.HASH_512 > Blake2bHashSize.HASH_256
        assert Blake2bHashSize.HASH_512 == Blake2bHashSize.HASH_256 * 2
        assert Blake2bHashSize.HASH_256 == Blake2bHashSize.HASH_224 + 4


class TestBlake2bHashSizeUseCases:
    """Tests for common use cases of Blake2bHashSize."""

    def test_can_use_as_buffer_size(self):
        """Test that Blake2bHashSize can be used to determine buffer sizes."""
        buffer_224 = bytearray(Blake2bHashSize.HASH_224)
        buffer_256 = bytearray(Blake2bHashSize.HASH_256)
        buffer_512 = bytearray(Blake2bHashSize.HASH_512)
        assert len(buffer_224) == 28
        assert len(buffer_256) == 32
        assert len(buffer_512) == 64

    def test_can_use_in_range(self):
        """Test that Blake2bHashSize can be used in range operations."""
        range_224 = list(range(Blake2bHashSize.HASH_224))
        range_256 = list(range(Blake2bHashSize.HASH_256))
        range_512 = list(range(Blake2bHashSize.HASH_512))
        assert len(range_224) == 28
        assert len(range_256) == 32
        assert len(range_512) == 64

    def test_can_use_for_slicing(self):
        """Test that Blake2bHashSize can be used for slicing."""
        data = bytes(100)
        slice_224 = data[:Blake2bHashSize.HASH_224]
        slice_256 = data[:Blake2bHashSize.HASH_256]
        slice_512 = data[:Blake2bHashSize.HASH_512]
        assert len(slice_224) == 28
        assert len(slice_256) == 32
        assert len(slice_512) == 64

    def test_can_use_for_byte_validation(self):
        """Test that Blake2bHashSize can be used to validate byte lengths."""
        valid_224 = bytes(28)
        valid_256 = bytes(32)
        valid_512 = bytes(64)
        assert len(valid_224) == Blake2bHashSize.HASH_224
        assert len(valid_256) == Blake2bHashSize.HASH_256
        assert len(valid_512) == Blake2bHashSize.HASH_512

    def test_can_compare_with_byte_length(self):
        """Test that Blake2bHashSize can be compared with byte lengths."""
        data_28 = bytes(28)
        data_32 = bytes(32)
        data_64 = bytes(64)
        assert len(data_28) == Blake2bHashSize.HASH_224
        assert len(data_32) == Blake2bHashSize.HASH_256
        assert len(data_64) == Blake2bHashSize.HASH_512
        assert len(data_28) < Blake2bHashSize.HASH_256
        assert len(data_32) < Blake2bHashSize.HASH_512
        assert len(data_64) > Blake2bHashSize.HASH_224
