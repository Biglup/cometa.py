"""
Tests for the cardano module.

This module contains comprehensive tests for the cardano module functions,
including get_lib_version() and memzero() with various valid and invalid arguments.
Test vectors adapted from vendor/cardano-c/lib/tests/cardano.cpp.
"""

import pytest
from cometa import get_lib_version, memzero


def test_get_lib_version_returns_valid_version():
    """Test that get_lib_version returns a valid version string."""
    version = get_lib_version()
    assert isinstance(version, str)
    assert len(version) > 0


def test_get_lib_version_follows_semver_format():
    """Test that the version string follows Semantic Versioning format."""
    version = get_lib_version()
    parts = version.split('.')
    assert len(parts) == 3
    for part in parts:
        assert part.isdigit() or part[0].isdigit()


def test_memzero_zeroes_buffer():
    """Test that memzero successfully zeroes out a buffer.

    Adapted from C test: cardano_memzero, zeroes_buffer
    """
    buffer = bytearray([0x01, 0x02, 0x03, 0x04, 0x05])
    memzero(buffer)
    assert buffer == bytearray([0x00, 0x00, 0x00, 0x00, 0x00])


def test_memzero_with_empty_buffer():
    """Test that memzero handles empty buffer gracefully.

    Adapted from C test: cardano_memzero, doesntCrashIfGivenNullOrEmpty
    """
    buffer = bytearray()
    memzero(buffer)
    assert buffer == bytearray()


def test_memzero_with_single_byte_buffer():
    """Test that memzero works with a single byte buffer."""
    buffer = bytearray([0xFF])
    memzero(buffer)
    assert buffer == bytearray([0x00])


def test_memzero_with_large_buffer():
    """Test that memzero works with a larger buffer."""
    buffer = bytearray(b"secret_key_12345_very_sensitive_data")
    memzero(buffer)
    assert buffer == bytearray([0x00] * len(buffer))
    assert all(byte == 0 for byte in buffer)


def test_memzero_raises_type_error_for_bytes():
    """Test that memzero raises TypeError for immutable bytes type."""
    buffer = b"immutable"
    with pytest.raises(TypeError, match="buffer must be a bytearray"):
        memzero(buffer)


def test_memzero_raises_type_error_for_string():
    """Test that memzero raises TypeError for string type."""
    buffer = "not a buffer"
    with pytest.raises(TypeError, match="buffer must be a bytearray"):
        memzero(buffer)


def test_memzero_raises_type_error_for_list():
    """Test that memzero raises TypeError for list type."""
    buffer = [1, 2, 3, 4, 5]
    with pytest.raises(TypeError, match="buffer must be a bytearray"):
        memzero(buffer)


def test_memzero_raises_type_error_for_none():
    """Test that memzero raises TypeError for None."""
    with pytest.raises(TypeError, match="buffer must be a bytearray"):
        memzero(None)


def test_memzero_modifies_buffer_in_place():
    """Test that memzero modifies the buffer in place without creating a copy."""
    original_buffer = bytearray([0xAA, 0xBB, 0xCC, 0xDD])
    buffer_reference = original_buffer
    memzero(original_buffer)
    assert original_buffer == bytearray([0x00, 0x00, 0x00, 0x00])
    assert buffer_reference == bytearray([0x00, 0x00, 0x00, 0x00])
    assert buffer_reference is original_buffer


def test_memzero_with_all_zeros():
    """Test that memzero works correctly on an already zeroed buffer."""
    buffer = bytearray([0x00, 0x00, 0x00])
    memzero(buffer)
    assert buffer == bytearray([0x00, 0x00, 0x00])


def test_memzero_with_max_byte_values():
    """Test that memzero works with buffer containing max byte values (0xFF)."""
    buffer = bytearray([0xFF] * 10)
    memzero(buffer)
    assert buffer == bytearray([0x00] * 10)


def test_get_lib_version_is_consistent():
    """Test that get_lib_version returns the same version across multiple calls."""
    version1 = get_lib_version()
    version2 = get_lib_version()
    assert version1 == version2


def test_get_lib_version_returns_string_not_bytes():
    """Test that get_lib_version returns str, not bytes."""
    version = get_lib_version()
    assert isinstance(version, str)
    assert not isinstance(version, bytes)
