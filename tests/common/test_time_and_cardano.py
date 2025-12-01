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
    NetworkMagic,
    get_lib_version,
    memzero,
    slot_from_unix_time,
    unix_time_from_slot,
    epoch_from_unix_time,
)


class TestNetworkMagic:
    """Tests for the NetworkMagic enum."""

    def test_network_magic_values(self):
        """Test that all network magic values are correct."""
        assert NetworkMagic.PREPROD == 1
        assert NetworkMagic.PREVIEW == 2
        assert NetworkMagic.SANCHONET == 4
        assert NetworkMagic.MAINNET == 764824073

    def test_network_magic_from_int(self):
        """Test creating NetworkMagic from integers."""
        assert NetworkMagic(1) == NetworkMagic.PREPROD
        assert NetworkMagic(2) == NetworkMagic.PREVIEW
        assert NetworkMagic(4) == NetworkMagic.SANCHONET
        assert NetworkMagic(764824073) == NetworkMagic.MAINNET

    def test_network_magic_str(self):
        """Test string representation of network magic values."""
        # The C library returns lowercase network names
        assert "mainnet" in str(NetworkMagic.MAINNET).lower()
        assert "preprod" in str(NetworkMagic.PREPROD).lower()
        assert "preview" in str(NetworkMagic.PREVIEW).lower()

    def test_network_magic_repr(self):
        """Test repr of network magic values."""
        assert repr(NetworkMagic.MAINNET) == "NetworkMagic.MAINNET"
        assert repr(NetworkMagic.PREPROD) == "NetworkMagic.PREPROD"


class TestGetLibVersion:
    """Tests for the get_lib_version function."""

    def test_get_lib_version_returns_string(self):
        """Test that get_lib_version returns a non-empty string."""
        version = get_lib_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_get_lib_version_semver_format(self):
        """Test that version follows semantic versioning format."""
        version = get_lib_version()
        # SemVer format: MAJOR.MINOR.PATCH
        parts = version.split(".")
        assert len(parts) >= 2  # At least MAJOR.MINOR
        # All parts should be numeric (possibly with suffix like -alpha)
        assert parts[0].isdigit()
        assert parts[1].isdigit()


class TestMemzero:
    """Tests for the memzero function."""

    def test_memzero_clears_buffer(self):
        """Test that memzero clears a buffer."""
        data = bytearray(b"sensitive_data_here")
        original_len = len(data)

        memzero(data)

        # Buffer should now be all zeros
        assert len(data) == original_len
        assert all(b == 0 for b in data)

    def test_memzero_empty_buffer(self):
        """Test that memzero handles empty buffer."""
        data = bytearray()
        memzero(data)  # Should not raise
        assert len(data) == 0

    def test_memzero_single_byte(self):
        """Test memzero with single byte buffer."""
        data = bytearray(b"X")
        memzero(data)
        assert data == bytearray(b"\x00")

    def test_memzero_large_buffer(self):
        """Test memzero with larger buffer."""
        data = bytearray(b"A" * 1024)
        memzero(data)
        assert all(b == 0 for b in data)

    def test_memzero_requires_bytearray(self):
        """Test that memzero requires a bytearray."""
        with pytest.raises(TypeError):
            memzero(b"immutable bytes")

        with pytest.raises(TypeError):
            memzero("string")

        with pytest.raises(TypeError):
            memzero([1, 2, 3])


class TestSlotFromUnixTime:
    """Tests for the slot_from_unix_time function."""

    def test_slot_from_unix_time_mainnet(self):
        """Test computing slot from unix time on mainnet."""
        # Use a known unix time
        unix_time = 1700000000  # November 14, 2023
        slot = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)

        assert isinstance(slot, int)
        assert slot > 0

    def test_slot_from_unix_time_with_int_magic(self):
        """Test that integer magic values work."""
        unix_time = 1700000000
        slot1 = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)
        slot2 = slot_from_unix_time(764824073, unix_time)  # Mainnet magic as int

        assert slot1 == slot2

    def test_slot_from_unix_time_different_networks(self):
        """Test that different networks give different slot values."""
        unix_time = 1700000000

        slot_mainnet = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)
        slot_preprod = slot_from_unix_time(NetworkMagic.PREPROD, unix_time)

        # Different networks should have different slot calculations
        assert slot_mainnet != slot_preprod


class TestUnixTimeFromSlot:
    """Tests for the unix_time_from_slot function."""

    def test_unix_time_from_slot_mainnet(self):
        """Test computing unix time from slot on mainnet."""
        slot = 100000000
        unix_time = unix_time_from_slot(NetworkMagic.MAINNET, slot)

        assert isinstance(unix_time, int)
        assert unix_time > 0

    def test_unix_time_from_slot_with_int_magic(self):
        """Test that integer magic values work."""
        slot = 100000000
        time1 = unix_time_from_slot(NetworkMagic.MAINNET, slot)
        time2 = unix_time_from_slot(764824073, slot)

        assert time1 == time2

    def test_slot_unix_time_roundtrip(self):
        """Test that slot <-> unix time conversion is reversible."""
        original_unix_time = 1700000000

        slot = slot_from_unix_time(NetworkMagic.MAINNET, original_unix_time)
        recovered_unix_time = unix_time_from_slot(NetworkMagic.MAINNET, slot)

        # Should be close (within slot duration)
        assert abs(recovered_unix_time - original_unix_time) <= 1


class TestEpochFromUnixTime:
    """Tests for the epoch_from_unix_time function."""

    def test_epoch_from_unix_time_mainnet(self):
        """Test computing epoch from unix time on mainnet."""
        unix_time = 1700000000
        epoch = epoch_from_unix_time(NetworkMagic.MAINNET, unix_time)

        assert isinstance(epoch, int)
        assert epoch > 0

    def test_epoch_from_unix_time_with_int_magic(self):
        """Test that integer magic values work."""
        unix_time = 1700000000
        epoch1 = epoch_from_unix_time(NetworkMagic.MAINNET, unix_time)
        epoch2 = epoch_from_unix_time(764824073, unix_time)

        assert epoch1 == epoch2

    def test_epoch_increases_with_time(self):
        """Test that epoch increases as time increases."""
        # One year apart in seconds
        unix_time1 = 1700000000
        unix_time2 = 1700000000 + (365 * 24 * 60 * 60)

        epoch1 = epoch_from_unix_time(NetworkMagic.MAINNET, unix_time1)
        epoch2 = epoch_from_unix_time(NetworkMagic.MAINNET, unix_time2)

        assert epoch2 > epoch1
