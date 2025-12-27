"""
Tests for time conversion functions.

This module contains comprehensive tests for time conversion functions
between Unix timestamps and Cardano slots, including valid and invalid arguments.
"""

import pytest
from cometa import NetworkMagic, slot_from_unix_time, unix_time_from_slot


def test_slot_from_unix_time_mainnet():
    """Test conversion from Unix time to slot on mainnet."""
    unix_time = 1730901968
    expected_slot = 139335677

    result = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)

    assert result == expected_slot
    assert isinstance(result, int)


def test_slot_from_unix_time_preview():
    """Test conversion from Unix time to slot on preview network."""
    unix_time = 1730901968
    expected_slot = 64245968

    result = slot_from_unix_time(NetworkMagic.PREVIEW, unix_time)

    assert result == expected_slot
    assert isinstance(result, int)


def test_slot_from_unix_time_preprod():
    """Test conversion from Unix time to slot on preprod network."""
    unix_time = 1730901968
    expected_slot = 75218768

    result = slot_from_unix_time(NetworkMagic.PREPROD, unix_time)

    assert result == expected_slot
    assert isinstance(result, int)


def test_slot_from_unix_time_with_int_magic():
    """Test conversion from Unix time to slot using integer network magic."""
    unix_time = 1730901968
    expected_slot = 139335677

    result = slot_from_unix_time(764824073, unix_time)

    assert result == expected_slot
    assert isinstance(result, int)


def test_slot_from_unix_time_zero():
    """Test conversion from Unix time zero."""
    result_mainnet = slot_from_unix_time(NetworkMagic.MAINNET, 0)
    result_preview = slot_from_unix_time(NetworkMagic.PREVIEW, 0)
    result_preprod = slot_from_unix_time(NetworkMagic.PREPROD, 0)

    assert isinstance(result_mainnet, int)
    assert isinstance(result_preview, int)
    assert isinstance(result_preprod, int)


def test_slot_from_unix_time_large_value():
    """Test conversion with large Unix timestamp."""
    unix_time = 2000000000

    result = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)

    assert isinstance(result, int)
    assert result > 0


def test_slot_from_unix_time_negative_raises_error():
    """Test that negative Unix time raises an appropriate error."""
    with pytest.raises((ValueError, OverflowError, OSError)):
        slot_from_unix_time(NetworkMagic.MAINNET, -1)


def test_unix_time_from_slot_mainnet():
    """Test conversion from slot to Unix time on mainnet."""
    slot = 139335677
    expected_unix_time = 1730901968

    result = unix_time_from_slot(NetworkMagic.MAINNET, slot)

    assert result == expected_unix_time
    assert isinstance(result, int)


def test_unix_time_from_slot_preview():
    """Test conversion from slot to Unix time on preview network."""
    slot = 64245968
    expected_unix_time = 1730901968

    result = unix_time_from_slot(NetworkMagic.PREVIEW, slot)

    assert result == expected_unix_time
    assert isinstance(result, int)


def test_unix_time_from_slot_preprod():
    """Test conversion from slot to Unix time on preprod network."""
    slot = 75218768
    expected_unix_time = 1730901968

    result = unix_time_from_slot(NetworkMagic.PREPROD, slot)

    assert result == expected_unix_time
    assert isinstance(result, int)


def test_unix_time_from_slot_with_int_magic():
    """Test conversion from slot to Unix time using integer network magic."""
    slot = 139335677
    expected_unix_time = 1730901968

    result = unix_time_from_slot(764824073, slot)

    assert result == expected_unix_time
    assert isinstance(result, int)


def test_unix_time_from_slot_zero():
    """Test conversion from slot zero."""
    result_mainnet = unix_time_from_slot(NetworkMagic.MAINNET, 0)
    result_preview = unix_time_from_slot(NetworkMagic.PREVIEW, 0)
    result_preprod = unix_time_from_slot(NetworkMagic.PREPROD, 0)

    assert isinstance(result_mainnet, int)
    assert isinstance(result_preview, int)
    assert isinstance(result_preprod, int)


def test_unix_time_from_slot_large_value():
    """Test conversion from large slot number."""
    slot = 1000000000

    result = unix_time_from_slot(NetworkMagic.MAINNET, slot)

    assert isinstance(result, int)
    assert result > 0


def test_unix_time_from_slot_negative_raises_error():
    """Test that negative slot raises an appropriate error."""
    with pytest.raises((ValueError, OverflowError, OSError)):
        unix_time_from_slot(NetworkMagic.MAINNET, -1)


def test_roundtrip_slot_to_time_to_slot():
    """Test roundtrip conversion: slot -> time -> slot."""
    original_slot = 139335677

    unix_time = unix_time_from_slot(NetworkMagic.MAINNET, original_slot)
    result_slot = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)

    assert result_slot == original_slot


def test_roundtrip_time_to_slot_to_time():
    """Test roundtrip conversion: time -> slot -> time."""
    original_time = 1730901968

    slot = slot_from_unix_time(NetworkMagic.MAINNET, original_time)
    result_time = unix_time_from_slot(NetworkMagic.MAINNET, slot)

    assert result_time == original_time


def test_roundtrip_all_networks():
    """Test roundtrip conversion across all networks."""
    unix_time = 1730901968

    for network in [NetworkMagic.MAINNET, NetworkMagic.PREVIEW, NetworkMagic.PREPROD]:
        slot = slot_from_unix_time(network, unix_time)
        result_time = unix_time_from_slot(network, slot)
        assert result_time == unix_time


def test_slot_from_unix_time_invalid_network_magic():
    """Test conversion with invalid network magic."""
    unix_time = 1730901968
    invalid_magic = 999999999

    result = slot_from_unix_time(invalid_magic, unix_time)
    assert isinstance(result, int)


def test_unix_time_from_slot_invalid_network_magic():
    """Test conversion with invalid network magic."""
    slot = 139335677
    invalid_magic = 999999999

    result = unix_time_from_slot(invalid_magic, slot)
    assert isinstance(result, int)


def test_slot_from_unix_time_sanchonet():
    """Test conversion from Unix time to slot on sanchonet."""
    unix_time = 1730901968

    result = slot_from_unix_time(NetworkMagic.SANCHONET, unix_time)

    assert isinstance(result, int)
    assert result >= 0


def test_unix_time_from_slot_sanchonet():
    """Test conversion from slot to Unix time on sanchonet."""
    slot = 100000

    result = unix_time_from_slot(NetworkMagic.SANCHONET, slot)

    assert isinstance(result, int)
    assert result >= 0


def test_slot_from_unix_time_early_cardano_era():
    """Test conversion with timestamp from early Cardano era."""
    unix_time = 1506203091

    result = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)

    assert isinstance(result, int)
    assert result >= 0


def test_slot_from_unix_time_multiple_values():
    """Test conversion with multiple Unix timestamps."""
    test_cases = [
        (1600000000, NetworkMagic.MAINNET),
        (1650000000, NetworkMagic.MAINNET),
        (1700000000, NetworkMagic.MAINNET),
        (1730901968, NetworkMagic.MAINNET),
    ]

    for unix_time, network in test_cases:
        result = slot_from_unix_time(network, unix_time)
        assert isinstance(result, int)
        assert result >= 0


def test_unix_time_from_slot_multiple_values():
    """Test conversion with multiple slot numbers."""
    test_cases = [
        (100000000, NetworkMagic.MAINNET),
        (120000000, NetworkMagic.MAINNET),
        (130000000, NetworkMagic.MAINNET),
        (139335677, NetworkMagic.MAINNET),
    ]

    for slot, network in test_cases:
        result = unix_time_from_slot(network, slot)
        assert isinstance(result, int)
        assert result >= 0


def test_slot_from_unix_time_type_validation():
    """Test that function handles type conversion properly."""
    unix_time = 1730901968

    result_enum = slot_from_unix_time(NetworkMagic.MAINNET, unix_time)
    result_int = slot_from_unix_time(764824073, unix_time)

    assert result_enum == result_int


def test_unix_time_from_slot_type_validation():
    """Test that function handles type conversion properly."""
    slot = 139335677

    result_enum = unix_time_from_slot(NetworkMagic.MAINNET, slot)
    result_int = unix_time_from_slot(764824073, slot)

    assert result_enum == result_int
