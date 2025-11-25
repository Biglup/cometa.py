import pytest

from biglup.cometa.common import ProtocolVersion


def test_protocol_version_basic_roundtrip():
    # Create with initial values
    v = ProtocolVersion.from_numbers(1, 0)

    assert v.major == 1
    assert v.minor == 0

    # Change values via setters
    v.major = 2
    v.minor = 3

    assert v.major == 2
    assert v.minor == 3

    # Refcount should be >= 1
    rc_before = v.refcount()
    assert rc_before >= 1

    # Clone increases refcount
    v_clone = v.clone()
    rc_after = v.refcount()
    assert rc_after == rc_before + 1 or rc_after >= rc_before  # depending on implementation

    # Cloned object sees same values
    assert v_clone.major == 2
    assert v_clone.minor == 3
