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
from cometa import IPv6, CborWriter, CborReader, CardanoError


class TestIPv6:
    """Comprehensive tests for IPv6 addresses."""

    IP_BYTES = bytes([0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                      0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04])
    CBOR_HEX = "5001020304010203040102030401020304"
    IP_STRING = "0102:0304:0102:0304:0102:0304:0102:0304"

    def test_from_bytes_valid(self):
        """Test creating IPv6 from valid bytes."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        assert ipv6 is not None
        assert ipv6.to_bytes() == self.IP_BYTES

    def test_from_bytes_bytearray(self):
        """Test creating IPv6 from bytearray."""
        ipv6 = IPv6.from_bytes(bytearray(self.IP_BYTES))
        assert ipv6 is not None
        assert ipv6.to_bytes() == self.IP_BYTES

    def test_from_bytes_invalid_length_short(self):
        """Test that invalid byte length (too short) raises error."""
        with pytest.raises(CardanoError, match="exactly 16 bytes"):
            IPv6.from_bytes(bytes([1, 2, 3, 4]))

    def test_from_bytes_invalid_length_long(self):
        """Test that invalid byte length (too long) raises error."""
        with pytest.raises(CardanoError, match="exactly 16 bytes"):
            IPv6.from_bytes(bytes([0] * 20))

    def test_from_bytes_empty(self):
        """Test that empty bytes raises error."""
        with pytest.raises(CardanoError, match="exactly 16 bytes"):
            IPv6.from_bytes(bytes())

    def test_from_string_valid(self):
        """Test creating IPv6 from valid string."""
        ipv6 = IPv6.from_string(self.IP_STRING)
        assert ipv6 is not None
        assert ipv6.to_string() == self.IP_STRING

    def test_from_string_loopback(self):
        """Test creating IPv6 loopback address (full notation)."""
        ipv6 = IPv6.from_string("0000:0000:0000:0000:0000:0000:0000:0001")
        assert ipv6 is not None
        data = ipv6.to_bytes()
        assert len(data) == 16
        assert data == bytes([0] * 15 + [1])

    def test_from_string_full_notation(self):
        """Test creating IPv6 from full notation string."""
        ipv6 = IPv6.from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert ipv6 is not None
        data = ipv6.to_bytes()
        assert len(data) == 16

    def test_from_string_empty(self):
        """Test that empty string raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_string("")

    def test_from_string_invalid_format(self):
        """Test that invalid IPv6 string raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_string("mm02:0304:0102:0304:0102:0304:0102:0304")

    def test_from_string_ipv4_address(self):
        """Test that IPv4 address format raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_string("10.3.2.1")

    def test_from_string_incomplete_ipv4(self):
        """Test that incomplete IPv4 address raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_string("10.3.2")

    def test_from_string_invalid_component(self):
        """Test that invalid component value raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_string("10.3.2.1216")

    def test_to_bytes(self):
        """Test converting IPv6 to bytes."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        data = ipv6.to_bytes()
        assert len(data) == 16
        assert data == self.IP_BYTES

    def test_to_bytes_loopback(self):
        """Test converting loopback address to bytes."""
        ipv6 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        data = ipv6.to_bytes()
        assert len(data) == 16
        assert data[-1] == 1
        assert all(b == 0 for b in data[:-1])

    def test_to_string(self):
        """Test converting IPv6 to string."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        ip_str = ipv6.to_string()
        assert ip_str == self.IP_STRING

    def test_to_string_loopback(self):
        """Test converting loopback address to string."""
        ipv6 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        ip_str = ipv6.to_string()
        assert ip_str == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_to_cbor(self):
        """Test serializing IPv6 to CBOR."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        writer = CborWriter()
        ipv6.to_cbor(writer)
        data = writer.encode()
        assert data is not None
        assert len(data) > 0

    def test_to_cbor_hex_encoding(self):
        """Test CBOR serialization matches expected hex."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        writer = CborWriter()
        ipv6.to_cbor(writer)
        hex_str = writer.encode().hex()
        assert hex_str == self.CBOR_HEX

    def test_to_cbor_invalid_writer(self):
        """Test that serializing with None writer raises error."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        with pytest.raises((CardanoError, AttributeError)):
            ipv6.to_cbor(None)

    def test_from_cbor(self):
        """Test deserializing IPv6 from CBOR."""
        reader = CborReader.from_hex(self.CBOR_HEX)
        ipv6 = IPv6.from_cbor(reader)
        assert ipv6 is not None
        assert ipv6.to_string() == self.IP_STRING

    def test_from_cbor_invalid_reader(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            IPv6.from_cbor(None)

    def test_from_cbor_invalid_data_type(self):
        """Test that deserializing invalid CBOR data type raises error."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            IPv6.from_cbor(reader)

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization roundtrip."""
        original = IPv6.from_bytes(self.IP_BYTES)
        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = IPv6.from_cbor(reader)
        assert original.to_bytes() == restored.to_bytes()
        assert original.to_string() == restored.to_string()

    def test_cbor_roundtrip_loopback(self):
        """Test CBOR roundtrip with loopback address."""
        original = IPv6.from_bytes(bytes([0] * 15 + [1]))
        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = IPv6.from_cbor(reader)
        assert original.to_bytes() == restored.to_bytes()

    def test_equality_same_bytes(self):
        """Test IPv6 equality with same bytes."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(self.IP_BYTES)
        assert ipv6_1 == ipv6_2

    def test_equality_from_string_and_bytes(self):
        """Test IPv6 equality from string and bytes."""
        ipv6_1 = IPv6.from_string(self.IP_STRING)
        ipv6_2 = IPv6.from_bytes(self.IP_BYTES)
        assert ipv6_1 == ipv6_2

    def test_inequality_different_bytes(self):
        """Test IPv6 inequality with different bytes."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        assert ipv6_1 != ipv6_2

    def test_equality_with_non_ipv6(self):
        """Test equality comparison with non-IPv6 object."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        assert ipv6 != "not an ipv6"
        assert ipv6 != 42
        assert ipv6 != None
        assert ipv6 != [1, 2, 3]

    def test_hash_same_address(self):
        """Test that same addresses have same hash."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(self.IP_BYTES)
        assert hash(ipv6_1) == hash(ipv6_2)

    def test_hash_different_address(self):
        """Test that different addresses have different hash."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        assert hash(ipv6_1) != hash(ipv6_2)

    def test_hash_usable_in_set(self):
        """Test that IPv6 can be used in a set."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_3 = IPv6.from_bytes(bytes([0] * 15 + [1]))

        ip_set = {ipv6_1, ipv6_2, ipv6_3}
        assert len(ip_set) == 2

    def test_hash_usable_in_dict(self):
        """Test that IPv6 can be used as dict key."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(bytes([0] * 15 + [1]))

        ip_dict = {ipv6_1: "first", ipv6_2: "second"}
        assert ip_dict[ipv6_1] == "first"
        assert ip_dict[ipv6_2] == "second"

    def test_repr(self):
        """Test IPv6 repr."""
        ipv6 = IPv6.from_string(self.IP_STRING)
        repr_str = repr(ipv6)
        assert "IPv6" in repr_str
        assert self.IP_STRING in repr_str

    def test_repr_loopback(self):
        """Test repr of loopback address."""
        ipv6 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        repr_str = repr(ipv6)
        assert "IPv6" in repr_str
        assert "0000:0000:0000:0000:0000:0000:0000:0001" in repr_str

    def test_str(self):
        """Test IPv6 str."""
        ipv6 = IPv6.from_string(self.IP_STRING)
        assert str(ipv6) == self.IP_STRING

    def test_str_loopback(self):
        """Test str of loopback address."""
        ipv6 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        assert str(ipv6) == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_context_manager_enter_exit(self):
        """Test IPv6 as context manager."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        with ipv6 as ip:
            assert ip is ipv6
            assert ip.to_bytes() == self.IP_BYTES

    def test_ip_size_constant(self):
        """Test IP_SIZE constant."""
        assert IPv6.IP_SIZE == 16

    def test_multiple_instances_independent(self):
        """Test that multiple IPv6 instances are independent."""
        ipv6_1 = IPv6.from_bytes(self.IP_BYTES)
        ipv6_2 = IPv6.from_bytes(bytes([0] * 15 + [1]))

        assert ipv6_1.to_bytes() == self.IP_BYTES
        assert ipv6_2.to_bytes() == bytes([0] * 15 + [1])

    def test_various_valid_addresses(self):
        """Test creating various valid IPv6 addresses."""
        test_cases = [
            ("0000:0000:0000:0000:0000:0000:0000:0001", bytes([0] * 15 + [1])),
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334",
             bytes([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0,
                   0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34])),
        ]

        for ip_string, expected_bytes in test_cases:
            ipv6 = IPv6.from_string(ip_string)
            assert ipv6.to_bytes() == expected_bytes

    def test_bytes_preservation(self):
        """Test that bytes are preserved exactly through conversion."""
        for i in range(0, 256, 16):
            test_bytes = bytes([i % 256] * 16)
            ipv6 = IPv6.from_bytes(test_bytes)
            assert ipv6.to_bytes() == test_bytes

    def test_string_roundtrip(self):
        """Test string to bytes and back."""
        ipv6_1 = IPv6.from_string(self.IP_STRING)
        ip_bytes = ipv6_1.to_bytes()
        ipv6_2 = IPv6.from_bytes(ip_bytes)
        assert ipv6_1.to_string() == ipv6_2.to_string()

    def test_invalid_handle_error(self):
        """Test that invalid handle raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            IPv6(ffi.NULL)

    def test_lifecycle_deletion(self):
        """Test that IPv6 can be properly deleted."""
        ipv6 = IPv6.from_bytes(self.IP_BYTES)
        data = ipv6.to_bytes()
        assert data == self.IP_BYTES
        del ipv6
