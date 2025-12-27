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
from cometa import IPv4, CardanoError
from cometa.cbor import CborReader, CborWriter


CBOR = "440a03020a"
IP_BYTES = bytes([10, 3, 2, 10])
IP_STRING = "10.3.2.10"


class TestIPv4FromBytes:
    """Tests for IPv4.from_bytes factory method."""

    def test_can_create_from_bytes(self):
        ipv4 = IPv4.from_bytes(IP_BYTES)
        assert ipv4 is not None
        assert ipv4.to_bytes() == IP_BYTES

    def test_can_create_from_bytearray(self):
        ipv4 = IPv4.from_bytes(bytearray(IP_BYTES))
        assert ipv4 is not None
        assert ipv4.to_bytes() == IP_BYTES

    def test_raises_error_if_bytes_invalid_length(self):
        with pytest.raises(CardanoError, match="IPv4 requires exactly 4 bytes"):
            IPv4.from_bytes(bytes([10, 3, 2]))

    def test_raises_error_if_bytes_empty(self):
        with pytest.raises(CardanoError, match="IPv4 requires exactly 4 bytes"):
            IPv4.from_bytes(bytes([]))

    def test_raises_error_if_bytes_too_long(self):
        with pytest.raises(CardanoError, match="IPv4 requires exactly 4 bytes"):
            IPv4.from_bytes(bytes([10, 3, 2, 10, 1]))


class TestIPv4FromString:
    """Tests for IPv4.from_string factory method."""

    def test_can_create_from_string(self):
        ipv4 = IPv4.from_string(IP_STRING)
        assert ipv4 is not None
        assert ipv4.to_string() == IP_STRING

    def test_can_create_various_valid_ips(self):
        test_cases = [
            ("0.0.0.0", bytes([0, 0, 0, 0])),
            ("255.255.255.255", bytes([255, 255, 255, 255])),
            ("192.168.1.1", bytes([192, 168, 1, 1])),
            ("127.0.0.1", bytes([127, 0, 0, 1])),
        ]
        for ip_str, expected_bytes in test_cases:
            ipv4 = IPv4.from_string(ip_str)
            assert ipv4.to_string() == ip_str
            assert ipv4.to_bytes() == expected_bytes

    def test_raises_error_if_string_invalid_format(self):
        with pytest.raises(CardanoError, match="Failed to create IPv4 from string"):
            IPv4.from_string("10.3.2")

    def test_raises_error_if_string_invalid_format_2(self):
        with pytest.raises(CardanoError, match="Failed to create IPv4 from string"):
            IPv4.from_string("10.32.23")

    def test_raises_error_if_octet_out_of_range(self):
        with pytest.raises(CardanoError, match="Failed to create IPv4 from string"):
            IPv4.from_string("10.3.2.1216")

    def test_raises_error_if_string_empty(self):
        with pytest.raises(CardanoError, match="Failed to create IPv4 from string"):
            IPv4.from_string("")

    def test_raises_error_if_string_invalid_characters(self):
        with pytest.raises(CardanoError, match="Failed to create IPv4 from string"):
            IPv4.from_string("abc.def.ghi.jkl")


class TestIPv4FromCbor:
    """Tests for IPv4.from_cbor deserialization."""

    def test_can_deserialize_from_cbor(self):
        reader = CborReader.from_hex(CBOR)
        ipv4 = IPv4.from_cbor(reader)
        assert ipv4 is not None
        assert ipv4.to_string() == IP_STRING

    def test_raises_error_if_cbor_invalid_major_type(self):
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError, match="Failed to deserialize IPv4 from CBOR"):
            IPv4.from_cbor(reader)

    def test_raises_error_if_cbor_reader_none(self):
        with pytest.raises(AttributeError):
            IPv4.from_cbor(None)


class TestIPv4ToBytes:
    """Tests for IPv4.to_bytes method."""

    def test_can_get_bytes(self):
        ipv4 = IPv4.from_bytes(IP_BYTES)
        result = ipv4.to_bytes()
        assert result == IP_BYTES
        assert len(result) == 4

    def test_bytes_are_correct_for_various_ips(self):
        test_cases = [
            ("0.0.0.0", bytes([0, 0, 0, 0])),
            ("255.255.255.255", bytes([255, 255, 255, 255])),
            ("192.168.1.1", bytes([192, 168, 1, 1])),
        ]
        for ip_str, expected_bytes in test_cases:
            ipv4 = IPv4.from_string(ip_str)
            assert ipv4.to_bytes() == expected_bytes


class TestIPv4ToString:
    """Tests for IPv4.to_string method."""

    def test_can_get_string(self):
        ipv4 = IPv4.from_string(IP_STRING)
        result = ipv4.to_string()
        assert result == IP_STRING

    def test_string_matches_for_various_ips(self):
        test_ips = [
            "0.0.0.0",
            "255.255.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "10.3.2.10",
        ]
        for ip_str in test_ips:
            ipv4 = IPv4.from_string(ip_str)
            assert ipv4.to_string() == ip_str


class TestIPv4ToCbor:
    """Tests for IPv4.to_cbor serialization."""

    def test_can_serialize_to_cbor(self):
        ipv4 = IPv4.from_bytes(IP_BYTES)
        writer = CborWriter()
        ipv4.to_cbor(writer)

        result_hex = writer.to_hex()
        assert result_hex == CBOR

    def test_raises_error_if_writer_none(self):
        ipv4 = IPv4.from_bytes(IP_BYTES)
        with pytest.raises(AttributeError):
            ipv4.to_cbor(None)


class TestIPv4Equality:
    """Tests for IPv4 equality comparison."""

    def test_equal_ipv4_addresses(self):
        ipv4_1 = IPv4.from_string(IP_STRING)
        ipv4_2 = IPv4.from_string(IP_STRING)
        assert ipv4_1 == ipv4_2

    def test_equal_from_bytes_and_string(self):
        ipv4_1 = IPv4.from_bytes(IP_BYTES)
        ipv4_2 = IPv4.from_string(IP_STRING)
        assert ipv4_1 == ipv4_2

    def test_not_equal_different_addresses(self):
        ipv4_1 = IPv4.from_string("192.168.1.1")
        ipv4_2 = IPv4.from_string("192.168.1.2")
        assert ipv4_1 != ipv4_2

    def test_not_equal_to_non_ipv4(self):
        ipv4 = IPv4.from_string(IP_STRING)
        assert ipv4 != "not an IPv4"
        assert ipv4 != 12345
        assert ipv4 != None


class TestIPv4Hash:
    """Tests for IPv4 hash functionality."""

    def test_can_hash_ipv4(self):
        ipv4 = IPv4.from_string(IP_STRING)
        hash_value = hash(ipv4)
        assert isinstance(hash_value, int)

    def test_equal_ipv4_have_equal_hash(self):
        ipv4_1 = IPv4.from_string(IP_STRING)
        ipv4_2 = IPv4.from_bytes(IP_BYTES)
        assert hash(ipv4_1) == hash(ipv4_2)

    def test_can_use_in_set(self):
        ipv4_1 = IPv4.from_string("192.168.1.1")
        ipv4_2 = IPv4.from_string("192.168.1.2")
        ipv4_3 = IPv4.from_string("192.168.1.1")

        ip_set = {ipv4_1, ipv4_2, ipv4_3}
        assert len(ip_set) == 2

    def test_can_use_as_dict_key(self):
        ipv4_1 = IPv4.from_string("192.168.1.1")
        ipv4_2 = IPv4.from_string("192.168.1.2")

        ip_dict = {ipv4_1: "first", ipv4_2: "second"}
        assert ip_dict[ipv4_1] == "first"
        assert ip_dict[ipv4_2] == "second"


class TestIPv4StringRepresentation:
    """Tests for IPv4 string representation methods."""

    def test_str_returns_dotted_decimal(self):
        ipv4 = IPv4.from_string(IP_STRING)
        assert str(ipv4) == IP_STRING

    def test_repr_returns_formatted_string(self):
        ipv4 = IPv4.from_string(IP_STRING)
        result = repr(ipv4)
        assert result == f"IPv4({IP_STRING})"
        assert "IPv4" in result
        assert IP_STRING in result


class TestIPv4ContextManager:
    """Tests for IPv4 context manager support."""

    def test_can_use_as_context_manager(self):
        with IPv4.from_string(IP_STRING) as ipv4:
            assert ipv4 is not None
            assert ipv4.to_string() == IP_STRING

    def test_context_manager_returns_self(self):
        ipv4 = IPv4.from_string(IP_STRING)
        with ipv4 as ctx_ipv4:
            assert ctx_ipv4 is ipv4


class TestIPv4RoundTrip:
    """Tests for IPv4 round-trip conversions."""

    def test_bytes_round_trip(self):
        original_bytes = IP_BYTES
        ipv4 = IPv4.from_bytes(original_bytes)
        result_bytes = ipv4.to_bytes()
        assert result_bytes == original_bytes

    def test_string_round_trip(self):
        original_string = IP_STRING
        ipv4 = IPv4.from_string(original_string)
        result_string = ipv4.to_string()
        assert result_string == original_string

    def test_cbor_round_trip(self):
        original = IPv4.from_bytes(IP_BYTES)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        result = IPv4.from_cbor(reader)

        assert original == result

    def test_bytes_string_round_trip(self):
        ipv4_from_bytes = IPv4.from_bytes(IP_BYTES)
        string_repr = ipv4_from_bytes.to_string()
        ipv4_from_string = IPv4.from_string(string_repr)
        result_bytes = ipv4_from_string.to_bytes()

        assert result_bytes == IP_BYTES


class TestIPv4EdgeCases:
    """Tests for IPv4 edge cases and special addresses."""

    def test_localhost(self):
        ipv4 = IPv4.from_string("127.0.0.1")
        assert ipv4.to_string() == "127.0.0.1"
        assert ipv4.to_bytes() == bytes([127, 0, 0, 1])

    def test_zero_address(self):
        ipv4 = IPv4.from_string("0.0.0.0")
        assert ipv4.to_string() == "0.0.0.0"
        assert ipv4.to_bytes() == bytes([0, 0, 0, 0])

    def test_broadcast_address(self):
        ipv4 = IPv4.from_string("255.255.255.255")
        assert ipv4.to_string() == "255.255.255.255"
        assert ipv4.to_bytes() == bytes([255, 255, 255, 255])

    def test_private_network_addresses(self):
        test_cases = [
            "10.0.0.0",
            "172.16.0.0",
            "192.168.0.0",
        ]
        for ip_str in test_cases:
            ipv4 = IPv4.from_string(ip_str)
            assert ipv4.to_string() == ip_str
