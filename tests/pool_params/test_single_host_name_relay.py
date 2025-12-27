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
from cometa import SingleHostNameRelay, CborWriter, CborReader, CardanoError, JsonWriter


class TestSingleHostNameRelay:
    """Comprehensive tests for SingleHostNameRelay."""

    URL = "example.com"
    CBOR = "8301f66b6578616d706c652e636f6d"
    CBOR_WITH_PORT = "83010a6b6578616d706c652e636f6d"

    def test_new_valid(self):
        """Test creating a single host name relay without port."""
        relay = SingleHostNameRelay.new(self.URL)
        assert relay is not None
        assert relay.dns == self.URL
        assert relay.port is None

    def test_new_with_port(self):
        """Test creating a single host name relay with port."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        assert relay is not None
        assert relay.dns == self.URL
        assert relay.port == 8080

    def test_new_with_zero_port(self):
        """Test creating relay with port 0."""
        relay = SingleHostNameRelay.new(self.URL, port=0)
        assert relay is not None
        assert relay.port == 0

    def test_new_with_max_port(self):
        """Test creating relay with maximum port value (65535)."""
        relay = SingleHostNameRelay.new(self.URL, port=65535)
        assert relay is not None
        assert relay.port == 65535

    def test_new_with_empty_dns(self):
        """Test that creating relay with empty DNS raises error."""
        with pytest.raises(CardanoError):
            SingleHostNameRelay.new("")

    def test_new_with_dns_too_long(self):
        """Test that creating relay with DNS longer than 64 chars raises error."""
        long_dns = "a" * 65
        with pytest.raises(CardanoError):
            SingleHostNameRelay.new(long_dns)

    def test_new_with_dns_max_length(self):
        """Test creating relay with DNS of maximum length (64 chars)."""
        max_dns = "a" * 64
        relay = SingleHostNameRelay.new(max_dns)
        assert relay is not None
        assert relay.dns == max_dns

    def test_to_cbor_without_port(self):
        """Test serializing relay without port to CBOR."""
        relay = SingleHostNameRelay.new(self.URL)
        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == self.CBOR

    def test_to_cbor_with_port(self):
        """Test serializing relay with port to CBOR."""
        relay = SingleHostNameRelay.new(self.URL, port=10)
        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == self.CBOR_WITH_PORT

    def test_to_cbor_invalid_writer(self):
        """Test that serializing with None writer raises error."""
        relay = SingleHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, AttributeError)):
            relay.to_cbor(None)

    def test_from_cbor_without_port(self):
        """Test deserializing relay without port from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        relay = SingleHostNameRelay.from_cbor(reader)
        assert relay is not None
        assert relay.dns == self.URL
        assert relay.port is None

    def test_from_cbor_with_port(self):
        """Test deserializing relay with port from CBOR."""
        reader = CborReader.from_hex(self.CBOR_WITH_PORT)
        relay = SingleHostNameRelay.from_cbor(reader)
        assert relay is not None
        assert relay.dns == self.URL
        assert relay.port == 10

    def test_from_cbor_invalid_reader(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            SingleHostNameRelay.from_cbor(None)

    def test_from_cbor_invalid_array_size(self):
        """Test that deserializing invalid CBOR array size raises error."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            SingleHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_array_size_two(self):
        """Test that deserializing CBOR with array size 2 raises error."""
        reader = CborReader.from_hex("82ff")
        with pytest.raises(CardanoError):
            SingleHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_second_element(self):
        """Test that deserializing CBOR with invalid second element raises error."""
        reader = CborReader.from_hex("8202ef")
        with pytest.raises(CardanoError):
            SingleHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_memory(self):
        """Test that deserializing CBOR with invalid memory structure raises error."""
        reader = CborReader.from_hex("83d81ea20102d81e820103")
        with pytest.raises(CardanoError):
            SingleHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_steps(self):
        """Test that deserializing CBOR with invalid steps raises error."""
        reader = CborReader.from_hex("83d81e820102d81ea20103")
        with pytest.raises(CardanoError):
            SingleHostNameRelay.from_cbor(reader)

    def test_cbor_roundtrip_without_port(self):
        """Test CBOR serialization/deserialization roundtrip without port."""
        original = SingleHostNameRelay.new(self.URL)
        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = SingleHostNameRelay.from_cbor(reader)
        assert original.dns == restored.dns
        assert original.port == restored.port

    def test_cbor_roundtrip_with_port(self):
        """Test CBOR serialization/deserialization roundtrip with port."""
        original = SingleHostNameRelay.new(self.URL, port=3001)
        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = SingleHostNameRelay.from_cbor(reader)
        assert original.dns == restored.dns
        assert original.port == restored.port

    def test_get_dns(self):
        """Test getting DNS property."""
        relay = SingleHostNameRelay.new(self.URL)
        assert relay.dns == self.URL

    def test_set_dns(self):
        """Test setting DNS property."""
        relay = SingleHostNameRelay.new(self.URL)
        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

    def test_set_dns_empty(self):
        """Test that setting empty DNS raises error."""
        relay = SingleHostNameRelay.new(self.URL)
        with pytest.raises(CardanoError):
            relay.dns = ""

    def test_set_dns_too_long(self):
        """Test that setting DNS longer than 64 chars raises error."""
        relay = SingleHostNameRelay.new(self.URL)
        long_dns = "a" * 65
        with pytest.raises(CardanoError):
            relay.dns = long_dns

    def test_set_dns_max_length(self):
        """Test setting DNS to maximum length (64 chars)."""
        relay = SingleHostNameRelay.new(self.URL)
        max_dns = "a" * 64
        relay.dns = max_dns
        assert relay.dns == max_dns

    def test_get_port_none(self):
        """Test getting port when not set."""
        relay = SingleHostNameRelay.new(self.URL)
        assert relay.port is None

    def test_get_port_set(self):
        """Test getting port when set."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        assert relay.port == 8080

    def test_set_port(self):
        """Test setting port property."""
        relay = SingleHostNameRelay.new(self.URL)
        relay.port = 8080
        assert relay.port == 8080

    def test_set_port_zero(self):
        """Test setting port to 0."""
        relay = SingleHostNameRelay.new(self.URL)
        relay.port = 0
        assert relay.port == 0

    def test_set_port_max(self):
        """Test setting port to maximum value (65535)."""
        relay = SingleHostNameRelay.new(self.URL)
        relay.port = 65535
        assert relay.port == 65535

    def test_set_port_none(self):
        """Test setting port to None (unsetting)."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        relay.port = None
        assert relay.port is None

    def test_unset_port(self):
        """Test unsetting port by setting to None."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        assert relay.port == 8080
        relay.port = None
        assert relay.port is None

    def test_to_cip116_json_with_port(self):
        """Test serializing to CIP-116 JSON with port."""
        relay = SingleHostNameRelay.new("example.com", port=65535)
        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"single_host_name"' in json_str
        assert '"port":65535' in json_str
        assert '"dns_name":"example.com"' in json_str

    def test_to_cip116_json_without_port(self):
        """Test serializing to CIP-116 JSON without port."""
        relay = SingleHostNameRelay.new("example.com")
        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"single_host_name"' in json_str
        assert '"port":null' in json_str
        assert '"dns_name":"example.com"' in json_str

    def test_to_cip116_json_invalid_writer(self):
        """Test that serializing to JSON with None writer raises error."""
        relay = SingleHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, TypeError)):
            relay.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        """Test that serializing to JSON with wrong type raises error."""
        relay = SingleHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, TypeError)):
            relay.to_cip116_json("not a writer")

    def test_repr_without_port(self):
        """Test repr without port."""
        relay = SingleHostNameRelay.new(self.URL)
        repr_str = repr(relay)
        assert "SingleHostNameRelay" in repr_str
        assert "dns=" in repr_str
        assert self.URL in repr_str
        assert "port=" not in repr_str

    def test_repr_with_port(self):
        """Test repr with port."""
        relay = SingleHostNameRelay.new(self.URL, port=3001)
        repr_str = repr(relay)
        assert "SingleHostNameRelay" in repr_str
        assert "dns=" in repr_str
        assert self.URL in repr_str
        assert "port=3001" in repr_str

    def test_str_without_port(self):
        """Test str without port."""
        relay = SingleHostNameRelay.new(self.URL)
        assert str(relay) == self.URL

    def test_str_with_port(self):
        """Test str with port."""
        relay = SingleHostNameRelay.new(self.URL, port=3001)
        assert str(relay) == f"{self.URL}:3001"

    def test_context_manager_enter_exit(self):
        """Test relay as context manager."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        with relay as r:
            assert r is relay
            assert r.dns == self.URL
            assert r.port == 8080

    def test_invalid_handle_error(self):
        """Test that invalid handle raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            SingleHostNameRelay(ffi.NULL)

    def test_lifecycle_deletion(self):
        """Test that relay can be properly deleted."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)
        dns = relay.dns
        port = relay.port
        assert dns == self.URL
        assert port == 8080
        del relay

    def test_multiple_instances_independent(self):
        """Test that multiple relay instances are independent."""
        relay1 = SingleHostNameRelay.new("relay1.example.com", port=3001)
        relay2 = SingleHostNameRelay.new("relay2.example.com", port=3002)

        assert relay1.dns == "relay1.example.com"
        assert relay1.port == 3001
        assert relay2.dns == "relay2.example.com"
        assert relay2.port == 3002

        relay1.dns = "updated1.example.com"
        relay1.port = 4001

        assert relay1.dns == "updated1.example.com"
        assert relay1.port == 4001
        assert relay2.dns == "relay2.example.com"
        assert relay2.port == 3002

    def test_dns_unicode_handling(self):
        """Test DNS with various characters."""
        test_cases = [
            "relay.example.com",
            "relay-1.example.com",
            "relay_1.example.com",
            "r.example.com",
            "very-long-relay-name-but-within-limit.example.com",
        ]
        for dns in test_cases:
            if len(dns) <= 64:
                relay = SingleHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_port_boundary_values(self):
        """Test port with various boundary values."""
        test_cases = [0, 1, 80, 443, 3000, 8080, 65534, 65535]
        for port in test_cases:
            relay = SingleHostNameRelay.new(self.URL, port=port)
            assert relay.port == port

    def test_cbor_serialization_consistency(self):
        """Test that multiple serializations produce same result."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)

        writer1 = CborWriter()
        relay.to_cbor(writer1)
        data1 = writer1.encode()

        writer2 = CborWriter()
        relay.to_cbor(writer2)
        data2 = writer2.encode()

        assert data1 == data2

    def test_property_modification_persistence(self):
        """Test that property modifications persist."""
        relay = SingleHostNameRelay.new(self.URL, port=8080)

        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

        relay.port = 9090
        assert relay.port == 9090

        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = SingleHostNameRelay.from_cbor(reader)
        assert restored.dns == "new.example.com"
        assert restored.port == 9090

    def test_various_valid_dns_names(self):
        """Test creating relays with various valid DNS names."""
        test_cases = [
            "a.com",
            "localhost",
            "relay.cardano.org",
            "relay-1.example.com",
            "relay_2.example.com",
            "r1.r2.r3.example.com",
        ]

        for dns in test_cases:
            if len(dns) <= 64:
                relay = SingleHostNameRelay.new(dns)
                assert relay.dns == dns
                assert relay.port is None

    def test_set_port_then_unset(self):
        """Test setting port and then unsetting it."""
        relay = SingleHostNameRelay.new(self.URL)
        assert relay.port is None

        relay.port = 8080
        assert relay.port == 8080

        relay.port = None
        assert relay.port is None

    def test_multiple_dns_updates(self):
        """Test updating DNS multiple times."""
        relay = SingleHostNameRelay.new(self.URL)
        assert relay.dns == self.URL

        relay.dns = "update1.com"
        assert relay.dns == "update1.com"

        relay.dns = "update2.com"
        assert relay.dns == "update2.com"

        relay.dns = "update3.com"
        assert relay.dns == "update3.com"

    def test_multiple_port_updates(self):
        """Test updating port multiple times."""
        relay = SingleHostNameRelay.new(self.URL, port=3001)
        assert relay.port == 3001

        relay.port = 3002
        assert relay.port == 3002

        relay.port = 3003
        assert relay.port == 3003

        relay.port = None
        assert relay.port is None

        relay.port = 3004
        assert relay.port == 3004
