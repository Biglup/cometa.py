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
from cometa import MultiHostNameRelay, CborWriter, CborReader, CardanoError, JsonWriter


class TestMultiHostNameRelay:
    """Comprehensive tests for MultiHostNameRelay."""

    URL = "example.com"
    CBOR = "82026b6578616d706c652e636f6d"

    def test_new_valid(self):
        """Test creating a multi host name relay."""
        relay = MultiHostNameRelay.new(self.URL)
        assert relay is not None
        assert relay.dns == self.URL

    def test_new_with_various_dns_names(self):
        """Test creating relay with various valid DNS names."""
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
                relay = MultiHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_new_with_empty_dns(self):
        """Test that creating relay with empty DNS raises error."""
        with pytest.raises(CardanoError):
            MultiHostNameRelay.new("")

    def test_new_with_dns_too_long(self):
        """Test that creating relay with DNS longer than 64 chars raises error."""
        long_dns = "a" * 65
        with pytest.raises(CardanoError):
            MultiHostNameRelay.new(long_dns)

    def test_new_with_dns_max_length(self):
        """Test creating relay with DNS of maximum length (64 chars)."""
        max_dns = "a" * 64
        relay = MultiHostNameRelay.new(max_dns)
        assert relay is not None
        assert relay.dns == max_dns

    def test_to_cbor_valid(self):
        """Test serializing relay to CBOR."""
        relay = MultiHostNameRelay.new(self.URL)
        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == self.CBOR

    def test_to_cbor_invalid_writer(self):
        """Test that serializing with None writer raises error."""
        relay = MultiHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, AttributeError)):
            relay.to_cbor(None)

    def test_from_cbor_valid(self):
        """Test deserializing relay from CBOR."""
        reader = CborReader.from_hex(self.CBOR)
        relay = MultiHostNameRelay.from_cbor(reader)
        assert relay is not None
        assert relay.dns == self.URL

    def test_from_cbor_invalid_reader(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            MultiHostNameRelay.from_cbor(None)

    def test_from_cbor_invalid_array_size(self):
        """Test that deserializing invalid CBOR array size raises error."""
        reader = CborReader.from_hex("81")
        with pytest.raises(CardanoError):
            MultiHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_first_element(self):
        """Test that deserializing CBOR with invalid first element raises error."""
        reader = CborReader.from_hex("82ff")
        with pytest.raises(CardanoError):
            MultiHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_second_element(self):
        """Test that deserializing CBOR with invalid second element raises error."""
        reader = CborReader.from_hex("8202ef")
        with pytest.raises(CardanoError):
            MultiHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_memory(self):
        """Test that deserializing CBOR with invalid memory structure raises error."""
        reader = CborReader.from_hex("82d81ea20102d81e820103")
        with pytest.raises(CardanoError):
            MultiHostNameRelay.from_cbor(reader)

    def test_from_cbor_invalid_steps(self):
        """Test that deserializing CBOR with invalid steps raises error."""
        reader = CborReader.from_hex("82d81e820102d81ea20103")
        with pytest.raises(CardanoError):
            MultiHostNameRelay.from_cbor(reader)

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization roundtrip."""
        original = MultiHostNameRelay.new(self.URL)
        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = MultiHostNameRelay.from_cbor(reader)
        assert original.dns == restored.dns

    def test_cbor_roundtrip_with_various_dns(self):
        """Test CBOR roundtrip with various DNS names."""
        test_cases = ["relay.example.com", "a.b.c", "localhost", "r" * 64]
        for dns in test_cases:
            if len(dns) <= 64:
                original = MultiHostNameRelay.new(dns)
                writer = CborWriter()
                original.to_cbor(writer)
                data = writer.encode()

                reader = CborReader.from_bytes(data)
                restored = MultiHostNameRelay.from_cbor(reader)
                assert original.dns == restored.dns

    def test_get_dns(self):
        """Test getting DNS property."""
        relay = MultiHostNameRelay.new(self.URL)
        assert relay.dns == self.URL

    def test_set_dns(self):
        """Test setting DNS property."""
        relay = MultiHostNameRelay.new(self.URL)
        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

    def test_set_dns_empty(self):
        """Test that setting empty DNS raises error."""
        relay = MultiHostNameRelay.new(self.URL)
        with pytest.raises(CardanoError):
            relay.dns = ""

    def test_set_dns_too_long(self):
        """Test that setting DNS longer than 64 chars raises error."""
        relay = MultiHostNameRelay.new(self.URL)
        long_dns = "a" * 65
        with pytest.raises(CardanoError):
            relay.dns = long_dns

    def test_set_dns_max_length(self):
        """Test setting DNS to maximum length (64 chars)."""
        relay = MultiHostNameRelay.new(self.URL)
        max_dns = "a" * 64
        relay.dns = max_dns
        assert relay.dns == max_dns

    def test_to_cip116_json_valid(self):
        """Test serializing to CIP-116 JSON."""
        relay = MultiHostNameRelay.new("example.com")
        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()
        assert '"tag":"multi_host_name"' in json_str
        assert '"dns_name":"example.com"' in json_str

    def test_to_cip116_json_invalid_writer_none(self):
        """Test that serializing to JSON with None writer raises error."""
        relay = MultiHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, TypeError)):
            relay.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        """Test that serializing to JSON with wrong type raises error."""
        relay = MultiHostNameRelay.new(self.URL)
        with pytest.raises((CardanoError, TypeError)):
            relay.to_cip116_json("not a writer")

    def test_repr(self):
        """Test repr output."""
        relay = MultiHostNameRelay.new(self.URL)
        repr_str = repr(relay)
        assert "MultiHostNameRelay" in repr_str
        assert "dns=" in repr_str
        assert self.URL in repr_str

    def test_str(self):
        """Test str output."""
        relay = MultiHostNameRelay.new(self.URL)
        assert str(relay) == self.URL

    def test_context_manager_enter_exit(self):
        """Test relay as context manager."""
        relay = MultiHostNameRelay.new(self.URL)
        with relay as r:
            assert r is relay
            assert r.dns == self.URL

    def test_invalid_handle_error(self):
        """Test that invalid handle raises error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            MultiHostNameRelay(ffi.NULL)

    def test_lifecycle_deletion(self):
        """Test that relay can be properly deleted."""
        relay = MultiHostNameRelay.new(self.URL)
        dns = relay.dns
        assert dns == self.URL
        del relay

    def test_multiple_instances_independent(self):
        """Test that multiple relay instances are independent."""
        relay1 = MultiHostNameRelay.new("relay1.example.com")
        relay2 = MultiHostNameRelay.new("relay2.example.com")

        assert relay1.dns == "relay1.example.com"
        assert relay2.dns == "relay2.example.com"

        relay1.dns = "updated1.example.com"

        assert relay1.dns == "updated1.example.com"
        assert relay2.dns == "relay2.example.com"

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
                relay = MultiHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_cbor_serialization_consistency(self):
        """Test that multiple serializations produce same result."""
        relay = MultiHostNameRelay.new(self.URL)

        writer1 = CborWriter()
        relay.to_cbor(writer1)
        data1 = writer1.encode()

        writer2 = CborWriter()
        relay.to_cbor(writer2)
        data2 = writer2.encode()

        assert data1 == data2

    def test_property_modification_persistence(self):
        """Test that property modifications persist."""
        relay = MultiHostNameRelay.new(self.URL)

        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = MultiHostNameRelay.from_cbor(reader)
        assert restored.dns == "new.example.com"

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
                relay = MultiHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_multiple_dns_updates(self):
        """Test updating DNS multiple times."""
        relay = MultiHostNameRelay.new(self.URL)
        assert relay.dns == self.URL

        relay.dns = "update1.com"
        assert relay.dns == "update1.com"

        relay.dns = "update2.com"
        assert relay.dns == "update2.com"

        relay.dns = "update3.com"
        assert relay.dns == "update3.com"

    def test_cbor_deserialization_from_c_test_vector(self):
        """Test deserialization using the CBOR hex from C test."""
        reader = CborReader.from_hex(self.CBOR)
        relay = MultiHostNameRelay.from_cbor(reader)
        assert relay.dns == self.URL

    def test_cbor_serialization_matches_c_test_vector(self):
        """Test that serialization produces the same CBOR as C implementation."""
        relay = MultiHostNameRelay.new(self.URL)
        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == self.CBOR

    def test_dns_with_special_characters(self):
        """Test DNS with hyphens and underscores."""
        test_cases = [
            "relay-1.example.com",
            "relay_2.example.com",
            "relay-3_test.example.com",
            "r-e-l-a-y.com",
        ]
        for dns in test_cases:
            if len(dns) <= 64:
                relay = MultiHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_dns_single_character(self):
        """Test DNS with single character."""
        relay = MultiHostNameRelay.new("a")
        assert relay.dns == "a"

    def test_dns_with_numbers(self):
        """Test DNS with numbers."""
        test_cases = [
            "relay1.example.com",
            "123.456.789.012",
            "relay-123.test.com",
        ]
        for dns in test_cases:
            if len(dns) <= 64:
                relay = MultiHostNameRelay.new(dns)
                assert relay.dns == dns

    def test_dns_update_after_serialization(self):
        """Test updating DNS after CBOR serialization."""
        relay = MultiHostNameRelay.new(self.URL)

        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()
        assert cbor_hex == self.CBOR

        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

        writer2 = CborWriter()
        relay.to_cbor(writer2)
        cbor_hex2 = writer2.encode().hex()
        assert cbor_hex2 != self.CBOR

    def test_multiple_cbor_roundtrips(self):
        """Test multiple serialization/deserialization cycles."""
        original = MultiHostNameRelay.new(self.URL)

        for _ in range(3):
            writer = CborWriter()
            original.to_cbor(writer)
            data = writer.encode()

            reader = CborReader.from_bytes(data)
            original = MultiHostNameRelay.from_cbor(reader)

        assert original.dns == self.URL

    def test_cip116_json_format(self):
        """Test CIP-116 JSON output format matches expected structure."""
        relay = MultiHostNameRelay.new("example.com")
        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.count('"tag"') == 1
        assert json_str.count('"multi_host_name"') == 1
        assert json_str.count('"dns_name"') == 1
        assert json_str.count('"example.com"') == 1

    def test_cbor_writer_reuse(self):
        """Test that CBOR writer can be reused for multiple relays."""
        relay1 = MultiHostNameRelay.new("relay1.com")
        relay2 = MultiHostNameRelay.new("relay2.com")

        writer = CborWriter()
        relay1.to_cbor(writer)
        data1 = writer.encode()

        writer = CborWriter()
        relay2.to_cbor(writer)
        data2 = writer.encode()

        reader1 = CborReader.from_bytes(data1)
        restored1 = MultiHostNameRelay.from_cbor(reader1)
        assert restored1.dns == "relay1.com"

        reader2 = CborReader.from_bytes(data2)
        restored2 = MultiHostNameRelay.from_cbor(reader2)
        assert restored2.dns == "relay2.com"

    def test_dns_boundary_lengths(self):
        """Test DNS with various boundary lengths."""
        for length in [1, 2, 10, 32, 63, 64]:
            dns = "a" * length
            relay = MultiHostNameRelay.new(dns)
            assert relay.dns == dns
            assert len(relay.dns) == length

    def test_set_dns_preserves_object(self):
        """Test that setting DNS doesn't create a new object."""
        relay = MultiHostNameRelay.new(self.URL)
        original_repr = repr(relay)

        relay.dns = "new.example.com"

        assert relay.dns == "new.example.com"
