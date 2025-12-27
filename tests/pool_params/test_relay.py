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
    Relay,
    RelayType,
    SingleHostAddrRelay,
    SingleHostNameRelay,
    MultiHostNameRelay,
    CborWriter,
    CborReader,
    CardanoError,
    JsonWriter,
    IPv4,
    IPv6,
)
from cometa.pool_params.relay import to_relay


class TestRelay:
    """Comprehensive tests for Relay."""

    SINGLE_HOST_NAME_RELAY_CBOR = "83010a6b6578616d706c652e636f6d"
    SINGLE_HOST_NAME_RELAY_NO_PORT_CBOR = "8301f66b6578616d706c652e636f6d"
    MULTI_HOST_NAME_RELAY_CBOR = "82026b6578616d706c652e636f6d"
    SINGLE_HOST_ADDR_RELAY_CBOR = "84000a440a03020a5001020304010203040102030401020304"
    SINGLE_HOST_ADDR_RELAY_IPV4_MAPPED_IPV6_CBOR = (
        "84000a440a03020a5000000000000000000000ffff0a03020a"
    )

    def test_from_single_host_addr_valid(self):
        """Test creating a Relay from a valid SingleHostAddrRelay."""
        ipv4 = IPv4.from_string("10.3.2.10")
        ipv6 = IPv6.from_string("0102:0304:0102:0304:0102:0304:0102:0304")
        single_host_addr = SingleHostAddrRelay.new(port=10, ipv4=ipv4, ipv6=ipv6)

        relay = Relay.from_single_host_addr(single_host_addr)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_from_single_host_addr_none(self):
        """Test that creating Relay from None raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            Relay.from_single_host_addr(None)

    def test_from_single_host_name_valid(self):
        """Test creating a Relay from a valid SingleHostNameRelay."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)

        relay = Relay.from_single_host_name(single_host_name)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_NAME

    def test_from_single_host_name_none(self):
        """Test that creating Relay from None raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            Relay.from_single_host_name(None)

    def test_from_multi_host_name_valid(self):
        """Test creating a Relay from a valid MultiHostNameRelay."""
        multi_host_name = MultiHostNameRelay.new("example.com")

        relay = Relay.from_multi_host_name(multi_host_name)

        assert relay is not None
        assert relay.relay_type == RelayType.MULTI_HOST_NAME

    def test_from_multi_host_name_none(self):
        """Test that creating Relay from None raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            Relay.from_multi_host_name(None)

    def test_from_cbor_single_host_name(self):
        """Test deserializing a single host name relay from CBOR."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)

        relay = Relay.from_cbor(reader)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_NAME

    def test_from_cbor_single_host_name_no_port(self):
        """Test deserializing a single host name relay without port from CBOR."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_NO_PORT_CBOR)

        relay = Relay.from_cbor(reader)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_NAME

    def test_from_cbor_multi_host_name(self):
        """Test deserializing a multi-host name relay from CBOR."""
        reader = CborReader.from_hex(self.MULTI_HOST_NAME_RELAY_CBOR)

        relay = Relay.from_cbor(reader)

        assert relay is not None
        assert relay.relay_type == RelayType.MULTI_HOST_NAME

    def test_from_cbor_single_host_addr(self):
        """Test deserializing a single host address relay from CBOR."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)

        relay = Relay.from_cbor(reader)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_from_cbor_single_host_addr_ipv4_mapped_ipv6(self):
        """Test deserializing a single host address relay with IPv4-mapped IPv6."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_IPV4_MAPPED_IPV6_CBOR)

        relay = Relay.from_cbor(reader)

        assert relay is not None
        assert relay.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_from_cbor_invalid_reader(self):
        """Test that deserializing with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            Relay.from_cbor(None)

    def test_from_cbor_invalid_cbor(self):
        """Test that deserializing invalid CBOR raises error."""
        reader = CborReader.from_hex("a10101")
        with pytest.raises(CardanoError):
            Relay.from_cbor(reader)

    def test_from_cbor_invalid_array_type(self):
        """Test that deserializing invalid CBOR array type raises error."""
        reader = CborReader.from_hex("81ef")
        with pytest.raises(CardanoError):
            Relay.from_cbor(reader)

    def test_from_cbor_invalid_single_host_addr_array_size(self):
        """Test that deserializing invalid single host address CBOR array size raises error."""
        reader = CborReader.from_hex("8200ef")
        with pytest.raises(CardanoError):
            Relay.from_cbor(reader)

    def test_from_cbor_invalid_single_host_name_array_size(self):
        """Test that deserializing invalid single host name CBOR array size raises error."""
        reader = CborReader.from_hex("8201ef")
        with pytest.raises(CardanoError):
            Relay.from_cbor(reader)

    def test_from_cbor_invalid_multi_host_name_cbor(self):
        """Test that deserializing invalid multi-host name CBOR raises error."""
        reader = CborReader.from_hex("8202ef")
        with pytest.raises(CardanoError):
            Relay.from_cbor(reader)

    def test_to_cbor_single_host_addr(self):
        """Test serializing a single host address relay to CBOR."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()

        assert cbor_hex == self.SINGLE_HOST_ADDR_RELAY_CBOR

    def test_to_cbor_single_host_name(self):
        """Test serializing a single host name relay to CBOR."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()

        assert cbor_hex == self.SINGLE_HOST_NAME_RELAY_CBOR

    def test_to_cbor_multi_host_name(self):
        """Test serializing a multi-host name relay to CBOR."""
        reader = CborReader.from_hex(self.MULTI_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        writer = CborWriter()
        relay.to_cbor(writer)
        cbor_hex = writer.encode().hex()

        assert cbor_hex == self.MULTI_HOST_NAME_RELAY_CBOR

    def test_to_cbor_invalid_writer(self):
        """Test that serializing with None writer raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises((CardanoError, AttributeError)):
            relay.to_cbor(None)

    def test_relay_type_single_host_address(self):
        """Test getting relay type for single host address relay."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        relay_type = relay.relay_type

        assert relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_relay_type_single_host_name(self):
        """Test getting relay type for single host name relay."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        relay_type = relay.relay_type

        assert relay_type == RelayType.SINGLE_HOST_NAME

    def test_relay_type_multi_host_name(self):
        """Test getting relay type for multi-host name relay."""
        reader = CborReader.from_hex(self.MULTI_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        relay_type = relay.relay_type

        assert relay_type == RelayType.MULTI_HOST_NAME

    def test_to_single_host_addr_valid(self):
        """Test converting relay to SingleHostAddrRelay."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        single_host_addr = relay.to_single_host_addr()

        assert single_host_addr is not None
        assert isinstance(single_host_addr, SingleHostAddrRelay)

    def test_to_single_host_addr_wrong_type(self):
        """Test that converting wrong relay type to SingleHostAddrRelay raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises(CardanoError):
            relay.to_single_host_addr()

    def test_to_single_host_name_valid(self):
        """Test converting relay to SingleHostNameRelay."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        single_host_name = relay.to_single_host_name()

        assert single_host_name is not None
        assert isinstance(single_host_name, SingleHostNameRelay)
        assert single_host_name.dns == "example.com"
        assert single_host_name.port == 10

    def test_to_single_host_name_wrong_type(self):
        """Test that converting wrong relay type to SingleHostNameRelay raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises(CardanoError):
            relay.to_single_host_name()

    def test_to_multi_host_name_valid(self):
        """Test converting relay to MultiHostNameRelay."""
        reader = CborReader.from_hex(self.MULTI_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        multi_host_name = relay.to_multi_host_name()

        assert multi_host_name is not None
        assert isinstance(multi_host_name, MultiHostNameRelay)
        assert multi_host_name.dns == "example.com"

    def test_to_multi_host_name_wrong_type(self):
        """Test that converting wrong relay type to MultiHostNameRelay raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_ADDR_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises(CardanoError):
            relay.to_multi_host_name()

    def test_to_cip116_json_single_host_addr(self):
        """Test serializing single host address relay to CIP-116 JSON."""
        ipv4 = IPv4.from_string("127.0.0.1")
        single_host_addr = SingleHostAddrRelay.new(port=3000, ipv4=ipv4)
        relay = Relay.from_single_host_addr(single_host_addr)

        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"single_host_addr"' in json_str
        assert '"port":3000' in json_str
        assert '"ipv4":"127.0.0.1"' in json_str
        assert '"ipv6":null' in json_str

    def test_to_cip116_json_single_host_name(self):
        """Test serializing single host name relay to CIP-116 JSON."""
        single_host_name = SingleHostNameRelay.new("relay.io", port=4000)
        relay = Relay.from_single_host_name(single_host_name)

        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"single_host_name"' in json_str
        assert '"port":4000' in json_str
        assert '"dns_name":"relay.io"' in json_str

    def test_to_cip116_json_multi_host_name(self):
        """Test serializing multi-host name relay to CIP-116 JSON."""
        multi_host_name = MultiHostNameRelay.new("multi.io")
        relay = Relay.from_multi_host_name(multi_host_name)

        writer = JsonWriter()
        relay.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"tag":"multi_host_name"' in json_str
        assert '"dns_name":"multi.io"' in json_str

    def test_to_cip116_json_invalid_writer(self):
        """Test that serializing to JSON with None writer raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises((CardanoError, TypeError)):
            relay.to_cip116_json(None)

    def test_to_cip116_json_invalid_writer_type(self):
        """Test that serializing to JSON with wrong type raises error."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        with pytest.raises(TypeError):
            relay.to_cip116_json("not a writer")

    def test_cbor_roundtrip_single_host_addr(self):
        """Test CBOR serialization/deserialization roundtrip for single host address relay."""
        ipv4 = IPv4.from_string("10.3.2.10")
        ipv6 = IPv6.from_string("0102:0304:0102:0304:0102:0304:0102:0304")
        single_host_addr = SingleHostAddrRelay.new(port=10, ipv4=ipv4, ipv6=ipv6)
        original = Relay.from_single_host_addr(single_host_addr)

        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = Relay.from_cbor(reader)

        assert original.relay_type == restored.relay_type
        assert restored.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_cbor_roundtrip_single_host_name(self):
        """Test CBOR serialization/deserialization roundtrip for single host name relay."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        original = Relay.from_single_host_name(single_host_name)

        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = Relay.from_cbor(reader)

        assert original.relay_type == restored.relay_type
        assert restored.relay_type == RelayType.SINGLE_HOST_NAME
        restored_host = restored.to_single_host_name()
        assert restored_host.dns == "example.com"
        assert restored_host.port == 10

    def test_cbor_roundtrip_multi_host_name(self):
        """Test CBOR serialization/deserialization roundtrip for multi-host name relay."""
        multi_host_name = MultiHostNameRelay.new("example.com")
        original = Relay.from_multi_host_name(multi_host_name)

        writer = CborWriter()
        original.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        restored = Relay.from_cbor(reader)

        assert original.relay_type == restored.relay_type
        assert restored.relay_type == RelayType.MULTI_HOST_NAME
        restored_host = restored.to_multi_host_name()
        assert restored_host.dns == "example.com"

    def test_repr_single_host_addr(self):
        """Test repr for single host address relay."""
        ipv4 = IPv4.from_string("127.0.0.1")
        single_host_addr = SingleHostAddrRelay.new(port=3000, ipv4=ipv4)
        relay = Relay.from_single_host_addr(single_host_addr)

        repr_str = repr(relay)

        assert "Relay" in repr_str
        assert "SingleHostAddrRelay" in repr_str

    def test_repr_single_host_name(self):
        """Test repr for single host name relay."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        relay = Relay.from_single_host_name(single_host_name)

        repr_str = repr(relay)

        assert "Relay" in repr_str
        assert "SingleHostNameRelay" in repr_str

    def test_repr_multi_host_name(self):
        """Test repr for multi-host name relay."""
        multi_host_name = MultiHostNameRelay.new("example.com")
        relay = Relay.from_multi_host_name(multi_host_name)

        repr_str = repr(relay)

        assert "Relay" in repr_str
        assert "MultiHostNameRelay" in repr_str

    def test_context_manager_enter_exit(self):
        """Test relay as context manager."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        relay = Relay.from_single_host_name(single_host_name)

        with relay as r:
            assert r is relay
            assert r.relay_type == RelayType.SINGLE_HOST_NAME

    def test_invalid_handle_error(self):
        """Test that invalid handle raises error."""
        from cometa._ffi import ffi

        with pytest.raises(CardanoError, match="invalid handle"):
            Relay(ffi.NULL)

    def test_lifecycle_deletion(self):
        """Test that relay can be properly deleted."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        relay = Relay.from_single_host_name(single_host_name)
        relay_type = relay.relay_type
        assert relay_type == RelayType.SINGLE_HOST_NAME
        del relay

    def test_multiple_relay_types_independent(self):
        """Test that multiple relay instances of different types are independent."""
        single_host_name = SingleHostNameRelay.new("example.com", port=3001)
        relay1 = Relay.from_single_host_name(single_host_name)

        multi_host_name = MultiHostNameRelay.new("multi.example.com")
        relay2 = Relay.from_multi_host_name(multi_host_name)

        ipv4 = IPv4.from_string("10.0.0.1")
        single_host_addr = SingleHostAddrRelay.new(port=3003, ipv4=ipv4)
        relay3 = Relay.from_single_host_addr(single_host_addr)

        assert relay1.relay_type == RelayType.SINGLE_HOST_NAME
        assert relay2.relay_type == RelayType.MULTI_HOST_NAME
        assert relay3.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_cbor_serialization_consistency(self):
        """Test that multiple serializations produce same result."""
        single_host_name = SingleHostNameRelay.new("example.com", port=8080)
        relay = Relay.from_single_host_name(single_host_name)

        writer1 = CborWriter()
        relay.to_cbor(writer1)
        data1 = writer1.encode()

        writer2 = CborWriter()
        relay.to_cbor(writer2)
        data2 = writer2.encode()

        assert data1 == data2

    def test_conversion_preserves_data(self):
        """Test that conversion to specific relay type preserves data."""
        reader = CborReader.from_hex(self.SINGLE_HOST_NAME_RELAY_CBOR)
        relay = Relay.from_cbor(reader)

        single_host_name = relay.to_single_host_name()

        assert single_host_name.dns == "example.com"
        assert single_host_name.port == 10

        writer = CborWriter()
        single_host_name.to_cbor(writer)
        cbor_hex = writer.encode().hex()

        assert cbor_hex == self.SINGLE_HOST_NAME_RELAY_CBOR


class TestToRelay:
    """Tests for to_relay helper function."""

    def test_to_relay_from_relay(self):
        """Test that to_relay returns same Relay instance."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        relay = Relay.from_single_host_name(single_host_name)

        result = to_relay(relay)

        assert result is relay

    def test_to_relay_from_single_host_addr(self):
        """Test converting SingleHostAddrRelay to Relay."""
        ipv4 = IPv4.from_string("127.0.0.1")
        single_host_addr = SingleHostAddrRelay.new(port=3000, ipv4=ipv4)

        result = to_relay(single_host_addr)

        assert isinstance(result, Relay)
        assert result.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_to_relay_from_single_host_name(self):
        """Test converting SingleHostNameRelay to Relay."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)

        result = to_relay(single_host_name)

        assert isinstance(result, Relay)
        assert result.relay_type == RelayType.SINGLE_HOST_NAME

    def test_to_relay_from_multi_host_name(self):
        """Test converting MultiHostNameRelay to Relay."""
        multi_host_name = MultiHostNameRelay.new("example.com")

        result = to_relay(multi_host_name)

        assert isinstance(result, Relay)
        assert result.relay_type == RelayType.MULTI_HOST_NAME

    def test_to_relay_invalid_type(self):
        """Test that to_relay raises TypeError for invalid type."""
        with pytest.raises(TypeError, match="Cannot convert"):
            to_relay("not a relay")

    def test_to_relay_none(self):
        """Test that to_relay raises TypeError for None."""
        with pytest.raises(TypeError, match="Cannot convert"):
            to_relay(None)

    def test_to_relay_integer(self):
        """Test that to_relay raises TypeError for integer."""
        with pytest.raises(TypeError, match="Cannot convert"):
            to_relay(42)

    def test_to_relay_preserves_type(self):
        """Test that to_relay preserves the underlying relay type."""
        single_host_name = SingleHostNameRelay.new("example.com", port=10)
        relay = to_relay(single_host_name)

        converted = relay.to_single_host_name()

        assert converted.dns == "example.com"
        assert converted.port == 10
