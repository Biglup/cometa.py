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
from cometa import SingleHostAddrRelay, IPv4, IPv6, CborReader, CborWriter, JsonWriter, CardanoError


CBOR_WITH_ALL = "84000a440a03020a5001020304010203040102030401020304"
CBOR_WITHOUT_PORT = "8400f6440a03020a5001020304010203040102030401020304"
CBOR_ALL_NULL = "8400f6f6f6"
IPV4_ADDR = "10.3.2.10"
IPV6_ADDR = "0102:0304:0102:0304:0102:0304:0102:0304"
PORT = 10


def test_new_with_all_fields():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    assert relay is not None
    assert relay.port == PORT
    assert relay.ipv4 is not None
    assert relay.ipv6 is not None


def test_new_without_port():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(ipv4=ipv4, ipv6=ipv6)
    assert relay is not None
    assert relay.port is None
    assert relay.ipv4 is not None
    assert relay.ipv6 is not None


def test_new_without_ipv4():
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv6=ipv6)
    assert relay is not None
    assert relay.port == PORT
    assert relay.ipv4 is None
    assert relay.ipv6 is not None


def test_new_without_ipv6():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    assert relay is not None
    assert relay.port == PORT
    assert relay.ipv4 is not None
    assert relay.ipv6 is None


def test_new_with_all_none():
    relay = SingleHostAddrRelay.new()
    assert relay is not None
    assert relay.port is None
    assert relay.ipv4 is None
    assert relay.ipv6 is None


def test_new_with_port_zero():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=0, ipv4=ipv4)
    assert relay is not None
    assert relay.port == 0


def test_new_with_port_max():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=65535, ipv4=ipv4)
    assert relay is not None
    assert relay.port == 65535


def test_new_with_invalid_port_negative():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    with pytest.raises((CardanoError, OverflowError)):
        SingleHostAddrRelay.new(port=-1, ipv4=ipv4)


def test_new_with_invalid_port_too_large():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    with pytest.raises((CardanoError, OverflowError)):
        SingleHostAddrRelay.new(port=65536, ipv4=ipv4)


def test_to_cbor_with_all_fields():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    writer = CborWriter()
    relay.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR_WITH_ALL


def test_to_cbor_without_port():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(ipv4=ipv4, ipv6=ipv6)
    writer = CborWriter()
    relay.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR_WITHOUT_PORT


def test_to_cbor_with_all_null():
    relay = SingleHostAddrRelay.new()
    writer = CborWriter()
    relay.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR_ALL_NULL


def test_to_cbor_with_none_writer():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        relay.to_cbor(None)


def test_from_cbor_with_all_fields():
    reader = CborReader.from_hex(CBOR_WITH_ALL)
    relay = SingleHostAddrRelay.from_cbor(reader)
    assert relay is not None
    assert relay.port == PORT


def test_from_cbor_without_port():
    reader = CborReader.from_hex(CBOR_WITHOUT_PORT)
    relay = SingleHostAddrRelay.from_cbor(reader)
    assert relay is not None
    assert relay.port is None


def test_from_cbor_with_all_null():
    reader = CborReader.from_hex(CBOR_ALL_NULL)
    relay = SingleHostAddrRelay.from_cbor(reader)
    assert relay is not None
    assert relay.port is None
    assert relay.ipv4 is None
    assert relay.ipv6 is None


def test_from_cbor_with_none_reader():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        SingleHostAddrRelay.from_cbor(None)


def test_from_cbor_with_invalid_array_size():
    reader = CborReader.from_hex("82")
    with pytest.raises(CardanoError):
        SingleHostAddrRelay.from_cbor(reader)


def test_from_cbor_with_invalid_port():
    reader = CborReader.from_hex("8400ef")
    with pytest.raises(CardanoError):
        SingleHostAddrRelay.from_cbor(reader)


def test_from_cbor_with_invalid_ipv4():
    reader = CborReader.from_hex("840000ef")
    with pytest.raises(CardanoError):
        SingleHostAddrRelay.from_cbor(reader)


def test_from_cbor_with_invalid_ipv6():
    reader = CborReader.from_hex("840000440A03020Aef")
    with pytest.raises(CardanoError):
        SingleHostAddrRelay.from_cbor(reader)


def test_from_cbor_with_invalid_first_element():
    reader = CborReader.from_hex("84ff")
    with pytest.raises(CardanoError):
        SingleHostAddrRelay.from_cbor(reader)


def test_from_cbor_round_trip():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay1 = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    writer = CborWriter()
    relay1.to_cbor(writer)
    cbor_hex = writer.to_hex()
    reader = CborReader.from_hex(cbor_hex)
    relay2 = SingleHostAddrRelay.from_cbor(reader)
    assert relay2.port == PORT


def test_get_port():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    assert relay.port == PORT


def test_get_port_when_none():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(ipv4=ipv4)
    assert relay.port is None


def test_set_port():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    new_port = 20
    relay.port = new_port
    assert relay.port == new_port


def test_set_port_to_zero():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    relay.port = 0
    assert relay.port == 0


def test_set_port_to_none():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    relay.port = None
    assert relay.port is None


def test_set_port_on_relay_with_none_port():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(ipv4=ipv4)
    relay.port = 100
    assert relay.port == 100


def test_set_port_invalid_negative():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    with pytest.raises((CardanoError, OverflowError)):
        relay.port = -1


def test_set_port_invalid_too_large():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    with pytest.raises((CardanoError, OverflowError)):
        relay.port = 65536


def test_get_ipv4():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    retrieved_ipv4 = relay.ipv4
    assert retrieved_ipv4 is not None


def test_get_ipv4_when_none():
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv6=ipv6)
    assert relay.ipv4 is None


def test_set_ipv4():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    new_ipv4 = IPv4.from_string("192.168.1.1")
    relay.ipv4 = new_ipv4
    assert relay.ipv4 is not None


def test_set_ipv4_to_none():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    with pytest.raises(CardanoError):
        relay.ipv4 = None


def test_get_ipv6():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    retrieved_ipv6 = relay.ipv6
    assert retrieved_ipv6 is not None


def test_get_ipv6_when_none():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    assert relay.ipv6 is None


def test_set_ipv6():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    new_ipv6 = IPv6.from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    relay.ipv6 = new_ipv6
    assert relay.ipv6 is not None


def test_set_ipv6_to_none():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    with pytest.raises(CardanoError):
        relay.ipv6 = None


def test_to_cip116_json_with_all_fields():
    port = 65535
    ipv4 = IPv4.from_string("10.3.2.10")
    ipv6 = IPv6.from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    relay = SingleHostAddrRelay.new(port=port, ipv4=ipv4, ipv6=ipv6)
    writer = JsonWriter()
    relay.to_cip116_json(writer)
    json_str = writer.encode()
    assert '"tag":"single_host_addr"' in json_str
    assert '"port":65535' in json_str
    assert '"ipv4":"10.3.2.10"' in json_str
    assert '"ipv6":"2001:0db8:85a3:0000:0000:8a2e:0370:7334"' in json_str


def test_to_cip116_json_with_only_ipv4():
    port = 65535
    ipv4 = IPv4.from_string("10.3.2.10")
    relay = SingleHostAddrRelay.new(port=port, ipv4=ipv4)
    writer = JsonWriter()
    relay.to_cip116_json(writer)
    json_str = writer.encode()
    assert '"tag":"single_host_addr"' in json_str
    assert '"port":65535' in json_str
    assert '"ipv4":"10.3.2.10"' in json_str
    assert '"ipv6":null' in json_str


def test_to_cip116_json_with_only_ipv6():
    port = 65535
    ipv6 = IPv6.from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    relay = SingleHostAddrRelay.new(port=port, ipv6=ipv6)
    writer = JsonWriter()
    relay.to_cip116_json(writer)
    json_str = writer.encode()
    assert '"tag":"single_host_addr"' in json_str
    assert '"port":65535' in json_str
    assert '"ipv4":null' in json_str
    assert '"ipv6":"2001:0db8:85a3:0000:0000:8a2e:0370:7334"' in json_str


def test_to_cip116_json_with_none_writer():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    with pytest.raises((CardanoError, TypeError)):
        relay.to_cip116_json(None)


def test_to_cip116_json_with_invalid_writer_type():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4)
    with pytest.raises(TypeError):
        relay.to_cip116_json("not a writer")


def test_repr():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    ipv6 = IPv6.from_string(IPV6_ADDR)
    relay = SingleHostAddrRelay.new(port=PORT, ipv4=ipv4, ipv6=ipv6)
    repr_str = repr(relay)
    assert "SingleHostAddrRelay" in repr_str
    assert "port=10" in repr_str


def test_repr_with_none_values():
    relay = SingleHostAddrRelay.new()
    repr_str = repr(relay)
    assert "SingleHostAddrRelay" in repr_str


def test_context_manager():
    ipv4 = IPv4.from_string(IPV4_ADDR)
    with SingleHostAddrRelay.new(port=PORT, ipv4=ipv4) as relay:
        assert relay is not None
        assert relay.port == PORT


def test_init_with_null_pointer():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        SingleHostAddrRelay(ffi.NULL)
