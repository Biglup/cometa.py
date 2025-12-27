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
    Relays,
    Relay,
    SingleHostNameRelay,
    SingleHostAddrRelay,
    MultiHostNameRelay,
    IPv4,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR_EMPTY = "80"
CBOR_FIVE_RELAYS = "858301f66b6578616d706c652e636f6d8301f66b6578616d706c652e636f6d8301f66b6578616d706c652e636f6d8301f66b6578616d706c652e636f6d8301f66b6578616d706c652e636f6d"
DNS_NAME = "example.com"


def test_new_creates_empty_relays():
    relays = Relays.new()
    assert relays is not None
    assert len(relays) == 0


def test_new_relays_is_iterable():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    count = 0
    for r in relays:
        assert r is not None
        count += 1
    assert count == 1


def test_len_returns_zero_for_empty():
    relays = Relays.new()
    assert len(relays) == 0


def test_len_returns_correct_count():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)

    relays.add(relay)
    assert len(relays) == 1

    relays.add(relay)
    assert len(relays) == 2


def test_add_single_relay():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)

    relays.add(relay)
    assert len(relays) == 1


def test_add_multiple_relays():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new(DNS_NAME)
    relay2 = SingleHostNameRelay.new("relay2.example.com")

    relays.add(relay1)
    relays.add(relay2)
    assert len(relays) == 2


def test_add_wrapped_relay():
    relays = Relays.new()
    inner_relay = SingleHostNameRelay.new(DNS_NAME)
    relay = Relay.from_single_host_name(inner_relay)

    relays.add(relay)
    assert len(relays) == 1


def test_add_invalid_relay_none():
    relays = Relays.new()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        relays.add(None)


def test_append_is_alias_for_add():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)

    relays.append(relay)
    assert len(relays) == 1


def test_extend_with_list():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new(DNS_NAME)
    relay2 = SingleHostNameRelay.new("relay2.example.com")

    relays.extend([relay1, relay2])
    assert len(relays) == 2


def test_extend_with_relays_collection():
    relays1 = Relays.new()
    relays2 = Relays.new()

    relay1 = SingleHostNameRelay.new(DNS_NAME)
    relay2 = SingleHostNameRelay.new("relay2.example.com")

    relays1.add(relay1)
    relays1.add(relay2)

    relays2.extend(relays1)
    assert len(relays2) == 2


def test_extend_with_empty_list():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    relays.extend([])
    assert len(relays) == 1


def test_getitem_with_valid_index():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    retrieved = relays[0]
    assert retrieved is not None


def test_getitem_with_negative_index():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new(DNS_NAME)
    relay2 = SingleHostNameRelay.new("relay2.example.com")
    relays.add(relay1)
    relays.add(relay2)

    last = relays[-1]
    assert last is not None


def test_getitem_with_invalid_positive_index():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    with pytest.raises(IndexError):
        _ = relays[10]


def test_getitem_with_invalid_negative_index():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    with pytest.raises(IndexError):
        _ = relays[-10]


def test_getitem_on_empty_relays():
    relays = Relays.new()

    with pytest.raises(IndexError):
        _ = relays[0]


def test_getitem_with_slice():
    relays = Relays.new()
    for i in range(5):
        relay = SingleHostNameRelay.new(f"relay{i}.example.com")
        relays.add(relay)

    subset = relays[1:3]
    assert isinstance(subset, list)
    assert len(subset) == 2


def test_getitem_with_slice_start_only():
    relays = Relays.new()
    for i in range(5):
        relay = SingleHostNameRelay.new(f"relay{i}.example.com")
        relays.add(relay)

    subset = relays[2:]
    assert isinstance(subset, list)
    assert len(subset) == 3


def test_getitem_with_slice_end_only():
    relays = Relays.new()
    for i in range(5):
        relay = SingleHostNameRelay.new(f"relay{i}.example.com")
        relays.add(relay)

    subset = relays[:3]
    assert isinstance(subset, list)
    assert len(subset) == 3


def test_getitem_with_slice_step():
    relays = Relays.new()
    for i in range(5):
        relay = SingleHostNameRelay.new(f"relay{i}.example.com")
        relays.add(relay)

    subset = relays[::2]
    assert isinstance(subset, list)
    assert len(subset) == 3


def test_iteration():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new(DNS_NAME)
    relay2 = SingleHostNameRelay.new("relay2.example.com")
    relays.add(relay1)
    relays.add(relay2)

    count = 0
    for r in relays:
        assert r is not None
        count += 1
    assert count == 2


def test_iteration_on_empty():
    relays = Relays.new()

    count = 0
    for _ in relays:
        count += 1
    assert count == 0


def test_contains_returns_false():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(relay)

    assert relay not in relays


def test_contains_with_non_relay():
    relays = Relays.new()

    assert "not a relay" not in relays
    assert 123 not in relays
    assert None not in relays


def test_repr():
    relays = Relays.new()
    repr_str = repr(relays)
    assert "Relays" in repr_str


def test_to_cbor_empty():
    relays = Relays.new()
    writer = CborWriter()

    relays.to_cbor(writer)
    hex_output = writer.to_hex()

    assert hex_output == CBOR_EMPTY


def test_to_cbor_with_relays():
    relays = Relays.new()
    for _ in range(5):
        relay = SingleHostNameRelay.new(DNS_NAME)
        relays.add(relay)

    writer = CborWriter()
    relays.to_cbor(writer)
    hex_output = writer.to_hex()

    assert hex_output == CBOR_FIVE_RELAYS


def test_to_cbor_invalid_writer_none():
    relays = Relays.new()

    with pytest.raises((CardanoError, TypeError, AttributeError)):
        relays.to_cbor(None)


def test_from_cbor_empty():
    reader = CborReader.from_hex(CBOR_EMPTY)
    relays = Relays.from_cbor(reader)

    assert relays is not None
    assert len(relays) == 0


def test_from_cbor_with_relays():
    reader = CborReader.from_hex(CBOR_FIVE_RELAYS)
    relays = Relays.from_cbor(reader)

    assert relays is not None
    assert len(relays) == 5


def test_from_cbor_roundtrip():
    reader = CborReader.from_hex(CBOR_FIVE_RELAYS)
    relays = Relays.from_cbor(reader)

    writer = CborWriter()
    relays.to_cbor(writer)
    hex_output = writer.to_hex()

    assert hex_output == CBOR_FIVE_RELAYS


def test_from_cbor_invalid_cbor_not_array():
    reader = CborReader.from_hex("01")

    with pytest.raises(CardanoError):
        Relays.from_cbor(reader)


def test_from_cbor_invalid_cbor_invalid_relay_elements():
    reader = CborReader.from_hex("9ffeff")

    with pytest.raises(CardanoError):
        Relays.from_cbor(reader)


def test_from_cbor_invalid_cbor_missing_end_array():
    reader = CborReader.from_hex("9f01")

    with pytest.raises(CardanoError):
        Relays.from_cbor(reader)


def test_from_cbor_invalid_reader_none():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        Relays.from_cbor(None)


def test_to_cip116_json_empty():
    relays = Relays.new()
    writer = JsonWriter()

    relays.to_cip116_json(writer)
    json_output = writer.encode()

    assert json_output == "[]"


def test_to_cip116_json_with_relays():
    relays = Relays.new()

    multi_relay = MultiHostNameRelay.new("example.com")
    relays.add(multi_relay)

    ipv4 = IPv4.from_string("127.0.0.1")
    addr_relay = SingleHostAddrRelay.new(port=3000, ipv4=ipv4)
    relays.add(addr_relay)

    writer = JsonWriter()
    relays.to_cip116_json(writer)
    json_output = writer.encode()

    expected = '[{"tag":"multi_host_name","dns_name":"example.com"},{"tag":"single_host_addr","port":3000,"ipv4":"127.0.0.1","ipv6":null}]'
    assert json_output == expected


def test_to_cip116_json_invalid_writer_none():
    relays = Relays.new()

    with pytest.raises((CardanoError, TypeError)):
        relays.to_cip116_json(None)


def test_to_cip116_json_invalid_writer_wrong_type():
    relays = Relays.new()

    with pytest.raises((CardanoError, TypeError)):
        relays.to_cip116_json("not a writer")


def test_context_manager():
    with Relays.new() as relays:
        relay = SingleHostNameRelay.new(DNS_NAME)
        relays.add(relay)
        assert len(relays) == 1


def test_multiple_additions_same_relay():
    relays = Relays.new()
    relay = SingleHostNameRelay.new(DNS_NAME)

    relays.add(relay)
    relays.add(relay)
    relays.add(relay)

    assert len(relays) == 3


def test_add_different_relay_types():
    relays = Relays.new()

    name_relay = SingleHostNameRelay.new(DNS_NAME)
    relays.add(name_relay)

    multi_relay = MultiHostNameRelay.new("multi.example.com")
    relays.add(multi_relay)

    ipv4 = IPv4.from_string("192.168.1.1")
    addr_relay = SingleHostAddrRelay.new(port=8080, ipv4=ipv4)
    relays.add(addr_relay)

    assert len(relays) == 3


def test_indexing_preserves_order():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new("relay1.com")
    relay2 = SingleHostNameRelay.new("relay2.com")
    relay3 = SingleHostNameRelay.new("relay3.com")

    relays.add(relay1)
    relays.add(relay2)
    relays.add(relay3)

    assert relays[0] is not None
    assert relays[1] is not None
    assert relays[2] is not None


def test_extend_preserves_order():
    relays = Relays.new()
    relay1 = SingleHostNameRelay.new("relay1.com")
    relay2 = SingleHostNameRelay.new("relay2.com")

    relays.extend([relay1, relay2])

    assert len(relays) == 2
