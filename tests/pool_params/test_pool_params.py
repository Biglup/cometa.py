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
    IPv4,
    IPv6,
    RelayType,
    SingleHostAddrRelay,
    SingleHostNameRelay,
    MultiHostNameRelay,
    Relay,
    Relays,
    PoolOwners,
    PoolMetadata,
    PoolParams,
    to_relay,
    Blake2bHash,
    UnitInterval,
    RewardAddress,
    NetworkId,
    Credential,
    CborWriter,
    CborReader,
    CardanoError,
)


class TestIPv4:
    """Tests for IPv4 addresses."""

    def test_from_string(self):
        """Test creating IPv4 from dotted-decimal string."""
        ipv4 = IPv4.from_string("192.168.1.1")
        assert str(ipv4) == "192.168.1.1"

    def test_from_bytes(self):
        """Test creating IPv4 from raw bytes."""
        ipv4 = IPv4.from_bytes(bytes([192, 168, 1, 1]))
        assert str(ipv4) == "192.168.1.1"

    def test_to_bytes(self):
        """Test converting IPv4 to bytes."""
        ipv4 = IPv4.from_string("10.0.0.1")
        data = ipv4.to_bytes()
        assert len(data) == 4
        assert data == bytes([10, 0, 0, 1])

    def test_equality(self):
        """Test IPv4 equality."""
        ip1 = IPv4.from_string("192.168.1.1")
        ip2 = IPv4.from_bytes(bytes([192, 168, 1, 1]))
        ip3 = IPv4.from_string("10.0.0.1")
        assert ip1 == ip2
        assert ip1 != ip3

    def test_hash(self):
        """Test IPv4 is hashable."""
        ip1 = IPv4.from_string("192.168.1.1")
        ip2 = IPv4.from_string("192.168.1.1")
        assert hash(ip1) == hash(ip2)

    def test_repr(self):
        """Test IPv4 repr."""
        ipv4 = IPv4.from_string("127.0.0.1")
        assert "127.0.0.1" in repr(ipv4)

    def test_invalid_bytes_length(self):
        """Test that invalid byte length raises error."""
        with pytest.raises(CardanoError):
            IPv4.from_bytes(bytes([1, 2, 3]))  # Only 3 bytes

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        ipv4 = IPv4.from_string("192.168.1.100")
        writer = CborWriter()
        ipv4.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        ipv4_restored = IPv4.from_cbor(reader)
        assert str(ipv4) == str(ipv4_restored)


class TestIPv6:
    """Tests for IPv6 addresses."""

    def test_from_string(self):
        """Test creating IPv6 from full notation string."""
        # The C library requires full IPv6 notation
        ipv6 = IPv6.from_string("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        data = ipv6.to_bytes()
        assert len(data) == 16

    def test_from_bytes(self):
        """Test creating IPv6 from raw bytes."""
        data = bytes([0] * 15 + [1])
        ipv6 = IPv6.from_bytes(data)
        assert ipv6.to_bytes() == data

    def test_equality(self):
        """Test IPv6 equality."""
        data = bytes([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34])
        ip1 = IPv6.from_bytes(data)
        ip2 = IPv6.from_bytes(data)
        assert ip1 == ip2

    def test_invalid_bytes_length(self):
        """Test that invalid byte length raises error."""
        with pytest.raises(CardanoError):
            IPv6.from_bytes(bytes([1, 2, 3, 4]))  # Only 4 bytes

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        data = bytes([0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34])
        ipv6 = IPv6.from_bytes(data)
        writer = CborWriter()
        ipv6.to_cbor(writer)
        cbor_data = writer.encode()

        reader = CborReader.from_bytes(cbor_data)
        ipv6_restored = IPv6.from_cbor(reader)
        assert ipv6.to_bytes() == ipv6_restored.to_bytes()


class TestRelayType:
    """Tests for RelayType enum."""

    def test_values(self):
        """Test relay type values."""
        assert RelayType.SINGLE_HOST_ADDRESS == 0
        assert RelayType.SINGLE_HOST_NAME == 1
        assert RelayType.MULTI_HOST_NAME == 2

    def test_is_int_enum(self):
        """Test that RelayType is an IntEnum."""
        assert isinstance(RelayType.SINGLE_HOST_ADDRESS, int)

    def test_to_string_single_host_address(self):
        """Test to_string for SINGLE_HOST_ADDRESS."""
        relay_type = RelayType.SINGLE_HOST_ADDRESS
        assert relay_type.to_string() == "Relay Type: Single Host Address"

    def test_to_string_single_host_name(self):
        """Test to_string for SINGLE_HOST_NAME."""
        relay_type = RelayType.SINGLE_HOST_NAME
        assert relay_type.to_string() == "Relay Type: Single Host Name"

    def test_to_string_multi_host_name(self):
        """Test to_string for MULTI_HOST_NAME."""
        relay_type = RelayType.MULTI_HOST_NAME
        assert relay_type.to_string() == "Relay Type: Multi Host Name"

    def test_to_string_unknown_value(self):
        """Test to_string with unknown/invalid value."""
        unknown_type = RelayType(0)
        unknown_type._value_ = 99999
        result = unknown_type.to_string()
        assert result == "Relay Type: Unknown" or result.startswith("Unknown(")


class TestSingleHostAddrRelay:
    """Tests for SingleHostAddrRelay."""

    def test_with_ipv4_and_port(self):
        """Test creating relay with IPv4 and port."""
        ipv4 = IPv4.from_string("192.168.1.1")
        relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        assert relay.port == 3001
        assert relay.ipv4 is not None
        assert str(relay.ipv4) == "192.168.1.1"
        assert relay.ipv6 is None

    def test_with_ipv6(self):
        """Test creating relay with IPv6."""
        ipv6 = IPv6.from_bytes(bytes([0] * 15 + [1]))
        relay = SingleHostAddrRelay.new(ipv6=ipv6)
        assert relay.ipv6 is not None
        assert relay.ipv4 is None

    def test_set_port(self):
        """Test setting port."""
        ipv4 = IPv4.from_string("10.0.0.1")
        relay = SingleHostAddrRelay.new(ipv4=ipv4)
        assert relay.port is None
        relay.port = 6000
        assert relay.port == 6000

    def test_repr(self):
        """Test repr."""
        ipv4 = IPv4.from_string("192.168.1.1")
        relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        repr_str = repr(relay)
        assert "SingleHostAddrRelay" in repr_str
        assert "port=3001" in repr_str

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        ipv4 = IPv4.from_string("192.168.1.1")
        relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        relay_restored = SingleHostAddrRelay.from_cbor(reader)
        assert relay_restored.port == 3001


class TestSingleHostNameRelay:
    """Tests for SingleHostNameRelay."""

    def test_with_dns_and_port(self):
        """Test creating relay with DNS and port."""
        relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        assert relay.dns == "relay.example.com"
        assert relay.port == 3001

    def test_dns_only(self):
        """Test creating relay with DNS only."""
        relay = SingleHostNameRelay.new("relay.pool.net")
        assert relay.dns == "relay.pool.net"
        assert relay.port is None

    def test_set_dns(self):
        """Test setting DNS name."""
        relay = SingleHostNameRelay.new("old.example.com")
        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

    def test_str(self):
        """Test string representation."""
        relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        assert str(relay) == "relay.example.com:3001"

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        relay_restored = SingleHostNameRelay.from_cbor(reader)
        assert relay_restored.dns == "relay.example.com"
        assert relay_restored.port == 3001


class TestMultiHostNameRelay:
    """Tests for MultiHostNameRelay."""

    def test_create(self):
        """Test creating multi-host name relay."""
        relay = MultiHostNameRelay.new("relay.example.com")
        assert relay.dns == "relay.example.com"

    def test_set_dns(self):
        """Test setting DNS name."""
        relay = MultiHostNameRelay.new("old.example.com")
        relay.dns = "new.example.com"
        assert relay.dns == "new.example.com"

    def test_repr(self):
        """Test repr."""
        relay = MultiHostNameRelay.new("relay.example.com")
        assert "MultiHostNameRelay" in repr(relay)
        assert "relay.example.com" in repr(relay)

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        relay = MultiHostNameRelay.new("relay.example.com")
        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        relay_restored = MultiHostNameRelay.from_cbor(reader)
        assert relay_restored.dns == "relay.example.com"


class TestRelay:
    """Tests for Relay wrapper."""

    def test_from_single_host_addr(self):
        """Test creating Relay from SingleHostAddrRelay."""
        ipv4 = IPv4.from_string("192.168.1.1")
        addr_relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        relay = Relay.from_single_host_addr(addr_relay)
        assert relay.relay_type == RelayType.SINGLE_HOST_ADDRESS

    def test_from_single_host_name(self):
        """Test creating Relay from SingleHostNameRelay."""
        name_relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        relay = Relay.from_single_host_name(name_relay)
        assert relay.relay_type == RelayType.SINGLE_HOST_NAME

    def test_from_multi_host_name(self):
        """Test creating Relay from MultiHostNameRelay."""
        multi_relay = MultiHostNameRelay.new("relay.example.com")
        relay = Relay.from_multi_host_name(multi_relay)
        assert relay.relay_type == RelayType.MULTI_HOST_NAME

    def test_to_single_host_addr(self):
        """Test converting Relay to SingleHostAddrRelay."""
        ipv4 = IPv4.from_string("192.168.1.1")
        addr_relay = SingleHostAddrRelay.new(port=3001, ipv4=ipv4)
        relay = Relay.from_single_host_addr(addr_relay)
        converted = relay.to_single_host_addr()
        assert converted.port == 3001

    def test_to_single_host_name(self):
        """Test converting Relay to SingleHostNameRelay."""
        name_relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        relay = Relay.from_single_host_name(name_relay)
        converted = relay.to_single_host_name()
        assert converted.dns == "relay.example.com"

    def test_to_multi_host_name(self):
        """Test converting Relay to MultiHostNameRelay."""
        multi_relay = MultiHostNameRelay.new("relay.example.com")
        relay = Relay.from_multi_host_name(multi_relay)
        converted = relay.to_multi_host_name()
        assert converted.dns == "relay.example.com"

    def test_to_relay_function(self):
        """Test to_relay helper function."""
        # With SingleHostNameRelay
        name_relay = SingleHostNameRelay.new("relay.example.com")
        relay = to_relay(name_relay)
        assert relay.relay_type == RelayType.SINGLE_HOST_NAME

        # With Relay (passthrough)
        relay2 = to_relay(relay)
        assert relay2.relay_type == RelayType.SINGLE_HOST_NAME

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        name_relay = SingleHostNameRelay.new("relay.example.com", port=3001)
        relay = Relay.from_single_host_name(name_relay)

        writer = CborWriter()
        relay.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        relay_restored = Relay.from_cbor(reader)
        assert relay_restored.relay_type == RelayType.SINGLE_HOST_NAME


class TestRelays:
    """Tests for Relays collection."""

    def test_create_empty(self):
        """Test creating empty relays collection."""
        relays = Relays.new()
        assert len(relays) == 0

    def test_add_relay(self):
        """Test adding relays."""
        relays = Relays.new()
        relay = SingleHostNameRelay.new("relay1.example.com", port=3001)
        relays.add(relay)
        assert len(relays) == 1

    def test_append(self):
        """Test append method."""
        relays = Relays.new()
        relays.append(SingleHostNameRelay.new("relay1.example.com"))
        relays.append(SingleHostNameRelay.new("relay2.example.com"))
        assert len(relays) == 2

    def test_indexing(self):
        """Test indexing."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay1.example.com", port=3001))
        relays.add(SingleHostNameRelay.new("relay2.example.com", port=3002))

        relay0 = relays[0]
        relay1 = relays[1]
        assert relay0.relay_type == RelayType.SINGLE_HOST_NAME
        assert relay1.relay_type == RelayType.SINGLE_HOST_NAME

    def test_negative_indexing(self):
        """Test negative indexing."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay1.example.com"))
        relays.add(SingleHostNameRelay.new("relay2.example.com"))

        relay_last = relays[-1]
        assert relay_last.relay_type == RelayType.SINGLE_HOST_NAME

    def test_slicing(self):
        """Test slicing."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay1.example.com"))
        relays.add(SingleHostNameRelay.new("relay2.example.com"))
        relays.add(SingleHostNameRelay.new("relay3.example.com"))

        subset = relays[0:2]
        assert len(subset) == 2

    def test_iteration(self):
        """Test iteration."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay1.example.com"))
        relays.add(SingleHostNameRelay.new("relay2.example.com"))

        count = 0
        for relay in relays:
            assert isinstance(relay, Relay)
            count += 1
        assert count == 2

    def test_extend(self):
        """Test extend method."""
        relays1 = Relays.new()
        relays1.add(SingleHostNameRelay.new("relay1.example.com"))

        relays2 = Relays.new()
        relays2.add(SingleHostNameRelay.new("relay2.example.com"))
        relays2.add(SingleHostNameRelay.new("relay3.example.com"))

        relays1.extend(relays2)
        assert len(relays1) == 3

    def test_index_out_of_range(self):
        """Test index out of range."""
        relays = Relays.new()
        with pytest.raises(IndexError):
            _ = relays[0]

    def test_cbor_roundtrip(self):
        """Test CBOR serialization/deserialization."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay1.example.com", port=3001))
        relays.add(SingleHostNameRelay.new("relay2.example.com", port=3002))

        writer = CborWriter()
        relays.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        relays_restored = Relays.from_cbor(reader)
        assert len(relays_restored) == 2


class TestPoolOwners:
    """Tests for PoolOwners collection."""

    @pytest.fixture
    def key_hash(self):
        """Create a test key hash."""
        return Blake2bHash.from_hex("00" * 28)

    @pytest.fixture
    def key_hash2(self):
        """Create another test key hash."""
        return Blake2bHash.from_hex("11" * 28)

    def test_create_empty(self):
        """Test creating empty pool owners."""
        owners = PoolOwners.new()
        assert len(owners) == 0

    def test_add_owner(self, key_hash):
        """Test adding an owner."""
        owners = PoolOwners.new()
        owners.add(key_hash)
        assert len(owners) == 1

    def test_indexing(self, key_hash, key_hash2):
        """Test indexing."""
        owners = PoolOwners.new()
        owners.add(key_hash)
        owners.add(key_hash2)

        owner0 = owners[0]
        owner1 = owners[1]
        assert isinstance(owner0, Blake2bHash)
        assert isinstance(owner1, Blake2bHash)

    def test_contains(self, key_hash, key_hash2):
        """Test contains check."""
        owners = PoolOwners.new()
        owners.add(key_hash)

        assert key_hash in owners
        assert key_hash2 not in owners

    def test_iteration(self, key_hash, key_hash2):
        """Test iteration."""
        owners = PoolOwners.new()
        owners.add(key_hash)
        owners.add(key_hash2)

        hashes = list(owners)
        assert len(hashes) == 2

    def test_extend(self, key_hash, key_hash2):
        """Test extend method."""
        owners1 = PoolOwners.new()
        owners1.add(key_hash)

        owners2 = PoolOwners.new()
        owners2.add(key_hash2)

        owners1.extend(owners2)
        assert len(owners1) == 2

    def test_cbor_roundtrip(self, key_hash, key_hash2):
        """Test CBOR serialization/deserialization."""
        owners = PoolOwners.new()
        owners.add(key_hash)
        owners.add(key_hash2)

        writer = CborWriter()
        owners.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        owners_restored = PoolOwners.from_cbor(reader)
        assert len(owners_restored) == 2


class TestPoolMetadata:
    """Tests for PoolMetadata."""

    @pytest.fixture
    def metadata_hash(self):
        """Create a test metadata hash."""
        return Blake2bHash.from_hex("00" * 32)

    def test_create(self, metadata_hash):
        """Test creating pool metadata."""
        metadata = PoolMetadata.new("https://example.com/pool.json", metadata_hash)
        assert metadata.url == "https://example.com/pool.json"

    def test_from_hash_hex(self):
        """Test creating from hex hash."""
        metadata = PoolMetadata.from_hash_hex(
            "https://example.com/pool.json",
            "00" * 32
        )
        assert metadata.url == "https://example.com/pool.json"

    def test_set_url(self, metadata_hash):
        """Test setting URL."""
        metadata = PoolMetadata.new("https://old.example.com", metadata_hash)
        metadata.url = "https://new.example.com"
        assert metadata.url == "https://new.example.com"

    def test_get_hash(self, metadata_hash):
        """Test getting hash."""
        metadata = PoolMetadata.new("https://example.com", metadata_hash)
        retrieved_hash = metadata.hash
        assert retrieved_hash.to_hex() == "00" * 32

    def test_repr(self, metadata_hash):
        """Test repr."""
        metadata = PoolMetadata.new("https://example.com/pool.json", metadata_hash)
        repr_str = repr(metadata)
        assert "PoolMetadata" in repr_str
        assert "https://example.com/pool.json" in repr_str

    def test_str(self, metadata_hash):
        """Test str."""
        metadata = PoolMetadata.new("https://example.com/pool.json", metadata_hash)
        assert str(metadata) == "https://example.com/pool.json"

    def test_cbor_roundtrip(self, metadata_hash):
        """Test CBOR serialization/deserialization."""
        metadata = PoolMetadata.new("https://example.com/pool.json", metadata_hash)

        writer = CborWriter()
        metadata.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        metadata_restored = PoolMetadata.from_cbor(reader)
        assert metadata_restored.url == "https://example.com/pool.json"


class TestPoolParams:
    """Tests for PoolParams."""

    @pytest.fixture
    def operator_hash(self):
        """Create a test operator key hash (28 bytes)."""
        return Blake2bHash.from_hex("aa" * 28)

    @pytest.fixture
    def vrf_hash(self):
        """Create a test VRF hash (32 bytes)."""
        return Blake2bHash.from_hex("bb" * 32)

    @pytest.fixture
    def margin(self):
        """Create a test margin (1%)."""
        return UnitInterval.new(1, 100)

    @pytest.fixture
    def reward_account(self, operator_hash):
        """Create a test reward account."""
        credential = Credential.from_key_hash(operator_hash)
        return RewardAddress.from_credentials(NetworkId.TESTNET, credential)

    @pytest.fixture
    def owners(self, operator_hash):
        """Create test pool owners."""
        owners = PoolOwners.new()
        owners.add(operator_hash)
        return owners

    @pytest.fixture
    def relays(self):
        """Create test relays."""
        relays = Relays.new()
        relays.add(SingleHostNameRelay.new("relay.example.com", port=3001))
        return relays

    @pytest.fixture
    def metadata(self):
        """Create test metadata."""
        hash = Blake2bHash.from_hex("cc" * 32)
        return PoolMetadata.new("https://example.com/pool.json", hash)

    def test_create_with_metadata(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays, metadata
    ):
        """Test creating pool params with metadata."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,  # 1000 ADA
            cost=340000000,     # 340 ADA
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=metadata,
        )
        assert params.pledge == 1000000000
        assert params.cost == 340000000
        assert params.metadata is not None

    def test_create_without_metadata(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test creating pool params without metadata."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=None,
        )
        assert params.metadata is None

    def test_get_operator_key_hash(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test getting operator key hash."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        assert params.operator_key_hash.to_hex() == "aa" * 28

    def test_get_vrf_hash(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test getting VRF hash."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        assert params.vrf_vk_hash.to_hex() == "bb" * 32

    def test_set_pledge(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting pledge."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        params.pledge = 2000000000
        assert params.pledge == 2000000000

    def test_set_cost(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting cost."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        params.cost = 500000000
        assert params.cost == 500000000

    def test_get_owners(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test getting owners."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        retrieved_owners = params.owners
        assert len(retrieved_owners) == 1

    def test_get_relays(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test getting relays."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        retrieved_relays = params.relays
        assert len(retrieved_relays) == 1

    def test_repr(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test repr."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        repr_str = repr(params)
        assert "PoolParams" in repr_str
        assert "pledge=1000000000" in repr_str
        assert "cost=340000000" in repr_str

    def test_cbor_roundtrip(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays, metadata
    ):
        """Test CBOR serialization/deserialization."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=metadata,
        )

        writer = CborWriter()
        params.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        params_restored = PoolParams.from_cbor(reader)

        assert params_restored.pledge == 1000000000
        assert params_restored.cost == 340000000
        assert len(params_restored.owners) == 1
        assert len(params_restored.relays) == 1
        assert params_restored.metadata is not None

    def test_cbor_roundtrip_without_metadata(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test CBOR serialization/deserialization without metadata."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=None,
        )

        writer = CborWriter()
        params.to_cbor(writer)
        data = writer.encode()

        reader = CborReader.from_bytes(data)
        params_restored = PoolParams.from_cbor(reader)

        assert params_restored.pledge == 1000000000
        assert params_restored.cost == 340000000
        assert params_restored.metadata is None

    def test_set_operator_key_hash(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting operator key hash."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_hash = Blake2bHash.from_hex("ff" * 28)
        params.operator_key_hash = new_hash
        assert params.operator_key_hash.to_hex() == "ff" * 28

    def test_set_vrf_vk_hash(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting VRF vk hash."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_hash = Blake2bHash.from_hex("ff" * 32)
        params.vrf_vk_hash = new_hash
        assert params.vrf_vk_hash.to_hex() == "ff" * 32

    def test_set_margin(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting margin."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_margin = UnitInterval.new(5, 100)
        params.margin = new_margin
        retrieved_margin = params.margin
        assert retrieved_margin.numerator == 5
        assert retrieved_margin.denominator == 100

    def test_set_reward_account(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting reward account."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_hash = Blake2bHash.from_hex("dd" * 28)
        new_credential = Credential.from_key_hash(new_hash)
        new_account = RewardAddress.from_credentials(NetworkId.MAINNET, new_credential)
        params.reward_account = new_account
        retrieved_account = params.reward_account
        assert retrieved_account is not None

    def test_set_owners(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting owners."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_owners = PoolOwners.new()
        new_owners.add(Blake2bHash.from_hex("ee" * 28))
        new_owners.add(Blake2bHash.from_hex("ff" * 28))
        params.owners = new_owners
        retrieved_owners = params.owners
        assert len(retrieved_owners) == 2

    def test_set_relays(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting relays."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        new_relays = Relays.new()
        new_relays.add(SingleHostNameRelay.new("relay1.example.com", port=3001))
        new_relays.add(SingleHostNameRelay.new("relay2.example.com", port=3002))
        params.relays = new_relays
        retrieved_relays = params.relays
        assert len(retrieved_relays) == 2

    def test_set_metadata(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test setting metadata."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=None,
        )
        assert params.metadata is None
        new_metadata = PoolMetadata.new(
            "https://new.example.com/pool.json",
            Blake2bHash.from_hex("ee" * 32)
        )
        params.metadata = new_metadata
        assert params.metadata is not None
        assert params.metadata.url == "https://new.example.com/pool.json"

    def test_set_metadata_to_none(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays, metadata
    ):
        """Test setting metadata to None."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=metadata,
        )
        assert params.metadata is not None
        params.metadata = None
        assert params.metadata is None

    def test_from_cbor_with_real_data(self):
        """Test deserialization with real CBOR data from C tests."""
        cbor_hex = (
            "581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
            "58208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db0"
            "1927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d"
            "965a99893828ec810fd9010281581ccb0ec2692497b458e46812c8a5bfa2931d1a2d"
            "965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f"
            "000001f682026b6578616d706c652e636f6d827368747470733a2f2f6578616d706c"
            "652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0"
            "e78f19d9d5"
        )
        reader = CborReader.from_hex(cbor_hex)
        params = PoolParams.from_cbor(reader)

        assert params.pledge == 10000
        assert params.cost == 1000

    def test_from_cbor_with_null_metadata(self):
        """Test deserialization with CBOR data containing null metadata."""
        cbor_hex = (
            "581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
            "58208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db0"
            "1927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d"
            "965a99893828ec810fd9010281581ccb0ec2692497b458e46812c8a5bfa2931d1a2d"
            "965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f"
            "000001f682026b6578616d706c652e636f6df6"
        )
        reader = CborReader.from_hex(cbor_hex)
        params = PoolParams.from_cbor(reader)

        assert params.pledge == 10000
        assert params.cost == 1000
        assert params.metadata is None

    def test_invalid_cbor_operator_hash(self):
        """Test that invalid operator hash CBOR raises error."""
        cbor_hex = "ef1cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"
        with pytest.raises(CardanoError):
            reader = CborReader.from_hex(cbor_hex)
            PoolParams.from_cbor(reader)

    def test_context_manager(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test PoolParams as context manager."""
        with PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        ) as params:
            assert params.pledge == 1000000000
            assert params.cost == 340000000

    def test_to_cip116_json(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays, metadata
    ):
        """Test CIP-116 JSON serialization."""
        from cometa import JsonWriter
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
            metadata=metadata,
        )
        writer = JsonWriter()
        params.to_cip116_json(writer)
        json_str = writer.encode()
        assert len(json_str) > 0
        assert "pledge" in json_str or "cost" in json_str

    def test_to_cip116_json_invalid_writer(
        self, operator_hash, vrf_hash, margin, reward_account, owners, relays
    ):
        """Test CIP-116 JSON serialization with invalid writer."""
        params = PoolParams.new(
            operator_key_hash=operator_hash,
            vrf_vk_hash=vrf_hash,
            pledge=1000000000,
            cost=340000000,
            margin=margin,
            reward_account=reward_account,
            owners=owners,
            relays=relays,
        )
        with pytest.raises(TypeError):
            params.to_cip116_json("not a writer")
