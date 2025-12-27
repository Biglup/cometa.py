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
    ProposedParamUpdates,
    ProtocolParamUpdate,
    Blake2bHash,
    CborReader,
    CborWriter,
    CardanoError,
    JsonWriter,
)


CBOR_HEX = "a3581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000002b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000003b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba"


class TestProposedParamUpdatesCreation:
    """Tests for ProposedParamUpdates factory methods and initialization."""

    def test_new_basic(self):
        """Test creating an empty ProposedParamUpdates (from C test)."""
        updates = ProposedParamUpdates.new()
        assert updates is not None
        assert len(updates) == 0

    def test_new_then_insert(self):
        """Test creating empty updates and inserting an item."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        assert len(updates) == 1


class TestProposedParamUpdatesCborSerialization:
    """Tests for ProposedParamUpdates CBOR serialization and deserialization."""

    def test_to_cbor_empty(self):
        """Test serializing empty ProposedParamUpdates to CBOR (from C test)."""
        updates = ProposedParamUpdates.new()
        writer = CborWriter()
        updates.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == "a0"

    def test_from_cbor_complex(self):
        """Test deserializing complex ProposedParamUpdates from CBOR (from C test)."""
        reader = CborReader.from_hex(CBOR_HEX)
        updates = ProposedParamUpdates.from_cbor(reader)
        assert updates is not None
        assert len(updates) == 3

    def test_cbor_roundtrip(self):
        """Test CBOR serialization roundtrip (from C test)."""
        reader = CborReader.from_hex(CBOR_HEX)
        original = ProposedParamUpdates.from_cbor(reader)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = ProposedParamUpdates.from_cbor(reader2)

        assert len(deserialized) == len(original)

    def test_from_cbor_invalid_not_map(self):
        """Test that deserializing non-map raises error (from C test)."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            ProposedParamUpdates.from_cbor(reader)

    def test_from_cbor_invalid_map(self):
        """Test that deserializing invalid map raises error (from C test)."""
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            ProposedParamUpdates.from_cbor(reader)


class TestProposedParamUpdatesMapOperations:
    """Tests for ProposedParamUpdates map operations (insert, get, etc.)."""

    def test_insert_basic(self):
        """Test inserting a parameter update (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        assert len(updates) == 1

    def test_insert_multiple_sorted(self):
        """Test that inserted elements remain sorted by hash (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")
        hash3 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000003")

        updates.insert(hash3, param_update)
        updates.insert(hash2, param_update)
        updates.insert(hash1, param_update)

        assert len(updates) == 3

        key0 = updates.get_key_at(0)
        key1 = updates.get_key_at(1)
        key2 = updates.get_key_at(2)

        assert key0.to_hex() == hash1.to_hex()
        assert key1.to_hex() == hash2.to_hex()
        assert key2.to_hex() == hash3.to_hex()

    def test_get_existing_key(self):
        """Test retrieving an existing parameter update (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        retrieved = updates.get(hash_obj)

        assert retrieved is not None

    def test_get_nonexistent_key(self):
        """Test retrieving a nonexistent key returns None (from C test)."""
        updates = ProposedParamUpdates.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        retrieved = updates.get(hash_obj)
        assert retrieved is None

    def test_get_multiple_keys(self):
        """Test retrieving correct update from multiple entries (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update1 = ProtocolParamUpdate.new()
        param_update2 = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update1)
        updates.insert(hash2, param_update2)

        retrieved1 = updates.get(hash1)
        retrieved2 = updates.get(hash2)

        assert retrieved1 is not None
        assert retrieved2 is not None


class TestProposedParamUpdatesIndexedAccess:
    """Tests for ProposedParamUpdates indexed access methods."""

    def test_get_key_at_valid_index(self):
        """Test getting key at valid index (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        key = updates.get_key_at(0)

        assert key is not None
        assert key.to_hex() == hash_obj.to_hex()

    def test_get_key_at_invalid_index(self):
        """Test getting key at invalid index returns None (from C test)."""
        updates = ProposedParamUpdates.new()
        key = updates.get_key_at(0)
        assert key is None

    def test_get_value_at_valid_index(self):
        """Test getting value at valid index (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        value = updates.get_value_at(0)

        assert value is not None

    def test_get_value_at_invalid_index(self):
        """Test getting value at invalid index returns None (from C test)."""
        updates = ProposedParamUpdates.new()
        value = updates.get_value_at(0)
        assert value is None


class TestProposedParamUpdatesDictProtocol:
    """Tests for ProposedParamUpdates dict-like protocol (__getitem__, __setitem__, etc.)."""

    def test_setitem(self):
        """Test setting item using dict syntax."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates[hash_obj] = param_update
        assert len(updates) == 1

    def test_getitem_existing(self):
        """Test getting existing item using dict syntax."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates[hash_obj] = param_update
        retrieved = updates[hash_obj]
        assert retrieved is not None

    def test_getitem_nonexistent_raises_keyerror(self):
        """Test getting nonexistent item raises KeyError."""
        updates = ProposedParamUpdates.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        with pytest.raises(KeyError):
            _ = updates[hash_obj]

    def test_contains_existing(self):
        """Test __contains__ with existing key."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates[hash_obj] = param_update
        assert hash_obj in updates

    def test_contains_nonexistent(self):
        """Test __contains__ with nonexistent key."""
        updates = ProposedParamUpdates.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        assert hash_obj not in updates


class TestProposedParamUpdatesIteration:
    """Tests for ProposedParamUpdates iteration methods."""

    def test_iter_empty(self):
        """Test iterating over empty updates."""
        updates = ProposedParamUpdates.new()
        items = list(updates)
        assert len(items) == 0

    def test_iter_single(self):
        """Test iterating over single item."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        items = list(updates)

        assert len(items) == 1
        key, value = items[0]
        assert key.to_hex() == hash_obj.to_hex()
        assert value is not None

    def test_iter_multiple(self):
        """Test iterating over multiple items."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)

        items = list(updates)
        assert len(items) == 2

    def test_keys_method(self):
        """Test keys() iterator method."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)

        keys = list(updates.keys())
        assert len(keys) == 2
        assert keys[0].to_hex() == hash1.to_hex()
        assert keys[1].to_hex() == hash2.to_hex()

    def test_values_method(self):
        """Test values() iterator method."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)

        values = list(updates.values())
        assert len(values) == 2

    def test_items_method(self):
        """Test items() iterator method."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)

        items = list(updates.items())
        assert len(items) == 2


class TestProposedParamUpdatesJsonSerialization:
    """Tests for ProposedParamUpdates JSON serialization."""

    def test_to_cip116_json_empty(self):
        """Test converting empty updates to CIP-116 JSON (from C test)."""
        updates = ProposedParamUpdates.new()
        writer = JsonWriter()
        updates.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "{}"

    def test_to_cip116_json_single_entry(self):
        """Test converting single entry to CIP-116 JSON (from C test)."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("10000000000000000000000000000000000000000000000000000000")

        updates.insert(hash_obj, param_update)

        writer = JsonWriter()
        updates.to_cip116_json(writer)
        json_str = writer.encode()

        assert "10000000000000000000000000000000000000000000000000000000" in json_str
        assert json_str.startswith("{")
        assert json_str.endswith("}")

    def test_to_cip116_json_invalid_writer(self):
        """Test that passing invalid writer raises error."""
        updates = ProposedParamUpdates.new()
        with pytest.raises(TypeError):
            updates.to_cip116_json("not a writer")


class TestProposedParamUpdatesMagicMethods:
    """Tests for ProposedParamUpdates magic methods."""

    def test_repr_empty(self):
        """Test __repr__ for empty updates."""
        updates = ProposedParamUpdates.new()
        assert repr(updates) == "ProposedParamUpdates(size=0)"

    def test_repr_with_items(self):
        """Test __repr__ with items."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)
        assert repr(updates) == "ProposedParamUpdates(size=1)"

    def test_len_empty(self):
        """Test __len__ for empty updates."""
        updates = ProposedParamUpdates.new()
        assert len(updates) == 0

    def test_len_with_items(self):
        """Test __len__ with items."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)

        assert len(updates) == 2


class TestProposedParamUpdatesContextManager:
    """Tests for ProposedParamUpdates context manager protocol."""

    def test_context_manager(self):
        """Test that ProposedParamUpdates can be used as context manager."""
        with ProposedParamUpdates.new() as updates:
            assert updates is not None
            assert len(updates) == 0

    def test_context_manager_exception(self):
        """Test context manager with exception."""
        try:
            with ProposedParamUpdates.new() as updates:
                assert updates is not None
                raise ValueError("test exception")
        except ValueError:
            pass


class TestProposedParamUpdatesEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_insert_same_key_twice(self):
        """Test inserting same key twice allows duplicate entries."""
        updates = ProposedParamUpdates.new()
        param_update1 = ProtocolParamUpdate.new()
        param_update2 = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update1)
        updates.insert(hash_obj, param_update2)

        assert len(updates) >= 1

    def test_multiple_inserts_preserve_order(self):
        """Test that multiple inserts maintain sorted order."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hashes = [
            Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000005"),
            Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001"),
            Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000003"),
            Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002"),
            Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000004"),
        ]

        for h in hashes:
            updates.insert(h, param_update)

        keys = [k.to_hex() for k in updates.keys()]
        assert keys == sorted(keys)

    def test_iteration_after_cbor_deserialization(self):
        """Test that iteration works after CBOR deserialization."""
        reader = CborReader.from_hex(CBOR_HEX)
        updates = ProposedParamUpdates.from_cbor(reader)

        count = 0
        for key, value in updates:
            assert key is not None
            assert value is not None
            count += 1

        assert count == len(updates)

    def test_get_key_at_all_indices(self):
        """Test getting keys at all valid indices."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")
        hash3 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000003")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)
        updates.insert(hash3, param_update)

        for i in range(len(updates)):
            key = updates.get_key_at(i)
            assert key is not None

    def test_get_value_at_all_indices(self):
        """Test getting values at all valid indices."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()

        hash1 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")
        hash2 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000002")
        hash3 = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000003")

        updates.insert(hash1, param_update)
        updates.insert(hash2, param_update)
        updates.insert(hash3, param_update)

        for i in range(len(updates)):
            value = updates.get_value_at(i)
            assert value is not None

    def test_empty_iteration(self):
        """Test that iterating empty updates doesn't raise errors."""
        updates = ProposedParamUpdates.new()

        for _ in updates:
            pytest.fail("Should not iterate over empty updates")

        for _ in updates.keys():
            pytest.fail("Should not iterate over empty keys")

        for _ in updates.values():
            pytest.fail("Should not iterate over empty values")

        for _ in updates.items():
            pytest.fail("Should not iterate over empty items")

    def test_cbor_serialization_after_operations(self):
        """Test CBOR serialization after various operations."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)

        writer = CborWriter()
        updates.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = ProposedParamUpdates.from_cbor(reader)

        assert len(deserialized) == 1

    def test_json_serialization_after_operations(self):
        """Test JSON serialization after various operations."""
        updates = ProposedParamUpdates.new()
        param_update = ProtocolParamUpdate.new()
        hash_obj = Blake2bHash.from_hex("00000000000000000000000000000000000000000000000000000001")

        updates.insert(hash_obj, param_update)

        writer = JsonWriter()
        updates.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str.startswith("{")
        assert json_str.endswith("}")
        assert "00000000000000000000000000000000000000000000000000000001" in json_str
