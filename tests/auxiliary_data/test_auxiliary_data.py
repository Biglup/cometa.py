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
    Metadatum,
    MetadatumKind,
    MetadatumList,
    MetadatumMap,
    MetadatumLabelList,
    TransactionMetadata,
    AuxiliaryData,
    CborReader,
    CborWriter,
    JsonWriter,
)


class TestMetadatumKind:
    """Tests for the MetadatumKind enum."""

    def test_enum_values(self):
        assert MetadatumKind.MAP == 0
        assert MetadatumKind.LIST == 1
        assert MetadatumKind.INTEGER == 2
        assert MetadatumKind.BYTES == 3
        assert MetadatumKind.TEXT == 4


class TestMetadatum:
    """Tests for the Metadatum class."""

    def test_from_int(self):
        meta = Metadatum.from_int(42)
        assert meta.kind == MetadatumKind.INTEGER

    def test_from_uint(self):
        meta = Metadatum.from_uint(18446744073709551615)
        assert meta.kind == MetadatumKind.INTEGER

    def test_from_integer_string(self):
        meta = Metadatum.from_integer_string("12345678901234567890")
        assert meta.kind == MetadatumKind.INTEGER

    def test_from_string(self):
        meta = Metadatum.from_string("Hello, Cardano!")
        assert meta.kind == MetadatumKind.TEXT

    def test_to_str(self):
        meta = Metadatum.from_string("Hello")
        assert meta.to_str() == "Hello"

    def test_from_bytes(self):
        meta = Metadatum.from_bytes(b"\xde\xad\xbe\xef")
        assert meta.kind == MetadatumKind.BYTES

    def test_to_bytes(self):
        meta = Metadatum.from_bytes(b"\xde\xad\xbe\xef")
        assert meta.to_bytes() == b"\xde\xad\xbe\xef"

    def test_from_hex(self):
        meta = Metadatum.from_hex("deadbeef")
        assert meta.kind == MetadatumKind.BYTES

    def test_to_json(self):
        meta = Metadatum.from_int(42)
        json = meta.to_json()
        assert "42" in json

    def test_from_json(self):
        meta = Metadatum.from_json('42')
        assert meta.kind == MetadatumKind.INTEGER

    def test_equality(self):
        meta1 = Metadatum.from_int(100)
        meta2 = Metadatum.from_int(100)
        meta3 = Metadatum.from_int(200)
        assert meta1 == meta2
        assert meta1 != meta3

    def test_cbor_roundtrip(self):
        original = Metadatum.from_string("Test metadata")
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()
        reader = CborReader.from_bytes(cbor_bytes)
        restored = Metadatum.from_cbor(reader)
        assert restored == original

    def test_from_map(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        assert meta.kind == MetadatumKind.MAP

    def test_from_list(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta = Metadatum.from_list(meta_list)
        assert meta.kind == MetadatumKind.LIST

    def test_to_map(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        meta = Metadatum.from_map(meta_map)
        retrieved_map = meta.to_map()
        assert len(retrieved_map) == 1

    def test_to_list(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta = Metadatum.from_list(meta_list)
        retrieved_list = meta.to_list()
        assert len(retrieved_list) == 2

    def test_to_cip116_json(self):
        meta = Metadatum.from_int(42)
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert "42" in json_str

    def test_to_cip116_json_map(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("name"), Metadatum.from_string("Alice"))
        meta = Metadatum.from_map(meta_map)
        writer = JsonWriter()
        meta.to_cip116_json(writer)
        json_str = writer.encode()
        assert "name" in json_str or "map" in json_str.lower()


class TestTransactionMetadata:
    """Tests for the TransactionMetadata class."""

    def test_new_empty(self):
        metadata = TransactionMetadata()
        assert len(metadata) == 0

    def test_insert_and_get(self):
        metadata = TransactionMetadata()
        meta = Metadatum.from_string("NFT metadata")
        metadata.insert(721, meta)
        retrieved = metadata.get(721)
        assert retrieved.kind == MetadatumKind.TEXT

    def test_len(self):
        metadata = TransactionMetadata()
        metadata.insert(1, Metadatum.from_int(100))
        metadata.insert(2, Metadatum.from_int(200))
        assert len(metadata) == 2

    def test_iteration(self):
        metadata = TransactionMetadata()
        metadata.insert(1, Metadatum.from_int(100))
        metadata.insert(2, Metadatum.from_int(200))
        items = list(metadata)
        assert len(items) == 2

    def test_contains(self):
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("data"))
        assert 721 in metadata
        assert 999 not in metadata

    def test_bracket_notation_get(self):
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("NFT"))
        result = metadata[721]
        assert result.kind == MetadatumKind.TEXT

    def test_bracket_notation_set(self):
        metadata = TransactionMetadata()
        metadata[721] = Metadatum.from_string("NFT data")
        assert 721 in metadata

    def test_cbor_roundtrip(self):
        original = TransactionMetadata()
        original.insert(721, Metadatum.from_string("NFT metadata"))
        original.insert(674, Metadatum.from_int(12345))

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = TransactionMetadata.from_cbor(reader)
        assert len(restored) == 2


class TestAuxiliaryData:
    """Tests for the AuxiliaryData class."""

    AUXILIARY_DATA_CBOR = "d90103a500a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b6501848204038205098202818200581c3542acb3a64d80c29302260d62c3b87a742ad14abf855ebc6733081e830300818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f5402844746010000220010474601000022001147460100002200124746010000220013038447460100002200104746010000220011474601000022001247460100002200130483474601000022001047460100002200114746010000220012"
    AUXILIARY_DATA_CBOR2 = "d90103a200a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b6501828202818200581c3542acb3a64d80c29302260d62c3b87a742ad14abf855ebc6733081e830300818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f54"
    AUXILIARY_DATA_CBOR3 = "d90103a100a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65"
    SHELLEY_AUXILIARY_DATA_CBOR = "82a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65828202818200581c3542acb3a64d80c29302260d62c3b87a742ad14abf855ebc6733081e830300818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f54"
    JUST_METADATA_AUXILIARY_DATA_CBOR = "a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b65"
    AUXILIARY_DATA_HASH = "d24e84d8dbf6f880b04f64ad919bb618bf66ce834b3c901b1efe2ce6b44beb7b"
    SHELLEY_AUXILIARY_DATA_HASH = "a02cace10f1fc93061cd0dcc31ccfafb9599eba245ae3f03a2ee69928f73d3ed"
    JUST_METADATA_AUXILIARY_DATA_HASH = "3bed6c134ce51ea7cfccec5ae44acbcb995b568c6408f2a1302f0e1c76d4ae63"

    def test_new_empty(self):
        aux_data = AuxiliaryData()
        assert aux_data.metadata is None

    def test_set_metadata(self):
        aux_data = AuxiliaryData()
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("NFT data"))
        aux_data.set_metadata(metadata)
        assert aux_data.metadata is not None

    def test_set_metadata_to_none(self):
        aux_data = AuxiliaryData()
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("Test"))
        aux_data.set_metadata(metadata)
        assert aux_data.metadata is not None
        aux_data.set_metadata(None)
        assert aux_data.metadata is None

    def test_remove_metadata(self):
        aux_data = AuxiliaryData()
        metadata = TransactionMetadata()
        metadata.insert(1, Metadatum.from_int(100))
        aux_data.set_metadata(metadata)
        assert aux_data.metadata is not None
        aux_data.set_metadata(None)
        assert aux_data.metadata is None

    def test_to_hash(self):
        aux_data = AuxiliaryData()
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("Test"))
        aux_data.set_metadata(metadata)
        hash_value = aux_data.to_hash()
        assert len(hash_value.to_bytes()) == 32

    def test_to_hash_with_test_vectors(self):
        reader1 = CborReader.from_hex(self.AUXILIARY_DATA_CBOR)
        aux_data1 = AuxiliaryData.from_cbor(reader1)
        hash1 = aux_data1.to_hash()
        assert hash1.to_hex() == self.AUXILIARY_DATA_HASH

        reader2 = CborReader.from_hex(self.SHELLEY_AUXILIARY_DATA_CBOR)
        aux_data2 = AuxiliaryData.from_cbor(reader2)
        hash2 = aux_data2.to_hash()
        assert hash2.to_hex() == self.SHELLEY_AUXILIARY_DATA_HASH

        reader3 = CborReader.from_hex(self.JUST_METADATA_AUXILIARY_DATA_CBOR)
        aux_data3 = AuxiliaryData.from_cbor(reader3)
        hash3 = aux_data3.to_hash()
        assert hash3.to_hex() == self.JUST_METADATA_AUXILIARY_DATA_HASH

    def test_cbor_roundtrip(self):
        original = AuxiliaryData()
        metadata = TransactionMetadata()
        metadata.insert(721, Metadatum.from_string("NFT metadata"))
        original.set_metadata(metadata)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = AuxiliaryData.from_cbor(reader)
        assert restored.metadata is not None
        assert len(restored.metadata) == 1

    def test_from_cbor_with_complex_data(self):
        reader = CborReader.from_hex(self.AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)
        assert aux_data.metadata is not None
        aux_data.clear_cbor_cache()

        writer = CborWriter()
        aux_data.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == self.AUXILIARY_DATA_CBOR

    def test_from_cbor_shelley_era(self):
        reader = CborReader.from_hex(self.SHELLEY_AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)
        assert aux_data.metadata is not None
        aux_data.clear_cbor_cache()

        writer = CborWriter()
        aux_data.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == self.AUXILIARY_DATA_CBOR2

    def test_from_cbor_just_metadata(self):
        reader = CborReader.from_hex(self.JUST_METADATA_AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)
        assert aux_data.metadata is not None
        aux_data.clear_cbor_cache()

        writer = CborWriter()
        aux_data.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == self.AUXILIARY_DATA_CBOR3

    def test_from_cbor_preserves_original(self):
        reader = CborReader.from_hex(self.SHELLEY_AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)

        writer = CborWriter()
        aux_data.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == self.SHELLEY_AUXILIARY_DATA_CBOR

    def test_clear_cbor_cache(self):
        reader = CborReader.from_hex(self.SHELLEY_AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)

        writer1 = CborWriter()
        aux_data.to_cbor(writer1)
        cbor_hex1 = writer1.to_hex()
        assert cbor_hex1 == self.SHELLEY_AUXILIARY_DATA_CBOR

        aux_data.clear_cbor_cache()

        writer2 = CborWriter()
        aux_data.to_cbor(writer2)
        cbor_hex2 = writer2.to_hex()
        assert cbor_hex2 == self.AUXILIARY_DATA_CBOR2

    def test_to_cip116_json(self):
        reader = CborReader.from_hex(self.AUXILIARY_DATA_CBOR)
        aux_data = AuxiliaryData.from_cbor(reader)

        writer = JsonWriter()
        aux_data.to_cip116_json(writer)
        json_str = writer.encode()

        assert "metadata" in json_str
        assert "native_scripts" in json_str
        assert "plutus_scripts" in json_str

    def test_to_cip116_json_with_invalid_writer_type(self):
        aux_data = AuxiliaryData()
        with pytest.raises(TypeError):
            aux_data.to_cip116_json("not a JsonWriter")

    def test_from_cbor_invalid_cbor(self):
        reader = CborReader.from_hex("01")
        with pytest.raises(Exception):
            AuxiliaryData.from_cbor(reader)

    def test_from_cbor_invalid_metadata(self):
        reader = CborReader.from_hex("a100ef")
        with pytest.raises(Exception):
            AuxiliaryData.from_cbor(reader)

    def test_from_cbor_invalid_tag(self):
        cbor = "d90113a500a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b6501848204038205098202818200581c3542acb3a64d80c29302260d62c3b87a742ad14abf855ebc6733081e830300818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f5402844746010000220010474601000022001147460100002200124746010000220013038447460100002200104746010000220011474601000022001247460100002200130483474601000022001047460100002200114746010000220012"
        reader = CborReader.from_hex(cbor)
        with pytest.raises(Exception):
            AuxiliaryData.from_cbor(reader)

    def test_context_manager(self):
        with AuxiliaryData() as aux_data:
            metadata = TransactionMetadata()
            metadata.insert(721, Metadatum.from_string("NFT"))
            aux_data.set_metadata(metadata)
            assert aux_data.metadata is not None

    def test_repr(self):
        aux_data = AuxiliaryData()
        assert repr(aux_data) == "AuxiliaryData()"


class TestMetadatumList:
    """Tests for the MetadatumList class."""

    def test_new_empty(self):
        meta_list = MetadatumList()
        assert len(meta_list) == 0

    def test_add_and_get(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(42))
        assert len(meta_list) == 1
        assert meta_list.get(0).kind == MetadatumKind.INTEGER

    def test_bracket_notation(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_string("hello"))
        assert meta_list[0].kind == MetadatumKind.INTEGER
        assert meta_list[1].kind == MetadatumKind.TEXT

    def test_iteration(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(Metadatum.from_int(3))
        count = sum(1 for _ in meta_list)
        assert count == 3

    def test_index_out_of_bounds(self):
        meta_list = MetadatumList()
        with pytest.raises(IndexError):
            _ = meta_list[0]

    def test_repr(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(42))
        assert "len=1" in repr(meta_list)

    def test_cbor_roundtrip(self):
        original = MetadatumList()
        original.add(Metadatum.from_int(1))
        original.add(Metadatum.from_string("test"))

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = MetadatumList.from_cbor(reader)
        assert len(restored) == 2

    def test_equality(self):
        list1 = MetadatumList()
        list1.add(Metadatum.from_int(42))
        list2 = MetadatumList()
        list2.add(Metadatum.from_int(42))
        list3 = MetadatumList()
        list3.add(Metadatum.from_int(99))
        assert list1 == list2
        assert list1 != list3

    def test_negative_index(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(1))
        meta_list.add(Metadatum.from_int(2))
        meta_list.add(Metadatum.from_int(3))
        assert int(meta_list[-1].to_integer()) == 3
        assert int(meta_list[-2].to_integer()) == 2

    def test_bool(self):
        meta_list = MetadatumList()
        assert not meta_list  # Empty list is falsy
        meta_list.add(Metadatum.from_int(1))
        assert meta_list  # Non-empty list is truthy

    def test_contains(self):
        meta_list = MetadatumList()
        meta_list.add(Metadatum.from_int(42))
        assert Metadatum.from_int(42) in meta_list
        assert Metadatum.from_int(99) not in meta_list

    def test_append(self):
        meta_list = MetadatumList()
        meta_list.append(Metadatum.from_int(1))
        assert len(meta_list) == 1

    def test_add_primitives(self):
        """Test adding Python primitives directly to list."""
        meta_list = MetadatumList()
        meta_list.add(42)  # int
        meta_list.add("hello")  # str
        meta_list.add(b"\xde\xad")  # bytes
        meta_list.add(bytearray([0xbe, 0xef]))  # bytearray
        assert len(meta_list) == 4
        assert meta_list[0].kind == MetadatumKind.INTEGER
        assert meta_list[1].kind == MetadatumKind.TEXT
        assert meta_list[2].kind == MetadatumKind.BYTES
        assert meta_list[3].kind == MetadatumKind.BYTES

    def test_append_primitives(self):
        """Test appending Python primitives directly to list."""
        meta_list = MetadatumList()
        meta_list.append(100)
        meta_list.append("world")
        assert len(meta_list) == 2

    def test_contains_primitives(self):
        """Test __contains__ with Python primitives."""
        meta_list = MetadatumList()
        meta_list.add(42)
        meta_list.add("hello")
        assert 42 in meta_list
        assert "hello" in meta_list
        assert 99 not in meta_list
        assert "other" not in meta_list


class TestMetadatumMap:
    """Tests for the MetadatumMap class."""

    def test_new_empty(self):
        meta_map = MetadatumMap()
        assert len(meta_map) == 0

    def test_insert_and_get(self):
        meta_map = MetadatumMap()
        key = Metadatum.from_string("key")
        value = Metadatum.from_int(42)
        meta_map.insert(key, value)
        assert len(meta_map) == 1
        retrieved = meta_map.get(key)
        assert retrieved.kind == MetadatumKind.INTEGER

    def test_get_at(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("name"), Metadatum.from_string("Alice"))
        key, value = meta_map.get_at(0)
        assert key.kind == MetadatumKind.TEXT
        assert value.kind == MetadatumKind.TEXT

    def test_iteration(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("a"), Metadatum.from_int(1))
        meta_map.insert(Metadatum.from_string("b"), Metadatum.from_int(2))
        # Iteration yields keys (like dict)
        keys = list(meta_map)
        assert len(keys) == 2
        for key in keys:
            assert key.kind == MetadatumKind.TEXT

    def test_index_out_of_bounds(self):
        meta_map = MetadatumMap()
        with pytest.raises(IndexError):
            _ = meta_map.get_at(0)

    def test_repr(self):
        meta_map = MetadatumMap()
        assert "len=0" in repr(meta_map)

    def test_cbor_roundtrip(self):
        original = MetadatumMap()
        original.insert(Metadatum.from_string("key1"), Metadatum.from_int(100))
        original.insert(Metadatum.from_string("key2"), Metadatum.from_string("value"))

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = MetadatumMap.from_cbor(reader)
        assert len(restored) == 2

    def test_equality(self):
        map1 = MetadatumMap()
        map1.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        map2 = MetadatumMap()
        map2.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
        map3 = MetadatumMap()
        map3.insert(Metadatum.from_string("key"), Metadatum.from_int(99))
        assert map1 == map2
        assert map1 != map3

    def test_get_keys(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("a"), Metadatum.from_int(1))
        meta_map.insert(Metadatum.from_string("b"), Metadatum.from_int(2))
        keys = meta_map.get_keys()
        assert len(keys) == 2

    def test_get_values(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("a"), Metadatum.from_int(1))
        meta_map.insert(Metadatum.from_string("b"), Metadatum.from_int(2))
        values = meta_map.get_values()
        assert len(values) == 2

    def test_bool(self):
        meta_map = MetadatumMap()
        assert not meta_map  # Empty map is falsy
        meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(1))
        assert meta_map  # Non-empty map is truthy

    def test_bracket_get_set(self):
        meta_map = MetadatumMap()
        key = Metadatum.from_string("key")
        meta_map[key] = Metadatum.from_int(42)
        assert meta_map[key].kind == MetadatumKind.INTEGER

    def test_contains(self):
        meta_map = MetadatumMap()
        key = Metadatum.from_string("key")
        meta_map[key] = Metadatum.from_int(42)
        assert key in meta_map
        assert Metadatum.from_string("other") not in meta_map

    def test_keys_values_items(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("a"), Metadatum.from_int(1))
        meta_map.insert(Metadatum.from_string("b"), Metadatum.from_int(2))
        keys = list(meta_map.keys())
        values = list(meta_map.values())
        items = list(meta_map.items())
        assert len(keys) == 2
        assert len(values) == 2
        assert len(items) == 2

    def test_iter_over_keys(self):
        meta_map = MetadatumMap()
        meta_map.insert(Metadatum.from_string("a"), Metadatum.from_int(1))
        # Iterating over map should yield keys (like dict)
        keys = list(meta_map)
        assert len(keys) == 1

    def test_insert_primitives(self):
        """Test inserting with Python primitives for both keys and values."""
        meta_map = MetadatumMap()
        meta_map.insert("name", "Alice")  # str key and value
        meta_map.insert("age", 30)  # str key, int value
        meta_map.insert(1, b"\xde\xad")  # int key, bytes value
        assert len(meta_map) == 3
        assert meta_map.get("name").to_str() == "Alice"
        assert int(meta_map.get("age").to_integer()) == 30
        assert meta_map.get(1).to_bytes() == b"\xde\xad"

    def test_bracket_notation_primitives(self):
        """Test bracket notation with Python primitives."""
        meta_map = MetadatumMap()
        meta_map["name"] = "Bob"
        meta_map["score"] = 100
        meta_map[42] = "answer"
        assert meta_map["name"].to_str() == "Bob"
        assert int(meta_map["score"].to_integer()) == 100
        assert meta_map[42].to_str() == "answer"

    def test_contains_primitives(self):
        """Test __contains__ with Python primitives."""
        meta_map = MetadatumMap()
        meta_map["name"] = "Alice"
        meta_map[123] = "value"
        assert "name" in meta_map
        assert 123 in meta_map
        assert "other" not in meta_map
        assert 999 not in meta_map

    def test_mixed_primitives_and_metadatum(self):
        """Test mixing Metadatum objects and primitives."""
        meta_map = MetadatumMap()
        # Insert with Metadatum key, primitive value
        key1 = Metadatum.from_string("key1")
        meta_map.insert(key1, 42)
        assert int(meta_map.get(key1).to_integer()) == 42
        # Insert with primitive key, Metadatum value
        meta_map.insert("key2", Metadatum.from_int(100))
        assert int(meta_map["key2"].to_integer()) == 100
        # Both work
        assert len(meta_map) == 2


class TestMetadatumLabelList:
    """Tests for the MetadatumLabelList class."""

    def test_new_empty(self):
        label_list = MetadatumLabelList()
        assert len(label_list) == 0

    def test_add_and_get(self):
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert len(label_list) == 1
        assert label_list.get(0) == 721

    def test_bracket_notation(self):
        label_list = MetadatumLabelList()
        label_list.add(721)
        label_list.add(674)
        # Labels are stored in sorted order
        assert label_list[0] == 674
        assert label_list[1] == 721

    def test_iteration(self):
        label_list = MetadatumLabelList()
        label_list.add(1)
        label_list.add(2)
        label_list.add(3)
        labels = list(label_list)
        assert labels == [1, 2, 3]

    def test_contains(self):
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert 721 in label_list
        assert 999 not in label_list

    def test_index_out_of_bounds(self):
        label_list = MetadatumLabelList()
        with pytest.raises(IndexError):
            _ = label_list[0]

    def test_repr(self):
        label_list = MetadatumLabelList()
        label_list.add(721)
        assert "len=1" in repr(label_list)

    def test_large_label(self):
        label_list = MetadatumLabelList()
        large_label = 18446744073709551615  # Max uint64
        label_list.add(large_label)
        assert label_list[0] == large_label
