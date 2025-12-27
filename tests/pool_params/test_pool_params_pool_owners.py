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
from cometa import PoolOwners, Blake2bHash, CborReader, CborWriter, JsonWriter, CardanoError


CBOR = "d9010285581c00000000000000000000000000000000000000000000000000000000581c11111111111111111111111111111111111111111111111111111111581c22222222222222222222222222222222222222222222222222222222581c33333333333333333333333333333333333333333333333333333333581c44444444444444444444444444444444444444444444444444444444"
CBOR_WITHOUT_TAG = "85581c00000000000000000000000000000000000000000000000000000000581c11111111111111111111111111111111111111111111111111111111581c22222222222222222222222222222222222222222222222222222222581c33333333333333333333333333333333333333333333333333333333581c44444444444444444444444444444444444444444444444444444444"
CBOR_EMPTY = "d9010280"

POOL_HASH1 = "00000000000000000000000000000000000000000000000000000000"
POOL_HASH2 = "11111111111111111111111111111111111111111111111111111111"
POOL_HASH3 = "22222222222222222222222222222222222222222222222222222222"
POOL_HASH4 = "33333333333333333333333333333333333333333333333333333333"
POOL_HASH5 = "44444444444444444444444444444444444444444444444444444444"


def test_new():
    pool_owners = PoolOwners.new()
    assert pool_owners is not None
    assert len(pool_owners) == 0


def test_new_creates_empty_set():
    pool_owners = PoolOwners.new()
    assert len(pool_owners) == 0


def test_add_single_owner():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)
    assert len(pool_owners) == 1


def test_add_multiple_owners():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    hash3 = Blake2bHash.from_hex(POOL_HASH3)
    pool_owners.add(hash1)
    pool_owners.add(hash2)
    pool_owners.add(hash3)
    assert len(pool_owners) == 3


def test_add_with_none_owner():
    pool_owners = PoolOwners.new()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        pool_owners.add(None)


def test_append_single_owner():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.append(hash1)
    assert len(pool_owners) == 1


def test_append_multiple_owners():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    pool_owners.append(hash1)
    pool_owners.append(hash2)
    assert len(pool_owners) == 2


def test_extend_with_pool_owners():
    pool_owners1 = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    pool_owners1.add(hash1)
    pool_owners1.add(hash2)

    pool_owners2 = PoolOwners.new()
    hash3 = Blake2bHash.from_hex(POOL_HASH3)
    pool_owners2.add(hash3)

    pool_owners2.extend(pool_owners1)
    assert len(pool_owners2) == 3


def test_extend_with_list():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    hash3 = Blake2bHash.from_hex(POOL_HASH3)

    pool_owners.extend([hash1, hash2, hash3])
    assert len(pool_owners) == 3


def test_extend_with_empty_list():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)
    pool_owners.extend([])
    assert len(pool_owners) == 1


def test_getitem_single_index():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    pool_owners.add(hash1)
    pool_owners.add(hash2)

    retrieved = pool_owners[0]
    assert retrieved is not None
    assert isinstance(retrieved, Blake2bHash)


def test_getitem_multiple_indices():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3, POOL_HASH4, POOL_HASH5]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    for i in range(5):
        retrieved = pool_owners[i]
        assert retrieved is not None


def test_getitem_negative_index():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    pool_owners.add(hash1)
    pool_owners.add(hash2)

    retrieved = pool_owners[-1]
    assert retrieved is not None


def test_getitem_out_of_bounds():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)

    with pytest.raises(IndexError):
        _ = pool_owners[10]


def test_getitem_negative_out_of_bounds():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)

    with pytest.raises(IndexError):
        _ = pool_owners[-10]


def test_getitem_on_empty():
    pool_owners = PoolOwners.new()
    with pytest.raises(IndexError):
        _ = pool_owners[0]


def test_getitem_slice():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    sliced = pool_owners[0:2]
    assert isinstance(sliced, list)
    assert len(sliced) == 2


def test_getitem_slice_all():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    sliced = pool_owners[:]
    assert isinstance(sliced, list)
    assert len(sliced) == 3


def test_len_empty():
    pool_owners = PoolOwners.new()
    assert len(pool_owners) == 0


def test_len_with_elements():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3, POOL_HASH4, POOL_HASH5]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))
    assert len(pool_owners) == 5


def test_iter():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    count = 0
    for owner in pool_owners:
        assert isinstance(owner, Blake2bHash)
        count += 1
    assert count == 3


def test_iter_empty():
    pool_owners = PoolOwners.new()
    count = 0
    for _ in pool_owners:
        count += 1
    assert count == 0


def test_contains_existing():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)

    hash_check = Blake2bHash.from_hex(POOL_HASH1)
    assert hash_check in pool_owners


def test_contains_non_existing():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)

    hash2 = Blake2bHash.from_hex(POOL_HASH2)
    assert hash2 not in pool_owners


def test_contains_empty():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    assert hash1 not in pool_owners


def test_contains_invalid_type():
    pool_owners = PoolOwners.new()
    assert "not a hash" not in pool_owners
    assert 42 not in pool_owners
    assert None not in pool_owners


def test_to_cbor_empty():
    pool_owners = PoolOwners.new()
    writer = CborWriter()
    pool_owners.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR_EMPTY


def test_to_cbor_with_owners():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3, POOL_HASH4, POOL_HASH5]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    writer = CborWriter()
    pool_owners.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR


def test_to_cbor_sorted():
    pool_owners = PoolOwners.new()
    hashes = [POOL_HASH5, POOL_HASH3, POOL_HASH1, POOL_HASH4, POOL_HASH2]
    for h in hashes:
        pool_owners.add(Blake2bHash.from_hex(h))

    writer = CborWriter()
    pool_owners.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR


def test_to_cbor_with_none_writer():
    pool_owners = PoolOwners.new()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        pool_owners.to_cbor(None)


def test_from_cbor():
    reader = CborReader.from_hex(CBOR)
    pool_owners = PoolOwners.from_cbor(reader)
    assert pool_owners is not None
    assert len(pool_owners) == 5


def test_from_cbor_without_tag():
    reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
    pool_owners = PoolOwners.from_cbor(reader)
    assert pool_owners is not None
    assert len(pool_owners) == 5


def test_from_cbor_empty():
    reader = CborReader.from_hex(CBOR_EMPTY)
    pool_owners = PoolOwners.from_cbor(reader)
    assert pool_owners is not None
    assert len(pool_owners) == 0


def test_from_cbor_verify_hashes():
    reader = CborReader.from_hex(CBOR)
    pool_owners = PoolOwners.from_cbor(reader)

    expected_hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3, POOL_HASH4, POOL_HASH5]
    for i, expected_hash in enumerate(expected_hashes):
        retrieved = pool_owners[i]
        assert retrieved.to_hex() == expected_hash


def test_from_cbor_with_none_reader():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        PoolOwners.from_cbor(None)


def test_from_cbor_with_invalid_cbor():
    reader = CborReader.from_hex("ff")
    with pytest.raises(CardanoError):
        PoolOwners.from_cbor(reader)


def test_from_cbor_with_invalid_array():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        PoolOwners.from_cbor(reader)


def test_from_cbor_with_invalid_elements():
    reader = CborReader.from_hex("9ffeff")
    with pytest.raises(CardanoError):
        PoolOwners.from_cbor(reader)


def test_from_cbor_round_trip():
    pool_owners1 = PoolOwners.new()
    hashes = [POOL_HASH1, POOL_HASH2, POOL_HASH3, POOL_HASH4, POOL_HASH5]
    for h in hashes:
        pool_owners1.add(Blake2bHash.from_hex(h))

    writer = CborWriter()
    pool_owners1.to_cbor(writer)
    cbor_hex = writer.to_hex()

    reader = CborReader.from_hex(cbor_hex)
    pool_owners2 = PoolOwners.from_cbor(reader)

    assert len(pool_owners2) == 5


def test_to_cip116_json():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex("1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361")
    pool_owners.add(hash1)

    writer = JsonWriter()
    pool_owners.to_cip116_json(writer)
    json_str = writer.encode()

    assert "1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361" in json_str


def test_to_cip116_json_empty():
    pool_owners = PoolOwners.new()
    writer = JsonWriter()
    pool_owners.to_cip116_json(writer)
    json_str = writer.encode()
    assert json_str == "[]"


def test_to_cip116_json_with_none_writer():
    pool_owners = PoolOwners.new()
    with pytest.raises((CardanoError, TypeError)):
        pool_owners.to_cip116_json(None)


def test_to_cip116_json_with_invalid_writer_type():
    pool_owners = PoolOwners.new()
    with pytest.raises(TypeError):
        pool_owners.to_cip116_json("not a writer")


def test_repr():
    pool_owners = PoolOwners.new()
    hash1 = Blake2bHash.from_hex(POOL_HASH1)
    pool_owners.add(hash1)
    repr_str = repr(pool_owners)
    assert "PoolOwners" in repr_str


def test_repr_empty():
    pool_owners = PoolOwners.new()
    repr_str = repr(pool_owners)
    assert "PoolOwners" in repr_str


def test_context_manager():
    with PoolOwners.new() as pool_owners:
        assert pool_owners is not None
        hash1 = Blake2bHash.from_hex(POOL_HASH1)
        pool_owners.add(hash1)
        assert len(pool_owners) == 1


def test_init_with_null_pointer():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        PoolOwners(ffi.NULL)
