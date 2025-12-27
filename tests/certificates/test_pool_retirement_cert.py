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
    PoolRetirementCert,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR = "8304581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef921903e8"
HASH = "d85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92"


def new_default_cert():
    reader = CborReader.from_hex(CBOR)
    return PoolRetirementCert.from_cbor(reader)


def test_new():
    pool_key_hash = Blake2bHash.from_hex(HASH)
    cert = PoolRetirementCert.new(pool_key_hash, 1000)
    assert cert is not None


def test_new_with_valid_hash_and_epoch():
    pool_key_hash = Blake2bHash.from_hex(HASH)
    epoch = 250
    cert = PoolRetirementCert.new(pool_key_hash, epoch)
    assert cert is not None
    assert cert.epoch == epoch


def test_new_with_zero_epoch():
    pool_key_hash = Blake2bHash.from_hex(HASH)
    cert = PoolRetirementCert.new(pool_key_hash, 0)
    assert cert is not None
    assert cert.epoch == 0


def test_new_with_large_epoch():
    pool_key_hash = Blake2bHash.from_hex(HASH)
    large_epoch = 999999999
    cert = PoolRetirementCert.new(pool_key_hash, large_epoch)
    assert cert is not None
    assert cert.epoch == large_epoch


def test_new_with_none_hash():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        PoolRetirementCert.new(None, 1000)


def test_from_cbor():
    reader = CborReader.from_hex(CBOR)
    cert = PoolRetirementCert.from_cbor(reader)
    assert cert is not None


def test_from_cbor_with_none_reader():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        PoolRetirementCert.from_cbor(None)


def test_from_cbor_with_invalid_cbor_not_array():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        PoolRetirementCert.from_cbor(reader)


def test_from_cbor_with_invalid_uint_as_type():
    reader = CborReader.from_hex("83ef")
    with pytest.raises(CardanoError):
        PoolRetirementCert.from_cbor(reader)


def test_from_cbor_with_invalid_hash():
    reader = CborReader.from_hex("8304ef1cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef921903e8")
    with pytest.raises(CardanoError):
        PoolRetirementCert.from_cbor(reader)


def test_from_cbor_with_invalid_epoch():
    reader = CborReader.from_hex("8304581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef92efefe8")
    with pytest.raises(CardanoError):
        PoolRetirementCert.from_cbor(reader)


def test_to_cbor():
    cert = new_default_cert()
    writer = CborWriter()
    cert.to_cbor(writer)
    result = writer.to_hex()
    assert result == CBOR


def test_to_cbor_with_none_writer():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.to_cbor(None)


def test_to_cbor_with_none_cert():
    writer = CborWriter()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert = None
        cert.to_cbor(writer)


def test_cbor_round_trip():
    cert1 = new_default_cert()
    writer = CborWriter()
    cert1.to_cbor(writer)
    cbor_hex = writer.to_hex()

    reader = CborReader.from_hex(cbor_hex)
    cert2 = PoolRetirementCert.from_cbor(reader)

    assert cert2 is not None
    assert cert2.epoch == cert1.epoch


def test_get_pool_key_hash():
    cert = new_default_cert()
    pool_key_hash = cert.pool_key_hash
    assert pool_key_hash is not None
    assert isinstance(pool_key_hash, Blake2bHash)


def test_get_pool_key_hash_returns_valid_hash():
    cert = new_default_cert()
    pool_key_hash = cert.pool_key_hash
    assert pool_key_hash is not None
    hash_hex = pool_key_hash.to_hex()
    assert hash_hex == HASH


def test_set_pool_key_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex(HASH)
    cert.pool_key_hash = new_hash
    retrieved_hash = cert.pool_key_hash
    assert retrieved_hash is not None


def test_set_pool_key_hash_with_valid_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex("56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20")
    cert.pool_key_hash = new_hash
    retrieved_hash = cert.pool_key_hash
    assert retrieved_hash.to_hex() == "56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20"


def test_set_pool_key_hash_with_none():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.pool_key_hash = None


def test_get_epoch():
    cert = new_default_cert()
    epoch = cert.epoch
    assert epoch == 1000


def test_get_epoch_returns_correct_value():
    pool_key_hash = Blake2bHash.from_hex(HASH)
    expected_epoch = 12345
    cert = PoolRetirementCert.new(pool_key_hash, expected_epoch)
    assert cert.epoch == expected_epoch


def test_set_epoch():
    cert = new_default_cert()
    new_epoch = 5000
    cert.epoch = new_epoch
    assert cert.epoch == new_epoch


def test_set_epoch_with_zero():
    cert = new_default_cert()
    cert.epoch = 0
    assert cert.epoch == 0


def test_set_epoch_with_large_value():
    cert = new_default_cert()
    large_epoch = 999999999
    cert.epoch = large_epoch
    assert cert.epoch == large_epoch


def test_to_cip116_json():
    pool_key_hash = Blake2bHash.from_hex("56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20")
    epoch = 12345
    cert = PoolRetirementCert.new(pool_key_hash, epoch)

    writer = JsonWriter()
    cert.to_cip116_json(writer)
    json_str = writer.encode()

    assert "pool_retirement" in json_str
    assert "pool_keyhash" in json_str
    assert "pool12c6egd4sj3e9ey7y2skx35gx2l3cc4l9t46t07r5t48jqmd4qf0" in json_str
    assert "12345" in json_str


def test_to_cip116_json_with_none_writer():
    cert = new_default_cert()
    with pytest.raises(TypeError):
        cert.to_cip116_json(None)


def test_to_cip116_json_with_invalid_writer_type():
    cert = new_default_cert()
    with pytest.raises(TypeError):
        cert.to_cip116_json("not a writer")


def test_repr():
    cert = new_default_cert()
    repr_str = repr(cert)
    assert "PoolRetirementCert" in repr_str
    assert "epoch=" in repr_str
    assert "1000" in repr_str


def test_context_manager():
    with new_default_cert() as cert:
        assert cert is not None
        epoch = cert.epoch
        assert epoch == 1000


def test_init_with_null_pointer():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        PoolRetirementCert(ffi.NULL)


def test_del_cleanup():
    cert = new_default_cert()
    del cert


def test_multiple_refs_to_pool_key_hash():
    cert = new_default_cert()
    hash1 = cert.pool_key_hash
    hash2 = cert.pool_key_hash
    assert hash1 is not None
    assert hash2 is not None
    assert hash1.to_hex() == hash2.to_hex()


def test_pool_key_hash_property_setter_getter_consistency():
    cert = new_default_cert()
    original_hash = cert.pool_key_hash
    cert.pool_key_hash = original_hash
    retrieved_hash = cert.pool_key_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == original_hash.to_hex()


def test_epoch_property_setter_getter_consistency():
    cert = new_default_cert()
    original_epoch = cert.epoch
    cert.epoch = original_epoch
    retrieved_epoch = cert.epoch
    assert retrieved_epoch == original_epoch


def test_cbor_deserialization_matches_expected_values():
    cert = new_default_cert()
    assert cert.epoch == 1000
    assert cert.pool_key_hash.to_hex() == HASH
