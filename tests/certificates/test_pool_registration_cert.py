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
    PoolRegistrationCert,
    PoolParams,
    Blake2bHash,
    UnitInterval,
    RewardAddress,
    PoolOwners,
    Relays,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR = "8a03581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef9258208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db01927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810fd9010281581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f000001f682026b6578616d706c652e636f6d827368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5"
POOL_PARAMS_CBOR = "581cd85087c646951407198c27b1b950fd2e99f28586c000ce39f6e6ef9258208dd154228946bd12967c12bedb1cb6038b78f8b84a1760b1a788fa72a4af3db01927101903e8d81e820105581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810fd9010281581ccb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8383011913886b6578616d706c652e636f6d8400191770447f000001f682026b6578616d706c652e636f6d827368747470733a2f2f6578616d706c652e636f6d58200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5"


def new_default_cert():
    reader = CborReader.from_hex(CBOR)
    return PoolRegistrationCert.from_cbor(reader)


def new_default_params():
    reader = CborReader.from_hex(POOL_PARAMS_CBOR)
    return PoolParams.from_cbor(reader)


def test_new():
    params = new_default_params()
    cert = PoolRegistrationCert.new(params)
    assert cert is not None


def test_new_with_valid_params():
    operator_hash = Blake2bHash.from_hex("56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20")
    vrf_hash = Blake2bHash.from_hex("ec3d672178061731255b26040701764e56424f705c8d5c049166867e0e4647c6")
    margin = UnitInterval.new(1, 10)
    reward_addr = RewardAddress.from_bech32("stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y")
    owners = PoolOwners.new()
    relays = Relays.new()

    params = PoolParams.new(
        operator_hash,
        vrf_hash,
        100,
        340000000,
        margin,
        reward_addr,
        owners,
        relays,
        None,
    )

    cert = PoolRegistrationCert.new(params)
    assert cert is not None


def test_new_with_none_params():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        PoolRegistrationCert.new(None)


def test_from_cbor():
    reader = CborReader.from_hex(CBOR)
    cert = PoolRegistrationCert.from_cbor(reader)
    assert cert is not None


def test_from_cbor_with_none_reader():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        PoolRegistrationCert.from_cbor(None)


def test_from_cbor_with_invalid_cbor_not_array():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        PoolRegistrationCert.from_cbor(reader)


def test_from_cbor_with_invalid_uint_as_type():
    reader = CborReader.from_hex("8aef")
    with pytest.raises(CardanoError):
        PoolRegistrationCert.from_cbor(reader)


def test_from_cbor_with_invalid_cert_type():
    reader = CborReader.from_hex("8a00")
    with pytest.raises(CardanoError):
        PoolRegistrationCert.from_cbor(reader)


def test_from_cbor_with_invalid_pool_params():
    reader = CborReader.from_hex("8a03ef")
    with pytest.raises(CardanoError):
        PoolRegistrationCert.from_cbor(reader)


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
    cert2 = PoolRegistrationCert.from_cbor(reader)

    assert cert2 is not None


def test_get_params():
    cert = new_default_cert()
    params = cert.params
    assert params is not None
    assert isinstance(params, PoolParams)


def test_get_params_returns_valid_object():
    cert = new_default_cert()
    params = cert.params
    assert params is not None


def test_set_params():
    cert = new_default_cert()
    new_params = new_default_params()
    cert.params = new_params
    retrieved_params = cert.params
    assert retrieved_params is not None


def test_set_params_with_valid_params():
    cert = new_default_cert()
    operator_hash = Blake2bHash.from_hex("56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20")
    vrf_hash = Blake2bHash.from_hex("ec3d672178061731255b26040701764e56424f705c8d5c049166867e0e4647c6")
    margin = UnitInterval.new(1, 10)
    reward_addr = RewardAddress.from_bech32("stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y")
    owners = PoolOwners.new()
    relays = Relays.new()

    params = PoolParams.new(
        operator_hash,
        vrf_hash,
        100,
        340000000,
        margin,
        reward_addr,
        owners,
        relays,
        None,
    )

    cert.params = params
    assert cert.params is not None


def test_set_params_with_none():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.params = None


def test_to_cip116_json():
    operator_hash = Blake2bHash.from_hex("56359436b094725c93c4542c68d10657e38c57e55d74b7f8745d4f20")
    vrf_hash = Blake2bHash.from_hex("ec3d672178061731255b26040701764e56424f705c8d5c049166867e0e4647c6")
    margin = UnitInterval.new(1, 10)
    reward_addr = RewardAddress.from_bech32("stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y")
    owners = PoolOwners.new()
    relays = Relays.new()

    params = PoolParams.new(
        operator_hash,
        vrf_hash,
        100,
        340000000,
        margin,
        reward_addr,
        owners,
        relays,
        None,
    )

    cert = PoolRegistrationCert.new(params)
    writer = JsonWriter()
    cert.to_cip116_json(writer)
    json_str = writer.encode()

    assert "pool_registration" in json_str
    assert "pool_params" in json_str
    assert "pool12c6egd4sj3e9ey7y2skx35gx2l3cc4l9t46t07r5t48jqmd4qf0" in json_str
    assert "stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y" in json_str


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
    assert "PoolRegistrationCert" in repr_str


def test_context_manager():
    with new_default_cert() as cert:
        assert cert is not None
        params = cert.params
        assert params is not None


def test_init_with_null_pointer():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        PoolRegistrationCert(ffi.NULL)


def test_del_cleanup():
    cert = new_default_cert()
    del cert


def test_multiple_refs_to_params():
    cert = new_default_cert()
    params1 = cert.params
    params2 = cert.params
    assert params1 is not None
    assert params2 is not None


def test_params_property_setter_getter_consistency():
    cert = new_default_cert()
    original_params = cert.params
    cert.params = original_params
    retrieved_params = cert.params
    assert retrieved_params is not None
