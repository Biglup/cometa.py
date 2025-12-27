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
    GenesisKeyDelegationCert,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR = "8405581c00010001000100010001000100010001000100010001000100010001581c0002000200020002000200020002000200020002000200020002000258200003000300030003000300030003000300030003000300030003000300030003"
GENESIS_HASH = "00010001000100010001000100010001000100010001000100010001"
GENESIS_DELEGATE_HASH = "00020002000200020002000200020002000200020002000200020002"
VRF_KEY_HASH = "0003000300030003000300030003000300030003000300030003000300030003"


def new_default_cert():
    reader = CborReader.from_hex(CBOR)
    return GenesisKeyDelegationCert.from_cbor(reader)


def test_new():
    genesis_hash = Blake2bHash.from_hex(GENESIS_HASH)
    genesis_delegate_hash = Blake2bHash.from_hex(GENESIS_DELEGATE_HASH)
    vrf_key_hash = Blake2bHash.from_hex(VRF_KEY_HASH)
    cert = GenesisKeyDelegationCert.new(genesis_hash, genesis_delegate_hash, vrf_key_hash)
    assert cert is not None


def test_new_with_valid_hashes():
    genesis_hash = Blake2bHash.from_hex(GENESIS_HASH)
    genesis_delegate_hash = Blake2bHash.from_hex(GENESIS_DELEGATE_HASH)
    vrf_key_hash = Blake2bHash.from_hex(VRF_KEY_HASH)
    cert = GenesisKeyDelegationCert.new(genesis_hash, genesis_delegate_hash, vrf_key_hash)
    assert cert is not None
    assert cert.genesis_hash.to_hex() == GENESIS_HASH
    assert cert.genesis_delegate_hash.to_hex() == GENESIS_DELEGATE_HASH
    assert cert.vrf_key_hash.to_hex() == VRF_KEY_HASH


def test_new_with_none_genesis_hash():
    genesis_delegate_hash = Blake2bHash.from_hex(GENESIS_DELEGATE_HASH)
    vrf_key_hash = Blake2bHash.from_hex(VRF_KEY_HASH)
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        GenesisKeyDelegationCert.new(None, genesis_delegate_hash, vrf_key_hash)


def test_new_with_none_genesis_delegate_hash():
    genesis_hash = Blake2bHash.from_hex(GENESIS_HASH)
    vrf_key_hash = Blake2bHash.from_hex(VRF_KEY_HASH)
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        GenesisKeyDelegationCert.new(genesis_hash, None, vrf_key_hash)


def test_new_with_none_vrf_key_hash():
    genesis_hash = Blake2bHash.from_hex(GENESIS_HASH)
    genesis_delegate_hash = Blake2bHash.from_hex(GENESIS_DELEGATE_HASH)
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        GenesisKeyDelegationCert.new(genesis_hash, genesis_delegate_hash, None)


def test_new_with_all_none():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        GenesisKeyDelegationCert.new(None, None, None)


def test_from_cbor():
    reader = CborReader.from_hex(CBOR)
    cert = GenesisKeyDelegationCert.from_cbor(reader)
    assert cert is not None


def test_from_cbor_with_none_reader():
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        GenesisKeyDelegationCert.from_cbor(None)


def test_from_cbor_with_invalid_cbor_not_array():
    reader = CborReader.from_hex("01")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


def test_from_cbor_with_invalid_uint_as_type():
    reader = CborReader.from_hex("83ef")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


def test_from_cbor_with_invalid_cert_type():
    reader = CborReader.from_hex("8400")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


def test_from_cbor_with_invalid_first_hash():
    reader = CborReader.from_hex("8405ef1c00010001000100010001000100010001000100010001000100010001581c0002000200020002000200020002000200020002000200020002000258200003000300030003000300030003000300030003000300030003000300030003")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


def test_from_cbor_with_invalid_second_hash():
    reader = CborReader.from_hex("8405581c00010001000100010001000100010001000100010001000100010001ef1c0002000200020002000200020002000200020002000200020002000258200003000300030003000300030003000300030003000300030003000300030003")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


def test_from_cbor_with_invalid_third_hash():
    reader = CborReader.from_hex("8405581c00010001000100010001000100010001000100010001000100010001581c00020002000200020002000200020002000200020002000200020002ef200003000300030003000300030003000300030003000300030003000300030003")
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert.from_cbor(reader)


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
    cert2 = GenesisKeyDelegationCert.from_cbor(reader)

    assert cert2 is not None
    assert cert2.genesis_hash.to_hex() == GENESIS_HASH
    assert cert2.genesis_delegate_hash.to_hex() == GENESIS_DELEGATE_HASH
    assert cert2.vrf_key_hash.to_hex() == VRF_KEY_HASH


def test_get_genesis_hash():
    cert = new_default_cert()
    genesis_hash = cert.genesis_hash
    assert genesis_hash is not None
    assert isinstance(genesis_hash, Blake2bHash)
    assert genesis_hash.to_hex() == GENESIS_HASH


def test_get_genesis_hash_returns_valid_hash():
    cert = new_default_cert()
    genesis_hash = cert.genesis_hash
    assert genesis_hash is not None
    assert len(genesis_hash.to_hex()) > 0


def test_set_genesis_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex("00020002000200020002000200020002000200020002000200020002")
    cert.genesis_hash = new_hash
    retrieved_hash = cert.genesis_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == "00020002000200020002000200020002000200020002000200020002"


def test_set_genesis_hash_with_valid_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex(GENESIS_DELEGATE_HASH)
    cert.genesis_hash = new_hash
    assert cert.genesis_hash.to_hex() == GENESIS_DELEGATE_HASH


def test_set_genesis_hash_with_none():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.genesis_hash = None


def test_get_genesis_delegate_hash():
    cert = new_default_cert()
    genesis_delegate_hash = cert.genesis_delegate_hash
    assert genesis_delegate_hash is not None
    assert isinstance(genesis_delegate_hash, Blake2bHash)
    assert genesis_delegate_hash.to_hex() == GENESIS_DELEGATE_HASH


def test_get_genesis_delegate_hash_returns_valid_hash():
    cert = new_default_cert()
    genesis_delegate_hash = cert.genesis_delegate_hash
    assert genesis_delegate_hash is not None
    assert len(genesis_delegate_hash.to_hex()) > 0


def test_set_genesis_delegate_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex("0003000300030003000300030003000300030003000300030003000300030003")
    cert.genesis_delegate_hash = new_hash
    retrieved_hash = cert.genesis_delegate_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == "0003000300030003000300030003000300030003000300030003000300030003"


def test_set_genesis_delegate_hash_with_valid_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex(VRF_KEY_HASH)
    cert.genesis_delegate_hash = new_hash
    assert cert.genesis_delegate_hash.to_hex() == VRF_KEY_HASH


def test_set_genesis_delegate_hash_with_none():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.genesis_delegate_hash = None


def test_get_vrf_key_hash():
    cert = new_default_cert()
    vrf_key_hash = cert.vrf_key_hash
    assert vrf_key_hash is not None
    assert isinstance(vrf_key_hash, Blake2bHash)
    assert vrf_key_hash.to_hex() == VRF_KEY_HASH


def test_get_vrf_key_hash_returns_valid_hash():
    cert = new_default_cert()
    vrf_key_hash = cert.vrf_key_hash
    assert vrf_key_hash is not None
    assert len(vrf_key_hash.to_hex()) > 0


def test_set_vrf_key_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex("00010001000100010001000100010001000100010001000100010001")
    cert.vrf_key_hash = new_hash
    retrieved_hash = cert.vrf_key_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == "00010001000100010001000100010001000100010001000100010001"


def test_set_vrf_key_hash_with_valid_hash():
    cert = new_default_cert()
    new_hash = Blake2bHash.from_hex(GENESIS_HASH)
    cert.vrf_key_hash = new_hash
    assert cert.vrf_key_hash.to_hex() == GENESIS_HASH


def test_set_vrf_key_hash_with_none():
    cert = new_default_cert()
    with pytest.raises((CardanoError, TypeError, AttributeError)):
        cert.vrf_key_hash = None


def test_to_cip116_json():
    cert = new_default_cert()
    writer = JsonWriter()
    cert.to_cip116_json(writer)
    json_str = writer.encode()
    assert "genesis_key_delegation" in json_str
    assert "genesis_hash" in json_str
    assert "genesis_delegate_hash" in json_str
    assert "vrf_keyhash" in json_str
    assert GENESIS_HASH in json_str
    assert GENESIS_DELEGATE_HASH in json_str


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
    assert "GenesisKeyDelegationCert" in repr_str


def test_context_manager():
    with new_default_cert() as cert:
        assert cert is not None
        genesis_hash = cert.genesis_hash
        assert genesis_hash is not None


def test_init_with_null_pointer():
    from cometa._ffi import ffi
    with pytest.raises(CardanoError):
        GenesisKeyDelegationCert(ffi.NULL)


def test_del_cleanup():
    cert = new_default_cert()
    del cert


def test_multiple_refs_to_genesis_hash():
    cert = new_default_cert()
    hash1 = cert.genesis_hash
    hash2 = cert.genesis_hash
    assert hash1 is not None
    assert hash2 is not None
    assert hash1.to_hex() == hash2.to_hex()


def test_multiple_refs_to_genesis_delegate_hash():
    cert = new_default_cert()
    hash1 = cert.genesis_delegate_hash
    hash2 = cert.genesis_delegate_hash
    assert hash1 is not None
    assert hash2 is not None
    assert hash1.to_hex() == hash2.to_hex()


def test_multiple_refs_to_vrf_key_hash():
    cert = new_default_cert()
    hash1 = cert.vrf_key_hash
    hash2 = cert.vrf_key_hash
    assert hash1 is not None
    assert hash2 is not None
    assert hash1.to_hex() == hash2.to_hex()


def test_genesis_hash_property_setter_getter_consistency():
    cert = new_default_cert()
    original_hash = cert.genesis_hash
    cert.genesis_hash = original_hash
    retrieved_hash = cert.genesis_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == original_hash.to_hex()


def test_genesis_delegate_hash_property_setter_getter_consistency():
    cert = new_default_cert()
    original_hash = cert.genesis_delegate_hash
    cert.genesis_delegate_hash = original_hash
    retrieved_hash = cert.genesis_delegate_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == original_hash.to_hex()


def test_vrf_key_hash_property_setter_getter_consistency():
    cert = new_default_cert()
    original_hash = cert.vrf_key_hash
    cert.vrf_key_hash = original_hash
    retrieved_hash = cert.vrf_key_hash
    assert retrieved_hash is not None
    assert retrieved_hash.to_hex() == original_hash.to_hex()


def test_all_properties_independent():
    cert = new_default_cert()
    new_genesis_hash = Blake2bHash.from_hex("0004000400040004000400040004000400040004000400040004000400040004")
    new_delegate_hash = Blake2bHash.from_hex("0005000500050005000500050005000500050005000500050005000500050005")
    new_vrf_hash = Blake2bHash.from_hex("00060006000600060006000600060006000600060006000600060006")

    cert.genesis_hash = new_genesis_hash
    cert.genesis_delegate_hash = new_delegate_hash
    cert.vrf_key_hash = new_vrf_hash

    assert cert.genesis_hash.to_hex() == "0004000400040004000400040004000400040004000400040004000400040004"
    assert cert.genesis_delegate_hash.to_hex() == "0005000500050005000500050005000500050005000500050005000500050005"
    assert cert.vrf_key_hash.to_hex() == "00060006000600060006000600060006000600060006000600060006"
