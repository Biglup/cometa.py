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
from cometa.cryptography import Blake2bHash
from cometa.cbor import CborReader, CborWriter
from cometa.errors import CardanoError


class TestBlake2bHashCompute:
    """Tests for Blake2bHash.compute()"""

    def test_compute_blake2b_224_hash_vector_1(self):
        """Test BLAKE2b-224 hash computation with test vector 1"""
        data = bytes.fromhex("00")
        hash_obj = Blake2bHash.compute(data, hash_size=28)
        expected = "0d94e174732ef9aae73f395ab44507bfa983d65023c11a951f0c32e4"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_224_hash_vector_2(self):
        """Test BLAKE2b-224 hash computation with test vector 2"""
        data = bytes.fromhex("0001")
        hash_obj = Blake2bHash.compute(data, hash_size=28)
        expected = "9430be1d5e37ea654ddb63370a3d04a8a0a171abb5c3710a9bc372f8"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_224_hash_vector_3(self):
        """Test BLAKE2b-224 hash computation with test vector 3"""
        data = bytes.fromhex("000102")
        hash_obj = Blake2bHash.compute(data, hash_size=28)
        expected = "495734948024c1ac1cc6dce8d3ab2aad5b8c4194203aaaa460af9437"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_224_hash_vector_4(self):
        """Test BLAKE2b-224 hash computation with test vector 4"""
        data = bytes.fromhex("000102030405060708090a0b0c")
        hash_obj = Blake2bHash.compute(data, hash_size=28)
        expected = "7b71eb4635c7fe17ef96c86ddd6230faa408657e79fb7451a47981ca"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_256_hash_vector_1(self):
        """Test BLAKE2b-256 hash computation with test vector 1"""
        data = bytes.fromhex("00")
        hash_obj = Blake2bHash.compute(data, hash_size=32)
        expected = "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_256_hash_vector_2(self):
        """Test BLAKE2b-256 hash computation with test vector 2"""
        data = bytes.fromhex("0001")
        hash_obj = Blake2bHash.compute(data, hash_size=32)
        expected = "01cf79da4945c370c68b265ef70641aaa65eaa8f5953e3900d97724c2c5aa095"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_256_hash_vector_3(self):
        """Test BLAKE2b-256 hash computation with test vector 3"""
        data = bytes.fromhex("000102")
        hash_obj = Blake2bHash.compute(data, hash_size=32)
        expected = "3d8c3d594928271f44aad7a04b177154806867bcf918e1549c0bc16f9da2b09b"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_256_hash_vector_4(self):
        """Test BLAKE2b-256 hash computation with test vector 4"""
        data = bytes.fromhex("000102030405060708090a0b0c")
        hash_obj = Blake2bHash.compute(data, hash_size=32)
        expected = "695e93b723e0a08e8dd8dd4656389363519564daf4cde5fe95a6a0ca71d3705e"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_512_hash_vector_1(self):
        """Test BLAKE2b-512 hash computation with test vector 1"""
        data = bytes.fromhex("00")
        hash_obj = Blake2bHash.compute(data, hash_size=64)
        expected = "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_512_hash_vector_2(self):
        """Test BLAKE2b-512 hash computation with test vector 2"""
        data = bytes.fromhex("0001")
        hash_obj = Blake2bHash.compute(data, hash_size=64)
        expected = "1c08798dc641aba9dee435e22519a4729a09b2bfe0ff00ef2dcd8ed6f8a07d15eaf4aee52bbf18ab5608a6190f70b90486c8a7d4873710b1115d3debbb4327b5"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_512_hash_vector_3(self):
        """Test BLAKE2b-512 hash computation with test vector 3"""
        data = bytes.fromhex("000102")
        hash_obj = Blake2bHash.compute(data, hash_size=64)
        expected = "40a374727302d9a4769c17b5f409ff32f58aa24ff122d7603e4fda1509e919d4107a52c57570a6d94e50967aea573b11f86f473f537565c66f7039830a85d186"
        assert hash_obj.to_hex() == expected

    def test_compute_blake2b_512_hash_vector_4(self):
        """Test BLAKE2b-512 hash computation with test vector 4"""
        data = bytes.fromhex("000102030405060708090a0b0c")
        hash_obj = Blake2bHash.compute(data, hash_size=64)
        expected = "dea9101cac62b8f6a3c650f90eea5bfae2653a4eafd63a6d1f0f132db9e4f2b1b662432ec85b17bcac41e775637881f6aab38dd66dcbd080f0990a7a6e9854fe"
        assert hash_obj.to_hex() == expected

    def test_compute_with_bytearray(self):
        """Test compute with bytearray input"""
        data = bytearray(b"hello world")
        hash_obj = Blake2bHash.compute(data, hash_size=32)
        assert len(hash_obj) == 32

    def test_compute_returns_correct_size(self):
        """Test that compute returns hash with correct size"""
        hash_obj = Blake2bHash.compute(b"test", hash_size=28)
        assert len(hash_obj) == 28
        hash_obj = Blake2bHash.compute(b"test", hash_size=32)
        assert len(hash_obj) == 32
        hash_obj = Blake2bHash.compute(b"test", hash_size=64)
        assert len(hash_obj) == 64

    def test_compute_with_invalid_hash_size(self):
        """Test compute with invalid hash size"""
        with pytest.raises(CardanoError):
            Blake2bHash.compute(b"test", hash_size=0)

    def test_compute_with_empty_data_raises_error(self):
        """Test compute with empty data raises error"""
        with pytest.raises(CardanoError):
            Blake2bHash.compute(b"", hash_size=32)


class TestBlake2bHashFromBytes:
    """Tests for Blake2bHash.from_bytes()"""

    def test_from_bytes_creates_hash(self):
        """Test creating hash from raw bytes"""
        data = bytes(32)
        hash_obj = Blake2bHash.from_bytes(data)
        assert len(hash_obj) == 32
        assert hash_obj.to_bytes() == data

    def test_from_bytes_with_different_sizes(self):
        """Test from_bytes with various hash sizes"""
        for size in [28, 32, 64]:
            data = bytes(size)
            hash_obj = Blake2bHash.from_bytes(data)
            assert len(hash_obj) == size

    def test_from_bytes_with_bytearray(self):
        """Test from_bytes with bytearray"""
        data = bytearray(b"data")
        hash_obj = Blake2bHash.from_bytes(data)
        assert hash_obj.to_bytes() == bytes(data)

    def test_from_bytes_with_custom_data(self):
        """Test from_bytes preserves data correctly"""
        data = b"data"
        hash_obj = Blake2bHash.from_bytes(data)
        assert hash_obj.to_bytes() == data

    def test_from_bytes_with_empty_data_raises_error(self):
        """Test from_bytes with empty data raises error"""
        with pytest.raises(CardanoError):
            Blake2bHash.from_bytes(b"")


class TestBlake2bHashFromHex:
    """Tests for Blake2bHash.from_hex()"""

    def test_from_hex_creates_hash(self):
        """Test creating hash from hex string"""
        hex_str = "00" * 32
        hash_obj = Blake2bHash.from_hex(hex_str)
        assert len(hash_obj) == 32
        assert hash_obj.to_hex() == hex_str

    def test_from_hex_with_64_byte_hash(self):
        """Test from_hex with 64-byte hash"""
        hex_str = "2fa3f686df876995167e7c2e5d74c4c7b6e48f8068fe0e44208344d480f7904c36963e44115fe3eb2a3ac8694c28bcb4f5a0f3276f2e79487d8219057a506e4b"
        hash_obj = Blake2bHash.from_hex(hex_str)
        assert len(hash_obj) == 64
        assert hash_obj.to_hex() == hex_str

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test from_hex with odd-length hex string raises error"""
        hex_str = "abc"
        with pytest.raises(CardanoError):
            Blake2bHash.from_hex(hex_str)

    def test_from_hex_with_empty_string_raises_error(self):
        """Test from_hex with empty string raises error"""
        with pytest.raises(CardanoError):
            Blake2bHash.from_hex("")


class TestBlake2bHashFromCbor:
    """Tests for Blake2bHash.from_cbor()"""

    def test_from_cbor_decodes_hash(self):
        """Test decoding hash from CBOR"""
        cbor_hex = "581c00000000000000000000000000000000000000000000000000000000"
        reader = CborReader.from_hex(cbor_hex)
        hash_obj = Blake2bHash.from_cbor(reader)
        assert len(hash_obj) == 28
        assert hash_obj.to_hex() == "00" * 28

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test from_cbor with invalid CBOR raises error"""
        reader = CborReader.from_hex("00")
        with pytest.raises(CardanoError):
            Blake2bHash.from_cbor(reader)


class TestBlake2bHashToBytes:
    """Tests for Blake2bHash.to_bytes()"""

    def test_to_bytes_returns_correct_data(self):
        """Test to_bytes returns correct raw bytes"""
        data = b"test"
        hash_obj = Blake2bHash.from_bytes(data)
        assert hash_obj.to_bytes() == data

    def test_to_bytes_with_computed_hash(self):
        """Test to_bytes with computed hash"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        result = hash_obj.to_bytes()
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_bytes_magic_method(self):
        """Test __bytes__ magic method"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        result = bytes(hash_obj)
        assert result == hash_obj.to_bytes()


class TestBlake2bHashToHex:
    """Tests for Blake2bHash.to_hex()"""

    def test_to_hex_returns_lowercase(self):
        """Test to_hex returns lowercase hex string"""
        data = bytes(32)
        hash_obj = Blake2bHash.from_bytes(data)
        hex_str = hash_obj.to_hex()
        assert hex_str == hex_str.lower()

    def test_to_hex_correct_length(self):
        """Test to_hex returns correct length"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        hex_str = hash_obj.to_hex()
        assert len(hex_str) == 64

    def test_str_magic_method(self):
        """Test __str__ magic method"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        assert str(hash_obj) == hash_obj.to_hex()


class TestBlake2bHashToCbor:
    """Tests for Blake2bHash.to_cbor()"""

    def test_to_cbor_encodes_hash(self):
        """Test encoding hash to CBOR"""
        hex_str = "00" * 28
        hash_obj = Blake2bHash.from_hex(hex_str)
        writer = CborWriter()
        hash_obj.to_cbor(writer)
        cbor_hex = writer.to_hex()
        expected = "581c00000000000000000000000000000000000000000000000000000000"
        assert cbor_hex == expected

    def test_to_cbor_round_trip(self):
        """Test CBOR round-trip encoding and decoding"""
        original = Blake2bHash.compute(b"test data", hash_size=32)
        writer = CborWriter()
        original.to_cbor(writer)
        reader = CborReader.from_hex(writer.to_hex())
        decoded = Blake2bHash.from_cbor(reader)
        assert original == decoded


class TestBlake2bHashSize:
    """Tests for Blake2bHash.size property"""

    def test_size_property_returns_correct_value(self):
        """Test size property returns correct byte size"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=28)
        assert hash_obj.size == 28
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        assert hash_obj.size == 32
        hash_obj = Blake2bHash.compute(b"data", hash_size=64)
        assert hash_obj.size == 64

    def test_len_magic_method(self):
        """Test __len__ magic method"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        assert len(hash_obj) == 32


class TestBlake2bHashCompare:
    """Tests for Blake2bHash.compare()"""

    def test_compare_equal_hashes_returns_zero(self):
        """Test compare returns 0 for equal hashes"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        assert hash1.compare(hash2) == 0

    def test_compare_different_hashes(self):
        """Test compare returns non-zero for different hashes"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data2", hash_size=32)
        result = hash1.compare(hash2)
        assert result != 0


class TestBlake2bHashEquality:
    """Tests for Blake2bHash equality operations"""

    def test_equality_with_same_hash(self):
        """Test equality with same hash values"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        assert hash1 == hash2

    def test_inequality_with_different_hash(self):
        """Test inequality with different hash values"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data2", hash_size=32)
        assert hash1 != hash2

    def test_equality_with_non_blake2b_hash_returns_false(self):
        """Test equality with non-Blake2bHash returns False"""
        hash_obj = Blake2bHash.compute(b"data", hash_size=32)
        assert not (hash_obj == "not a hash")
        assert not (hash_obj == 123)
        assert not (hash_obj == None)


class TestBlake2bHashComparison:
    """Tests for Blake2bHash comparison operations"""

    def test_less_than_comparison(self):
        """Test less than comparison"""
        hash1 = Blake2bHash.compute(b"data2", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        if hash1.compare(hash2) < 0:
            assert hash1 < hash2
            assert not (hash1 >= hash2)
        else:
            assert hash2 < hash1
            assert not (hash2 >= hash1)

    def test_less_than_or_equal_comparison(self):
        """Test less than or equal comparison"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        assert hash1 <= hash2
        assert hash2 <= hash1

    def test_greater_than_comparison(self):
        """Test greater than comparison"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data2", hash_size=32)
        if hash1.compare(hash2) > 0:
            assert hash1 > hash2
            assert not (hash1 <= hash2)
        else:
            assert hash2 > hash1
            assert not (hash2 <= hash1)

    def test_greater_than_or_equal_comparison(self):
        """Test greater than or equal comparison"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        assert hash1 >= hash2
        assert hash2 >= hash1


class TestBlake2bHashHash:
    """Tests for Blake2bHash.__hash__()"""

    def test_hash_method_allows_use_in_set(self):
        """Test __hash__ allows hash to be used in set"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data", hash_size=32)
        hash3 = Blake2bHash.compute(b"data2", hash_size=32)
        hash_set = {hash1, hash2, hash3}
        assert len(hash_set) == 2

    def test_hash_method_allows_use_in_dict(self):
        """Test __hash__ allows hash to be used as dict key"""
        hash1 = Blake2bHash.compute(b"data", hash_size=32)
        hash2 = Blake2bHash.compute(b"data2", hash_size=32)
        hash_dict = {hash1: "value1", hash2: "value2"}
        assert len(hash_dict) == 2
        assert hash_dict[hash1] == "value1"


class TestBlake2bHashRepr:
    """Tests for Blake2bHash.__repr__()"""

    def test_repr_includes_hex(self):
        """Test __repr__ includes hex representation"""
        hash_obj = Blake2bHash.from_hex("00" * 32)
        repr_str = repr(hash_obj)
        assert "Blake2bHash" in repr_str
        assert "00" * 32 in repr_str


class TestBlake2bHashContextManager:
    """Tests for Blake2bHash context manager protocol"""

    def test_context_manager_usage(self):
        """Test hash can be used as context manager"""
        with Blake2bHash.compute(b"data", hash_size=32) as hash_obj:
            assert len(hash_obj) == 32
            hex_str = hash_obj.to_hex()
        assert len(hex_str) == 64


class TestBlake2bHashEdgeCases:
    """Tests for Blake2bHash edge cases"""

    def test_hash_with_large_input(self):
        """Test hash computation with large input"""
        large_data = b"x" * 10000
        hash_obj = Blake2bHash.compute(large_data, hash_size=32)
        assert len(hash_obj) == 32

    def test_hash_with_single_byte(self):
        """Test hash computation with single byte input"""
        hash_obj = Blake2bHash.compute(b"\x00", hash_size=32)
        assert len(hash_obj) == 32

    def test_consecutive_hashes_are_independent(self):
        """Test that consecutive hash computations are independent"""
        hash1 = Blake2bHash.compute(b"data1", hash_size=32)
        hash2 = Blake2bHash.compute(b"data2", hash_size=32)
        assert hash1 != hash2

    def test_from_bytes_preserves_all_byte_values(self):
        """Test from_bytes preserves all byte values including zeros"""
        data = bytes(range(32))
        hash_obj = Blake2bHash.from_bytes(data)
        assert hash_obj.to_bytes() == data
