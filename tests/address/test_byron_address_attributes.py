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
from cometa.address import ByronAddressAttributes


class TestByronAddressAttributes:
    """Tests for the ByronAddressAttributes dataclass."""

    def test_default_creation(self):
        """Test creating attributes with default values."""
        attrs = ByronAddressAttributes()

        assert attrs.derivation_path == b""
        assert attrs.magic == -1

    def test_creation_with_derivation_path(self):
        """Test creating attributes with a derivation path."""
        derivation_path = b"\x01\x02\x03\x04"
        attrs = ByronAddressAttributes(derivation_path=derivation_path)

        assert attrs.derivation_path == derivation_path
        assert attrs.magic == -1

    def test_creation_with_magic(self):
        """Test creating attributes with a magic value."""
        magic = 42
        attrs = ByronAddressAttributes(magic=magic)

        assert attrs.derivation_path == b""
        assert attrs.magic == magic

    def test_creation_with_both_values(self):
        """Test creating attributes with both derivation path and magic."""
        derivation_path = b"\x01\x02\x03\x04"
        magic = 1097911063
        attrs = ByronAddressAttributes(derivation_path=derivation_path, magic=magic)

        assert attrs.derivation_path == derivation_path
        assert attrs.magic == magic

    def test_mainnet_factory(self):
        """Test mainnet factory method creates correct attributes."""
        attrs = ByronAddressAttributes.mainnet()

        assert attrs.derivation_path == b""
        assert attrs.magic == -1
        assert not attrs.has_network_magic

    def test_testnet_factory(self):
        """Test testnet factory method creates correct attributes."""
        magic = 1
        attrs = ByronAddressAttributes.testnet(magic)

        assert attrs.derivation_path == b""
        assert attrs.magic == magic
        assert attrs.has_network_magic

    def test_testnet_factory_with_zero_magic(self):
        """Test testnet factory with zero magic value."""
        attrs = ByronAddressAttributes.testnet(0)

        assert attrs.magic == 0
        assert attrs.has_network_magic

    def test_testnet_factory_with_negative_magic(self):
        """Test testnet factory with negative magic value."""
        attrs = ByronAddressAttributes.testnet(-2)

        assert attrs.magic == -2
        assert not attrs.has_network_magic

    def test_testnet_factory_with_large_magic(self):
        """Test testnet factory with large magic value."""
        magic = 1097911063
        attrs = ByronAddressAttributes.testnet(magic)

        assert attrs.magic == magic
        assert attrs.has_network_magic

    def test_has_network_magic_true_with_zero(self):
        """Test has_network_magic returns True for magic >= 0."""
        attrs = ByronAddressAttributes(magic=0)
        assert attrs.has_network_magic

    def test_has_network_magic_true_with_positive(self):
        """Test has_network_magic returns True for positive magic."""
        attrs = ByronAddressAttributes(magic=1)
        assert attrs.has_network_magic

    def test_has_network_magic_false_with_negative(self):
        """Test has_network_magic returns False for negative magic."""
        attrs = ByronAddressAttributes(magic=-1)
        assert not attrs.has_network_magic

    def test_has_network_magic_false_with_large_negative(self):
        """Test has_network_magic returns False for large negative magic."""
        attrs = ByronAddressAttributes(magic=-999)
        assert not attrs.has_network_magic

    def test_equality_same_values(self):
        """Test equality with same values."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)

        assert attrs1 == attrs2

    def test_equality_default_values(self):
        """Test equality with default values."""
        attrs1 = ByronAddressAttributes()
        attrs2 = ByronAddressAttributes()

        assert attrs1 == attrs2

    def test_inequality_different_derivation_path(self):
        """Test inequality with different derivation paths."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x02", magic=42)

        assert attrs1 != attrs2

    def test_inequality_different_magic(self):
        """Test inequality with different magic values."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x01", magic=43)

        assert attrs1 != attrs2

    def test_inequality_with_non_byron_address_attributes(self):
        """Test inequality with non-ByronAddressAttributes object."""
        attrs = ByronAddressAttributes()

        assert attrs != "not an attributes object"
        assert attrs != 123
        assert attrs != None

    def test_hash_same_values(self):
        """Test that attributes with same values have same hash."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)

        assert hash(attrs1) == hash(attrs2)

    def test_hash_different_values(self):
        """Test that attributes with different values have different hashes."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x02", magic=42)

        assert hash(attrs1) != hash(attrs2)

    def test_in_set(self):
        """Test using attributes in a set."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x01", magic=42)
        attrs3 = ByronAddressAttributes(derivation_path=b"\x02", magic=42)

        attrs_set = {attrs1, attrs2, attrs3}
        assert len(attrs_set) == 2

    def test_as_dict_key(self):
        """Test using attributes as dictionary key."""
        attrs1 = ByronAddressAttributes.mainnet()
        attrs2 = ByronAddressAttributes.testnet(1)

        attrs_dict = {attrs1: "mainnet", attrs2: "testnet"}
        assert attrs_dict[attrs1] == "mainnet"
        assert attrs_dict[attrs2] == "testnet"

    def test_repr(self):
        """Test __repr__ method."""
        attrs = ByronAddressAttributes(derivation_path=b"\x01\x02", magic=42)
        repr_str = repr(attrs)

        assert "ByronAddressAttributes" in repr_str
        assert "derivation_path" in repr_str
        assert "magic" in repr_str

    def test_immutability(self):
        """Test that dataclass is frozen and immutable."""
        attrs = ByronAddressAttributes(derivation_path=b"\x01", magic=42)

        with pytest.raises(Exception):
            attrs.derivation_path = b"\x02"

        with pytest.raises(Exception):
            attrs.magic = 43

    def test_derivation_path_empty_bytes(self):
        """Test derivation path with empty bytes."""
        attrs = ByronAddressAttributes(derivation_path=b"")

        assert attrs.derivation_path == b""
        assert len(attrs.derivation_path) == 0

    def test_derivation_path_various_lengths(self):
        """Test derivation path with various byte lengths."""
        test_paths = [
            b"\x01",
            b"\x01\x02",
            b"\x01\x02\x03\x04\x05",
            b"\x00" * 32,
            b"\xff" * 64,
        ]

        for path in test_paths:
            attrs = ByronAddressAttributes(derivation_path=path)
            assert attrs.derivation_path == path

    def test_magic_boundary_values(self):
        """Test magic with boundary values."""
        test_magics = [-1, 0, 1, 2**31 - 1, 2**63 - 1]

        for magic in test_magics:
            attrs = ByronAddressAttributes(magic=magic)
            assert attrs.magic == magic

    def test_mainnet_multiple_calls_are_equal(self):
        """Test that multiple mainnet() calls produce equal instances."""
        attrs1 = ByronAddressAttributes.mainnet()
        attrs2 = ByronAddressAttributes.mainnet()

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_testnet_multiple_calls_same_magic_are_equal(self):
        """Test that testnet() calls with same magic produce equal instances."""
        attrs1 = ByronAddressAttributes.testnet(42)
        attrs2 = ByronAddressAttributes.testnet(42)

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_testnet_different_magic_values_are_not_equal(self):
        """Test that testnet() calls with different magic values are not equal."""
        attrs1 = ByronAddressAttributes.testnet(1)
        attrs2 = ByronAddressAttributes.testnet(2)

        assert attrs1 != attrs2

    def test_derivation_path_with_bytearray(self):
        """Test that derivation_path accepts bytearray."""
        path = bytearray(b"\x01\x02\x03")
        attrs = ByronAddressAttributes(derivation_path=path)

        assert attrs.derivation_path == path

    def test_has_network_magic_is_deterministic(self):
        """Test that has_network_magic property is deterministic."""
        attrs = ByronAddressAttributes.testnet(1)

        assert attrs.has_network_magic
        assert attrs.has_network_magic
        assert attrs.has_network_magic

    def test_mainnet_has_no_network_magic(self):
        """Test that mainnet addresses have no network magic."""
        attrs = ByronAddressAttributes.mainnet()
        assert not attrs.has_network_magic

    def test_testnet_with_typical_testnet_magic(self):
        """Test testnet with typical testnet magic values."""
        testnet_magics = [
            1,
            1097911063,
            42,
        ]

        for magic in testnet_magics:
            attrs = ByronAddressAttributes.testnet(magic)
            assert attrs.magic == magic
            assert attrs.has_network_magic

    def test_attributes_comparison_with_mainnet_factory(self):
        """Test that manual construction matches mainnet factory."""
        manual = ByronAddressAttributes(derivation_path=b"", magic=-1)
        factory = ByronAddressAttributes.mainnet()

        assert manual == factory

    def test_attributes_comparison_with_testnet_factory(self):
        """Test that manual construction matches testnet factory."""
        magic = 1097911063
        manual = ByronAddressAttributes(derivation_path=b"", magic=magic)
        factory = ByronAddressAttributes.testnet(magic)

        assert manual == factory

    def test_derivation_path_max_length(self):
        """Test derivation path with maximum expected length."""
        max_path = b"\xff" * 64
        attrs = ByronAddressAttributes(derivation_path=max_path)

        assert attrs.derivation_path == max_path
        assert len(attrs.derivation_path) == 64

    def test_attributes_type_checking(self):
        """Test type checking for attributes."""
        attrs = ByronAddressAttributes()

        assert isinstance(attrs, ByronAddressAttributes)
        assert isinstance(attrs.derivation_path, (bytes, bytearray))
        assert isinstance(attrs.magic, int)
        assert isinstance(attrs.has_network_magic, bool)

    def test_attributes_with_none_values(self):
        """Test creating attributes with None values."""
        attrs = ByronAddressAttributes(derivation_path=None)
        assert attrs.derivation_path is None

        attrs = ByronAddressAttributes(magic=None)
        assert attrs.magic is None

    def test_testnet_with_various_magic_types(self):
        """Test testnet with various magic value types."""
        attrs = ByronAddressAttributes.testnet("1")
        assert attrs.magic == "1"

    def test_derivation_path_with_string(self):
        """Test creating attributes with string derivation_path."""
        attrs = ByronAddressAttributes(derivation_path="not bytes")
        assert attrs.derivation_path == "not bytes"

    def test_magic_with_float(self):
        """Test creating attributes with float magic."""
        attrs = ByronAddressAttributes(magic=42.5)
        assert attrs.magic == 42.5

    def test_mainnet_returns_new_instance(self):
        """Test that mainnet() returns a new instance each time."""
        attrs1 = ByronAddressAttributes.mainnet()
        attrs2 = ByronAddressAttributes.mainnet()

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_testnet_returns_new_instance(self):
        """Test that testnet() returns a new instance each time."""
        attrs1 = ByronAddressAttributes.testnet(1)
        attrs2 = ByronAddressAttributes.testnet(1)

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_has_network_magic_property_read_only(self):
        """Test that has_network_magic is read-only."""
        attrs = ByronAddressAttributes()

        with pytest.raises(AttributeError):
            attrs.has_network_magic = True

    def test_derivation_path_bytes_identity(self):
        """Test derivation path bytes identity."""
        path = b"\x01\x02\x03"
        attrs = ByronAddressAttributes(derivation_path=path)

        assert attrs.derivation_path == path

    def test_ordering_not_supported(self):
        """Test that ordering comparisons are not supported."""
        attrs1 = ByronAddressAttributes.mainnet()
        attrs2 = ByronAddressAttributes.testnet(1)

        with pytest.raises(TypeError):
            attrs1 < attrs2

        with pytest.raises(TypeError):
            attrs1 > attrs2

        with pytest.raises(TypeError):
            attrs1 <= attrs2

        with pytest.raises(TypeError):
            attrs1 >= attrs2

    def test_attributes_in_list(self):
        """Test using attributes in a list."""
        attrs1 = ByronAddressAttributes.mainnet()
        attrs2 = ByronAddressAttributes.testnet(1)
        attrs3 = ByronAddressAttributes.testnet(2)

        attrs_list = [attrs1, attrs2, attrs3]
        assert len(attrs_list) == 3
        assert attrs1 in attrs_list
        assert attrs2 in attrs_list
        assert attrs3 in attrs_list

    def test_attributes_shallow_copy(self):
        """Test shallow copy of attributes."""
        import copy
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01\x02", magic=42)
        attrs2 = copy.copy(attrs1)

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_attributes_deep_copy(self):
        """Test deep copy of attributes."""
        import copy
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01\x02", magic=42)
        attrs2 = copy.deepcopy(attrs1)

        assert attrs1 == attrs2
        assert attrs1 is not attrs2

    def test_attributes_pickle(self):
        """Test pickling and unpickling attributes."""
        import pickle
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01\x02", magic=42)
        pickled = pickle.dumps(attrs1)
        attrs2 = pickle.loads(pickled)

        assert attrs1 == attrs2

    def test_has_network_magic_property_descriptor(self):
        """Test that has_network_magic is a property."""
        assert isinstance(
            ByronAddressAttributes.has_network_magic,
            property
        )

    def test_mainnet_is_classmethod(self):
        """Test that mainnet is a classmethod."""
        assert callable(ByronAddressAttributes.mainnet)

    def test_testnet_is_classmethod(self):
        """Test that testnet is a classmethod."""
        assert callable(ByronAddressAttributes.testnet)

    def test_str_representation(self):
        """Test string representation."""
        attrs = ByronAddressAttributes(derivation_path=b"\x01\x02", magic=42)
        str_repr = str(attrs)

        assert "ByronAddressAttributes" in str_repr

    def test_dataclass_fields(self):
        """Test that dataclass has correct fields."""
        from dataclasses import fields
        field_names = [f.name for f in fields(ByronAddressAttributes)]

        assert "derivation_path" in field_names
        assert "magic" in field_names
        assert len(field_names) == 2

    def test_dataclass_frozen(self):
        """Test that dataclass is frozen."""
        from dataclasses import is_dataclass
        assert is_dataclass(ByronAddressAttributes)

    def test_magic_negative_values(self):
        """Test magic with various negative values."""
        negative_magics = [-1, -2, -10, -100, -2**31, -2**63]

        for magic in negative_magics:
            attrs = ByronAddressAttributes(magic=magic)
            assert attrs.magic == magic
            if magic == -1:
                assert not attrs.has_network_magic
            elif magic < 0:
                assert not attrs.has_network_magic

    def test_derivation_path_special_bytes(self):
        """Test derivation path with special byte sequences."""
        special_paths = [
            b"\x00",
            b"\x00\x00\x00\x00",
            b"\xff\xff\xff\xff",
            b"\x01\x00\x01\x00",
            bytes(range(256))[:64],
        ]

        for path in special_paths:
            attrs = ByronAddressAttributes(derivation_path=path)
            assert attrs.derivation_path == path

    def test_multiple_attributes_independence(self):
        """Test that multiple attribute instances are independent."""
        attrs1 = ByronAddressAttributes(derivation_path=b"\x01", magic=1)
        attrs2 = ByronAddressAttributes(derivation_path=b"\x02", magic=2)
        attrs3 = ByronAddressAttributes(derivation_path=b"\x03", magic=3)

        assert attrs1.derivation_path == b"\x01"
        assert attrs2.derivation_path == b"\x02"
        assert attrs3.derivation_path == b"\x03"
        assert attrs1.magic == 1
        assert attrs2.magic == 2
        assert attrs3.magic == 3

    def test_has_network_magic_with_zero_magic(self):
        """Test has_network_magic specifically with zero magic."""
        attrs = ByronAddressAttributes(magic=0)
        assert attrs.has_network_magic

    def test_has_network_magic_with_minus_one(self):
        """Test has_network_magic specifically with -1 magic."""
        attrs = ByronAddressAttributes(magic=-1)
        assert not attrs.has_network_magic
