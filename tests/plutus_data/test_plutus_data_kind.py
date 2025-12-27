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
from cometa import PlutusDataKind


class TestPlutusDataKind:
    """Tests for the PlutusDataKind enum."""

    def test_constr_value(self):
        """Test that CONSTR has the correct value."""
        assert PlutusDataKind.CONSTR == 0

    def test_map_value(self):
        """Test that MAP has the correct value."""
        assert PlutusDataKind.MAP == 1

    def test_list_value(self):
        """Test that LIST has the correct value."""
        assert PlutusDataKind.LIST == 2

    def test_integer_value(self):
        """Test that INTEGER has the correct value."""
        assert PlutusDataKind.INTEGER == 3

    def test_bytes_value(self):
        """Test that BYTES has the correct value."""
        assert PlutusDataKind.BYTES == 4


class TestPlutusDataKindComparison:
    """Tests for PlutusDataKind enum comparison and identity."""

    def test_enum_comparison_equal(self):
        """Test that enum members can be compared for equality."""
        assert PlutusDataKind.CONSTR == PlutusDataKind.CONSTR
        assert PlutusDataKind.MAP == PlutusDataKind.MAP

    def test_enum_comparison_not_equal(self):
        """Test that different enum members are not equal."""
        assert PlutusDataKind.CONSTR != PlutusDataKind.MAP
        assert PlutusDataKind.LIST != PlutusDataKind.INTEGER
        assert PlutusDataKind.BYTES != PlutusDataKind.CONSTR

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        kind1 = PlutusDataKind.CONSTR
        kind2 = PlutusDataKind.CONSTR
        assert kind1 is kind2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(PlutusDataKind.CONSTR) == 0
        assert int(PlutusDataKind.MAP) == 1
        assert int(PlutusDataKind.LIST) == 2
        assert int(PlutusDataKind.INTEGER) == 3
        assert int(PlutusDataKind.BYTES) == 4


class TestPlutusDataKindIteration:
    """Tests for iterating over PlutusDataKind enum members."""

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_kinds = list(PlutusDataKind)
        assert len(all_kinds) == 5
        assert PlutusDataKind.CONSTR in all_kinds
        assert PlutusDataKind.MAP in all_kinds
        assert PlutusDataKind.LIST in all_kinds
        assert PlutusDataKind.INTEGER in all_kinds
        assert PlutusDataKind.BYTES in all_kinds

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert PlutusDataKind.CONSTR in PlutusDataKind
        assert PlutusDataKind.MAP in PlutusDataKind
        assert PlutusDataKind.LIST in PlutusDataKind
        assert PlutusDataKind.INTEGER in PlutusDataKind
        assert PlutusDataKind.BYTES in PlutusDataKind


class TestPlutusDataKindAttributes:
    """Tests for PlutusDataKind enum attributes."""

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert PlutusDataKind.CONSTR.name == "CONSTR"
        assert PlutusDataKind.MAP.name == "MAP"
        assert PlutusDataKind.LIST.name == "LIST"
        assert PlutusDataKind.INTEGER.name == "INTEGER"
        assert PlutusDataKind.BYTES.name == "BYTES"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert PlutusDataKind.CONSTR.value == 0
        assert PlutusDataKind.MAP.value == 1
        assert PlutusDataKind.LIST.value == 2
        assert PlutusDataKind.INTEGER.value == 3
        assert PlutusDataKind.BYTES.value == 4


class TestPlutusDataKindFromValue:
    """Tests for creating PlutusDataKind from integer values."""

    def test_from_value_constr(self):
        """Test creating CONSTR from integer value."""
        assert PlutusDataKind(0) == PlutusDataKind.CONSTR

    def test_from_value_map(self):
        """Test creating MAP from integer value."""
        assert PlutusDataKind(1) == PlutusDataKind.MAP

    def test_from_value_list(self):
        """Test creating LIST from integer value."""
        assert PlutusDataKind(2) == PlutusDataKind.LIST

    def test_from_value_integer(self):
        """Test creating INTEGER from integer value."""
        assert PlutusDataKind(3) == PlutusDataKind.INTEGER

    def test_from_value_bytes(self):
        """Test creating BYTES from integer value."""
        assert PlutusDataKind(4) == PlutusDataKind.BYTES


class TestPlutusDataKindInvalidValues:
    """Tests for invalid PlutusDataKind values."""

    def test_invalid_value_raises_error(self):
        """Test that invalid positive values raise ValueError."""
        with pytest.raises(ValueError):
            PlutusDataKind(5)

    def test_invalid_large_value_raises_error(self):
        """Test that large invalid values raise ValueError."""
        with pytest.raises(ValueError):
            PlutusDataKind(100)

    def test_invalid_negative_value_raises_error(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            PlutusDataKind(-1)

    def test_invalid_negative_large_value_raises_error(self):
        """Test that large negative values raise ValueError."""
        with pytest.raises(ValueError):
            PlutusDataKind(-100)


class TestPlutusDataKindStringRepresentation:
    """Tests for string representation of PlutusDataKind."""

    def test_str_representation_constr(self):
        """Test string representation of CONSTR."""
        assert str(PlutusDataKind.CONSTR) == "PlutusDataKind.CONSTR"

    def test_str_representation_map(self):
        """Test string representation of MAP."""
        assert str(PlutusDataKind.MAP) == "PlutusDataKind.MAP"

    def test_str_representation_list(self):
        """Test string representation of LIST."""
        assert str(PlutusDataKind.LIST) == "PlutusDataKind.LIST"

    def test_str_representation_integer(self):
        """Test string representation of INTEGER."""
        assert str(PlutusDataKind.INTEGER) == "PlutusDataKind.INTEGER"

    def test_str_representation_bytes(self):
        """Test string representation of BYTES."""
        assert str(PlutusDataKind.BYTES) == "PlutusDataKind.BYTES"

    def test_repr_representation_constr(self):
        """Test repr representation of CONSTR."""
        assert repr(PlutusDataKind.CONSTR) == "<PlutusDataKind.CONSTR: 0>"

    def test_repr_representation_map(self):
        """Test repr representation of MAP."""
        assert repr(PlutusDataKind.MAP) == "<PlutusDataKind.MAP: 1>"

    def test_repr_representation_list(self):
        """Test repr representation of LIST."""
        assert repr(PlutusDataKind.LIST) == "<PlutusDataKind.LIST: 2>"

    def test_repr_representation_integer(self):
        """Test repr representation of INTEGER."""
        assert repr(PlutusDataKind.INTEGER) == "<PlutusDataKind.INTEGER: 3>"

    def test_repr_representation_bytes(self):
        """Test repr representation of BYTES."""
        assert repr(PlutusDataKind.BYTES) == "<PlutusDataKind.BYTES: 4>"


class TestPlutusDataKindUseCases:
    """Tests for common use cases of PlutusDataKind."""

    def test_use_in_dictionary_key(self):
        """Test that PlutusDataKind can be used as dictionary key."""
        kind_dict = {
            PlutusDataKind.CONSTR: "Constructor",
            PlutusDataKind.MAP: "Map",
            PlutusDataKind.LIST: "List",
            PlutusDataKind.INTEGER: "Integer",
            PlutusDataKind.BYTES: "Bytes",
        }
        assert kind_dict[PlutusDataKind.CONSTR] == "Constructor"
        assert kind_dict[PlutusDataKind.MAP] == "Map"
        assert kind_dict[PlutusDataKind.LIST] == "List"
        assert kind_dict[PlutusDataKind.INTEGER] == "Integer"
        assert kind_dict[PlutusDataKind.BYTES] == "Bytes"

    def test_use_in_set(self):
        """Test that PlutusDataKind can be used in sets."""
        kind_set = {PlutusDataKind.CONSTR, PlutusDataKind.MAP, PlutusDataKind.LIST}
        assert PlutusDataKind.CONSTR in kind_set
        assert PlutusDataKind.MAP in kind_set
        assert PlutusDataKind.LIST in kind_set
        assert PlutusDataKind.INTEGER not in kind_set
        assert PlutusDataKind.BYTES not in kind_set

    def test_use_in_comparison_operations(self):
        """Test that PlutusDataKind can be used in comparison operations."""
        assert PlutusDataKind.CONSTR < PlutusDataKind.MAP
        assert PlutusDataKind.MAP < PlutusDataKind.LIST
        assert PlutusDataKind.LIST < PlutusDataKind.INTEGER
        assert PlutusDataKind.INTEGER < PlutusDataKind.BYTES
        assert PlutusDataKind.BYTES > PlutusDataKind.CONSTR

    def test_sorting(self):
        """Test that PlutusDataKind values can be sorted."""
        kinds = [
            PlutusDataKind.BYTES,
            PlutusDataKind.CONSTR,
            PlutusDataKind.INTEGER,
            PlutusDataKind.LIST,
            PlutusDataKind.MAP,
        ]
        sorted_kinds = sorted(kinds)
        expected = [
            PlutusDataKind.CONSTR,
            PlutusDataKind.MAP,
            PlutusDataKind.LIST,
            PlutusDataKind.INTEGER,
            PlutusDataKind.BYTES,
        ]
        assert sorted_kinds == expected

    def test_hash_consistency(self):
        """Test that PlutusDataKind members have consistent hash values."""
        kind1 = PlutusDataKind.CONSTR
        kind2 = PlutusDataKind.CONSTR
        assert hash(kind1) == hash(kind2)

    def test_all_members_are_hashable(self):
        """Test that all PlutusDataKind members are hashable."""
        for kind in PlutusDataKind:
            hash_value = hash(kind)
            assert isinstance(hash_value, int)
