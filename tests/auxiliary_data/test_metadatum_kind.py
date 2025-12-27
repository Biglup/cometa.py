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
from cometa import MetadatumKind


class TestMetadatumKind:
    """Tests for the MetadatumKind enum."""

    def test_metadatum_kind_values(self):
        """Test that MetadatumKind enum values are correct."""
        assert MetadatumKind.MAP == 0
        assert MetadatumKind.LIST == 1
        assert MetadatumKind.INTEGER == 2
        assert MetadatumKind.BYTES == 3
        assert MetadatumKind.TEXT == 4

    def test_metadatum_kind_from_int(self):
        """Test creating MetadatumKind from integer values."""
        assert MetadatumKind(0) == MetadatumKind.MAP
        assert MetadatumKind(1) == MetadatumKind.LIST
        assert MetadatumKind(2) == MetadatumKind.INTEGER
        assert MetadatumKind(3) == MetadatumKind.BYTES
        assert MetadatumKind(4) == MetadatumKind.TEXT

    def test_metadatum_kind_comparison(self):
        """Test comparison between MetadatumKind values."""
        assert MetadatumKind.MAP != MetadatumKind.LIST
        assert MetadatumKind.MAP == MetadatumKind.MAP
        assert MetadatumKind.LIST == MetadatumKind.LIST
        assert MetadatumKind.INTEGER == MetadatumKind.INTEGER
        assert MetadatumKind.BYTES == MetadatumKind.BYTES
        assert MetadatumKind.TEXT == MetadatumKind.TEXT

    def test_metadatum_kind_names(self):
        """Test that MetadatumKind enum has correct names."""
        assert MetadatumKind.MAP.name == "MAP"
        assert MetadatumKind.LIST.name == "LIST"
        assert MetadatumKind.INTEGER.name == "INTEGER"
        assert MetadatumKind.BYTES.name == "BYTES"
        assert MetadatumKind.TEXT.name == "TEXT"

    def test_metadatum_kind_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            MetadatumKind(5)
        with pytest.raises(ValueError):
            MetadatumKind(-1)
        with pytest.raises(ValueError):
            MetadatumKind(100)
        with pytest.raises(ValueError):
            MetadatumKind(-100)

    def test_metadatum_kind_is_int_enum(self):
        """Test that MetadatumKind values can be used as integers."""
        assert isinstance(MetadatumKind.MAP, int)
        assert isinstance(MetadatumKind.LIST, int)
        assert isinstance(MetadatumKind.INTEGER, int)
        assert isinstance(MetadatumKind.BYTES, int)
        assert isinstance(MetadatumKind.TEXT, int)
        assert MetadatumKind.MAP + 1 == 1
        assert MetadatumKind.LIST - 1 == 0
        assert MetadatumKind.INTEGER * 2 == 4
        assert MetadatumKind.TEXT - 1 == 3

    def test_metadatum_kind_iteration(self):
        """Test iteration over MetadatumKind enum."""
        values = list(MetadatumKind)
        assert len(values) == 5
        assert MetadatumKind.MAP in values
        assert MetadatumKind.LIST in values
        assert MetadatumKind.INTEGER in values
        assert MetadatumKind.BYTES in values
        assert MetadatumKind.TEXT in values

    def test_metadatum_kind_membership(self):
        """Test membership testing with MetadatumKind."""
        assert 0 in MetadatumKind.__members__.values()
        assert 1 in MetadatumKind.__members__.values()
        assert 2 in MetadatumKind.__members__.values()
        assert 3 in MetadatumKind.__members__.values()
        assert 4 in MetadatumKind.__members__.values()
        assert "MAP" in MetadatumKind.__members__
        assert "LIST" in MetadatumKind.__members__
        assert "INTEGER" in MetadatumKind.__members__
        assert "BYTES" in MetadatumKind.__members__
        assert "TEXT" in MetadatumKind.__members__

    def test_metadatum_kind_string_representation(self):
        """Test string representation of MetadatumKind values."""
        assert str(MetadatumKind.MAP) == "MetadatumKind.MAP"
        assert str(MetadatumKind.LIST) == "MetadatumKind.LIST"
        assert str(MetadatumKind.INTEGER) == "MetadatumKind.INTEGER"
        assert str(MetadatumKind.BYTES) == "MetadatumKind.BYTES"
        assert str(MetadatumKind.TEXT) == "MetadatumKind.TEXT"

    def test_metadatum_kind_repr(self):
        """Test repr of MetadatumKind values."""
        assert repr(MetadatumKind.MAP) == "<MetadatumKind.MAP: 0>"
        assert repr(MetadatumKind.LIST) == "<MetadatumKind.LIST: 1>"
        assert repr(MetadatumKind.INTEGER) == "<MetadatumKind.INTEGER: 2>"
        assert repr(MetadatumKind.BYTES) == "<MetadatumKind.BYTES: 3>"
        assert repr(MetadatumKind.TEXT) == "<MetadatumKind.TEXT: 4>"

    def test_metadatum_kind_bool_conversion(self):
        """Test boolean conversion of MetadatumKind values."""
        assert bool(MetadatumKind.MAP) is False
        assert bool(MetadatumKind.LIST) is True
        assert bool(MetadatumKind.INTEGER) is True
        assert bool(MetadatumKind.BYTES) is True
        assert bool(MetadatumKind.TEXT) is True

    def test_metadatum_kind_arithmetic(self):
        """Test arithmetic operations with MetadatumKind values."""
        assert MetadatumKind.MAP + MetadatumKind.LIST == 1
        assert MetadatumKind.TEXT - MetadatumKind.MAP == 4
        assert MetadatumKind.INTEGER * 2 == 4
        assert MetadatumKind.TEXT // 2 == 2
        assert MetadatumKind.LIST + MetadatumKind.INTEGER == 3

    def test_metadatum_kind_hash(self):
        """Test that MetadatumKind values are hashable."""
        kind_set = {
            MetadatumKind.MAP,
            MetadatumKind.LIST,
            MetadatumKind.INTEGER,
            MetadatumKind.BYTES,
            MetadatumKind.TEXT
        }
        assert len(kind_set) == 5
        assert MetadatumKind.MAP in kind_set
        assert MetadatumKind.LIST in kind_set
        assert MetadatumKind.INTEGER in kind_set
        assert MetadatumKind.BYTES in kind_set
        assert MetadatumKind.TEXT in kind_set

    def test_metadatum_kind_as_dict_key(self):
        """Test using MetadatumKind as dictionary key."""
        kind_dict = {
            MetadatumKind.MAP: "map",
            MetadatumKind.LIST: "list",
            MetadatumKind.INTEGER: "integer",
            MetadatumKind.BYTES: "bytes",
            MetadatumKind.TEXT: "text"
        }
        assert kind_dict[MetadatumKind.MAP] == "map"
        assert kind_dict[MetadatumKind.LIST] == "list"
        assert kind_dict[MetadatumKind.INTEGER] == "integer"
        assert kind_dict[MetadatumKind.BYTES] == "bytes"
        assert kind_dict[MetadatumKind.TEXT] == "text"

    def test_metadatum_kind_ordering(self):
        """Test ordering comparison between MetadatumKind values."""
        assert MetadatumKind.MAP < MetadatumKind.LIST
        assert MetadatumKind.LIST < MetadatumKind.INTEGER
        assert MetadatumKind.INTEGER < MetadatumKind.BYTES
        assert MetadatumKind.BYTES < MetadatumKind.TEXT
        assert MetadatumKind.TEXT > MetadatumKind.MAP
        assert MetadatumKind.MAP <= MetadatumKind.MAP
        assert MetadatumKind.TEXT >= MetadatumKind.TEXT

    def test_metadatum_kind_all_types_unique(self):
        """Test that all MetadatumKind values are unique."""
        values = [
            MetadatumKind.MAP,
            MetadatumKind.LIST,
            MetadatumKind.INTEGER,
            MetadatumKind.BYTES,
            MetadatumKind.TEXT
        ]
        assert len(values) == len(set(values))

    def test_metadatum_kind_sequential_values(self):
        """Test that MetadatumKind values are sequential from 0 to 4."""
        assert MetadatumKind.MAP == 0
        assert MetadatumKind.LIST == MetadatumKind.MAP + 1
        assert MetadatumKind.INTEGER == MetadatumKind.LIST + 1
        assert MetadatumKind.BYTES == MetadatumKind.INTEGER + 1
        assert MetadatumKind.TEXT == MetadatumKind.BYTES + 1

    def test_metadatum_kind_invalid_type(self):
        """Test that invalid types raise appropriate errors."""
        with pytest.raises((ValueError, TypeError)):
            MetadatumKind("MAP")
        with pytest.raises((ValueError, TypeError)):
            MetadatumKind(1.5)
        with pytest.raises((ValueError, TypeError)):
            MetadatumKind(None)
        with pytest.raises((ValueError, TypeError)):
            MetadatumKind([])

    def test_metadatum_kind_comparison_with_int(self):
        """Test comparison of MetadatumKind with integer values."""
        assert MetadatumKind.MAP == 0
        assert MetadatumKind.LIST == 1
        assert MetadatumKind.INTEGER == 2
        assert MetadatumKind.BYTES == 3
        assert MetadatumKind.TEXT == 4
        assert 0 == MetadatumKind.MAP
        assert 1 == MetadatumKind.LIST

    def test_metadatum_kind_all_members(self):
        """Test accessing all members of MetadatumKind."""
        members = MetadatumKind.__members__
        assert "MAP" in members
        assert "LIST" in members
        assert "INTEGER" in members
        assert "BYTES" in members
        assert "TEXT" in members
        assert len(members) == 5

    def test_metadatum_kind_value_property(self):
        """Test accessing the value property of MetadatumKind."""
        assert MetadatumKind.MAP.value == 0
        assert MetadatumKind.LIST.value == 1
        assert MetadatumKind.INTEGER.value == 2
        assert MetadatumKind.BYTES.value == 3
        assert MetadatumKind.TEXT.value == 4
