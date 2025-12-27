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
from cometa import DatumType


class TestDatumType:
    """Tests for the DatumType enum."""

    def test_datum_type_values(self):
        """Test that DatumType enum values are correct."""
        assert DatumType.DATA_HASH == 0
        assert DatumType.INLINE_DATA == 1

    def test_datum_type_from_int(self):
        """Test creating DatumType from integer values."""
        assert DatumType(0) == DatumType.DATA_HASH
        assert DatumType(1) == DatumType.INLINE_DATA

    def test_datum_type_comparison(self):
        """Test comparison between DatumType values."""
        assert DatumType.DATA_HASH != DatumType.INLINE_DATA
        assert DatumType.DATA_HASH == DatumType.DATA_HASH
        assert DatumType.INLINE_DATA == DatumType.INLINE_DATA

    def test_datum_type_names(self):
        """Test that DatumType enum has correct names."""
        assert DatumType.DATA_HASH.name == "DATA_HASH"
        assert DatumType.INLINE_DATA.name == "INLINE_DATA"

    def test_datum_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            DatumType(2)
        with pytest.raises(ValueError):
            DatumType(-1)
        with pytest.raises(ValueError):
            DatumType(100)

    def test_datum_type_is_int_enum(self):
        """Test that DatumType values can be used as integers."""
        assert isinstance(DatumType.DATA_HASH, int)
        assert isinstance(DatumType.INLINE_DATA, int)
        assert DatumType.DATA_HASH + 1 == 1
        assert DatumType.INLINE_DATA - 1 == 0

    def test_datum_type_iteration(self):
        """Test iteration over DatumType enum."""
        values = list(DatumType)
        assert len(values) == 2
        assert DatumType.DATA_HASH in values
        assert DatumType.INLINE_DATA in values

    def test_datum_type_membership(self):
        """Test membership testing with DatumType."""
        assert 0 in DatumType.__members__.values()
        assert 1 in DatumType.__members__.values()
        assert "DATA_HASH" in DatumType.__members__
        assert "INLINE_DATA" in DatumType.__members__

    def test_datum_type_string_representation(self):
        """Test string representation of DatumType values."""
        assert str(DatumType.DATA_HASH) == "DatumType.DATA_HASH"
        assert str(DatumType.INLINE_DATA) == "DatumType.INLINE_DATA"

    def test_datum_type_repr(self):
        """Test repr of DatumType values."""
        assert repr(DatumType.DATA_HASH) == "<DatumType.DATA_HASH: 0>"
        assert repr(DatumType.INLINE_DATA) == "<DatumType.INLINE_DATA: 1>"

    def test_datum_type_bool_conversion(self):
        """Test boolean conversion of DatumType values."""
        assert bool(DatumType.DATA_HASH) is False
        assert bool(DatumType.INLINE_DATA) is True

    def test_datum_type_arithmetic(self):
        """Test arithmetic operations with DatumType values."""
        assert DatumType.DATA_HASH + DatumType.INLINE_DATA == 1
        assert DatumType.INLINE_DATA * 2 == 2
        assert DatumType.INLINE_DATA // 1 == 1

    def test_datum_type_hash(self):
        """Test that DatumType values are hashable."""
        datum_set = {DatumType.DATA_HASH, DatumType.INLINE_DATA}
        assert len(datum_set) == 2
        assert DatumType.DATA_HASH in datum_set
        assert DatumType.INLINE_DATA in datum_set

    def test_datum_type_as_dict_key(self):
        """Test using DatumType as dictionary key."""
        datum_dict = {
            DatumType.DATA_HASH: "data_hash",
            DatumType.INLINE_DATA: "inline_data"
        }
        assert datum_dict[DatumType.DATA_HASH] == "data_hash"
        assert datum_dict[DatumType.INLINE_DATA] == "inline_data"

    def test_datum_type_ordering(self):
        """Test ordering comparison between DatumType values."""
        assert DatumType.DATA_HASH < DatumType.INLINE_DATA
        assert DatumType.INLINE_DATA > DatumType.DATA_HASH
        assert DatumType.DATA_HASH <= DatumType.DATA_HASH
        assert DatumType.INLINE_DATA >= DatumType.INLINE_DATA
