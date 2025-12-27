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
from cometa import JsonFormat


class TestJsonFormat:
    """Tests for the JsonFormat enum."""

    def test_json_format_values(self):
        """Test that JsonFormat enum values are correct."""
        assert JsonFormat.COMPACT == 0
        assert JsonFormat.PRETTY == 1

    def test_json_format_from_int(self):
        """Test creating JsonFormat from integer values."""
        assert JsonFormat(0) == JsonFormat.COMPACT
        assert JsonFormat(1) == JsonFormat.PRETTY

    def test_json_format_comparison(self):
        """Test comparison between JsonFormat values."""
        assert JsonFormat.COMPACT != JsonFormat.PRETTY
        assert JsonFormat.COMPACT == JsonFormat.COMPACT
        assert JsonFormat.PRETTY == JsonFormat.PRETTY

    def test_json_format_names(self):
        """Test that JsonFormat enum has correct names."""
        assert JsonFormat.COMPACT.name == "COMPACT"
        assert JsonFormat.PRETTY.name == "PRETTY"

    def test_json_format_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            JsonFormat(2)
        with pytest.raises(ValueError):
            JsonFormat(-1)
        with pytest.raises(ValueError):
            JsonFormat(100)

    def test_json_format_is_int_enum(self):
        """Test that JsonFormat values can be used as integers."""
        assert isinstance(JsonFormat.COMPACT, int)
        assert isinstance(JsonFormat.PRETTY, int)
        assert JsonFormat.COMPACT + 1 == 1
        assert JsonFormat.PRETTY - 1 == 0

    def test_json_format_iteration(self):
        """Test iteration over JsonFormat enum."""
        values = list(JsonFormat)
        assert len(values) == 2
        assert JsonFormat.COMPACT in values
        assert JsonFormat.PRETTY in values

    def test_json_format_membership(self):
        """Test membership testing with JsonFormat."""
        assert 0 in JsonFormat.__members__.values()
        assert 1 in JsonFormat.__members__.values()
        assert "COMPACT" in JsonFormat.__members__
        assert "PRETTY" in JsonFormat.__members__

    def test_json_format_string_representation(self):
        """Test string representation of JsonFormat values."""
        assert str(JsonFormat.COMPACT) == "JsonFormat.COMPACT"
        assert str(JsonFormat.PRETTY) == "JsonFormat.PRETTY"

    def test_json_format_repr(self):
        """Test repr of JsonFormat values."""
        assert repr(JsonFormat.COMPACT) == "<JsonFormat.COMPACT: 0>"
        assert repr(JsonFormat.PRETTY) == "<JsonFormat.PRETTY: 1>"

    def test_json_format_bool_conversion(self):
        """Test boolean conversion of JsonFormat values."""
        assert bool(JsonFormat.COMPACT) is False
        assert bool(JsonFormat.PRETTY) is True

    def test_json_format_arithmetic(self):
        """Test arithmetic operations with JsonFormat values."""
        assert JsonFormat.COMPACT + JsonFormat.PRETTY == 1
        assert JsonFormat.PRETTY * 2 == 2
        assert JsonFormat.PRETTY // 2 == 0

    def test_json_format_hash(self):
        """Test that JsonFormat values are hashable."""
        format_set = {JsonFormat.COMPACT, JsonFormat.PRETTY}
        assert len(format_set) == 2
        assert JsonFormat.COMPACT in format_set
        assert JsonFormat.PRETTY in format_set

    def test_json_format_as_dict_key(self):
        """Test using JsonFormat as dictionary key."""
        format_dict = {
            JsonFormat.COMPACT: "compact",
            JsonFormat.PRETTY: "pretty"
        }
        assert format_dict[JsonFormat.COMPACT] == "compact"
        assert format_dict[JsonFormat.PRETTY] == "pretty"

    def test_json_format_ordering(self):
        """Test ordering comparison between JsonFormat values."""
        assert JsonFormat.COMPACT < JsonFormat.PRETTY
        assert JsonFormat.PRETTY > JsonFormat.COMPACT
        assert JsonFormat.COMPACT <= JsonFormat.COMPACT
        assert JsonFormat.PRETTY >= JsonFormat.PRETTY
        assert JsonFormat.COMPACT <= JsonFormat.PRETTY
        assert JsonFormat.PRETTY >= JsonFormat.COMPACT

    def test_json_format_type_check(self):
        """Test type checking with JsonFormat."""
        assert type(JsonFormat.COMPACT) is JsonFormat
        assert type(JsonFormat.PRETTY) is JsonFormat

    def test_json_format_identity(self):
        """Test identity checks with JsonFormat values."""
        assert JsonFormat.COMPACT is JsonFormat.COMPACT
        assert JsonFormat.PRETTY is JsonFormat.PRETTY
        assert JsonFormat(0) is JsonFormat.COMPACT
        assert JsonFormat(1) is JsonFormat.PRETTY

    def test_json_format_all_members(self):
        """Test that all expected members exist and no unexpected ones."""
        members = list(JsonFormat.__members__.keys())
        assert len(members) == 2
        assert "COMPACT" in members
        assert "PRETTY" in members

    def test_json_format_values_unique(self):
        """Test that all JsonFormat values are unique."""
        values = [e.value for e in JsonFormat]
        assert len(values) == len(set(values))

    def test_json_format_sequential_values(self):
        """Test that JsonFormat values are sequential starting from 0."""
        values = sorted([e.value for e in JsonFormat])
        assert values == list(range(len(values)))
