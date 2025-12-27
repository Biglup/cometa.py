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
from cometa import JsonContext


class TestJsonContext:
    """Tests for the JsonContext enum."""

    def test_json_context_values(self):
        """Test that JsonContext enum values are correct."""
        assert JsonContext.ROOT == 0
        assert JsonContext.OBJECT == 1
        assert JsonContext.ARRAY == 2

    def test_json_context_from_int(self):
        """Test creating JsonContext from integer values."""
        assert JsonContext(0) == JsonContext.ROOT
        assert JsonContext(1) == JsonContext.OBJECT
        assert JsonContext(2) == JsonContext.ARRAY

    def test_json_context_comparison(self):
        """Test comparison between JsonContext values."""
        assert JsonContext.ROOT != JsonContext.OBJECT
        assert JsonContext.ROOT != JsonContext.ARRAY
        assert JsonContext.OBJECT != JsonContext.ARRAY
        assert JsonContext.ROOT == JsonContext.ROOT
        assert JsonContext.OBJECT == JsonContext.OBJECT
        assert JsonContext.ARRAY == JsonContext.ARRAY

    def test_json_context_names(self):
        """Test that JsonContext enum has correct names."""
        assert JsonContext.ROOT.name == "ROOT"
        assert JsonContext.OBJECT.name == "OBJECT"
        assert JsonContext.ARRAY.name == "ARRAY"

    def test_json_context_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            JsonContext(3)
        with pytest.raises(ValueError):
            JsonContext(-1)
        with pytest.raises(ValueError):
            JsonContext(100)

    def test_json_context_is_int_enum(self):
        """Test that JsonContext values can be used as integers."""
        assert isinstance(JsonContext.ROOT, int)
        assert isinstance(JsonContext.OBJECT, int)
        assert isinstance(JsonContext.ARRAY, int)
        assert JsonContext.ROOT + 1 == 1
        assert JsonContext.OBJECT - 1 == 0
        assert JsonContext.ARRAY - 2 == 0

    def test_json_context_iteration(self):
        """Test iteration over JsonContext enum."""
        values = list(JsonContext)
        assert len(values) == 3
        assert JsonContext.ROOT in values
        assert JsonContext.OBJECT in values
        assert JsonContext.ARRAY in values

    def test_json_context_membership(self):
        """Test membership testing with JsonContext."""
        assert 0 in JsonContext.__members__.values()
        assert 1 in JsonContext.__members__.values()
        assert 2 in JsonContext.__members__.values()
        assert "ROOT" in JsonContext.__members__
        assert "OBJECT" in JsonContext.__members__
        assert "ARRAY" in JsonContext.__members__

    def test_json_context_string_representation(self):
        """Test string representation of JsonContext values."""
        assert str(JsonContext.ROOT) == "JsonContext.ROOT"
        assert str(JsonContext.OBJECT) == "JsonContext.OBJECT"
        assert str(JsonContext.ARRAY) == "JsonContext.ARRAY"

    def test_json_context_repr(self):
        """Test repr of JsonContext values."""
        assert repr(JsonContext.ROOT) == "<JsonContext.ROOT: 0>"
        assert repr(JsonContext.OBJECT) == "<JsonContext.OBJECT: 1>"
        assert repr(JsonContext.ARRAY) == "<JsonContext.ARRAY: 2>"

    def test_json_context_bool_conversion(self):
        """Test boolean conversion of JsonContext values."""
        assert bool(JsonContext.ROOT) is False
        assert bool(JsonContext.OBJECT) is True
        assert bool(JsonContext.ARRAY) is True

    def test_json_context_arithmetic(self):
        """Test arithmetic operations with JsonContext values."""
        assert JsonContext.ROOT + JsonContext.OBJECT == 1
        assert JsonContext.OBJECT + JsonContext.ARRAY == 3
        assert JsonContext.ARRAY * 2 == 4
        assert JsonContext.ARRAY // 2 == 1

    def test_json_context_hash(self):
        """Test that JsonContext values are hashable."""
        context_set = {JsonContext.ROOT, JsonContext.OBJECT, JsonContext.ARRAY}
        assert len(context_set) == 3
        assert JsonContext.ROOT in context_set
        assert JsonContext.OBJECT in context_set
        assert JsonContext.ARRAY in context_set

    def test_json_context_as_dict_key(self):
        """Test using JsonContext as dictionary key."""
        context_dict = {
            JsonContext.ROOT: "root",
            JsonContext.OBJECT: "object",
            JsonContext.ARRAY: "array"
        }
        assert context_dict[JsonContext.ROOT] == "root"
        assert context_dict[JsonContext.OBJECT] == "object"
        assert context_dict[JsonContext.ARRAY] == "array"

    def test_json_context_ordering(self):
        """Test ordering comparison between JsonContext values."""
        assert JsonContext.ROOT < JsonContext.OBJECT
        assert JsonContext.ROOT < JsonContext.ARRAY
        assert JsonContext.OBJECT < JsonContext.ARRAY
        assert JsonContext.ARRAY > JsonContext.OBJECT
        assert JsonContext.ARRAY > JsonContext.ROOT
        assert JsonContext.OBJECT > JsonContext.ROOT
        assert JsonContext.ROOT <= JsonContext.ROOT
        assert JsonContext.OBJECT >= JsonContext.OBJECT
        assert JsonContext.ARRAY <= JsonContext.ARRAY

    def test_json_context_type_check(self):
        """Test type checking with JsonContext."""
        assert type(JsonContext.ROOT) is JsonContext
        assert type(JsonContext.OBJECT) is JsonContext
        assert type(JsonContext.ARRAY) is JsonContext

    def test_json_context_identity(self):
        """Test identity checks with JsonContext values."""
        assert JsonContext.ROOT is JsonContext.ROOT
        assert JsonContext.OBJECT is JsonContext.OBJECT
        assert JsonContext.ARRAY is JsonContext.ARRAY
        assert JsonContext(0) is JsonContext.ROOT
        assert JsonContext(1) is JsonContext.OBJECT
        assert JsonContext(2) is JsonContext.ARRAY
