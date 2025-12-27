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
from cometa import ScriptLanguage


class TestScriptLanguage:
    """Tests for the ScriptLanguage enum."""

    def test_script_language_values(self):
        """Test that ScriptLanguage enum values are correct."""
        assert ScriptLanguage.NATIVE == 0
        assert ScriptLanguage.PLUTUS_V1 == 1
        assert ScriptLanguage.PLUTUS_V2 == 2
        assert ScriptLanguage.PLUTUS_V3 == 3

    def test_script_language_from_int(self):
        """Test creating ScriptLanguage from integer values."""
        assert ScriptLanguage(0) == ScriptLanguage.NATIVE
        assert ScriptLanguage(1) == ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage(2) == ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage(3) == ScriptLanguage.PLUTUS_V3

    def test_script_language_comparison(self):
        """Test comparison between ScriptLanguage values."""
        assert ScriptLanguage.NATIVE != ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.NATIVE == ScriptLanguage.NATIVE
        assert ScriptLanguage.PLUTUS_V1 == ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.PLUTUS_V2 == ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage.PLUTUS_V3 == ScriptLanguage.PLUTUS_V3

    def test_script_language_names(self):
        """Test that ScriptLanguage enum has correct names."""
        assert ScriptLanguage.NATIVE.name == "NATIVE"
        assert ScriptLanguage.PLUTUS_V1.name == "PLUTUS_V1"
        assert ScriptLanguage.PLUTUS_V2.name == "PLUTUS_V2"
        assert ScriptLanguage.PLUTUS_V3.name == "PLUTUS_V3"

    def test_script_language_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            ScriptLanguage(4)
        with pytest.raises(ValueError):
            ScriptLanguage(-1)
        with pytest.raises(ValueError):
            ScriptLanguage(100)
        with pytest.raises(ValueError):
            ScriptLanguage(999)

    def test_script_language_is_int_enum(self):
        """Test that ScriptLanguage values can be used as integers."""
        assert isinstance(ScriptLanguage.NATIVE, int)
        assert isinstance(ScriptLanguage.PLUTUS_V1, int)
        assert isinstance(ScriptLanguage.PLUTUS_V2, int)
        assert isinstance(ScriptLanguage.PLUTUS_V3, int)
        assert ScriptLanguage.NATIVE + 1 == 1
        assert ScriptLanguage.PLUTUS_V1 - 1 == 0
        assert ScriptLanguage.PLUTUS_V2 + 1 == 3
        assert ScriptLanguage.PLUTUS_V3 - 1 == 2

    def test_script_language_iteration(self):
        """Test iteration over ScriptLanguage enum."""
        values = list(ScriptLanguage)
        assert len(values) == 4
        assert ScriptLanguage.NATIVE in values
        assert ScriptLanguage.PLUTUS_V1 in values
        assert ScriptLanguage.PLUTUS_V2 in values
        assert ScriptLanguage.PLUTUS_V3 in values

    def test_script_language_membership(self):
        """Test membership testing with ScriptLanguage."""
        assert 0 in ScriptLanguage.__members__.values()
        assert 1 in ScriptLanguage.__members__.values()
        assert 2 in ScriptLanguage.__members__.values()
        assert 3 in ScriptLanguage.__members__.values()
        assert "NATIVE" in ScriptLanguage.__members__
        assert "PLUTUS_V1" in ScriptLanguage.__members__
        assert "PLUTUS_V2" in ScriptLanguage.__members__
        assert "PLUTUS_V3" in ScriptLanguage.__members__

    def test_script_language_string_representation(self):
        """Test string representation of ScriptLanguage values."""
        assert str(ScriptLanguage.NATIVE) == "ScriptLanguage.NATIVE"
        assert str(ScriptLanguage.PLUTUS_V1) == "ScriptLanguage.PLUTUS_V1"
        assert str(ScriptLanguage.PLUTUS_V2) == "ScriptLanguage.PLUTUS_V2"
        assert str(ScriptLanguage.PLUTUS_V3) == "ScriptLanguage.PLUTUS_V3"

    def test_script_language_repr(self):
        """Test repr of ScriptLanguage values."""
        assert repr(ScriptLanguage.NATIVE) == "<ScriptLanguage.NATIVE: 0>"
        assert repr(ScriptLanguage.PLUTUS_V1) == "<ScriptLanguage.PLUTUS_V1: 1>"
        assert repr(ScriptLanguage.PLUTUS_V2) == "<ScriptLanguage.PLUTUS_V2: 2>"
        assert repr(ScriptLanguage.PLUTUS_V3) == "<ScriptLanguage.PLUTUS_V3: 3>"

    def test_script_language_bool_conversion(self):
        """Test boolean conversion of ScriptLanguage values."""
        assert bool(ScriptLanguage.NATIVE) is False
        assert bool(ScriptLanguage.PLUTUS_V1) is True
        assert bool(ScriptLanguage.PLUTUS_V2) is True
        assert bool(ScriptLanguage.PLUTUS_V3) is True

    def test_script_language_arithmetic(self):
        """Test arithmetic operations with ScriptLanguage values."""
        assert ScriptLanguage.NATIVE + ScriptLanguage.PLUTUS_V1 == 1
        assert ScriptLanguage.PLUTUS_V2 * 2 == 4
        assert ScriptLanguage.PLUTUS_V3 // 3 == 1
        assert ScriptLanguage.PLUTUS_V3 - ScriptLanguage.NATIVE == 3
        assert ScriptLanguage.PLUTUS_V2 + 1 == ScriptLanguage.PLUTUS_V3

    def test_script_language_hash(self):
        """Test that ScriptLanguage values are hashable."""
        script_set = {
            ScriptLanguage.NATIVE,
            ScriptLanguage.PLUTUS_V1,
            ScriptLanguage.PLUTUS_V2,
            ScriptLanguage.PLUTUS_V3
        }
        assert len(script_set) == 4
        assert ScriptLanguage.NATIVE in script_set
        assert ScriptLanguage.PLUTUS_V1 in script_set
        assert ScriptLanguage.PLUTUS_V2 in script_set
        assert ScriptLanguage.PLUTUS_V3 in script_set

    def test_script_language_as_dict_key(self):
        """Test using ScriptLanguage as dictionary key."""
        script_dict = {
            ScriptLanguage.NATIVE: "native",
            ScriptLanguage.PLUTUS_V1: "plutus_v1",
            ScriptLanguage.PLUTUS_V2: "plutus_v2",
            ScriptLanguage.PLUTUS_V3: "plutus_v3"
        }
        assert script_dict[ScriptLanguage.NATIVE] == "native"
        assert script_dict[ScriptLanguage.PLUTUS_V1] == "plutus_v1"
        assert script_dict[ScriptLanguage.PLUTUS_V2] == "plutus_v2"
        assert script_dict[ScriptLanguage.PLUTUS_V3] == "plutus_v3"

    def test_script_language_ordering(self):
        """Test ordering comparison between ScriptLanguage values."""
        assert ScriptLanguage.NATIVE < ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.PLUTUS_V1 < ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage.PLUTUS_V2 < ScriptLanguage.PLUTUS_V3
        assert ScriptLanguage.PLUTUS_V3 > ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage.PLUTUS_V2 > ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.PLUTUS_V1 > ScriptLanguage.NATIVE
        assert ScriptLanguage.NATIVE <= ScriptLanguage.NATIVE
        assert ScriptLanguage.PLUTUS_V1 <= ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.PLUTUS_V2 >= ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage.PLUTUS_V3 >= ScriptLanguage.PLUTUS_V3

    def test_script_language_enum_members_count(self):
        """Test that ScriptLanguage has exactly 4 members."""
        assert len(ScriptLanguage.__members__) == 4

    def test_script_language_uniqueness(self):
        """Test that all ScriptLanguage values are unique."""
        values = [member.value for member in ScriptLanguage]
        assert len(values) == len(set(values))

    def test_script_language_type_checking(self):
        """Test type checking for ScriptLanguage values."""
        from enum import IntEnum
        assert isinstance(ScriptLanguage.NATIVE, IntEnum)
        assert isinstance(ScriptLanguage.PLUTUS_V1, IntEnum)
        assert isinstance(ScriptLanguage.PLUTUS_V2, IntEnum)
        assert isinstance(ScriptLanguage.PLUTUS_V3, IntEnum)

    def test_script_language_invalid_type(self):
        """Test that non-integer types raise appropriate errors."""
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage("native")
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage(None)
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage([0])
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage({"value": 0})

    def test_script_language_float_conversion(self):
        """Test that float values are converted to integers or raise errors."""
        assert ScriptLanguage(0.0) == ScriptLanguage.NATIVE
        assert ScriptLanguage(1.0) == ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage(2.0) == ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage(3.0) == ScriptLanguage.PLUTUS_V3
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage(1.5)
        with pytest.raises((ValueError, TypeError)):
            ScriptLanguage(2.9)

    def test_script_language_identity(self):
        """Test that same enum values are identical."""
        assert ScriptLanguage.NATIVE is ScriptLanguage.NATIVE
        assert ScriptLanguage.PLUTUS_V1 is ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage.PLUTUS_V2 is ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage.PLUTUS_V3 is ScriptLanguage.PLUTUS_V3
        assert ScriptLanguage(0) is ScriptLanguage.NATIVE
        assert ScriptLanguage(1) is ScriptLanguage.PLUTUS_V1
        assert ScriptLanguage(2) is ScriptLanguage.PLUTUS_V2
        assert ScriptLanguage(3) is ScriptLanguage.PLUTUS_V3

    def test_script_language_in_conditional(self):
        """Test using ScriptLanguage in conditional statements."""
        lang = ScriptLanguage.NATIVE
        if lang == ScriptLanguage.NATIVE:
            result = "native"
        else:
            result = "plutus"
        assert result == "native"

        lang = ScriptLanguage.PLUTUS_V2
        if lang in (ScriptLanguage.PLUTUS_V1, ScriptLanguage.PLUTUS_V2, ScriptLanguage.PLUTUS_V3):
            result = "plutus"
        else:
            result = "native"
        assert result == "plutus"

    def test_script_language_sorting(self):
        """Test sorting ScriptLanguage values."""
        languages = [
            ScriptLanguage.PLUTUS_V3,
            ScriptLanguage.NATIVE,
            ScriptLanguage.PLUTUS_V2,
            ScriptLanguage.PLUTUS_V1
        ]
        sorted_languages = sorted(languages)
        assert sorted_languages == [
            ScriptLanguage.NATIVE,
            ScriptLanguage.PLUTUS_V1,
            ScriptLanguage.PLUTUS_V2,
            ScriptLanguage.PLUTUS_V3
        ]

    def test_script_language_max_min(self):
        """Test max and min operations with ScriptLanguage values."""
        all_languages = list(ScriptLanguage)
        assert max(all_languages) == ScriptLanguage.PLUTUS_V3
        assert min(all_languages) == ScriptLanguage.NATIVE

    def test_script_language_documentation(self):
        """Test that ScriptLanguage has proper documentation."""
        assert ScriptLanguage.__doc__ is not None
        assert len(ScriptLanguage.__doc__.strip()) > 0
