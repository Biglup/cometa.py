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
from cometa import NativeScriptType


class TestNativeScriptType:
    """Tests for the NativeScriptType enum."""

    def test_native_script_type_values(self):
        """Test that NativeScriptType enum values are correct."""
        assert NativeScriptType.REQUIRE_PUBKEY == 0
        assert NativeScriptType.REQUIRE_ALL_OF == 1
        assert NativeScriptType.REQUIRE_ANY_OF == 2
        assert NativeScriptType.REQUIRE_N_OF_K == 3
        assert NativeScriptType.INVALID_BEFORE == 4
        assert NativeScriptType.INVALID_AFTER == 5

    def test_native_script_type_from_int(self):
        """Test creating NativeScriptType from integer values."""
        assert NativeScriptType(0) == NativeScriptType.REQUIRE_PUBKEY
        assert NativeScriptType(1) == NativeScriptType.REQUIRE_ALL_OF
        assert NativeScriptType(2) == NativeScriptType.REQUIRE_ANY_OF
        assert NativeScriptType(3) == NativeScriptType.REQUIRE_N_OF_K
        assert NativeScriptType(4) == NativeScriptType.INVALID_BEFORE
        assert NativeScriptType(5) == NativeScriptType.INVALID_AFTER

    def test_native_script_type_comparison(self):
        """Test comparison between NativeScriptType values."""
        assert NativeScriptType.REQUIRE_PUBKEY != NativeScriptType.REQUIRE_ALL_OF
        assert NativeScriptType.REQUIRE_PUBKEY == NativeScriptType.REQUIRE_PUBKEY
        assert NativeScriptType.REQUIRE_ALL_OF == NativeScriptType.REQUIRE_ALL_OF
        assert NativeScriptType.REQUIRE_ANY_OF == NativeScriptType.REQUIRE_ANY_OF
        assert NativeScriptType.REQUIRE_N_OF_K == NativeScriptType.REQUIRE_N_OF_K
        assert NativeScriptType.INVALID_BEFORE == NativeScriptType.INVALID_BEFORE
        assert NativeScriptType.INVALID_AFTER == NativeScriptType.INVALID_AFTER

    def test_native_script_type_names(self):
        """Test that NativeScriptType enum has correct names."""
        assert NativeScriptType.REQUIRE_PUBKEY.name == "REQUIRE_PUBKEY"
        assert NativeScriptType.REQUIRE_ALL_OF.name == "REQUIRE_ALL_OF"
        assert NativeScriptType.REQUIRE_ANY_OF.name == "REQUIRE_ANY_OF"
        assert NativeScriptType.REQUIRE_N_OF_K.name == "REQUIRE_N_OF_K"
        assert NativeScriptType.INVALID_BEFORE.name == "INVALID_BEFORE"
        assert NativeScriptType.INVALID_AFTER.name == "INVALID_AFTER"

    def test_native_script_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            NativeScriptType(6)
        with pytest.raises(ValueError):
            NativeScriptType(-1)
        with pytest.raises(ValueError):
            NativeScriptType(100)

    def test_native_script_type_is_int_enum(self):
        """Test that NativeScriptType values can be used as integers."""
        assert isinstance(NativeScriptType.REQUIRE_PUBKEY, int)
        assert isinstance(NativeScriptType.REQUIRE_ALL_OF, int)
        assert isinstance(NativeScriptType.REQUIRE_ANY_OF, int)
        assert isinstance(NativeScriptType.REQUIRE_N_OF_K, int)
        assert isinstance(NativeScriptType.INVALID_BEFORE, int)
        assert isinstance(NativeScriptType.INVALID_AFTER, int)
        assert NativeScriptType.REQUIRE_PUBKEY + 1 == 1
        assert NativeScriptType.REQUIRE_ALL_OF - 1 == 0
        assert NativeScriptType.INVALID_AFTER - 1 == 4

    def test_native_script_type_iteration(self):
        """Test iteration over NativeScriptType enum."""
        values = list(NativeScriptType)
        assert len(values) == 6
        assert NativeScriptType.REQUIRE_PUBKEY in values
        assert NativeScriptType.REQUIRE_ALL_OF in values
        assert NativeScriptType.REQUIRE_ANY_OF in values
        assert NativeScriptType.REQUIRE_N_OF_K in values
        assert NativeScriptType.INVALID_BEFORE in values
        assert NativeScriptType.INVALID_AFTER in values

    def test_native_script_type_membership(self):
        """Test membership testing with NativeScriptType."""
        assert 0 in NativeScriptType.__members__.values()
        assert 1 in NativeScriptType.__members__.values()
        assert 2 in NativeScriptType.__members__.values()
        assert 3 in NativeScriptType.__members__.values()
        assert 4 in NativeScriptType.__members__.values()
        assert 5 in NativeScriptType.__members__.values()
        assert "REQUIRE_PUBKEY" in NativeScriptType.__members__
        assert "REQUIRE_ALL_OF" in NativeScriptType.__members__
        assert "REQUIRE_ANY_OF" in NativeScriptType.__members__
        assert "REQUIRE_N_OF_K" in NativeScriptType.__members__
        assert "INVALID_BEFORE" in NativeScriptType.__members__
        assert "INVALID_AFTER" in NativeScriptType.__members__

    def test_native_script_type_string_representation(self):
        """Test string representation of NativeScriptType values."""
        assert str(NativeScriptType.REQUIRE_PUBKEY) == "NativeScriptType.REQUIRE_PUBKEY"
        assert str(NativeScriptType.REQUIRE_ALL_OF) == "NativeScriptType.REQUIRE_ALL_OF"
        assert str(NativeScriptType.REQUIRE_ANY_OF) == "NativeScriptType.REQUIRE_ANY_OF"
        assert str(NativeScriptType.REQUIRE_N_OF_K) == "NativeScriptType.REQUIRE_N_OF_K"
        assert str(NativeScriptType.INVALID_BEFORE) == "NativeScriptType.INVALID_BEFORE"
        assert str(NativeScriptType.INVALID_AFTER) == "NativeScriptType.INVALID_AFTER"

    def test_native_script_type_repr(self):
        """Test repr of NativeScriptType values."""
        assert repr(NativeScriptType.REQUIRE_PUBKEY) == "<NativeScriptType.REQUIRE_PUBKEY: 0>"
        assert repr(NativeScriptType.REQUIRE_ALL_OF) == "<NativeScriptType.REQUIRE_ALL_OF: 1>"
        assert repr(NativeScriptType.REQUIRE_ANY_OF) == "<NativeScriptType.REQUIRE_ANY_OF: 2>"
        assert repr(NativeScriptType.REQUIRE_N_OF_K) == "<NativeScriptType.REQUIRE_N_OF_K: 3>"
        assert repr(NativeScriptType.INVALID_BEFORE) == "<NativeScriptType.INVALID_BEFORE: 4>"
        assert repr(NativeScriptType.INVALID_AFTER) == "<NativeScriptType.INVALID_AFTER: 5>"

    def test_native_script_type_bool_conversion(self):
        """Test boolean conversion of NativeScriptType values."""
        assert bool(NativeScriptType.REQUIRE_PUBKEY) is False
        assert bool(NativeScriptType.REQUIRE_ALL_OF) is True
        assert bool(NativeScriptType.REQUIRE_ANY_OF) is True
        assert bool(NativeScriptType.REQUIRE_N_OF_K) is True
        assert bool(NativeScriptType.INVALID_BEFORE) is True
        assert bool(NativeScriptType.INVALID_AFTER) is True

    def test_native_script_type_arithmetic(self):
        """Test arithmetic operations with NativeScriptType values."""
        assert NativeScriptType.REQUIRE_PUBKEY + NativeScriptType.REQUIRE_ALL_OF == 1
        assert NativeScriptType.REQUIRE_ALL_OF * 2 == 2
        assert NativeScriptType.REQUIRE_ALL_OF // 1 == 1
        assert NativeScriptType.INVALID_AFTER - NativeScriptType.REQUIRE_PUBKEY == 5
        assert NativeScriptType.REQUIRE_N_OF_K + 2 == 5

    def test_native_script_type_hash(self):
        """Test that NativeScriptType values are hashable."""
        script_type_set = {
            NativeScriptType.REQUIRE_PUBKEY,
            NativeScriptType.REQUIRE_ALL_OF,
            NativeScriptType.REQUIRE_ANY_OF,
            NativeScriptType.REQUIRE_N_OF_K,
            NativeScriptType.INVALID_BEFORE,
            NativeScriptType.INVALID_AFTER,
        }
        assert len(script_type_set) == 6
        assert NativeScriptType.REQUIRE_PUBKEY in script_type_set
        assert NativeScriptType.REQUIRE_ALL_OF in script_type_set
        assert NativeScriptType.REQUIRE_ANY_OF in script_type_set
        assert NativeScriptType.REQUIRE_N_OF_K in script_type_set
        assert NativeScriptType.INVALID_BEFORE in script_type_set
        assert NativeScriptType.INVALID_AFTER in script_type_set

    def test_native_script_type_as_dict_key(self):
        """Test using NativeScriptType as dictionary key."""
        script_type_dict = {
            NativeScriptType.REQUIRE_PUBKEY: "require_pubkey",
            NativeScriptType.REQUIRE_ALL_OF: "require_all_of",
            NativeScriptType.REQUIRE_ANY_OF: "require_any_of",
            NativeScriptType.REQUIRE_N_OF_K: "require_n_of_k",
            NativeScriptType.INVALID_BEFORE: "invalid_before",
            NativeScriptType.INVALID_AFTER: "invalid_after",
        }
        assert script_type_dict[NativeScriptType.REQUIRE_PUBKEY] == "require_pubkey"
        assert script_type_dict[NativeScriptType.REQUIRE_ALL_OF] == "require_all_of"
        assert script_type_dict[NativeScriptType.REQUIRE_ANY_OF] == "require_any_of"
        assert script_type_dict[NativeScriptType.REQUIRE_N_OF_K] == "require_n_of_k"
        assert script_type_dict[NativeScriptType.INVALID_BEFORE] == "invalid_before"
        assert script_type_dict[NativeScriptType.INVALID_AFTER] == "invalid_after"

    def test_native_script_type_ordering(self):
        """Test ordering comparison between NativeScriptType values."""
        assert NativeScriptType.REQUIRE_PUBKEY < NativeScriptType.REQUIRE_ALL_OF
        assert NativeScriptType.REQUIRE_ALL_OF < NativeScriptType.REQUIRE_ANY_OF
        assert NativeScriptType.REQUIRE_ANY_OF < NativeScriptType.REQUIRE_N_OF_K
        assert NativeScriptType.REQUIRE_N_OF_K < NativeScriptType.INVALID_BEFORE
        assert NativeScriptType.INVALID_BEFORE < NativeScriptType.INVALID_AFTER
        assert NativeScriptType.INVALID_AFTER > NativeScriptType.REQUIRE_PUBKEY
        assert NativeScriptType.REQUIRE_PUBKEY <= NativeScriptType.REQUIRE_PUBKEY
        assert NativeScriptType.INVALID_AFTER >= NativeScriptType.INVALID_AFTER

    def test_native_script_type_unique_values(self):
        """Test that all NativeScriptType values are unique."""
        values = [
            NativeScriptType.REQUIRE_PUBKEY,
            NativeScriptType.REQUIRE_ALL_OF,
            NativeScriptType.REQUIRE_ANY_OF,
            NativeScriptType.REQUIRE_N_OF_K,
            NativeScriptType.INVALID_BEFORE,
            NativeScriptType.INVALID_AFTER,
        ]
        assert len(set(values)) == len(values)

    def test_native_script_type_exhaustive_coverage(self):
        """Test all expected script types are present."""
        expected_types = {
            "REQUIRE_PUBKEY",
            "REQUIRE_ALL_OF",
            "REQUIRE_ANY_OF",
            "REQUIRE_N_OF_K",
            "INVALID_BEFORE",
            "INVALID_AFTER",
        }
        actual_types = set(NativeScriptType.__members__.keys())
        assert expected_types == actual_types
