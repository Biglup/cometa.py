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
from cometa import PlutusLanguageVersion


class TestPlutusLanguageVersion:
    """Tests for the PlutusLanguageVersion enum."""

    def test_plutus_language_version_values(self):
        """Test that PlutusLanguageVersion enum values are correct."""
        assert PlutusLanguageVersion.V1 == 0
        assert PlutusLanguageVersion.V2 == 1
        assert PlutusLanguageVersion.V3 == 2

    def test_plutus_language_version_from_int(self):
        """Test creating PlutusLanguageVersion from integer values."""
        assert PlutusLanguageVersion(0) == PlutusLanguageVersion.V1
        assert PlutusLanguageVersion(1) == PlutusLanguageVersion.V2
        assert PlutusLanguageVersion(2) == PlutusLanguageVersion.V3

    def test_plutus_language_version_comparison(self):
        """Test comparison between PlutusLanguageVersion values."""
        assert PlutusLanguageVersion.V1 != PlutusLanguageVersion.V2
        assert PlutusLanguageVersion.V1 == PlutusLanguageVersion.V1
        assert PlutusLanguageVersion.V2 == PlutusLanguageVersion.V2
        assert PlutusLanguageVersion.V3 == PlutusLanguageVersion.V3
        assert PlutusLanguageVersion.V1 != PlutusLanguageVersion.V3
        assert PlutusLanguageVersion.V2 != PlutusLanguageVersion.V3

    def test_plutus_language_version_names(self):
        """Test that PlutusLanguageVersion enum has correct names."""
        assert PlutusLanguageVersion.V1.name == "V1"
        assert PlutusLanguageVersion.V2.name == "V2"
        assert PlutusLanguageVersion.V3.name == "V3"

    def test_plutus_language_version_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            PlutusLanguageVersion(3)
        with pytest.raises(ValueError):
            PlutusLanguageVersion(-1)
        with pytest.raises(ValueError):
            PlutusLanguageVersion(100)

    def test_plutus_language_version_is_int_enum(self):
        """Test that PlutusLanguageVersion values can be used as integers."""
        assert isinstance(PlutusLanguageVersion.V1, int)
        assert isinstance(PlutusLanguageVersion.V2, int)
        assert isinstance(PlutusLanguageVersion.V3, int)
        assert PlutusLanguageVersion.V1 + 1 == 1
        assert PlutusLanguageVersion.V2 - 1 == 0
        assert PlutusLanguageVersion.V3 - 1 == 1

    def test_plutus_language_version_iteration(self):
        """Test iteration over PlutusLanguageVersion enum."""
        values = list(PlutusLanguageVersion)
        assert len(values) == 3
        assert PlutusLanguageVersion.V1 in values
        assert PlutusLanguageVersion.V2 in values
        assert PlutusLanguageVersion.V3 in values

    def test_plutus_language_version_membership(self):
        """Test membership testing with PlutusLanguageVersion."""
        assert 0 in PlutusLanguageVersion.__members__.values()
        assert 1 in PlutusLanguageVersion.__members__.values()
        assert 2 in PlutusLanguageVersion.__members__.values()
        assert "V1" in PlutusLanguageVersion.__members__
        assert "V2" in PlutusLanguageVersion.__members__
        assert "V3" in PlutusLanguageVersion.__members__

    def test_plutus_language_version_string_representation(self):
        """Test string representation of PlutusLanguageVersion values."""
        assert str(PlutusLanguageVersion.V1) == "PlutusLanguageVersion.V1"
        assert str(PlutusLanguageVersion.V2) == "PlutusLanguageVersion.V2"
        assert str(PlutusLanguageVersion.V3) == "PlutusLanguageVersion.V3"

    def test_plutus_language_version_repr(self):
        """Test repr of PlutusLanguageVersion values."""
        assert repr(PlutusLanguageVersion.V1) == "<PlutusLanguageVersion.V1: 0>"
        assert repr(PlutusLanguageVersion.V2) == "<PlutusLanguageVersion.V2: 1>"
        assert repr(PlutusLanguageVersion.V3) == "<PlutusLanguageVersion.V3: 2>"

    def test_plutus_language_version_bool_conversion(self):
        """Test boolean conversion of PlutusLanguageVersion values."""
        assert bool(PlutusLanguageVersion.V1) is False
        assert bool(PlutusLanguageVersion.V2) is True
        assert bool(PlutusLanguageVersion.V3) is True

    def test_plutus_language_version_arithmetic(self):
        """Test arithmetic operations with PlutusLanguageVersion values."""
        assert PlutusLanguageVersion.V1 + PlutusLanguageVersion.V2 == 1
        assert PlutusLanguageVersion.V2 * 2 == 2
        assert PlutusLanguageVersion.V2 // 1 == 1
        assert PlutusLanguageVersion.V3 - PlutusLanguageVersion.V1 == 2
        assert PlutusLanguageVersion.V1 + 2 == 2

    def test_plutus_language_version_hash(self):
        """Test that PlutusLanguageVersion values are hashable."""
        version_set = {
            PlutusLanguageVersion.V1,
            PlutusLanguageVersion.V2,
            PlutusLanguageVersion.V3,
        }
        assert len(version_set) == 3
        assert PlutusLanguageVersion.V1 in version_set
        assert PlutusLanguageVersion.V2 in version_set
        assert PlutusLanguageVersion.V3 in version_set

    def test_plutus_language_version_as_dict_key(self):
        """Test using PlutusLanguageVersion as dictionary key."""
        version_dict = {
            PlutusLanguageVersion.V1: "v1",
            PlutusLanguageVersion.V2: "v2",
            PlutusLanguageVersion.V3: "v3",
        }
        assert version_dict[PlutusLanguageVersion.V1] == "v1"
        assert version_dict[PlutusLanguageVersion.V2] == "v2"
        assert version_dict[PlutusLanguageVersion.V3] == "v3"

    def test_plutus_language_version_ordering(self):
        """Test ordering comparison between PlutusLanguageVersion values."""
        assert PlutusLanguageVersion.V1 < PlutusLanguageVersion.V2
        assert PlutusLanguageVersion.V2 < PlutusLanguageVersion.V3
        assert PlutusLanguageVersion.V3 > PlutusLanguageVersion.V1
        assert PlutusLanguageVersion.V1 <= PlutusLanguageVersion.V1
        assert PlutusLanguageVersion.V3 >= PlutusLanguageVersion.V3
        assert PlutusLanguageVersion.V2 > PlutusLanguageVersion.V1
        assert PlutusLanguageVersion.V3 >= PlutusLanguageVersion.V2

    def test_plutus_language_version_unique_values(self):
        """Test that all PlutusLanguageVersion values are unique."""
        values = [
            PlutusLanguageVersion.V1,
            PlutusLanguageVersion.V2,
            PlutusLanguageVersion.V3,
        ]
        assert len(set(values)) == len(values)

    def test_plutus_language_version_exhaustive_coverage(self):
        """Test all expected language versions are present."""
        expected_versions = {"V1", "V2", "V3"}
        actual_versions = set(PlutusLanguageVersion.__members__.keys())
        assert expected_versions == actual_versions

    def test_plutus_language_version_alonzo_hard_fork(self):
        """Test V1 was introduced in Alonzo hard fork."""
        assert PlutusLanguageVersion.V1 == 0

    def test_plutus_language_version_vasil_hard_fork(self):
        """Test V2 was introduced in Vasil hard fork."""
        assert PlutusLanguageVersion.V2 == 1

    def test_plutus_language_version_conway_hard_fork(self):
        """Test V3 was introduced in Conway hard fork."""
        assert PlutusLanguageVersion.V3 == 2

    def test_plutus_language_version_count(self):
        """Test total number of language versions."""
        assert len(PlutusLanguageVersion) == 3

    def test_plutus_language_version_sequential(self):
        """Test that version values are sequential starting from 0."""
        versions = sorted(PlutusLanguageVersion)
        for i, version in enumerate(versions):
            assert version == i

    def test_plutus_language_version_type_error_with_string(self):
        """Test that passing a string raises TypeError."""
        with pytest.raises((ValueError, KeyError)):
            PlutusLanguageVersion("V1")

    def test_plutus_language_version_type_error_with_float(self):
        """Test that passing a float raises TypeError."""
        with pytest.raises((ValueError, TypeError)):
            PlutusLanguageVersion(1.5)

    def test_plutus_language_version_type_error_with_none(self):
        """Test that passing None raises ValueError."""
        with pytest.raises(ValueError):
            PlutusLanguageVersion(None)

    def test_plutus_language_version_identity(self):
        """Test that enum members are singletons."""
        v1_a = PlutusLanguageVersion.V1
        v1_b = PlutusLanguageVersion(0)
        assert v1_a is v1_b

        v2_a = PlutusLanguageVersion.V2
        v2_b = PlutusLanguageVersion(1)
        assert v2_a is v2_b

        v3_a = PlutusLanguageVersion.V3
        v3_b = PlutusLanguageVersion(2)
        assert v3_a is v3_b

    def test_plutus_language_version_min_max(self):
        """Test min and max values of PlutusLanguageVersion."""
        all_versions = list(PlutusLanguageVersion)
        assert min(all_versions) == PlutusLanguageVersion.V1
        assert max(all_versions) == PlutusLanguageVersion.V3

    def test_plutus_language_version_in_condition(self):
        """Test using PlutusLanguageVersion in conditional statements."""
        version = PlutusLanguageVersion.V2
        if version == PlutusLanguageVersion.V1:
            pytest.fail("Should not match V1")
        elif version == PlutusLanguageVersion.V2:
            assert True
        else:
            pytest.fail("Should match V2")

    def test_plutus_language_version_switch_case_pattern(self):
        """Test pattern matching style with PlutusLanguageVersion."""
        def get_description(version):
            if version == PlutusLanguageVersion.V1:
                return "Alonzo"
            elif version == PlutusLanguageVersion.V2:
                return "Vasil"
            elif version == PlutusLanguageVersion.V3:
                return "Conway"
            else:
                return "Unknown"

        assert get_description(PlutusLanguageVersion.V1) == "Alonzo"
        assert get_description(PlutusLanguageVersion.V2) == "Vasil"
        assert get_description(PlutusLanguageVersion.V3) == "Conway"

    def test_plutus_language_version_serialization_value(self):
        """Test that enum values match C library constants."""
        assert PlutusLanguageVersion.V1.value == 0
        assert PlutusLanguageVersion.V2.value == 1
        assert PlutusLanguageVersion.V3.value == 2
