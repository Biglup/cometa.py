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
from cometa import CredentialType


class TestCredentialType:
    """Tests for the CredentialType enum."""

    def test_credential_type_values(self):
        """Test that CredentialType enum values are correct."""
        assert CredentialType.KEY_HASH == 0
        assert CredentialType.SCRIPT_HASH == 1

    def test_credential_type_from_int(self):
        """Test creating CredentialType from integer values."""
        assert CredentialType(0) == CredentialType.KEY_HASH
        assert CredentialType(1) == CredentialType.SCRIPT_HASH

    def test_credential_type_comparison(self):
        """Test comparison between CredentialType values."""
        assert CredentialType.KEY_HASH != CredentialType.SCRIPT_HASH
        assert CredentialType.KEY_HASH == CredentialType.KEY_HASH
        assert CredentialType.SCRIPT_HASH == CredentialType.SCRIPT_HASH

    def test_credential_type_names(self):
        """Test that CredentialType enum has correct names."""
        assert CredentialType.KEY_HASH.name == "KEY_HASH"
        assert CredentialType.SCRIPT_HASH.name == "SCRIPT_HASH"

    def test_credential_type_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CredentialType(2)
        with pytest.raises(ValueError):
            CredentialType(-1)
        with pytest.raises(ValueError):
            CredentialType(100)

    def test_credential_type_is_int_enum(self):
        """Test that CredentialType values can be used as integers."""
        assert isinstance(CredentialType.KEY_HASH, int)
        assert isinstance(CredentialType.SCRIPT_HASH, int)
        assert CredentialType.KEY_HASH + 1 == 1
        assert CredentialType.SCRIPT_HASH - 1 == 0

    def test_credential_type_iteration(self):
        """Test iteration over CredentialType enum."""
        values = list(CredentialType)
        assert len(values) == 2
        assert CredentialType.KEY_HASH in values
        assert CredentialType.SCRIPT_HASH in values

    def test_credential_type_membership(self):
        """Test membership testing with CredentialType."""
        assert 0 in CredentialType.__members__.values()
        assert 1 in CredentialType.__members__.values()
        assert "KEY_HASH" in CredentialType.__members__
        assert "SCRIPT_HASH" in CredentialType.__members__

    def test_credential_type_string_representation(self):
        """Test string representation of CredentialType values."""
        assert str(CredentialType.KEY_HASH) == "CredentialType.KEY_HASH"
        assert str(CredentialType.SCRIPT_HASH) == "CredentialType.SCRIPT_HASH"

    def test_credential_type_repr(self):
        """Test repr of CredentialType values."""
        assert repr(CredentialType.KEY_HASH) == "<CredentialType.KEY_HASH: 0>"
        assert repr(CredentialType.SCRIPT_HASH) == "<CredentialType.SCRIPT_HASH: 1>"

    def test_credential_type_bool_conversion(self):
        """Test boolean conversion of CredentialType values."""
        assert bool(CredentialType.KEY_HASH) is False
        assert bool(CredentialType.SCRIPT_HASH) is True

    def test_credential_type_arithmetic(self):
        """Test arithmetic operations with CredentialType values."""
        assert CredentialType.KEY_HASH + CredentialType.SCRIPT_HASH == 1
        assert CredentialType.SCRIPT_HASH * 2 == 2
        assert CredentialType.SCRIPT_HASH // 1 == 1

    def test_credential_type_hash(self):
        """Test that CredentialType values are hashable."""
        credential_set = {CredentialType.KEY_HASH, CredentialType.SCRIPT_HASH}
        assert len(credential_set) == 2
        assert CredentialType.KEY_HASH in credential_set
        assert CredentialType.SCRIPT_HASH in credential_set

    def test_credential_type_as_dict_key(self):
        """Test using CredentialType as dictionary key."""
        credential_dict = {
            CredentialType.KEY_HASH: "key_hash",
            CredentialType.SCRIPT_HASH: "script_hash"
        }
        assert credential_dict[CredentialType.KEY_HASH] == "key_hash"
        assert credential_dict[CredentialType.SCRIPT_HASH] == "script_hash"

    def test_credential_type_ordering(self):
        """Test ordering comparison between CredentialType values."""
        assert CredentialType.KEY_HASH < CredentialType.SCRIPT_HASH
        assert CredentialType.SCRIPT_HASH > CredentialType.KEY_HASH
        assert CredentialType.KEY_HASH <= CredentialType.KEY_HASH
        assert CredentialType.SCRIPT_HASH >= CredentialType.SCRIPT_HASH
