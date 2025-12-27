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
from cometa import CborTag


class TestCborTag:
    """Tests for the CborTag enum."""

    def test_date_time_string_value(self):
        """Test that DATE_TIME_STRING has the correct value."""
        assert CborTag.DATE_TIME_STRING == 0

    def test_unix_time_seconds_value(self):
        """Test that UNIX_TIME_SECONDS has the correct value."""
        assert CborTag.UNIX_TIME_SECONDS == 1

    def test_unsigned_big_num_value(self):
        """Test that UNSIGNED_BIG_NUM has the correct value."""
        assert CborTag.UNSIGNED_BIG_NUM == 2

    def test_negative_big_num_value(self):
        """Test that NEGATIVE_BIG_NUM has the correct value."""
        assert CborTag.NEGATIVE_BIG_NUM == 3

    def test_decimal_fraction_value(self):
        """Test that DECIMAL_FRACTION has the correct value."""
        assert CborTag.DECIMAL_FRACTION == 4

    def test_big_float_value(self):
        """Test that BIG_FLOAT has the correct value."""
        assert CborTag.BIG_FLOAT == 5

    def test_encoded_cbor_data_item_value(self):
        """Test that ENCODED_CBOR_DATA_ITEM has the correct value."""
        assert CborTag.ENCODED_CBOR_DATA_ITEM == 24

    def test_encoded_cbor_rational_number_value(self):
        """Test that ENCODED_CBOR_RATIONAL_NUMBER has the correct value."""
        assert CborTag.ENCODED_CBOR_RATIONAL_NUMBER == 30

    def test_set_value(self):
        """Test that SET has the correct value."""
        assert CborTag.SET == 258

    def test_self_describe_cbor_value(self):
        """Test that SELF_DESCRIBE_CBOR has the correct value."""
        assert CborTag.SELF_DESCRIBE_CBOR == 55799


class TestCborTagToString:
    """Tests for the to_string() method of CborTag."""

    def test_date_time_string_to_string(self):
        """Test converting DATE_TIME_STRING to string."""
        tag = CborTag.DATE_TIME_STRING
        result = tag.to_string()
        assert result == "Tag: Date Time String"

    def test_unix_time_seconds_to_string(self):
        """Test converting UNIX_TIME_SECONDS to string."""
        tag = CborTag.UNIX_TIME_SECONDS
        result = tag.to_string()
        assert result == "Tag: Unix Time Seconds"

    def test_unsigned_big_num_to_string(self):
        """Test converting UNSIGNED_BIG_NUM to string."""
        tag = CborTag.UNSIGNED_BIG_NUM
        result = tag.to_string()
        assert result == "Tag: Unsigned Bignum"

    def test_negative_big_num_to_string(self):
        """Test converting NEGATIVE_BIG_NUM to string."""
        tag = CborTag.NEGATIVE_BIG_NUM
        result = tag.to_string()
        assert result == "Tag: Negative Bignum"

    def test_decimal_fraction_to_string(self):
        """Test converting DECIMAL_FRACTION to string."""
        tag = CborTag.DECIMAL_FRACTION
        result = tag.to_string()
        assert result == "Tag: Decimal Fraction"

    def test_big_float_to_string(self):
        """Test converting BIG_FLOAT to string."""
        tag = CborTag.BIG_FLOAT
        result = tag.to_string()
        assert result == "Tag: Big Float"

    def test_encoded_cbor_data_item_to_string(self):
        """Test converting ENCODED_CBOR_DATA_ITEM to string."""
        tag = CborTag.ENCODED_CBOR_DATA_ITEM
        result = tag.to_string()
        assert result == "Tag: CBOR Data Item"

    def test_encoded_cbor_rational_number_to_string(self):
        """Test converting ENCODED_CBOR_RATIONAL_NUMBER to string."""
        tag = CborTag.ENCODED_CBOR_RATIONAL_NUMBER
        result = tag.to_string()
        assert result == "Tag: Rational Number"

    def test_set_to_string(self):
        """Test converting SET to string."""
        tag = CborTag.SET
        result = tag.to_string()
        assert result == "Tag: Set"

    def test_self_describe_cbor_to_string(self):
        """Test converting SELF_DESCRIBE_CBOR to string."""
        tag = CborTag.SELF_DESCRIBE_CBOR
        result = tag.to_string()
        assert result == "Tag: Self Describe CBOR"

    def test_all_enum_members_have_to_string(self):
        """Test that all enum members can be converted to string without error."""
        for tag in CborTag:
            result = tag.to_string()
            assert isinstance(result, str)
            assert len(result) > 0


class TestCborTagEdgeCases:
    """Tests for edge cases and invalid values."""

    def test_enum_comparison(self):
        """Test that enum members can be compared."""
        assert CborTag.DATE_TIME_STRING == CborTag.DATE_TIME_STRING
        assert CborTag.DATE_TIME_STRING != CborTag.UNIX_TIME_SECONDS

    def test_enum_identity(self):
        """Test that enum members maintain identity."""
        tag1 = CborTag.DATE_TIME_STRING
        tag2 = CborTag.DATE_TIME_STRING
        assert tag1 is tag2

    def test_enum_int_value(self):
        """Test that enum members can be used as integers."""
        assert int(CborTag.DATE_TIME_STRING) == 0
        assert int(CborTag.UNIX_TIME_SECONDS) == 1
        assert int(CborTag.UNSIGNED_BIG_NUM) == 2
        assert int(CborTag.NEGATIVE_BIG_NUM) == 3
        assert int(CborTag.DECIMAL_FRACTION) == 4
        assert int(CborTag.BIG_FLOAT) == 5
        assert int(CborTag.ENCODED_CBOR_DATA_ITEM) == 24
        assert int(CborTag.ENCODED_CBOR_RATIONAL_NUMBER) == 30
        assert int(CborTag.SET) == 258
        assert int(CborTag.SELF_DESCRIBE_CBOR) == 55799

    def test_enum_iteration(self):
        """Test that we can iterate over all enum members."""
        all_tags = list(CborTag)
        assert len(all_tags) == 10
        assert CborTag.DATE_TIME_STRING in all_tags
        assert CborTag.UNIX_TIME_SECONDS in all_tags
        assert CborTag.UNSIGNED_BIG_NUM in all_tags
        assert CborTag.NEGATIVE_BIG_NUM in all_tags
        assert CborTag.DECIMAL_FRACTION in all_tags
        assert CborTag.BIG_FLOAT in all_tags
        assert CborTag.ENCODED_CBOR_DATA_ITEM in all_tags
        assert CborTag.ENCODED_CBOR_RATIONAL_NUMBER in all_tags
        assert CborTag.SET in all_tags
        assert CborTag.SELF_DESCRIBE_CBOR in all_tags

    def test_enum_membership(self):
        """Test enum membership checks."""
        assert CborTag.DATE_TIME_STRING in CborTag
        assert CborTag.UNIX_TIME_SECONDS in CborTag
        assert CborTag.UNSIGNED_BIG_NUM in CborTag
        assert CborTag.NEGATIVE_BIG_NUM in CborTag
        assert CborTag.DECIMAL_FRACTION in CborTag
        assert CborTag.BIG_FLOAT in CborTag
        assert CborTag.ENCODED_CBOR_DATA_ITEM in CborTag
        assert CborTag.ENCODED_CBOR_RATIONAL_NUMBER in CborTag
        assert CborTag.SET in CborTag
        assert CborTag.SELF_DESCRIBE_CBOR in CborTag

    def test_enum_name_attribute(self):
        """Test that enum members have name attribute."""
        assert CborTag.DATE_TIME_STRING.name == "DATE_TIME_STRING"
        assert CborTag.UNIX_TIME_SECONDS.name == "UNIX_TIME_SECONDS"
        assert CborTag.UNSIGNED_BIG_NUM.name == "UNSIGNED_BIG_NUM"
        assert CborTag.NEGATIVE_BIG_NUM.name == "NEGATIVE_BIG_NUM"
        assert CborTag.DECIMAL_FRACTION.name == "DECIMAL_FRACTION"
        assert CborTag.BIG_FLOAT.name == "BIG_FLOAT"
        assert CborTag.ENCODED_CBOR_DATA_ITEM.name == "ENCODED_CBOR_DATA_ITEM"
        assert CborTag.ENCODED_CBOR_RATIONAL_NUMBER.name == "ENCODED_CBOR_RATIONAL_NUMBER"
        assert CborTag.SET.name == "SET"
        assert CborTag.SELF_DESCRIBE_CBOR.name == "SELF_DESCRIBE_CBOR"

    def test_enum_value_attribute(self):
        """Test that enum members have value attribute."""
        assert CborTag.DATE_TIME_STRING.value == 0
        assert CborTag.UNIX_TIME_SECONDS.value == 1
        assert CborTag.UNSIGNED_BIG_NUM.value == 2
        assert CborTag.NEGATIVE_BIG_NUM.value == 3
        assert CborTag.DECIMAL_FRACTION.value == 4
        assert CborTag.BIG_FLOAT.value == 5
        assert CborTag.ENCODED_CBOR_DATA_ITEM.value == 24
        assert CborTag.ENCODED_CBOR_RATIONAL_NUMBER.value == 30
        assert CborTag.SET.value == 258
        assert CborTag.SELF_DESCRIBE_CBOR.value == 55799

    def test_from_value(self):
        """Test creating enum from integer value."""
        assert CborTag(0) == CborTag.DATE_TIME_STRING
        assert CborTag(1) == CborTag.UNIX_TIME_SECONDS
        assert CborTag(2) == CborTag.UNSIGNED_BIG_NUM
        assert CborTag(3) == CborTag.NEGATIVE_BIG_NUM
        assert CborTag(4) == CborTag.DECIMAL_FRACTION
        assert CborTag(5) == CborTag.BIG_FLOAT
        assert CborTag(24) == CborTag.ENCODED_CBOR_DATA_ITEM
        assert CborTag(30) == CborTag.ENCODED_CBOR_RATIONAL_NUMBER
        assert CborTag(258) == CborTag.SET
        assert CborTag(55799) == CborTag.SELF_DESCRIBE_CBOR

    def test_invalid_value_raises_error(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborTag(999)

    def test_invalid_value_raises_error_negative(self):
        """Test that invalid negative values raise ValueError."""
        with pytest.raises(ValueError):
            CborTag(-1)

    def test_invalid_value_raises_error_large(self):
        """Test that large invalid values raise ValueError."""
        with pytest.raises(ValueError):
            CborTag(999999)

    def test_string_representation(self):
        """Test string representation of enum members."""
        assert str(CborTag.DATE_TIME_STRING) == "CborTag.DATE_TIME_STRING"
        assert repr(CborTag.UNIX_TIME_SECONDS) == "<CborTag.UNIX_TIME_SECONDS: 1>"

    def test_invalid_custom_values_raise_error(self):
        """Test that custom tag values that are not in the enum raise ValueError."""
        custom_tags = [6, 7, 10, 25, 31, 100, 1000, 10000]
        for value in custom_tags:
            with pytest.raises(ValueError):
                CborTag(value)

    def test_boundary_values(self):
        """Test behavior at boundary values."""
        assert CborTag(0).to_string() == "Tag: Date Time String"
        assert CborTag(5).to_string() == "Tag: Big Float"
        assert CborTag(55799).to_string() == "Tag: Self Describe CBOR"
