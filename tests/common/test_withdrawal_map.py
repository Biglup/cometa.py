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
from cometa import (
    WithdrawalMap,
    RewardAddress,
    RewardAddressList,
    CardanoError,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
)


REWARD_KEY = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
REWARD_SCRIPT = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"
CBOR = "a1581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d005"


class TestWithdrawalMapNew:
    """Tests for WithdrawalMap() constructor."""

    def test_can_create_empty_map(self):
        """Test that an empty WithdrawalMap can be created."""
        withdrawal_map = WithdrawalMap()
        assert withdrawal_map is not None
        assert len(withdrawal_map) == 0

    def test_new_map_is_empty(self):
        """Test that newly created map has zero length."""
        withdrawal_map = WithdrawalMap()
        assert len(withdrawal_map) == 0

    def test_new_map_is_falsy(self):
        """Test that empty map evaluates to False."""
        withdrawal_map = WithdrawalMap()
        assert not withdrawal_map

    def test_raises_error_if_invalid_ptr(self):
        """Test that invalid ptr raises an error."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError):
            WithdrawalMap(ffi.NULL)


class TestWithdrawalMapFromCbor:
    """Tests for WithdrawalMap.from_cbor() factory method."""

    def test_can_deserialize_from_cbor(self):
        """Test that WithdrawalMap can be deserialized from CBOR."""
        reader = CborReader.from_hex(CBOR)
        withdrawal_map = WithdrawalMap.from_cbor(reader)
        assert withdrawal_map is not None
        assert len(withdrawal_map) == 1

    def test_can_roundtrip_cbor(self):
        """Test that CBOR serialization roundtrips correctly."""
        reader = CborReader.from_hex(CBOR)
        withdrawal_map = WithdrawalMap.from_cbor(reader)
        writer = CborWriter()
        withdrawal_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == CBOR

    def test_raises_error_if_reader_is_none(self):
        """Test that None reader raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            WithdrawalMap.from_cbor(None)

    def test_raises_error_if_invalid_cbor_not_a_map(self):
        """Test that invalid CBOR (not a map) raises an error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            WithdrawalMap.from_cbor(reader)

    def test_raises_error_if_invalid_cbor_incomplete_map(self):
        """Test that incomplete map raises an error."""
        reader = CborReader.from_hex("a100")
        with pytest.raises(CardanoError):
            WithdrawalMap.from_cbor(reader)

    def test_raises_error_if_invalid_withdrawal_amount(self):
        """Test that invalid withdrawal amount raises an error."""
        reader = CborReader.from_hex("a1581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0ef")
        with pytest.raises(CardanoError):
            WithdrawalMap.from_cbor(reader)


class TestWithdrawalMapToCbor:
    """Tests for WithdrawalMap.to_cbor() method."""

    def test_can_serialize_empty_map(self):
        """Test that empty map can be serialized."""
        withdrawal_map = WithdrawalMap()
        writer = CborWriter()
        withdrawal_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == "a0"

    def test_can_serialize_map_with_entries(self):
        """Test that map with entries can be serialized."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 5)
        writer = CborWriter()
        withdrawal_map.to_cbor(writer)
        hex_result = writer.to_hex()
        assert hex_result == "a1581de1337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c4725105"

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            withdrawal_map.to_cbor(None)


class TestWithdrawalMapFromDict:
    """Tests for WithdrawalMap.from_dict() factory method."""

    def test_can_create_from_dict(self):
        """Test that WithdrawalMap can be created from dictionary."""
        data = {REWARD_KEY: 1000000, REWARD_SCRIPT: 2000000}
        withdrawal_map = WithdrawalMap.from_dict(data)
        assert withdrawal_map is not None
        assert len(withdrawal_map) == 2

    def test_can_create_from_empty_dict(self):
        """Test that WithdrawalMap can be created from empty dict."""
        withdrawal_map = WithdrawalMap.from_dict({})
        assert withdrawal_map is not None
        assert len(withdrawal_map) == 0

    def test_can_create_from_single_entry_dict(self):
        """Test that WithdrawalMap can be created from single entry dict."""
        withdrawal_map = WithdrawalMap.from_dict({REWARD_KEY: 1000000})
        assert len(withdrawal_map) == 1

    def test_raises_error_if_invalid_address(self):
        """Test that invalid address in dict raises an error."""
        with pytest.raises(CardanoError):
            WithdrawalMap.from_dict({"invalid_address": 1000000})


class TestWithdrawalMapInsert:
    """Tests for WithdrawalMap.insert() method."""

    def test_can_insert_entry(self):
        """Test that entry can be inserted."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        assert len(withdrawal_map) == 1

    def test_can_insert_multiple_entries(self):
        """Test that multiple entries can be inserted."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1000000)
        withdrawal_map.insert(addr2, 2000000)
        assert len(withdrawal_map) == 2

    def test_insert_allows_duplicate_keys(self):
        """Test that inserting same key multiple times is allowed (map allows duplicates)."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        withdrawal_map.insert(addr, 2000000)
        assert len(withdrawal_map) == 2

    def test_raises_error_if_address_is_none(self):
        """Test that None address raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            withdrawal_map.insert(None, 1000000)

    def test_keeps_elements_sorted(self):
        """Test that elements are kept sorted by address."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        writer = CborWriter()
        withdrawal_map.to_cbor(writer)
        hex_result = writer.to_hex()
        expected = "a2581de1337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c4725101581df1c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f02"
        assert hex_result == expected


class TestWithdrawalMapInsertEx:
    """Tests for WithdrawalMap.insert_ex() method."""

    def test_can_insert_with_bech32_string(self):
        """Test that entry can be inserted using Bech32 string."""
        withdrawal_map = WithdrawalMap()
        withdrawal_map.insert_ex(REWARD_KEY, 1000000)
        assert len(withdrawal_map) == 1

    def test_can_insert_multiple_entries_ex(self):
        """Test that multiple entries can be inserted with insert_ex."""
        withdrawal_map = WithdrawalMap()
        withdrawal_map.insert_ex(REWARD_KEY, 1000000)
        withdrawal_map.insert_ex(REWARD_SCRIPT, 2000000)
        assert len(withdrawal_map) == 2

    def test_raises_error_if_invalid_bech32_address(self):
        """Test that invalid Bech32 address raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(CardanoError):
            withdrawal_map.insert_ex("invalid_address", 1000000)


class TestWithdrawalMapGet:
    """Tests for WithdrawalMap.get() method."""

    def test_can_get_value_by_key(self):
        """Test that value can be retrieved by key."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 65)
        value = withdrawal_map.get(addr)
        assert value == 65

    def test_returns_none_if_key_not_found(self):
        """Test that None is returned if key not found."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        value = withdrawal_map.get(addr)
        assert value is None

    def test_returns_default_if_key_not_found(self):
        """Test that default value is returned if key not found."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        value = withdrawal_map.get(addr, 999)
        assert value == 999

    def test_can_get_correct_value_from_multiple_entries(self):
        """Test that correct value is retrieved when multiple entries exist."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        assert withdrawal_map.get(addr1) == 1
        assert withdrawal_map.get(addr2) == 2


class TestWithdrawalMapGetKeyAt:
    """Tests for WithdrawalMap.get_key_at() method."""

    def test_can_get_key_at_index(self):
        """Test that key can be retrieved by index."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        retrieved = withdrawal_map.get_key_at(0)
        assert retrieved is not None
        assert retrieved.to_bech32() == REWARD_KEY

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_key_at(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_key_at(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises an error."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        with pytest.raises(IndexError):
            withdrawal_map.get_key_at(1)

    def test_can_get_multiple_keys(self):
        """Test that multiple keys can be retrieved by index."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        key0 = withdrawal_map.get_key_at(0)
        key1 = withdrawal_map.get_key_at(1)
        assert key0 is not None
        assert key1 is not None


class TestWithdrawalMapGetValueAt:
    """Tests for WithdrawalMap.get_value_at() method."""

    def test_can_get_value_at_index(self):
        """Test that value can be retrieved by index."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 2)
        value = withdrawal_map.get_value_at(0)
        assert value == 2

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_value_at(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_value_at(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises an error."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        with pytest.raises(IndexError):
            withdrawal_map.get_value_at(1)


class TestWithdrawalMapGetKeyValueAt:
    """Tests for WithdrawalMap.get_key_value_at() method."""

    def test_can_get_key_value_pair_at_index(self):
        """Test that key-value pair can be retrieved by index."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 10)
        key, value = withdrawal_map.get_key_value_at(0)
        assert key is not None
        assert key.to_bech32() == REWARD_KEY
        assert value == 10

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_key_value_at(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(IndexError):
            withdrawal_map.get_key_value_at(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises an error."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        with pytest.raises(IndexError):
            withdrawal_map.get_key_value_at(1)


class TestWithdrawalMapGetKeys:
    """Tests for WithdrawalMap.get_keys() method."""

    def test_can_get_keys_from_map(self):
        """Test that all keys can be retrieved from map."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys = withdrawal_map.get_keys()
        assert isinstance(keys, RewardAddressList)
        assert len(keys) == 2

    def test_returns_empty_list_for_empty_map(self):
        """Test that empty list is returned for empty map."""
        withdrawal_map = WithdrawalMap()
        keys = withdrawal_map.get_keys()
        assert len(keys) == 0

    def test_keys_match_inserted_addresses(self):
        """Test that keys match the inserted addresses."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys = withdrawal_map.get_keys()
        key0 = keys.get(0)
        key1 = keys.get(1)
        assert key0.to_bech32() == REWARD_KEY
        assert key1.to_bech32() == REWARD_SCRIPT


class TestWithdrawalMapLen:
    """Tests for len() and __len__() method."""

    def test_len_returns_zero_for_empty_map(self):
        """Test that len returns 0 for empty map."""
        withdrawal_map = WithdrawalMap()
        assert len(withdrawal_map) == 0

    def test_len_returns_correct_value_after_insert(self):
        """Test that len returns correct value after inserting elements."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        assert len(withdrawal_map) == 1

    def test_len_increases_with_each_insertion(self):
        """Test that len increases with each insertion."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1000000)
        assert len(withdrawal_map) == 1
        withdrawal_map.insert(addr2, 2000000)
        assert len(withdrawal_map) == 2


class TestWithdrawalMapIter:
    """Tests for iteration and __iter__() method."""

    def test_can_iterate_over_map(self):
        """Test that map can be iterated."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        items = list(withdrawal_map)
        assert len(items) == 2

    def test_iteration_returns_keys(self):
        """Test that iteration returns keys (like Python dict)."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys = list(withdrawal_map)
        assert all(isinstance(key, RewardAddress) for key in keys)

    def test_can_use_for_loop(self):
        """Test that for loop works with map."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        count = 0
        for key in withdrawal_map:
            count += 1
            assert isinstance(key, RewardAddress)
        assert count == 2

    def test_empty_map_iteration(self):
        """Test that empty map can be iterated."""
        withdrawal_map = WithdrawalMap()
        items = list(withdrawal_map)
        assert len(items) == 0


class TestWithdrawalMapGetItem:
    """Tests for bracket notation and __getitem__() method."""

    def test_can_use_bracket_notation(self):
        """Test that bracket notation works for accessing values."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        assert withdrawal_map[addr] == 1000000

    def test_returns_none_if_key_not_found(self):
        """Test that None is returned if key not found."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        assert withdrawal_map[addr] is None


class TestWithdrawalMapSetItem:
    """Tests for bracket notation assignment and __setitem__() method."""

    def test_can_use_bracket_notation_for_assignment(self):
        """Test that bracket notation works for setting values."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map[addr] = 1000000
        assert len(withdrawal_map) == 1
        assert withdrawal_map[addr] == 1000000

    def test_bracket_assignment_allows_duplicates(self):
        """Test that bracket assignment allows duplicate keys."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map[addr] = 1000000
        withdrawal_map[addr] = 2000000
        assert len(withdrawal_map) == 2


class TestWithdrawalMapBool:
    """Tests for boolean evaluation and __bool__() method."""

    def test_empty_map_is_falsy(self):
        """Test that empty map evaluates to False."""
        withdrawal_map = WithdrawalMap()
        assert not withdrawal_map

    def test_non_empty_map_is_truthy(self):
        """Test that non-empty map evaluates to True."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        assert withdrawal_map

    def test_can_use_in_if_statement(self):
        """Test that map can be used in if statement."""
        withdrawal_map = WithdrawalMap()
        if withdrawal_map:
            pytest.fail("Empty map should be falsy")

        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        if not withdrawal_map:
            pytest.fail("Non-empty map should be truthy")


class TestWithdrawalMapContains:
    """Tests for membership test and __contains__() method."""

    def test_can_check_if_key_in_map(self):
        """Test that membership test works."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        assert addr in withdrawal_map

    def test_returns_false_for_key_not_in_map(self):
        """Test that membership test returns False for missing key."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1000000)
        assert addr2 not in withdrawal_map


class TestWithdrawalMapKeys:
    """Tests for WithdrawalMap.keys() method."""

    def test_keys_returns_iterator(self):
        """Test that keys method returns an iterator."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys = list(withdrawal_map.keys())
        assert len(keys) == 2

    def test_keys_match_iteration(self):
        """Test that keys() matches direct iteration."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys1 = list(withdrawal_map.keys())
        keys2 = list(withdrawal_map)
        assert len(keys1) == len(keys2)


class TestWithdrawalMapValues:
    """Tests for WithdrawalMap.values() method."""

    def test_values_returns_iterator(self):
        """Test that values method returns an iterator."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        values = list(withdrawal_map.values())
        assert len(values) == 2

    def test_values_are_correct(self):
        """Test that values are correct."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        values = list(withdrawal_map.values())
        assert 100 in values
        assert 200 in values


class TestWithdrawalMapItems:
    """Tests for WithdrawalMap.items() method."""

    def test_items_returns_iterator(self):
        """Test that items method returns an iterator."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        items = list(withdrawal_map.items())
        assert len(items) == 2

    def test_items_are_tuples(self):
        """Test that items are tuples of (key, value)."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 100)
        items = list(withdrawal_map.items())
        key, value = items[0]
        assert isinstance(key, RewardAddress)
        assert value == 100

    def test_items_match_map_contents(self):
        """Test that items match the map contents."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        items = dict(withdrawal_map.items())
        assert items[addr1] == 100
        assert items[addr2] == 200


class TestWithdrawalMapToCip116Json:
    """Tests for WithdrawalMap.to_cip116_json() method."""

    def test_can_convert_to_cip116_json(self):
        """Test that map can be converted to CIP-116 JSON."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 966)
        withdrawal_map.insert(addr2, 22563)
        writer = JsonWriter(JsonFormat.COMPACT)
        withdrawal_map.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '[{"key":"stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw","value":"966"},{"key":"stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5","value":"22563"}]'
        assert json_str == expected

    def test_can_convert_empty_map_to_json(self):
        """Test that empty map converts to empty JSON array."""
        withdrawal_map = WithdrawalMap()
        writer = JsonWriter(JsonFormat.COMPACT)
        withdrawal_map.to_cip116_json(writer)
        json_str = writer.encode()
        assert json_str == "[]"

    def test_raises_error_if_writer_is_none(self):
        """Test that None writer raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises((CardanoError, TypeError)):
            withdrawal_map.to_cip116_json(None)

    def test_raises_error_if_writer_is_not_json_writer(self):
        """Test that non-JsonWriter raises an error."""
        withdrawal_map = WithdrawalMap()
        with pytest.raises(TypeError):
            withdrawal_map.to_cip116_json("not a writer")


class TestWithdrawalMapRepr:
    """Tests for __repr__() method."""

    def test_repr_contains_class_name(self):
        """Test that repr contains class name."""
        withdrawal_map = WithdrawalMap()
        repr_str = repr(withdrawal_map)
        assert "WithdrawalMap" in repr_str

    def test_repr_contains_length(self):
        """Test that repr contains length information."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        repr_str = repr(withdrawal_map)
        assert "1" in repr_str

    def test_repr_updates_with_length(self):
        """Test that repr updates when length changes."""
        withdrawal_map = WithdrawalMap()
        repr1 = repr(withdrawal_map)
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 1000000)
        repr2 = repr(withdrawal_map)
        assert repr1 != repr2


class TestWithdrawalMapContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that WithdrawalMap can be used as a context manager."""
        with WithdrawalMap() as withdrawal_map:
            assert withdrawal_map is not None
            assert len(withdrawal_map) == 0

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit does not crash."""
        withdrawal_map = WithdrawalMap()
        with withdrawal_map:
            addr = RewardAddress.from_bech32(REWARD_KEY)
            withdrawal_map.insert(addr, 1000000)
        assert len(withdrawal_map) == 1

    def test_can_use_context_manager_with_exception(self):
        """Test that context manager handles exceptions properly."""
        try:
            with WithdrawalMap() as withdrawal_map:
                addr = RewardAddress.from_bech32(REWARD_KEY)
                withdrawal_map.insert(addr, 1000000)
                raise ValueError("test exception")
        except ValueError:
            pass


class TestWithdrawalMapEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_can_insert_many_entries(self):
        """Test that many entries can be inserted."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        for i in range(100):
            withdrawal_map.insert(addr, i)
        assert len(withdrawal_map) == 100

    def test_iteration_returns_all_keys(self):
        """Test that iteration returns all keys."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 1)
        withdrawal_map.insert(addr2, 2)
        keys = list(withdrawal_map)
        assert len(keys) == 2

    def test_values_iteration_returns_all_values(self):
        """Test that values iteration returns all values."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        values = list(withdrawal_map.values())
        assert len(values) == 2
        assert 100 in values
        assert 200 in values

    def test_items_iteration_returns_all_pairs(self):
        """Test that items iteration returns all key-value pairs."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        items = list(withdrawal_map.items())
        assert len(items) == 2

    def test_mapping_protocol_compliance(self):
        """Test that WithdrawalMap implements Mapping protocol correctly."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        assert len(withdrawal_map) == 2
        assert addr1 in withdrawal_map
        assert addr2 in withdrawal_map
        assert withdrawal_map[addr1] == 100
        assert withdrawal_map[addr2] == 200
        keys = list(withdrawal_map.keys())
        values = list(withdrawal_map.values())
        items = list(withdrawal_map.items())
        assert len(keys) == 2
        assert len(values) == 2
        assert len(items) == 2

    def test_can_use_dict_methods(self):
        """Test that dict-like methods work correctly."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map[addr1] = 100
        withdrawal_map[addr2] = 200
        assert len(withdrawal_map) == 2
        assert list(withdrawal_map.keys())
        assert list(withdrawal_map.values())
        assert list(withdrawal_map.items())

    def test_multiple_iterations(self):
        """Test that map can be iterated multiple times."""
        withdrawal_map = WithdrawalMap()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        withdrawal_map.insert(addr1, 100)
        withdrawal_map.insert(addr2, 200)
        items1 = list(withdrawal_map)
        items2 = list(withdrawal_map)
        assert len(items1) == len(items2)

    def test_large_withdrawal_amounts(self):
        """Test that large withdrawal amounts are handled correctly."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        large_amount = 45000000000000000
        withdrawal_map.insert(addr, large_amount)
        assert withdrawal_map.get(addr) == large_amount

    def test_zero_withdrawal_amount(self):
        """Test that zero withdrawal amount is handled correctly."""
        withdrawal_map = WithdrawalMap()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        withdrawal_map.insert(addr, 0)
        assert withdrawal_map.get(addr) == 0

    def test_from_dict_preserves_order(self):
        """Test that from_dict preserves insertion semantics."""
        data = {REWARD_KEY: 100, REWARD_SCRIPT: 200}
        withdrawal_map = WithdrawalMap.from_dict(data)
        assert len(withdrawal_map) == 2
        assert withdrawal_map.get_value_at(0) in [100, 200]
        assert withdrawal_map.get_value_at(1) in [100, 200]
