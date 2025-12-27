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
    RewardAddressList,
    RewardAddress,
    CardanoError,
)


REWARD_KEY = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
REWARD_SCRIPT = "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5"
INVALID_REWARD_ADDRESS = "invalid_address"


class TestRewardAddressListNew:
    """Tests for RewardAddressList() constructor."""

    def test_can_create_empty_list(self):
        """Test that an empty RewardAddressList can be created."""
        addr_list = RewardAddressList()
        assert addr_list is not None
        assert len(addr_list) == 0

    def test_new_list_is_empty(self):
        """Test that newly created list has zero length."""
        addr_list = RewardAddressList()
        assert len(addr_list) == 0

    def test_new_list_is_falsy(self):
        """Test that empty list evaluates to False."""
        addr_list = RewardAddressList()
        assert not addr_list


class TestRewardAddressListFromList:
    """Tests for RewardAddressList.from_list() factory method."""

    def test_can_create_from_list(self):
        """Test that RewardAddressList can be created from Python list."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        assert addr_list is not None
        assert len(addr_list) == 2

    def test_can_create_from_empty_list(self):
        """Test that RewardAddressList can be created from empty list."""
        addr_list = RewardAddressList.from_list([])
        assert addr_list is not None
        assert len(addr_list) == 0

    def test_can_create_from_single_element_list(self):
        """Test that RewardAddressList can be created from single element list."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        assert len(addr_list) == 1

    def test_raises_error_if_list_contains_invalid_element(self):
        """Test that creating from list with invalid element raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            RewardAddressList.from_list(["not an address"])

    def test_raises_error_if_list_contains_none(self):
        """Test that creating from list with None raises an error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            RewardAddressList.from_list([None])


class TestRewardAddressListAdd:
    """Tests for RewardAddressList.add() method."""

    def test_can_add_address(self):
        """Test that reward address can be added to list."""
        addr_list = RewardAddressList()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.add(addr)
        assert len(addr_list) == 1

    def test_can_add_multiple_addresses(self):
        """Test that multiple addresses can be added."""
        addr_list = RewardAddressList()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list.add(addr1)
        addr_list.add(addr2)
        assert len(addr_list) == 2

    def test_can_add_same_address_multiple_times(self):
        """Test that same address can be added multiple times."""
        addr_list = RewardAddressList()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.add(addr)
        addr_list.add(addr)
        assert len(addr_list) == 2

    def test_raises_error_if_address_is_none(self):
        """Test that adding None raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            addr_list.add(None)

    def test_raises_error_if_address_is_invalid_type(self):
        """Test that adding invalid type raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            addr_list.add("not an address")


class TestRewardAddressListAppend:
    """Tests for RewardAddressList.append() method."""

    def test_append_is_alias_for_add(self):
        """Test that append works the same as add."""
        addr_list = RewardAddressList()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.append(addr)
        assert len(addr_list) == 1

    def test_can_append_multiple_addresses(self):
        """Test that multiple addresses can be appended."""
        addr_list = RewardAddressList()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list.append(addr1)
        addr_list.append(addr2)
        assert len(addr_list) == 2

    def test_raises_error_if_address_is_none(self):
        """Test that appending None raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            addr_list.append(None)


class TestRewardAddressListGet:
    """Tests for RewardAddressList.get() method."""

    def test_can_get_address_at_index(self):
        """Test that address can be retrieved by index."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        retrieved = addr_list.get(0)
        assert retrieved is not None
        assert retrieved.to_bech32() == REWARD_KEY

    def test_can_get_second_address(self):
        """Test that second address can be retrieved."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        retrieved = addr_list.get(1)
        assert retrieved.to_bech32() == REWARD_SCRIPT

    def test_raises_error_for_negative_index(self):
        """Test that negative index raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises(IndexError):
            addr_list.get(-1)

    def test_raises_error_for_out_of_bounds_index(self):
        """Test that out of bounds index raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises(IndexError):
            addr_list.get(0)

    def test_raises_error_for_index_beyond_length(self):
        """Test that index beyond length raises an error."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        with pytest.raises(IndexError):
            addr_list.get(1)


class TestRewardAddressListLen:
    """Tests for len() and __len__() method."""

    def test_len_returns_zero_for_empty_list(self):
        """Test that len returns 0 for empty list."""
        addr_list = RewardAddressList()
        assert len(addr_list) == 0

    def test_len_returns_correct_value_after_add(self):
        """Test that len returns correct value after adding elements."""
        addr_list = RewardAddressList()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.add(addr)
        assert len(addr_list) == 1

    def test_len_increases_with_each_addition(self):
        """Test that len increases with each addition."""
        addr_list = RewardAddressList()
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list.add(addr1)
        assert len(addr_list) == 1
        addr_list.add(addr2)
        assert len(addr_list) == 2


class TestRewardAddressListGetItem:
    """Tests for bracket notation and __getitem__() method."""

    def test_can_use_bracket_notation(self):
        """Test that bracket notation works for accessing elements."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        assert addr_list[0].to_bech32() == REWARD_KEY

    def test_can_use_negative_index(self):
        """Test that negative index works."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        assert addr_list[-1].to_bech32() == REWARD_SCRIPT

    def test_can_access_all_elements_with_negative_indices(self):
        """Test that all elements can be accessed with negative indices."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        assert addr_list[-2].to_bech32() == REWARD_KEY
        assert addr_list[-1].to_bech32() == REWARD_SCRIPT

    def test_raises_error_for_out_of_bounds_positive_index(self):
        """Test that out of bounds positive index raises an error."""
        addr_list = RewardAddressList()
        with pytest.raises(IndexError):
            _ = addr_list[0]

    def test_raises_error_for_out_of_bounds_negative_index(self):
        """Test that out of bounds negative index raises an error."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        with pytest.raises(IndexError):
            _ = addr_list[-2]


class TestRewardAddressListIter:
    """Tests for iteration and __iter__() method."""

    def test_can_iterate_over_list(self):
        """Test that list can be iterated."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        items = list(addr_list)
        assert len(items) == 2

    def test_iteration_returns_correct_addresses(self):
        """Test that iteration returns correct addresses in order."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        items = list(addr_list)
        assert items[0].to_bech32() == REWARD_KEY
        assert items[1].to_bech32() == REWARD_SCRIPT

    def test_can_use_for_loop(self):
        """Test that for loop works with list."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        count = 0
        for addr in addr_list:
            count += 1
            assert addr is not None
        assert count == 2

    def test_empty_list_iteration(self):
        """Test that empty list can be iterated."""
        addr_list = RewardAddressList()
        items = list(addr_list)
        assert len(items) == 0


class TestRewardAddressListReversed:
    """Tests for reversed iteration and __reversed__() method."""

    def test_can_iterate_in_reverse(self):
        """Test that list can be iterated in reverse."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        items = list(reversed(addr_list))
        assert len(items) == 2
        assert items[0].to_bech32() == REWARD_SCRIPT
        assert items[1].to_bech32() == REWARD_KEY

    def test_reversed_empty_list(self):
        """Test that reversed empty list works."""
        addr_list = RewardAddressList()
        items = list(reversed(addr_list))
        assert len(items) == 0

    def test_reversed_single_element(self):
        """Test that reversed single element list works."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        items = list(reversed(addr_list))
        assert len(items) == 1
        assert items[0].to_bech32() == REWARD_KEY


class TestRewardAddressListBool:
    """Tests for boolean evaluation and __bool__() method."""

    def test_empty_list_is_falsy(self):
        """Test that empty list evaluates to False."""
        addr_list = RewardAddressList()
        assert not addr_list

    def test_non_empty_list_is_truthy(self):
        """Test that non-empty list evaluates to True."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        assert addr_list

    def test_can_use_in_if_statement(self):
        """Test that list can be used in if statement."""
        addr_list = RewardAddressList()
        if addr_list:
            pytest.fail("Empty list should be falsy")

        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.add(addr)
        if not addr_list:
            pytest.fail("Non-empty list should be truthy")


class TestRewardAddressListIndex:
    """Tests for RewardAddressList.index() method."""

    def test_can_find_index_of_element(self):
        """Test that index of element can be found."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        index = addr_list.index(addr1)
        assert index == 0

    def test_can_find_index_of_second_element(self):
        """Test that index of second element can be found."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        index = addr_list.index(addr2)
        assert index == 1

    def test_can_use_start_parameter(self):
        """Test that start parameter works."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2, addr1])
        index = addr_list.index(addr2, 1)
        assert index == 2

    def test_can_use_stop_parameter(self):
        """Test that stop parameter works."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2, addr1])
        index = addr_list.index(addr1, 0, 2)
        assert index == 0

    def test_raises_error_if_element_not_found(self):
        """Test that ValueError is raised if element not found."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1])
        with pytest.raises(ValueError):
            addr_list.index(addr2)

    def test_raises_error_if_element_not_in_range(self):
        """Test that ValueError is raised if element not in specified range."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])
        with pytest.raises(ValueError):
            addr_list.index(addr2, 0, 1)


class TestRewardAddressListCount:
    """Tests for RewardAddressList.count() method."""

    def test_count_returns_zero_if_not_found(self):
        """Test that count returns 0 if element not found."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1])
        count = addr_list.count(addr2)
        assert count == 0

    def test_count_returns_one_for_single_occurrence(self):
        """Test that count returns 1 for single occurrence."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        count = addr_list.count(addr)
        assert count == 1

    def test_count_returns_correct_value_for_multiple_occurrences(self):
        """Test that count returns correct value for multiple occurrences."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2, addr1, addr1])
        count = addr_list.count(addr1)
        assert count == 3

    def test_count_returns_zero_for_empty_list(self):
        """Test that count returns 0 for empty list."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList()
        count = addr_list.count(addr)
        assert count == 0


class TestRewardAddressListRepr:
    """Tests for __repr__() method."""

    def test_repr_contains_class_name(self):
        """Test that repr contains class name."""
        addr_list = RewardAddressList()
        repr_str = repr(addr_list)
        assert "RewardAddressList" in repr_str

    def test_repr_contains_length(self):
        """Test that repr contains length information."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        repr_str = repr(addr_list)
        assert "1" in repr_str

    def test_repr_updates_with_length(self):
        """Test that repr updates when length changes."""
        addr_list = RewardAddressList()
        repr1 = repr(addr_list)
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list.add(addr)
        repr2 = repr(addr_list)
        assert repr1 != repr2


class TestRewardAddressListContextManager:
    """Tests for context manager protocol (__enter__, __exit__)."""

    def test_can_use_as_context_manager(self):
        """Test that RewardAddressList can be used as a context manager."""
        with RewardAddressList() as addr_list:
            assert addr_list is not None
            assert len(addr_list) == 0

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        addr_list = RewardAddressList()
        with addr_list:
            addr = RewardAddress.from_bech32(REWARD_KEY)
            addr_list.add(addr)
        assert len(addr_list) == 1

    def test_can_use_context_manager_with_exception(self):
        """Test that context manager handles exceptions properly."""
        try:
            with RewardAddressList() as addr_list:
                addr_list.add(RewardAddress.from_bech32(REWARD_KEY))
                raise ValueError("test exception")
        except ValueError:
            pass


class TestRewardAddressListEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_can_add_many_addresses(self):
        """Test that many addresses can be added."""
        addr_list = RewardAddressList()
        addr = RewardAddress.from_bech32(REWARD_KEY)
        for _ in range(100):
            addr_list.add(addr)
        assert len(addr_list) == 100

    def test_iteration_returns_all_added_elements(self):
        """Test that iteration returns all added elements."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList()
        addr_list.add(addr1)
        addr_list.add(addr2)
        addr_list.add(addr1)
        items = list(addr_list)
        assert len(items) == 3
        key_count = sum(1 for item in items if item.to_bech32() == REWARD_KEY)
        script_count = sum(1 for item in items if item.to_bech32() == REWARD_SCRIPT)
        assert key_count == 2
        assert script_count == 1

    def test_can_mix_add_and_append(self):
        """Test that add and append can be mixed."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList()
        addr_list.add(addr1)
        addr_list.append(addr2)
        assert len(addr_list) == 2
        assert addr_list[0].to_bech32() == REWARD_KEY
        assert addr_list[1].to_bech32() == REWARD_SCRIPT

    def test_from_list_with_duplicate_addresses(self):
        """Test that from_list handles duplicate addresses."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr, addr, addr])
        assert len(addr_list) == 3

    def test_index_with_start_equal_to_length(self):
        """Test that index with start equal to length raises ValueError."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        with pytest.raises(ValueError):
            addr_list.index(addr, 1)

    def test_index_with_start_greater_than_stop(self):
        """Test that index with start greater than stop raises ValueError."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        with pytest.raises(ValueError):
            addr_list.index(addr, 1, 0)

    def test_get_with_large_index(self):
        """Test that get with very large index raises IndexError."""
        addr_list = RewardAddressList()
        with pytest.raises(IndexError):
            addr_list.get(999999)

    def test_negative_index_beyond_length(self):
        """Test that negative index beyond length raises IndexError."""
        addr = RewardAddress.from_bech32(REWARD_KEY)
        addr_list = RewardAddressList.from_list([addr])
        with pytest.raises(IndexError):
            _ = addr_list[-999]

    def test_list_behavior_consistency(self):
        """Test that RewardAddressList behaves consistently with Python list."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)

        addr_list = RewardAddressList()
        addr_list.add(addr1)
        addr_list.add(addr2)

        assert len(addr_list) == 2
        assert addr_list[0] == addr1
        assert addr_list[1] == addr2
        assert addr_list[-1] == addr2
        assert addr_list[-2] == addr1

        items = list(addr_list)
        assert len(items) == 2

        reversed_items = list(reversed(addr_list))
        assert reversed_items[0] == addr2
        assert reversed_items[1] == addr1

    def test_multiple_iterations(self):
        """Test that list can be iterated multiple times."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])

        items1 = list(addr_list)
        items2 = list(addr_list)

        assert len(items1) == len(items2)
        assert items1[0].to_bech32() == items2[0].to_bech32()
        assert items1[1].to_bech32() == items2[1].to_bech32()

    def test_sequence_protocol_compliance(self):
        """Test that RewardAddressList implements sequence protocol correctly."""
        addr1 = RewardAddress.from_bech32(REWARD_KEY)
        addr2 = RewardAddress.from_bech32(REWARD_SCRIPT)
        addr_list = RewardAddressList.from_list([addr1, addr2])

        assert len(addr_list) == 2
        assert addr_list[0] is not None
        assert addr_list[-1] is not None

        count = 0
        for _ in addr_list:
            count += 1
        assert count == 2

        assert addr_list.count(addr1) == 1
        assert addr_list.index(addr2) == 1
