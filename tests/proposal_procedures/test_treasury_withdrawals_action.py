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
    TreasuryWithdrawalsAction,
    WithdrawalMap,
    Blake2bHash,
    CborReader,
    CborWriter,
    JsonWriter,
    JsonFormat,
    CardanoError,
    RewardAddress,
)


CBOR = "8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
CBOR_WITHOUT_POLICY_HASH = "8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01f6"
POLICY_HASH = "8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
WITHDRAWAL_CBOR = "a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01"


def new_default_treasury_withdrawals_action():
    """Creates a new default instance of TreasuryWithdrawalsAction."""
    reader = CborReader.from_hex(CBOR)
    return TreasuryWithdrawalsAction.from_cbor(reader)


def new_default_hash(hash_hex):
    """Creates a new default instance of Blake2bHash."""
    return Blake2bHash.from_hex(hash_hex)


def new_default_withdrawal_map(cbor_hex):
    """Creates a new default instance of WithdrawalMap."""
    reader = CborReader.from_hex(cbor_hex)
    return WithdrawalMap.from_cbor(reader)


class TestTreasuryWithdrawalsAction:
    """Tests for TreasuryWithdrawalsAction lifecycle methods."""

    def test_init_with_valid_ptr(self):
        """Test that __init__ accepts a valid pointer."""
        action = new_default_treasury_withdrawals_action()
        assert action is not None

    def test_init_with_null_ptr_raises_error(self):
        """Test that __init__ with NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="invalid handle"):
            TreasuryWithdrawalsAction(ffi.NULL)

    def test_repr(self):
        """Test __repr__ method."""
        action = new_default_treasury_withdrawals_action()
        assert repr(action) == "TreasuryWithdrawalsAction(...)"

    def test_context_manager(self):
        """Test context manager protocol."""
        action = new_default_treasury_withdrawals_action()
        with action as ctx:
            assert ctx is action


class TestTreasuryWithdrawalsActionNew:
    """Tests for TreasuryWithdrawalsAction.new() factory method."""

    def test_new_without_policy_hash(self):
        """Test creating a new action without policy hash."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        action = TreasuryWithdrawalsAction.new(withdrawal_map, None)
        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR_WITHOUT_POLICY_HASH

    def test_new_with_policy_hash(self):
        """Test creating a new action with policy hash."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        policy_hash = new_default_hash(POLICY_HASH)
        action = TreasuryWithdrawalsAction.new(withdrawal_map, policy_hash)
        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_new_with_null_withdrawals_raises_error(self):
        """Test that new() with None withdrawals raises CardanoError."""
        with pytest.raises((CardanoError, AttributeError)):
            TreasuryWithdrawalsAction.new(None, None)


class TestTreasuryWithdrawalsActionFromCbor:
    """Tests for TreasuryWithdrawalsAction.from_cbor() method."""

    def test_from_cbor_with_policy_hash(self):
        """Test deserializing action with policy hash from CBOR."""
        reader = CborReader.from_hex(CBOR)
        action = TreasuryWithdrawalsAction.from_cbor(reader)
        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == CBOR

    def test_from_cbor_without_policy_hash(self):
        """Test deserializing action without policy hash from CBOR."""
        reader = CborReader.from_hex(CBOR_WITHOUT_POLICY_HASH)
        action = TreasuryWithdrawalsAction.from_cbor(reader)
        assert action is not None

        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == CBOR_WITHOUT_POLICY_HASH

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that from_cbor() with None reader raises error."""
        with pytest.raises((CardanoError, AttributeError)):
            TreasuryWithdrawalsAction.from_cbor(None)

    def test_from_cbor_with_invalid_cbor_not_array(self):
        """Test from_cbor with CBOR that doesn't start with array."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            TreasuryWithdrawalsAction.from_cbor(reader)

    def test_from_cbor_with_invalid_array_size(self):
        """Test from_cbor with invalid array size."""
        reader = CborReader.from_hex("8100")
        with pytest.raises(CardanoError):
            TreasuryWithdrawalsAction.from_cbor(reader)

    def test_from_cbor_with_invalid_id(self):
        """Test from_cbor with invalid action ID."""
        reader = CborReader.from_hex("83effe820103")
        with pytest.raises(CardanoError):
            TreasuryWithdrawalsAction.from_cbor(reader)

    def test_from_cbor_with_invalid_withdrawal(self):
        """Test from_cbor with invalid withdrawal data."""
        reader = CborReader.from_hex("8302ef820103")
        with pytest.raises(CardanoError):
            TreasuryWithdrawalsAction.from_cbor(reader)

    def test_from_cbor_with_invalid_policy_hash(self):
        """Test from_cbor with invalid policy hash."""
        reader = CborReader.from_hex(
            "8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581cef"
        )
        with pytest.raises(CardanoError):
            TreasuryWithdrawalsAction.from_cbor(reader)


class TestTreasuryWithdrawalsActionToCbor:
    """Tests for TreasuryWithdrawalsAction.to_cbor() method."""

    def test_to_cbor_success(self):
        """Test serializing action to CBOR."""
        action = new_default_treasury_withdrawals_action()
        writer = CborWriter()
        action.to_cbor(writer)
        assert writer.to_hex() == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that to_cbor() with None writer raises error."""
        action = new_default_treasury_withdrawals_action()
        with pytest.raises((CardanoError, AttributeError)):
            action.to_cbor(None)


class TestTreasuryWithdrawalsActionWithdrawals:
    """Tests for withdrawals property getter and setter."""

    def test_get_withdrawals(self):
        """Test getting withdrawals from action."""
        action = new_default_treasury_withdrawals_action()
        withdrawals = action.withdrawals
        assert withdrawals is not None
        assert isinstance(withdrawals, WithdrawalMap)

    def test_set_withdrawals(self):
        """Test setting withdrawals on action."""
        action = new_default_treasury_withdrawals_action()
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        action.withdrawals = withdrawal_map
        retrieved = action.withdrawals
        assert retrieved is not None

    def test_set_withdrawals_with_none_raises_error(self):
        """Test that setting withdrawals to None raises error."""
        action = new_default_treasury_withdrawals_action()
        with pytest.raises((CardanoError, AttributeError)):
            action.withdrawals = None


class TestTreasuryWithdrawalsActionPolicyHash:
    """Tests for policy_hash property getter and setter."""

    def test_get_policy_hash_when_present(self):
        """Test getting policy hash when it's present."""
        action = new_default_treasury_withdrawals_action()
        policy_hash = action.policy_hash
        assert policy_hash is not None
        assert isinstance(policy_hash, Blake2bHash)

    def test_get_policy_hash_when_absent(self):
        """Test getting policy hash when it's not present."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        action = TreasuryWithdrawalsAction.new(withdrawal_map, None)
        policy_hash = action.policy_hash
        assert policy_hash is None

    def test_set_policy_hash(self):
        """Test setting policy hash on action."""
        action = new_default_treasury_withdrawals_action()
        new_policy_hash = new_default_hash(POLICY_HASH)
        action.policy_hash = new_policy_hash
        retrieved = action.policy_hash
        assert retrieved is not None

    def test_set_policy_hash_to_none(self):
        """Test setting policy hash to None."""
        action = new_default_treasury_withdrawals_action()
        action.policy_hash = None
        retrieved = action.policy_hash
        assert retrieved is None


class TestTreasuryWithdrawalsActionToCip116Json:
    """Tests for TreasuryWithdrawalsAction.to_cip116_json() method."""

    def test_to_cip116_json_with_policy_hash(self):
        """Test serializing action with policy hash to CIP-116 JSON."""
        withdrawals = WithdrawalMap()
        addr = RewardAddress.from_bech32(
            "stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y"
        )
        withdrawals.insert(addr, 100000000)

        policy_hash = Blake2bHash.from_hex(
            "1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"
        )
        action = TreasuryWithdrawalsAction.new(withdrawals, policy_hash)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        expected = (
            '{"tag":"treasury_withdrawals_action",'
            '"rewards":[{"key":"stake1u87qlejzjkrxm9ja7k6h0x7xuepd3q8njesv2s62lz83ttszp4x0y",'
            '"value":"100000000"}],'
            '"policy_hash":"1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361"}'
        )
        assert json_str == expected

    def test_to_cip116_json_without_policy_hash(self):
        """Test serializing action without policy hash to CIP-116 JSON."""
        withdrawals = WithdrawalMap()
        action = TreasuryWithdrawalsAction.new(withdrawals, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"tag":"treasury_withdrawals_action","rewards":[]}'
        assert json_str == expected

    def test_to_cip116_json_with_null_writer_raises_error(self):
        """Test that to_cip116_json() with None writer raises error."""
        action = new_default_treasury_withdrawals_action()
        with pytest.raises((CardanoError, TypeError)):
            action.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_type_raises_error(self):
        """Test that to_cip116_json() with invalid writer type raises TypeError."""
        action = new_default_treasury_withdrawals_action()
        with pytest.raises(TypeError, match="writer must be a JsonWriter instance"):
            action.to_cip116_json("not a writer")


class TestTreasuryWithdrawalsActionEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_multiple_operations_sequence(self):
        """Test performing multiple operations in sequence."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        policy_hash = new_default_hash(POLICY_HASH)

        action = TreasuryWithdrawalsAction.new(withdrawal_map, policy_hash)

        assert action.withdrawals is not None
        assert action.policy_hash is not None

        writer = CborWriter()
        action.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        action2 = TreasuryWithdrawalsAction.from_cbor(reader)

        assert action2.withdrawals is not None
        assert action2.policy_hash is not None

    def test_roundtrip_serialization_with_policy_hash(self):
        """Test roundtrip serialization maintains data integrity."""
        original = new_default_treasury_withdrawals_action()

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = TreasuryWithdrawalsAction.from_cbor(reader)

        writer2 = CborWriter()
        deserialized.to_cbor(writer2)
        cbor_hex2 = writer2.to_hex()

        assert cbor_hex == cbor_hex2

    def test_roundtrip_serialization_without_policy_hash(self):
        """Test roundtrip serialization without policy hash."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        original = TreasuryWithdrawalsAction.new(withdrawal_map, None)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        deserialized = TreasuryWithdrawalsAction.from_cbor(reader)

        writer2 = CborWriter()
        deserialized.to_cbor(writer2)
        cbor_hex2 = writer2.to_hex()

        assert cbor_hex == cbor_hex2
        assert deserialized.policy_hash is None

    def test_modify_after_creation(self):
        """Test modifying action properties after creation."""
        withdrawal_map = new_default_withdrawal_map(WITHDRAWAL_CBOR)
        action = TreasuryWithdrawalsAction.new(withdrawal_map, None)

        assert action.policy_hash is None

        new_policy = new_default_hash(POLICY_HASH)
        action.policy_hash = new_policy

        assert action.policy_hash is not None

        action.policy_hash = None
        assert action.policy_hash is None
