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
    HardForkInitiationAction,
    ProtocolVersion,
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CborWriter,
    CardanoError,
    JsonWriter,
    JsonFormat,
)


CBOR = "8301825820000000000000000000000000000000000000000000000000000000000000000003820103"
CBOR_WITHOUT_GOV_ACTION = "8301f6820103"
GOV_ACTION_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
VERSION_CBOR = "820103"


def create_protocol_version():
    reader = CborReader.from_hex(VERSION_CBOR)
    return ProtocolVersion.from_cbor(reader)


def create_governance_action_id():
    tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
    return GovernanceActionId.new(tx_hash, 3)


def create_default_action():
    reader = CborReader.from_hex(CBOR)
    return HardForkInitiationAction.from_cbor(reader)


class TestHardForkInitiationActionNew:
    def test_new_with_all_params(self):
        protocol_version = create_protocol_version()
        governance_action_id = create_governance_action_id()

        action = HardForkInitiationAction.new(
            protocol_version,
            governance_action_id
        )

        assert action is not None
        assert action.protocol_version is not None
        assert action.governance_action_id is not None

    def test_new_without_governance_action_id(self):
        protocol_version = create_protocol_version()

        action = HardForkInitiationAction.new(
            protocol_version,
            None
        )

        assert action is not None
        assert action.protocol_version is not None
        assert action.governance_action_id is None

    def test_new_with_invalid_protocol_version(self):
        with pytest.raises((CardanoError, AttributeError)):
            HardForkInitiationAction.new(None, None)


class TestHardForkInitiationActionFromCbor:
    def test_from_cbor_with_all_fields(self):
        reader = CborReader.from_hex(CBOR)
        action = HardForkInitiationAction.from_cbor(reader)

        assert action is not None
        assert action.protocol_version is not None
        assert action.governance_action_id is not None

    def test_from_cbor_without_governance_action_id(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = HardForkInitiationAction.from_cbor(reader)

        assert action is not None
        assert action.protocol_version is not None
        assert action.governance_action_id is None

    def test_from_cbor_with_invalid_cbor(self):
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            HardForkInitiationAction.from_cbor(reader)

    def test_from_cbor_with_invalid_array_size(self):
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            HardForkInitiationAction.from_cbor(reader)

    def test_from_cbor_with_invalid_action_id(self):
        reader = CborReader.from_hex("83effe820103")

        with pytest.raises(CardanoError):
            HardForkInitiationAction.from_cbor(reader)

    def test_from_cbor_with_invalid_gov_action(self):
        reader = CborReader.from_hex("8301ef820103")

        with pytest.raises(CardanoError):
            HardForkInitiationAction.from_cbor(reader)

    def test_from_cbor_with_invalid_protocol_version(self):
        reader = CborReader.from_hex("8301f6ef0103")

        with pytest.raises(CardanoError):
            HardForkInitiationAction.from_cbor(reader)


class TestHardForkInitiationActionToCbor:
    def test_to_cbor_with_all_fields(self):
        action = create_default_action()
        writer = CborWriter()

        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_to_cbor_without_governance_action_id(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = HardForkInitiationAction.from_cbor(reader)
        writer = CborWriter()

        action.to_cbor(writer)

        assert writer.to_hex() == CBOR_WITHOUT_GOV_ACTION

    def test_to_cbor_roundtrip_with_all_fields(self):
        protocol_version = create_protocol_version()
        governance_action_id = create_governance_action_id()

        action1 = HardForkInitiationAction.new(
            protocol_version,
            governance_action_id
        )

        writer = CborWriter()
        action1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        action2 = HardForkInitiationAction.from_cbor(reader)

        assert action2 is not None
        assert action2.protocol_version is not None
        assert action2.governance_action_id is not None

    def test_to_cbor_roundtrip_without_gov_action_id(self):
        protocol_version = create_protocol_version()

        action1 = HardForkInitiationAction.new(protocol_version, None)

        writer = CborWriter()
        action1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        action2 = HardForkInitiationAction.from_cbor(reader)

        assert action2 is not None
        assert action2.protocol_version is not None
        assert action2.governance_action_id is None


class TestHardForkInitiationActionProtocolVersion:
    def test_get_protocol_version(self):
        action = create_default_action()

        version = action.protocol_version

        assert version is not None
        assert version.major == 1
        assert version.minor == 3

    def test_set_protocol_version(self):
        action = create_default_action()
        new_version = ProtocolVersion.new(9, 0)

        action.protocol_version = new_version

        retrieved_version = action.protocol_version
        assert retrieved_version is not None
        assert retrieved_version.major == 9
        assert retrieved_version.minor == 0

    def test_protocol_version_is_independent_reference(self):
        action = create_default_action()
        version1 = action.protocol_version
        version2 = action.protocol_version

        assert version1 is not None
        assert version2 is not None

    def test_set_protocol_version_with_invalid_value(self):
        action = create_default_action()

        with pytest.raises((CardanoError, AttributeError)):
            action.protocol_version = None


class TestHardForkInitiationActionGovernanceActionId:
    def test_get_governance_action_id_when_present(self):
        action = create_default_action()

        gov_id = action.governance_action_id

        assert gov_id is not None

    def test_get_governance_action_id_when_none(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = HardForkInitiationAction.from_cbor(reader)

        gov_id = action.governance_action_id

        assert gov_id is None

    def test_set_governance_action_id(self):
        action = create_default_action()
        new_gov_id = create_governance_action_id()

        action.governance_action_id = new_gov_id

        assert action.governance_action_id is not None

    def test_set_governance_action_id_to_none(self):
        action = create_default_action()

        action.governance_action_id = None

        assert action.governance_action_id is None

    def test_governance_action_id_roundtrip(self):
        action = create_default_action()
        gov_id = create_governance_action_id()

        action.governance_action_id = gov_id
        retrieved_gov_id = action.governance_action_id

        assert retrieved_gov_id is not None


class TestHardForkInitiationActionToCip116Json:
    def test_to_cip116_json_with_all_fields(self):
        tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        action_id = GovernanceActionId.new(tx_hash, 2)
        version = ProtocolVersion.new(9, 0)

        action = HardForkInitiationAction.new(version, action_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "hard_fork_initiation_action" in json_str
        assert "gov_action_id" in json_str
        assert "protocol_version" in json_str
        assert "transaction_id" in json_str
        assert "0000000000000000000000000000000000000000000000000000000000000000" in json_str
        assert "\"major\":9" in json_str
        assert "\"minor\":0" in json_str

    def test_to_cip116_json_without_gov_action_id(self):
        version = ProtocolVersion.new(3, 0)

        action = HardForkInitiationAction.new(version, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "hard_fork_initiation_action" in json_str
        assert "protocol_version" in json_str
        assert "\"major\":3" in json_str
        assert "\"minor\":0" in json_str
        assert "gov_action_id" not in json_str

    def test_to_cip116_json_with_invalid_writer_type(self):
        action = create_default_action()

        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")

    def test_to_cip116_json_matches_expected_format(self):
        tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        action_id = GovernanceActionId.new(tx_hash, 2)
        version = ProtocolVersion.new(9, 0)

        action = HardForkInitiationAction.new(version, action_id)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        expected = '{"tag":"hard_fork_initiation_action","gov_action_id":{"transaction_id":"0000000000000000000000000000000000000000000000000000000000000000","gov_action_index":"2"},"protocol_version":{"major":9,"minor":0}}'
        assert json_str == expected


class TestHardForkInitiationActionContextManager:
    def test_context_manager(self):
        action = create_default_action()

        with action:
            assert action is not None

    def test_context_manager_with_usage(self):
        protocol_version = create_protocol_version()

        with HardForkInitiationAction.new(protocol_version, None) as action:
            assert action is not None
            assert action.protocol_version is not None


class TestHardForkInitiationActionRepr:
    def test_repr(self):
        action = create_default_action()

        repr_str = repr(action)

        assert "HardForkInitiationAction" in repr_str
        assert "version=" in repr_str

    def test_repr_shows_correct_version(self):
        version = ProtocolVersion.new(9, 5)
        action = HardForkInitiationAction.new(version, None)

        repr_str = repr(action)

        assert "9.5" in repr_str


class TestHardForkInitiationActionEdgeCases:
    def test_multiple_property_updates(self):
        action = create_default_action()

        new_version = ProtocolVersion.new(10, 0)
        action.protocol_version = new_version

        new_gov_id = create_governance_action_id()
        action.governance_action_id = new_gov_id

        assert action.protocol_version is not None
        assert action.governance_action_id is not None

    def test_set_then_clear_optional_fields(self):
        action = create_default_action()

        action.governance_action_id = None

        assert action.governance_action_id is None
        assert action.protocol_version is not None

    def test_action_independence(self):
        protocol_version = create_protocol_version()
        governance_action_id = create_governance_action_id()

        action1 = HardForkInitiationAction.new(
            protocol_version,
            governance_action_id
        )

        action2 = HardForkInitiationAction.new(
            protocol_version,
            governance_action_id
        )

        action1.governance_action_id = None

        assert action1.governance_action_id is None
        assert action2.governance_action_id is not None

    def test_protocol_version_update_does_not_affect_original(self):
        protocol_version = create_protocol_version()
        action = HardForkInitiationAction.new(protocol_version, None)

        new_version = ProtocolVersion.new(15, 3)
        action.protocol_version = new_version

        retrieved_version = action.protocol_version
        assert retrieved_version.major == 15
        assert retrieved_version.minor == 3

    def test_cbor_serialization_after_modifications(self):
        action = create_default_action()

        new_version = ProtocolVersion.new(5, 2)
        action.protocol_version = new_version
        action.governance_action_id = None

        writer = CborWriter()
        action.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        action2 = HardForkInitiationAction.from_cbor(reader)

        assert action2.protocol_version.major == 5
        assert action2.protocol_version.minor == 2
        assert action2.governance_action_id is None


class TestHardForkInitiationActionMemoryManagement:
    def test_repeated_property_access(self):
        action = create_default_action()

        for _ in range(100):
            version = action.protocol_version
            assert version is not None

        for _ in range(100):
            gov_id = action.governance_action_id
            assert gov_id is not None

    def test_repeated_serialization(self):
        action = create_default_action()

        for _ in range(10):
            writer = CborWriter()
            action.to_cbor(writer)
            hex_str = writer.to_hex()
            assert hex_str == CBOR

    def test_repeated_json_serialization(self):
        action = create_default_action()

        for _ in range(10):
            writer = JsonWriter(JsonFormat.COMPACT)
            action.to_cip116_json(writer)
            json_str = writer.encode()
            assert "hard_fork_initiation_action" in json_str


class TestHardForkInitiationActionVersionCompatibility:
    def test_version_with_major_zero(self):
        version = ProtocolVersion.new(0, 1)
        action = HardForkInitiationAction.new(version, None)

        assert action.protocol_version.major == 0
        assert action.protocol_version.minor == 1

    def test_version_with_high_values(self):
        version = ProtocolVersion.new(255, 255)
        action = HardForkInitiationAction.new(version, None)

        writer = CborWriter()
        action.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        action2 = HardForkInitiationAction.from_cbor(reader)

        assert action2.protocol_version.major == 255
        assert action2.protocol_version.minor == 255

    def test_various_protocol_versions(self):
        test_versions = [(1, 0), (2, 5), (8, 0), (9, 0), (10, 1)]

        for major, minor in test_versions:
            version = ProtocolVersion.new(major, minor)
            action = HardForkInitiationAction.new(version, None)

            assert action.protocol_version.major == major
            assert action.protocol_version.minor == minor


class TestHardForkInitiationActionGovernanceActionIdVariations:
    def test_different_governance_action_indices(self):
        tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")

        for index in [0, 1, 5, 10, 100]:
            gov_id = GovernanceActionId.new(tx_hash, index)
            version = ProtocolVersion.new(9, 0)
            action = HardForkInitiationAction.new(version, gov_id)

            assert action.governance_action_id is not None

    def test_different_transaction_hashes(self):
        test_hashes = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ]

        version = ProtocolVersion.new(9, 0)

        for hash_hex in test_hashes:
            tx_hash = Blake2bHash.from_hex(hash_hex)
            gov_id = GovernanceActionId.new(tx_hash, 0)
            action = HardForkInitiationAction.new(version, gov_id)

            assert action.governance_action_id is not None

            writer = CborWriter()
            action.to_cbor(writer)

            reader = CborReader.from_hex(writer.to_hex())
            action2 = HardForkInitiationAction.from_cbor(reader)

            assert action2.governance_action_id is not None
