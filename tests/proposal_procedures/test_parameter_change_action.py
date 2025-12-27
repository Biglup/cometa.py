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
    ParameterChangeAction,
    ProtocolParamUpdate,
    GovernanceActionId,
    Blake2bHash,
    CborReader,
    CborWriter,
    CardanoError,
    JsonWriter,
    JsonFormat,
)


CBOR = "8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
CBOR_WITHOUT_GOV_ACTION = "8400f6b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
CBOR_WITHOUT_POLICY_HASH = "8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388f6"
GOV_ACTION_CBOR = "825820000000000000000000000000000000000000000000000000000000000000000003"
PROTOCOL_PARAM_UPDATE_CBOR = "b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388"
POLICY_HASH = "8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"


def create_protocol_param_update():
    reader = CborReader.from_hex(PROTOCOL_PARAM_UPDATE_CBOR)
    return ProtocolParamUpdate.from_cbor(reader)


def create_governance_action_id():
    tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
    return GovernanceActionId.new(tx_hash, 3)


def create_policy_hash():
    return Blake2bHash.from_hex(POLICY_HASH)


def create_default_action():
    reader = CborReader.from_hex(CBOR)
    return ParameterChangeAction.from_cbor(reader)


class TestParameterChangeActionNew:
    def test_new_with_all_params(self):
        protocol_param_update = create_protocol_param_update()
        governance_action_id = create_governance_action_id()
        policy_hash = create_policy_hash()

        action = ParameterChangeAction.new(
            protocol_param_update,
            governance_action_id,
            policy_hash
        )

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is not None
        assert action.policy_hash is not None

    def test_new_without_governance_action_id(self):
        protocol_param_update = create_protocol_param_update()
        policy_hash = create_policy_hash()

        action = ParameterChangeAction.new(
            protocol_param_update,
            None,
            policy_hash
        )

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is None
        assert action.policy_hash is not None

    def test_new_without_policy_hash(self):
        protocol_param_update = create_protocol_param_update()
        governance_action_id = create_governance_action_id()

        action = ParameterChangeAction.new(
            protocol_param_update,
            governance_action_id,
            None
        )

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is not None
        assert action.policy_hash is None

    def test_new_with_only_required_params(self):
        protocol_param_update = create_protocol_param_update()

        action = ParameterChangeAction.new(
            protocol_param_update,
            None,
            None
        )

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is None
        assert action.policy_hash is None


class TestParameterChangeActionFromCbor:
    def test_from_cbor_with_all_fields(self):
        reader = CborReader.from_hex(CBOR)
        action = ParameterChangeAction.from_cbor(reader)

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is not None
        assert action.policy_hash is not None

    def test_from_cbor_without_governance_action_id(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = ParameterChangeAction.from_cbor(reader)

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is None
        assert action.policy_hash is not None

    def test_from_cbor_without_policy_hash(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_POLICY_HASH)
        action = ParameterChangeAction.from_cbor(reader)

        assert action is not None
        assert action.protocol_param_update is not None
        assert action.governance_action_id is not None
        assert action.policy_hash is None

    def test_from_cbor_with_invalid_cbor(self):
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            ParameterChangeAction.from_cbor(reader)

    def test_from_cbor_with_invalid_array_size(self):
        reader = CborReader.from_hex("8100")

        with pytest.raises(CardanoError):
            ParameterChangeAction.from_cbor(reader)


class TestParameterChangeActionToCbor:
    def test_to_cbor_with_all_fields(self):
        action = create_default_action()
        writer = CborWriter()

        action.to_cbor(writer)

        assert writer.to_hex() == CBOR

    def test_to_cbor_without_governance_action_id(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = ParameterChangeAction.from_cbor(reader)
        writer = CborWriter()

        action.to_cbor(writer)

        assert writer.to_hex() == CBOR_WITHOUT_GOV_ACTION

    def test_to_cbor_without_policy_hash(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_POLICY_HASH)
        action = ParameterChangeAction.from_cbor(reader)
        writer = CborWriter()

        action.to_cbor(writer)

        assert writer.to_hex() == CBOR_WITHOUT_POLICY_HASH

    def test_to_cbor_roundtrip(self):
        protocol_param_update = create_protocol_param_update()
        governance_action_id = create_governance_action_id()
        policy_hash = create_policy_hash()

        action1 = ParameterChangeAction.new(
            protocol_param_update,
            governance_action_id,
            policy_hash
        )

        writer = CborWriter()
        action1.to_cbor(writer)

        reader = CborReader.from_hex(writer.to_hex())
        action2 = ParameterChangeAction.from_cbor(reader)

        assert action2 is not None
        assert action2.protocol_param_update is not None
        assert action2.governance_action_id is not None
        assert action2.policy_hash is not None


class TestParameterChangeActionProtocolParamUpdate:
    def test_get_protocol_param_update(self):
        action = create_default_action()

        update = action.protocol_param_update

        assert update is not None

    def test_set_protocol_param_update(self):
        action = create_default_action()
        new_update = create_protocol_param_update()

        action.protocol_param_update = new_update

        assert action.protocol_param_update is not None

    def test_protocol_param_update_is_independent_reference(self):
        action = create_default_action()
        update1 = action.protocol_param_update
        update2 = action.protocol_param_update

        assert update1 is not None
        assert update2 is not None


class TestParameterChangeActionGovernanceActionId:
    def test_get_governance_action_id_when_present(self):
        action = create_default_action()

        gov_id = action.governance_action_id

        assert gov_id is not None

    def test_get_governance_action_id_when_none(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_GOV_ACTION)
        action = ParameterChangeAction.from_cbor(reader)

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


class TestParameterChangeActionPolicyHash:
    def test_get_policy_hash_when_present(self):
        action = create_default_action()

        policy = action.policy_hash

        assert policy is not None

    def test_get_policy_hash_when_none(self):
        reader = CborReader.from_hex(CBOR_WITHOUT_POLICY_HASH)
        action = ParameterChangeAction.from_cbor(reader)

        policy = action.policy_hash

        assert policy is None

    def test_set_policy_hash(self):
        action = create_default_action()
        new_policy = create_policy_hash()

        action.policy_hash = new_policy

        assert action.policy_hash is not None

    def test_set_policy_hash_to_none(self):
        action = create_default_action()

        action.policy_hash = None

        assert action.policy_hash is None

    def test_policy_hash_roundtrip(self):
        action = create_default_action()
        policy = create_policy_hash()

        action.policy_hash = policy
        retrieved_policy = action.policy_hash

        assert retrieved_policy is not None


class TestParameterChangeActionToCip116Json:
    def test_to_cip116_json_with_all_fields(self):
        updates = ProtocolParamUpdate.new()
        updates.min_fee_b = 1000

        tx_hash = Blake2bHash.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        action_id = GovernanceActionId.new(tx_hash, 1)

        policy_hash = Blake2bHash.from_hex("1c12f03c1ef2e935acc35ec2e6f96c650fd3bfba3e96550504d53361")

        action = ParameterChangeAction.new(updates, action_id, policy_hash)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "parameter_change_action" in json_str
        assert "gov_action_id" in json_str
        assert "protocol_param_update" in json_str
        assert "policy_hash" in json_str
        assert "1000" in json_str

    def test_to_cip116_json_with_required_fields_only(self):
        updates = ProtocolParamUpdate.new()
        updates.min_fee_b = 500

        action = ParameterChangeAction.new(updates, None, None)

        writer = JsonWriter(JsonFormat.COMPACT)
        action.to_cip116_json(writer)
        json_str = writer.encode()

        assert "parameter_change_action" in json_str
        assert "protocol_param_update" in json_str
        assert "500" in json_str

    def test_to_cip116_json_with_invalid_writer_type(self):
        action = create_default_action()

        with pytest.raises(TypeError):
            action.to_cip116_json("not a writer")


class TestParameterChangeActionContextManager:
    def test_context_manager(self):
        action = create_default_action()

        with action:
            assert action is not None

    def test_context_manager_with_usage(self):
        protocol_param_update = create_protocol_param_update()

        with ParameterChangeAction.new(protocol_param_update, None, None) as action:
            assert action is not None
            assert action.protocol_param_update is not None


class TestParameterChangeActionRepr:
    def test_repr(self):
        action = create_default_action()

        repr_str = repr(action)

        assert "ParameterChangeAction" in repr_str


class TestParameterChangeActionEdgeCases:
    def test_multiple_property_updates(self):
        action = create_default_action()

        new_update = create_protocol_param_update()
        action.protocol_param_update = new_update

        new_gov_id = create_governance_action_id()
        action.governance_action_id = new_gov_id

        new_policy = create_policy_hash()
        action.policy_hash = new_policy

        assert action.protocol_param_update is not None
        assert action.governance_action_id is not None
        assert action.policy_hash is not None

    def test_set_then_clear_optional_fields(self):
        action = create_default_action()

        action.governance_action_id = None
        action.policy_hash = None

        assert action.governance_action_id is None
        assert action.policy_hash is None
        assert action.protocol_param_update is not None

    def test_action_independence(self):
        protocol_param_update = create_protocol_param_update()
        governance_action_id = create_governance_action_id()
        policy_hash = create_policy_hash()

        action1 = ParameterChangeAction.new(
            protocol_param_update,
            governance_action_id,
            policy_hash
        )

        action2 = ParameterChangeAction.new(
            protocol_param_update,
            governance_action_id,
            policy_hash
        )

        action1.governance_action_id = None

        assert action1.governance_action_id is None
        assert action2.governance_action_id is not None
