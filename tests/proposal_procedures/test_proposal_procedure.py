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
    ProposalProcedure,
    ParameterChangeAction,
    HardForkInitiationAction,
    TreasuryWithdrawalsAction,
    NoConfidenceAction,
    UpdateCommitteeAction,
    NewConstitutionAction,
    InfoAction,
    GovernanceActionType,
    RewardAddress,
    Anchor,
    CborReader,
    CborWriter,
    CardanoError,
    JsonWriter,
    JsonFormat,
)


PARAMETER_CHANGE_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
HARD_FORK_INITIATION_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8301825820000000000000000000000000000000000000000000000000000000000000000003820103827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
TREASURY_WITHDRAWALS_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
NO_CONFIDENCE_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8203825820000000000000000000000000000000000000000000000000000000000000000003827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
UPDATE_COMMITTEE_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8504825820000000000000000000000000000000000000000000000000000000000000000003d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
NEW_CONSTITUTION_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f830582582000000000000000000000000000000000000000000000000000000000000000000382827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
INFO_PROPOSAL_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8106827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"

PARAMETER_CHANGE_CBOR = "8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
HARD_FORK_INITIATION_CBOR = "8301825820000000000000000000000000000000000000000000000000000000000000000003820103"
TREASURY_WITHDRAWALS_CBOR = "8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d"
NO_CONFIDENCE_CBOR = "8203825820000000000000000000000000000000000000000000000000000000000000000003"
UPDATE_COMMITTEE_CBOR = "8504825820000000000000000000000000000000000000000000000000000000000000000003d90102828200581c000000000000000000000000000000000000000000000000000000008200581c20000000000000000000000000000000000000000000000000000000a28200581c30000000000000000000000000000000000000000000000000000000018200581c4000000000000000000000000000000000000000000000000000000002d81e820105"
NEW_CONSTITUTION_CBOR = "830582582000000000000000000000000000000000000000000000000000000000000000000382827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000f6"
INFO_CBOR = "8106"

ANCHOR_CBOR = "827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
REWARD_ACCOUNT = "stake1u89sasnfyjtmgk8ydqfv3fdl52f36x3djedfnzfc9rkgzrcss5vgr"
DEPOSIT = 1000000


def create_parameter_change_action():
    reader = CborReader.from_hex(PARAMETER_CHANGE_CBOR)
    return ParameterChangeAction.from_cbor(reader)


def create_hard_fork_initiation_action():
    reader = CborReader.from_hex(HARD_FORK_INITIATION_CBOR)
    return HardForkInitiationAction.from_cbor(reader)


def create_treasury_withdrawals_action():
    reader = CborReader.from_hex(TREASURY_WITHDRAWALS_CBOR)
    return TreasuryWithdrawalsAction.from_cbor(reader)


def create_no_confidence_action():
    reader = CborReader.from_hex(NO_CONFIDENCE_CBOR)
    return NoConfidenceAction.from_cbor(reader)


def create_update_committee_action():
    reader = CborReader.from_hex(UPDATE_COMMITTEE_CBOR)
    return UpdateCommitteeAction.from_cbor(reader)


def create_new_constitution_action():
    reader = CborReader.from_hex(NEW_CONSTITUTION_CBOR)
    return NewConstitutionAction.from_cbor(reader)


def create_info_action():
    reader = CborReader.from_hex(INFO_CBOR)
    return InfoAction.from_cbor(reader)


def create_anchor():
    reader = CborReader.from_hex(ANCHOR_CBOR)
    return Anchor.from_cbor(reader)


def create_reward_address():
    return RewardAddress.from_bech32(REWARD_ACCOUNT)


def create_default_proposal_procedure(cbor):
    reader = CborReader.from_hex(cbor)
    return ProposalProcedure.from_cbor(reader)


class TestProposalProcedureNewParameterChangeAction:
    def test_can_create_parameter_change_proposal(self):
        action = create_parameter_change_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_parameter_change_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.PARAMETER_CHANGE

    def test_new_parameter_change_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_parameter_change_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_parameter_change_action_with_invalid_reward_address(self):
        action = create_parameter_change_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_parameter_change_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_parameter_change_action_with_invalid_anchor(self):
        action = create_parameter_change_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_parameter_change_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewHardForkInitiationAction:
    def test_can_create_hard_fork_initiation_proposal(self):
        action = create_hard_fork_initiation_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_hard_fork_initiation_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.HARD_FORK_INITIATION

    def test_new_hard_fork_initiation_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_hard_fork_initiation_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_hard_fork_initiation_action_with_invalid_reward_address(self):
        action = create_hard_fork_initiation_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_hard_fork_initiation_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_hard_fork_initiation_action_with_invalid_anchor(self):
        action = create_hard_fork_initiation_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_hard_fork_initiation_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewTreasuryWithdrawalsAction:
    def test_can_create_treasury_withdrawals_proposal(self):
        action = create_treasury_withdrawals_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_treasury_withdrawals_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.TREASURY_WITHDRAWALS

    def test_new_treasury_withdrawals_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_treasury_withdrawals_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_treasury_withdrawals_action_with_invalid_reward_address(self):
        action = create_treasury_withdrawals_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_treasury_withdrawals_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_treasury_withdrawals_action_with_invalid_anchor(self):
        action = create_treasury_withdrawals_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_treasury_withdrawals_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewNoConfidenceAction:
    def test_can_create_no_confidence_proposal(self):
        action = create_no_confidence_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_no_confidence_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.NO_CONFIDENCE

    def test_new_no_confidence_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_no_confidence_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_no_confidence_action_with_invalid_reward_address(self):
        action = create_no_confidence_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_no_confidence_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_no_confidence_action_with_invalid_anchor(self):
        action = create_no_confidence_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_no_confidence_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewUpdateCommitteeAction:
    def test_can_create_update_committee_proposal(self):
        action = create_update_committee_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_update_committee_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.UPDATE_COMMITTEE

    def test_new_update_committee_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_update_committee_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_update_committee_action_with_invalid_reward_address(self):
        action = create_update_committee_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_update_committee_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_update_committee_action_with_invalid_anchor(self):
        action = create_update_committee_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_update_committee_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewConstitutionAction:
    def test_can_create_constitution_proposal(self):
        action = create_new_constitution_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_constitution_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.NEW_CONSTITUTION

    def test_new_constitution_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_constitution_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_constitution_action_with_invalid_reward_address(self):
        action = create_new_constitution_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_constitution_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_constitution_action_with_invalid_anchor(self):
        action = create_new_constitution_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_constitution_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureNewInfoAction:
    def test_can_create_info_proposal(self):
        action = create_info_action()
        reward_address = create_reward_address()
        anchor = create_anchor()

        proposal = ProposalProcedure.new_info_action(
            DEPOSIT,
            reward_address,
            anchor,
            action
        )

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.INFO

    def test_new_info_action_with_invalid_action(self):
        reward_address = create_reward_address()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_info_action(
                DEPOSIT,
                reward_address,
                anchor,
                None
            )

    def test_new_info_action_with_invalid_reward_address(self):
        action = create_info_action()
        anchor = create_anchor()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_info_action(
                DEPOSIT,
                None,
                anchor,
                action
            )

    def test_new_info_action_with_invalid_anchor(self):
        action = create_info_action()
        reward_address = create_reward_address()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedure.new_info_action(
                DEPOSIT,
                reward_address,
                None,
                action
            )


class TestProposalProcedureFromCbor:
    def test_from_cbor_parameter_change(self):
        reader = CborReader.from_hex(PARAMETER_CHANGE_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.PARAMETER_CHANGE

    def test_from_cbor_hard_fork_initiation(self):
        reader = CborReader.from_hex(HARD_FORK_INITIATION_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.HARD_FORK_INITIATION

    def test_from_cbor_treasury_withdrawals(self):
        reader = CborReader.from_hex(TREASURY_WITHDRAWALS_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.TREASURY_WITHDRAWALS

    def test_from_cbor_no_confidence(self):
        reader = CborReader.from_hex(NO_CONFIDENCE_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.NO_CONFIDENCE

    def test_from_cbor_update_committee(self):
        reader = CborReader.from_hex(UPDATE_COMMITTEE_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.UPDATE_COMMITTEE

    def test_from_cbor_new_constitution(self):
        reader = CborReader.from_hex(NEW_CONSTITUTION_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.NEW_CONSTITUTION

    def test_from_cbor_info(self):
        reader = CborReader.from_hex(INFO_PROPOSAL_CBOR)
        proposal = ProposalProcedure.from_cbor(reader)

        assert proposal is not None
        assert proposal.deposit == DEPOSIT
        assert proposal.action_type == GovernanceActionType.INFO

    def test_from_cbor_with_invalid_cbor(self):
        reader = CborReader.from_hex("80")

        with pytest.raises(CardanoError):
            ProposalProcedure.from_cbor(reader)


class TestProposalProcedureToCbor:
    def test_to_cbor_parameter_change(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == PARAMETER_CHANGE_PROPOSAL_CBOR.lower()

    def test_to_cbor_hard_fork_initiation(self):
        proposal = create_default_proposal_procedure(HARD_FORK_INITIATION_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == HARD_FORK_INITIATION_PROPOSAL_CBOR.lower()

    def test_to_cbor_treasury_withdrawals(self):
        proposal = create_default_proposal_procedure(TREASURY_WITHDRAWALS_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == TREASURY_WITHDRAWALS_PROPOSAL_CBOR.lower()

    def test_to_cbor_no_confidence(self):
        proposal = create_default_proposal_procedure(NO_CONFIDENCE_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == NO_CONFIDENCE_PROPOSAL_CBOR.lower()

    def test_to_cbor_update_committee(self):
        proposal = create_default_proposal_procedure(UPDATE_COMMITTEE_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == UPDATE_COMMITTEE_PROPOSAL_CBOR.lower()

    def test_to_cbor_new_constitution(self):
        proposal = create_default_proposal_procedure(NEW_CONSTITUTION_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == NEW_CONSTITUTION_PROPOSAL_CBOR.lower()

    def test_to_cbor_info(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)
        writer = CborWriter()

        proposal.to_cbor(writer)

        serialized = writer.encode().hex()
        assert serialized == INFO_PROPOSAL_CBOR.lower()


class TestProposalProcedureProperties:
    def test_deposit_property(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        assert proposal.deposit == DEPOSIT

    def test_deposit_setter(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)
        new_deposit = 2000000

        proposal.deposit = new_deposit

        assert proposal.deposit == new_deposit

    def test_action_type_property(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)

        assert proposal.action_type == GovernanceActionType.PARAMETER_CHANGE

    def test_anchor_property(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        anchor = proposal.anchor

        assert anchor is not None
        assert anchor.url == "https://www.someurl.io"

    def test_anchor_setter(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)
        new_anchor = create_anchor()

        proposal.anchor = new_anchor

        assert proposal.anchor is not None

    def test_reward_address_property(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        reward_address = proposal.reward_address

        assert reward_address is not None
        assert reward_address.to_bech32() == REWARD_ACCOUNT

    def test_reward_address_setter(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)
        new_reward_address = create_reward_address()

        proposal.reward_address = new_reward_address

        assert proposal.reward_address is not None


class TestProposalProcedureConversions:
    def test_to_parameter_change_action(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)

        action = proposal.to_parameter_change_action()

        assert action is not None
        assert isinstance(action, ParameterChangeAction)

    def test_to_parameter_change_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_parameter_change_action()

    def test_to_hard_fork_initiation_action(self):
        proposal = create_default_proposal_procedure(HARD_FORK_INITIATION_PROPOSAL_CBOR)

        action = proposal.to_hard_fork_initiation_action()

        assert action is not None
        assert isinstance(action, HardForkInitiationAction)

    def test_to_hard_fork_initiation_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_hard_fork_initiation_action()

    def test_to_treasury_withdrawals_action(self):
        proposal = create_default_proposal_procedure(TREASURY_WITHDRAWALS_PROPOSAL_CBOR)

        action = proposal.to_treasury_withdrawals_action()

        assert action is not None
        assert isinstance(action, TreasuryWithdrawalsAction)

    def test_to_treasury_withdrawals_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_treasury_withdrawals_action()

    def test_to_no_confidence_action(self):
        proposal = create_default_proposal_procedure(NO_CONFIDENCE_PROPOSAL_CBOR)

        action = proposal.to_no_confidence_action()

        assert action is not None
        assert isinstance(action, NoConfidenceAction)

    def test_to_no_confidence_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_no_confidence_action()

    def test_to_update_committee_action(self):
        proposal = create_default_proposal_procedure(UPDATE_COMMITTEE_PROPOSAL_CBOR)

        action = proposal.to_update_committee_action()

        assert action is not None
        assert isinstance(action, UpdateCommitteeAction)

    def test_to_update_committee_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_update_committee_action()

    def test_to_constitution_action(self):
        proposal = create_default_proposal_procedure(NEW_CONSTITUTION_PROPOSAL_CBOR)

        action = proposal.to_constitution_action()

        assert action is not None
        assert isinstance(action, NewConstitutionAction)

    def test_to_constitution_action_wrong_type(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_constitution_action()

    def test_to_info_action(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        action = proposal.to_info_action()

        assert action is not None
        assert isinstance(action, InfoAction)

    def test_to_info_action_wrong_type(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)

        with pytest.raises(CardanoError):
            proposal.to_info_action()

    def test_get_action_parameter_change(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, ParameterChangeAction)

    def test_get_action_hard_fork_initiation(self):
        proposal = create_default_proposal_procedure(HARD_FORK_INITIATION_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, HardForkInitiationAction)

    def test_get_action_treasury_withdrawals(self):
        proposal = create_default_proposal_procedure(TREASURY_WITHDRAWALS_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, TreasuryWithdrawalsAction)

    def test_get_action_no_confidence(self):
        proposal = create_default_proposal_procedure(NO_CONFIDENCE_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, NoConfidenceAction)

    def test_get_action_update_committee(self):
        proposal = create_default_proposal_procedure(UPDATE_COMMITTEE_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, UpdateCommitteeAction)

    def test_get_action_new_constitution(self):
        proposal = create_default_proposal_procedure(NEW_CONSTITUTION_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, NewConstitutionAction)

    def test_get_action_info(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        action = proposal.get_action()

        assert action is not None
        assert isinstance(action, InfoAction)


class TestProposalProcedureToCip116Json:
    def test_to_cip116_json(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)
        writer = JsonWriter()

        proposal.to_cip116_json(writer)

        json_str = writer.encode()
        assert json_str is not None
        assert len(json_str) > 0

    def test_to_cip116_json_with_invalid_writer(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        with pytest.raises((TypeError, CardanoError, AttributeError)):
            proposal.to_cip116_json(None)


class TestProposalProcedureRepr:
    def test_repr_parameter_change(self):
        proposal = create_default_proposal_procedure(PARAMETER_CHANGE_PROPOSAL_CBOR)

        repr_str = repr(proposal)

        assert "ProposalProcedure" in repr_str
        assert "PARAMETER_CHANGE" in repr_str

    def test_repr_info(self):
        proposal = create_default_proposal_procedure(INFO_PROPOSAL_CBOR)

        repr_str = repr(proposal)

        assert "ProposalProcedure" in repr_str
        assert "INFO" in repr_str
