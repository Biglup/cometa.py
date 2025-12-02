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

"""Tests for Sequence, Set, and Mapping protocol compliance across collection types."""

import pytest
from collections.abc import Sequence, Set, Mapping


class TestAssetIdListSequence:
    """Tests for AssetIdList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.assets import AssetIdList
        lst = AssetIdList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        assert len(lst) == 0
        lst.add(AssetId.new_lovelace())
        assert len(lst) == 1

    def test_getitem(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        assert lst[0] == aid
        assert lst[-1] == aid

    def test_getitem_out_of_bounds(self):
        from cometa.assets import AssetIdList
        lst = AssetIdList()
        with pytest.raises(IndexError):
            _ = lst[0]

    def test_iter(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        lst.add(aid)
        items = list(lst)
        assert len(items) == 2

    def test_contains(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        assert aid in lst

    def test_reversed(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid1 = AssetId.new_lovelace()
        lst.add(aid1)
        lst.add(aid1)
        reversed_items = list(reversed(lst))
        assert len(reversed_items) == 2

    def test_index(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        assert lst.index(aid) == 0

    def test_index_not_found(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        with pytest.raises(ValueError):
            lst.index(aid)

    def test_index_with_start_stop(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        lst.add(aid)
        lst.add(aid)
        assert lst.index(aid, 1) == 1
        assert lst.index(aid, 0, 2) == 0

    def test_count(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        lst.add(aid)
        lst.add(aid)
        assert lst.count(aid) == 2

    def test_count_empty(self):
        from cometa.assets import AssetIdList, AssetId
        lst = AssetIdList()
        aid = AssetId.new_lovelace()
        assert lst.count(aid) == 0


class TestAssetNameListSequence:
    """Tests for AssetNameList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.assets import AssetNameList
        lst = AssetNameList()
        assert isinstance(lst, Sequence)

    def test_len_getitem_iter(self):
        from cometa.assets import AssetNameList, AssetName
        lst = AssetNameList()
        name = AssetName.from_string("TestToken")
        lst.add(name)
        assert len(lst) == 1
        assert lst[0] == name
        assert list(lst) == [name]

    def test_index_count_reversed(self):
        from cometa.assets import AssetNameList, AssetName
        lst = AssetNameList()
        name = AssetName.from_string("TestToken")
        lst.add(name)
        lst.add(name)
        assert lst.index(name) == 0
        assert lst.count(name) == 2
        assert len(list(reversed(lst))) == 2


class TestMetadatumListSequence:
    """Tests for MetadatumList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.auxiliary_data import MetadatumList
        lst = MetadatumList()
        assert isinstance(lst, Sequence)

    def test_len_getitem_iter(self):
        from cometa.auxiliary_data import MetadatumList, Metadatum
        lst = MetadatumList()
        lst.add(42)
        lst.add("hello")
        assert len(lst) == 2
        # Metadatum doesn't have to_int/to_string, just compare equality
        assert lst[0] == Metadatum.from_int(42)
        assert lst[1] == Metadatum.from_string("hello")

    def test_index_count_reversed(self):
        from cometa.auxiliary_data import MetadatumList, Metadatum
        lst = MetadatumList()
        lst.add(42)
        lst.add(42)
        meta = Metadatum.from_int(42)
        assert lst.index(meta) == 0
        assert lst.count(meta) == 2
        assert len(list(reversed(lst))) == 2


class TestPlusListSequence:
    """Tests for PlutusList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.plutus_data import PlutusList
        lst = PlutusList()
        assert isinstance(lst, Sequence)

    def test_len_getitem_iter(self):
        from cometa.plutus_data import PlutusList
        lst = PlutusList()
        lst.append(42)
        lst.append("hello")
        assert len(lst) == 2
        assert lst[0].to_int() == 42

    def test_index_count_reversed(self):
        from cometa.plutus_data import PlutusList, PlutusData
        lst = PlutusList()
        lst.append(42)
        lst.append(42)
        assert lst.index(42) == 0
        assert lst.count(42) == 2
        assert len(list(reversed(lst))) == 2


class TestUtxoListSequence:
    """Tests for UtxoList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.common.utxo_list import UtxoList
        lst = UtxoList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.common.utxo_list import UtxoList
        lst = UtxoList()
        assert len(lst) == 0


class TestRewardAddressListSequence:
    """Tests for RewardAddressList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.common import RewardAddressList
        lst = RewardAddressList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.common import RewardAddressList
        lst = RewardAddressList()
        assert len(lst) == 0


class TestTransactionOutputListSequence:
    """Tests for TransactionOutputList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.transaction_body import TransactionOutputList
        lst = TransactionOutputList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.transaction_body import TransactionOutputList
        lst = TransactionOutputList()
        assert len(lst) == 0


class TestRedeemerListSequence:
    """Tests for RedeemerList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.witness_set import RedeemerList
        lst = RedeemerList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.witness_set import RedeemerList
        lst = RedeemerList()
        assert len(lst) == 0


class TestNativeScriptListSequence:
    """Tests for NativeScriptList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.scripts.native_scripts import NativeScriptList
        lst = NativeScriptList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.scripts.native_scripts import NativeScriptList
        lst = NativeScriptList()
        assert len(lst) == 0


class TestVoterListSequence:
    """Tests for VoterList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.voting_procedures import VoterList
        lst = VoterList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.voting_procedures import VoterList
        lst = VoterList()
        assert len(lst) == 0


class TestVotingProcedureListSequence:
    """Tests for VotingProcedureList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.voting_procedures import VotingProcedureList
        lst = VotingProcedureList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.voting_procedures import VotingProcedureList
        lst = VotingProcedureList()
        assert len(lst) == 0


class TestGovernanceActionIdListSequence:
    """Tests for GovernanceActionIdList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.voting_procedures import GovernanceActionIdList
        lst = GovernanceActionIdList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.voting_procedures import GovernanceActionIdList
        lst = GovernanceActionIdList()
        assert len(lst) == 0


class TestPlutusScriptListsSequence:
    """Tests for Plutus script list Sequence compliance."""

    def test_plutus_v1_script_list_isinstance_sequence(self):
        from cometa.auxiliary_data import PlutusV1ScriptList
        lst = PlutusV1ScriptList()
        assert isinstance(lst, Sequence)

    def test_plutus_v2_script_list_isinstance_sequence(self):
        from cometa.auxiliary_data import PlutusV2ScriptList
        lst = PlutusV2ScriptList()
        assert isinstance(lst, Sequence)

    def test_plutus_v3_script_list_isinstance_sequence(self):
        from cometa.auxiliary_data import PlutusV3ScriptList
        lst = PlutusV3ScriptList()
        assert isinstance(lst, Sequence)


class TestPolicyIdListSequence:
    """Tests for PolicyIdList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.assets import PolicyIdList
        lst = PolicyIdList()
        assert isinstance(lst, Sequence)

    def test_len(self):
        from cometa.assets import PolicyIdList
        lst = PolicyIdList()
        assert len(lst) == 0


class TestMetadatumLabelListSequence:
    """Tests for MetadatumLabelList Sequence compliance."""

    def test_isinstance_sequence(self):
        from cometa.auxiliary_data import MetadatumLabelList
        lst = MetadatumLabelList()
        assert isinstance(lst, Sequence)

    def test_len_getitem_iter(self):
        from cometa.auxiliary_data import MetadatumLabelList
        lst = MetadatumLabelList()
        lst.add(721)
        lst.add(1)
        assert len(lst) == 2
        # MetadatumLabelList stores labels, check they're present
        labels = list(lst)
        assert len(labels) == 2
        assert 721 in labels
        assert 1 in labels

    def test_index_count_reversed(self):
        from cometa.auxiliary_data import MetadatumLabelList
        lst = MetadatumLabelList()
        lst.add(721)
        lst.add(721)
        assert lst.index(721) == 0
        assert lst.count(721) == 2
        assert len(list(reversed(lst))) == 2


# ============================================================================
# Set Protocol Compliance Tests
# ============================================================================


class TestBlake2bHashSetSetCompliance:
    """Tests for Blake2bHashSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.cryptography import Blake2bHashSet
        s = Blake2bHashSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.cryptography import Blake2bHashSet, Blake2bHash
        s = Blake2bHashSet()
        assert len(s) == 0
        s.add(Blake2bHash.from_hex("00" * 32))
        assert len(s) == 1

    def test_contains(self):
        from cometa.cryptography import Blake2bHashSet, Blake2bHash
        s = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        s.add(h)
        assert h in s

    def test_iter(self):
        from cometa.cryptography import Blake2bHashSet, Blake2bHash
        s = Blake2bHashSet()
        h = Blake2bHash.from_hex("00" * 32)
        s.add(h)
        items = list(s)
        assert len(items) == 1

    def test_isdisjoint(self):
        from cometa.cryptography import Blake2bHashSet, Blake2bHash
        s1 = Blake2bHashSet()
        s2 = Blake2bHashSet()
        h1 = Blake2bHash.from_hex("00" * 32)
        h2 = Blake2bHash.from_hex("11" * 32)
        s1.add(h1)
        s2.add(h2)
        assert s1.isdisjoint(s2)
        s2.add(h1)
        assert not s1.isdisjoint(s2)


class TestCertificateSetSetCompliance:
    """Tests for CertificateSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.certificates import CertificateSet
        # CertificateSet requires a ptr, check class hierarchy instead
        assert issubclass(CertificateSet, Set)

    def test_certificate_set_from_cbor(self):
        from cometa.certificates import CertificateSet
        from cometa.cbor import CborReader
        # Empty certificate set CBOR (empty array)
        reader = CborReader.from_hex("d9010280")
        s = CertificateSet.from_cbor(reader)
        assert isinstance(s, Set)
        assert len(s) == 0


class TestCredentialSetSetCompliance:
    """Tests for CredentialSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.proposal_procedures import CredentialSet
        s = CredentialSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.proposal_procedures import CredentialSet
        s = CredentialSet()
        assert len(s) == 0


class TestTransactionInputSetSetCompliance:
    """Tests for TransactionInputSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.transaction_body import TransactionInputSet
        s = TransactionInputSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.transaction_body import TransactionInputSet
        s = TransactionInputSet()
        assert len(s) == 0


class TestVkeyWitnessSetSetCompliance:
    """Tests for VkeyWitnessSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.witness_set import VkeyWitnessSet
        s = VkeyWitnessSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.witness_set import VkeyWitnessSet
        s = VkeyWitnessSet()
        assert len(s) == 0


class TestBootstrapWitnessSetSetCompliance:
    """Tests for BootstrapWitnessSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.witness_set import BootstrapWitnessSet
        s = BootstrapWitnessSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.witness_set import BootstrapWitnessSet
        s = BootstrapWitnessSet()
        assert len(s) == 0


class TestNativeScriptSetSetCompliance:
    """Tests for NativeScriptSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.witness_set import NativeScriptSet
        s = NativeScriptSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.witness_set import NativeScriptSet
        s = NativeScriptSet()
        assert len(s) == 0


class TestPlutusDataSetSetCompliance:
    """Tests for PlutusDataSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.witness_set import PlutusDataSet
        s = PlutusDataSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.witness_set import PlutusDataSet
        s = PlutusDataSet()
        assert len(s) == 0


class TestPlutusScriptSetsSetCompliance:
    """Tests for Plutus script sets Set compliance."""

    def test_plutus_v1_script_set_isinstance_set(self):
        from cometa.witness_set import PlutusV1ScriptSet
        s = PlutusV1ScriptSet()
        assert isinstance(s, Set)

    def test_plutus_v2_script_set_isinstance_set(self):
        from cometa.witness_set import PlutusV2ScriptSet
        s = PlutusV2ScriptSet()
        assert isinstance(s, Set)

    def test_plutus_v3_script_set_isinstance_set(self):
        from cometa.witness_set import PlutusV3ScriptSet
        s = PlutusV3ScriptSet()
        assert isinstance(s, Set)


class TestProposalProcedureSetSetCompliance:
    """Tests for ProposalProcedureSet Set compliance."""

    def test_isinstance_set(self):
        from cometa.proposal_procedures import ProposalProcedureSet
        s = ProposalProcedureSet()
        assert isinstance(s, Set)

    def test_len(self):
        from cometa.proposal_procedures import ProposalProcedureSet
        s = ProposalProcedureSet()
        assert len(s) == 0


# ============================================================================
# Mapping Protocol Compliance Tests
# ============================================================================


class TestAssetIdMapMappingCompliance:
    """Tests for AssetIdMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.assets import AssetIdMap
        m = AssetIdMap()
        assert isinstance(m, Mapping)

    def test_len(self):
        from cometa.assets import AssetIdMap, AssetId
        m = AssetIdMap()
        assert len(m) == 0
        m[AssetId.new_lovelace()] = 1000000
        assert len(m) == 1

    def test_getitem(self):
        from cometa.assets import AssetIdMap, AssetId
        m = AssetIdMap()
        aid = AssetId.new_lovelace()
        m[aid] = 1000000
        assert m[aid] == 1000000

    def test_iter(self):
        from cometa.assets import AssetIdMap, AssetId
        m = AssetIdMap()
        aid = AssetId.new_lovelace()
        m[aid] = 1000000
        keys = list(m)
        assert len(keys) == 1

    def test_contains(self):
        from cometa.assets import AssetIdMap, AssetId
        m = AssetIdMap()
        aid = AssetId.new_lovelace()
        m[aid] = 1000000
        assert aid in m

    def test_keys_values_items(self):
        from cometa.assets import AssetIdMap, AssetId
        m = AssetIdMap()
        aid = AssetId.new_lovelace()
        m[aid] = 1000000
        assert len(list(m.keys())) == 1
        assert list(m.values()) == [1000000]
        items = list(m.items())
        assert len(items) == 1
        assert items[0][1] == 1000000


class TestAssetNameMapMappingCompliance:
    """Tests for AssetNameMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.assets import AssetNameMap
        m = AssetNameMap()
        assert isinstance(m, Mapping)

    def test_len(self):
        from cometa.assets import AssetNameMap
        m = AssetNameMap()
        assert len(m) == 0


class TestMetadatumMapMappingCompliance:
    """Tests for MetadatumMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.auxiliary_data import MetadatumMap
        m = MetadatumMap()
        assert isinstance(m, Mapping)

    def test_len_getitem(self):
        from cometa.auxiliary_data import MetadatumMap, Metadatum
        m = MetadatumMap()
        m["key"] = "value"
        assert len(m) == 1
        assert m["key"] == Metadatum.from_string("value")

    def test_keys_values_items(self):
        from cometa.auxiliary_data import MetadatumMap
        m = MetadatumMap()
        m["key1"] = "value1"
        m["key2"] = "value2"
        assert len(list(m.keys())) == 2
        assert len(list(m.values())) == 2
        assert len(list(m.items())) == 2


class TestWithdrawalMapMappingCompliance:
    """Tests for WithdrawalMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.common import WithdrawalMap
        m = WithdrawalMap()
        assert isinstance(m, Mapping)

    def test_len(self):
        from cometa.common import WithdrawalMap
        m = WithdrawalMap()
        assert len(m) == 0


class TestPlutusMapMappingCompliance:
    """Tests for PlutusMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.plutus_data import PlutusMap
        m = PlutusMap()
        assert isinstance(m, Mapping)

    def test_len(self):
        from cometa.plutus_data import PlutusMap
        m = PlutusMap()
        assert len(m) == 0


class TestCommitteeMembersMapMappingCompliance:
    """Tests for CommitteeMembersMap Mapping compliance."""

    def test_isinstance_mapping(self):
        from cometa.proposal_procedures import CommitteeMembersMap
        m = CommitteeMembersMap()
        assert isinstance(m, Mapping)

    def test_len(self):
        from cometa.proposal_procedures import CommitteeMembersMap
        m = CommitteeMembersMap()
        assert len(m) == 0
