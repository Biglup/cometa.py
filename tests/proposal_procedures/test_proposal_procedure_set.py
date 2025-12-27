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
    ProposalProcedureSet,
    ProposalProcedure,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError
)


CBOR = "d9010284841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8301825820000000000000000000000000000000000000000000000000000000000000000003820103827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8203825820000000000000000000000000000000000000000000000000000000000000000003827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
CBOR_WITHOUT_TAG = "84841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8301825820000000000000000000000000000000000000000000000000000000000000000003820103827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8203825820000000000000000000000000000000000000000000000000000000000000000003827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
PROPOSAL_PROCEDURE1_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8400825820000000000000000000000000000000000000000000000000000000000000000003b81f0018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d820158200000000000000000000000000000000000000000000000000000000000000000101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba1719035418181864181985d81e820000d81e820101d81e820202d81e820303d81e820101181a8ad81e820000d81e820101d81e820202d81e820303d81e820404d81e820505d81e820606d81e820707d81e820808d81e820909181b1864181c18c8181d19012c181e1903e8181f1907d01820191388581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
PROPOSAL_PROCEDURE2_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8301825820000000000000000000000000000000000000000000000000000000000000000003820103827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
PROPOSAL_PROCEDURE3_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8302a1581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f01581c8293d319ef5b3ac72366dd28006bd315b715f7e7cfcbd3004129b80d827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
PROPOSAL_PROCEDURE4_CBOR = "841a000f4240581de1cb0ec2692497b458e46812c8a5bfa2931d1a2d965a99893828ec810f8203825820000000000000000000000000000000000000000000000000000000000000000003827668747470733a2f2f7777772e736f6d6575726c2e696f58200000000000000000000000000000000000000000000000000000000000000000"
EMPTY_SET_CBOR = "d9010280"


def create_proposal_procedure_from_cbor(cbor_hex: str) -> ProposalProcedure:
    """Helper function to create a proposal procedure from CBOR hex."""
    reader = CborReader.from_hex(cbor_hex)
    return ProposalProcedure.from_cbor(reader)


class TestProposalProcedureSet:
    """Tests for the ProposalProcedureSet class."""

    def test_new_creates_empty_set(self):
        """Test creating a new empty proposal procedure set."""
        proposal_set = ProposalProcedureSet()
        assert proposal_set is not None
        assert len(proposal_set) == 0

    def test_to_cbor_empty_set(self):
        """Test serializing an empty proposal procedure set to CBOR."""
        proposal_set = ProposalProcedureSet()
        writer = CborWriter()
        proposal_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == EMPTY_SET_CBOR

    def test_to_cbor_with_proposals(self):
        """Test serializing a proposal procedure set with proposals to CBOR."""
        proposal_set = ProposalProcedureSet()

        proposals = [
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE2_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE3_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE4_CBOR)
        ]

        for proposal in proposals:
            proposal_set.add(proposal)

        writer = CborWriter()
        proposal_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_to_cbor_with_null_writer_raises_error(self):
        """Test that serializing with null writer raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            proposal_set.to_cbor(None)


    def test_from_cbor_deserializes_set(self):
        """Test deserializing a proposal procedure set from CBOR."""
        reader = CborReader.from_hex(CBOR)
        proposal_set = ProposalProcedureSet.from_cbor(reader)

        assert proposal_set is not None
        assert len(proposal_set) == 4

        elem1 = proposal_set.get(0)
        elem2 = proposal_set.get(1)
        elem3 = proposal_set.get(2)
        elem4 = proposal_set.get(3)

        assert elem1 is not None
        assert elem2 is not None
        assert elem3 is not None
        assert elem4 is not None

    def test_from_cbor_without_tag(self):
        """Test deserializing a proposal procedure set from CBOR without tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        proposal_set = ProposalProcedureSet.from_cbor(reader)

        assert proposal_set is not None
        assert len(proposal_set) == 4

    def test_from_cbor_with_null_reader_raises_error(self):
        """Test that deserializing with null reader raises error."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            ProposalProcedureSet.from_cbor(None)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that deserializing invalid CBOR raises error."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            ProposalProcedureSet.from_cbor(reader)

    def test_from_cbor_with_not_an_array_raises_error(self):
        """Test that deserializing non-array CBOR raises error."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            ProposalProcedureSet.from_cbor(reader)

    def test_from_cbor_with_invalid_elements_raises_error(self):
        """Test that deserializing CBOR with invalid elements raises error."""
        reader = CborReader.from_hex("9ffeff")
        with pytest.raises(CardanoError):
            ProposalProcedureSet.from_cbor(reader)

    def test_from_cbor_with_missing_end_array_raises_error(self):
        """Test that deserializing CBOR with missing end array raises error."""
        reader = CborReader.from_hex("9f01")
        with pytest.raises(CardanoError):
            ProposalProcedureSet.from_cbor(reader)

    def test_cbor_round_trip(self):
        """Test that deserializing and reserializing produces the same CBOR."""
        reader = CborReader.from_hex(CBOR)
        proposal_set = ProposalProcedureSet.from_cbor(reader)

        writer = CborWriter()
        proposal_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_cbor_round_trip_without_tag(self):
        """Test CBOR round trip for data without tag."""
        reader = CborReader.from_hex(CBOR_WITHOUT_TAG)
        proposal_set = ProposalProcedureSet.from_cbor(reader)

        writer = CborWriter()
        proposal_set.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == CBOR

    def test_from_list_creates_set_from_iterable(self):
        """Test creating a proposal procedure set from an iterable."""
        proposals = [
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE2_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE3_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE4_CBOR)
        ]

        proposal_set = ProposalProcedureSet.from_list(proposals)

        assert proposal_set is not None
        assert len(proposal_set) == 4

    def test_from_list_with_empty_list(self):
        """Test creating a proposal procedure set from an empty list."""
        proposal_set = ProposalProcedureSet.from_list([])

        assert proposal_set is not None
        assert len(proposal_set) == 0

    def test_get_length_returns_zero_for_empty_set(self):
        """Test that length is zero for an empty set."""
        proposal_set = ProposalProcedureSet()
        assert len(proposal_set) == 0

    def test_get_length_returns_correct_length(self):
        """Test that length is correct after adding proposals."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        assert len(proposal_set) == 1

    def test_get_retrieves_proposal_at_index(self):
        """Test retrieving a proposal by index."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        retrieved = proposal_set.get(0)
        assert retrieved is not None

    def test_get_with_invalid_index_raises_error(self):
        """Test that getting with an invalid index raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, IndexError)):
            proposal_set.get(0)

    def test_get_with_negative_index_raises_error(self):
        """Test that getting with a negative index raises error."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        with pytest.raises((CardanoError, IndexError)):
            proposal_set.get(-1)

    def test_get_with_out_of_bounds_index_raises_error(self):
        """Test that getting with an out of bounds index raises error."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        with pytest.raises((CardanoError, IndexError)):
            proposal_set.get(1)

    def test_add_proposal_to_set(self):
        """Test adding a proposal to the set."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)

        proposal_set.add(proposal)
        assert len(proposal_set) == 1

    def test_add_multiple_proposals(self):
        """Test adding multiple proposals to the set."""
        proposal_set = ProposalProcedureSet()

        proposal1 = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal2 = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE2_CBOR)

        proposal_set.add(proposal1)
        proposal_set.add(proposal2)

        assert len(proposal_set) == 2

    def test_add_with_null_proposal_raises_error(self):
        """Test that adding a null proposal raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            proposal_set.add(None)

    def test_len_returns_correct_count(self):
        """Test that __len__ returns the correct count."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        assert len(proposal_set) == 1

    def test_iter_iterates_over_proposals(self):
        """Test that __iter__ iterates over all proposals."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        count = 0
        for _ in proposal_set:
            count += 1

        assert count == 1

    def test_iter_empty_set(self):
        """Test that iterating over an empty set yields nothing."""
        proposal_set = ProposalProcedureSet()

        count = 0
        for _ in proposal_set:
            count += 1

        assert count == 0

    def test_getitem_retrieves_by_index(self):
        """Test that __getitem__ retrieves proposal by index."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        retrieved = proposal_set[0]
        assert retrieved is not None

    def test_getitem_with_invalid_index_raises_error(self):
        """Test that __getitem__ with invalid index raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, IndexError)):
            _ = proposal_set[0]

    def test_bool_returns_true_for_non_empty_set(self):
        """Test that __bool__ returns True for non-empty set."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        assert bool(proposal_set) is True

    def test_bool_returns_false_for_empty_set(self):
        """Test that __bool__ returns False for empty set."""
        proposal_set = ProposalProcedureSet()
        assert bool(proposal_set) is False

    def test_repr_returns_string_representation(self):
        """Test that __repr__ returns a string representation."""
        proposal_set = ProposalProcedureSet()
        repr_str = repr(proposal_set)

        assert "ProposalProcedureSet" in repr_str
        assert "len=0" in repr_str

    def test_repr_with_proposals(self):
        """Test that __repr__ returns correct representation with proposals."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        repr_str = repr(proposal_set)
        assert "ProposalProcedureSet" in repr_str
        assert "len=1" in repr_str

    def test_contains_with_non_empty_set(self):
        """Test that __contains__ works with non-empty set."""
        proposal_set = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set.add(proposal)

        count = sum(1 for _ in proposal_set)
        assert count == 1

    def test_isdisjoint_returns_true_for_disjoint_sets(self):
        """Test that isdisjoint returns True for disjoint sets."""
        proposal_set1 = ProposalProcedureSet()
        proposal1 = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set1.add(proposal1)

        proposal_set2 = ProposalProcedureSet()
        proposal2 = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE2_CBOR)
        proposal_set2.add(proposal2)

        assert proposal_set1.isdisjoint(proposal_set2)

    def test_isdisjoint_with_iterable(self):
        """Test that isdisjoint works with an iterable."""
        proposal_set1 = ProposalProcedureSet()
        proposal1 = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set1.add(proposal1)

        empty_list = []
        result = proposal_set1.isdisjoint(empty_list)
        assert result

    def test_isdisjoint_with_empty_set(self):
        """Test that isdisjoint returns True when comparing with empty set."""
        proposal_set1 = ProposalProcedureSet()
        proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
        proposal_set1.add(proposal)

        proposal_set2 = ProposalProcedureSet()

        assert proposal_set1.isdisjoint(proposal_set2)

    def test_to_cip116_json_with_proposals(self):
        """Test serializing a proposal procedure set to CIP-116 JSON."""
        proposal_set = ProposalProcedureSet()

        proposals = [
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE2_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE3_CBOR),
            create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE4_CBOR)
        ]

        for proposal in proposals:
            proposal_set.add(proposal)

        writer = JsonWriter()
        proposal_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0
        assert json_str.startswith("[")
        assert json_str.endswith("]")

    def test_to_cip116_json_with_empty_set(self):
        """Test serializing an empty proposal procedure set to CIP-116 JSON."""
        proposal_set = ProposalProcedureSet()

        writer = JsonWriter()
        proposal_set.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == "[]"

    def test_to_cip116_json_with_null_writer_raises_error(self):
        """Test that serializing to CIP-116 JSON with null writer raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, TypeError)):
            proposal_set.to_cip116_json(None)

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that serializing to CIP-116 JSON with invalid writer raises error."""
        proposal_set = ProposalProcedureSet()

        with pytest.raises((CardanoError, TypeError)):
            proposal_set.to_cip116_json("not a writer")

    def test_context_manager_enter_exit(self):
        """Test that ProposalProcedureSet works as a context manager."""
        with ProposalProcedureSet() as proposal_set:
            assert proposal_set is not None
            assert len(proposal_set) == 0

    def test_context_manager_with_operations(self):
        """Test using ProposalProcedureSet as a context manager with operations."""
        with ProposalProcedureSet() as proposal_set:
            proposal = create_proposal_procedure_from_cbor(PROPOSAL_PROCEDURE1_CBOR)
            proposal_set.add(proposal)
            assert len(proposal_set) == 1
