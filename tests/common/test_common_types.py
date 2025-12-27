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
    Anchor,
    ByteOrder,
    Credential,
    CredentialType,
    Datum,
    DatumType,
    DRep,
    DRepType,
    ExUnits,
    GovernanceActionId,
    GovernanceKeyType,
    UnitInterval,
    Blake2bHash,
    CborReader,
    CborWriter,
)


class TestByteOrder:
    """Tests for the ByteOrder enum."""

    def test_byte_order_values(self):
        """Test that ByteOrder enum values are correct."""
        assert ByteOrder.LITTLE_ENDIAN == 0
        assert ByteOrder.BIG_ENDIAN == 1

    def test_byte_order_from_int(self):
        """Test creating ByteOrder from integer values."""
        assert ByteOrder(0) == ByteOrder.LITTLE_ENDIAN
        assert ByteOrder(1) == ByteOrder.BIG_ENDIAN

    def test_byte_order_comparison(self):
        """Test comparison between ByteOrder values."""
        assert ByteOrder.LITTLE_ENDIAN != ByteOrder.BIG_ENDIAN
        assert ByteOrder.LITTLE_ENDIAN == ByteOrder.LITTLE_ENDIAN
        assert ByteOrder.BIG_ENDIAN == ByteOrder.BIG_ENDIAN

    def test_byte_order_names(self):
        """Test that ByteOrder enum has correct names."""
        assert ByteOrder.LITTLE_ENDIAN.name == "LITTLE_ENDIAN"
        assert ByteOrder.BIG_ENDIAN.name == "BIG_ENDIAN"

    def test_byte_order_invalid_value(self):
        """Test that invalid values raise ValueError."""
        with pytest.raises(ValueError):
            ByteOrder(2)
        with pytest.raises(ValueError):
            ByteOrder(-1)
        with pytest.raises(ValueError):
            ByteOrder(100)

    def test_byte_order_is_int_enum(self):
        """Test that ByteOrder values can be used as integers."""
        assert isinstance(ByteOrder.LITTLE_ENDIAN, int)
        assert isinstance(ByteOrder.BIG_ENDIAN, int)
        assert ByteOrder.LITTLE_ENDIAN + 1 == 1
        assert ByteOrder.BIG_ENDIAN - 1 == 0

    def test_byte_order_iteration(self):
        """Test iteration over ByteOrder enum."""
        values = list(ByteOrder)
        assert len(values) == 2
        assert ByteOrder.LITTLE_ENDIAN in values
        assert ByteOrder.BIG_ENDIAN in values

    def test_byte_order_membership(self):
        """Test membership testing with ByteOrder."""
        assert 0 in ByteOrder.__members__.values()
        assert 1 in ByteOrder.__members__.values()
        assert "LITTLE_ENDIAN" in ByteOrder.__members__
        assert "BIG_ENDIAN" in ByteOrder.__members__


class TestDatumType:
    """Tests for the DatumType enum."""

    def test_datum_type_values(self):
        assert DatumType.DATA_HASH == 0
        assert DatumType.INLINE_DATA == 1

    def test_datum_type_from_int(self):
        assert DatumType(0) == DatumType.DATA_HASH
        assert DatumType(1) == DatumType.INLINE_DATA


class TestDRepType:
    """Tests for the DRepType enum."""

    def test_drep_type_values(self):
        assert DRepType.KEY_HASH == 0
        assert DRepType.SCRIPT_HASH == 1
        assert DRepType.ABSTAIN == 2
        assert DRepType.NO_CONFIDENCE == 3

    def test_drep_type_from_int(self):
        assert DRepType(0) == DRepType.KEY_HASH
        assert DRepType(1) == DRepType.SCRIPT_HASH
        assert DRepType(2) == DRepType.ABSTAIN
        assert DRepType(3) == DRepType.NO_CONFIDENCE


class TestGovernanceKeyType:
    """Tests for the GovernanceKeyType enum."""

    def test_governance_key_type_values(self):
        assert GovernanceKeyType.CC_HOT == 0
        assert GovernanceKeyType.CC_COLD == 1
        assert GovernanceKeyType.DREP == 2

    def test_governance_key_type_from_int(self):
        assert GovernanceKeyType(0) == GovernanceKeyType.CC_HOT
        assert GovernanceKeyType(1) == GovernanceKeyType.CC_COLD
        assert GovernanceKeyType(2) == GovernanceKeyType.DREP


class TestUnitInterval:
    """Tests for the UnitInterval class."""

    def test_new(self):
        interval = UnitInterval.new(1, 4)
        assert interval.numerator == 1
        assert interval.denominator == 4

    def test_from_float(self):
        interval = UnitInterval.from_float(0.25)
        assert interval.to_float() == pytest.approx(0.25)

    def test_to_float(self):
        interval = UnitInterval.new(3, 4)
        assert interval.to_float() == pytest.approx(0.75)

    def test_float_magic_method(self):
        interval = UnitInterval.new(1, 2)
        assert float(interval) == pytest.approx(0.5)

    def test_setters(self):
        interval = UnitInterval.new(1, 4)
        interval.numerator = 3
        interval.denominator = 8
        assert interval.numerator == 3
        assert interval.denominator == 8

    def test_equality(self):
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 4)
        interval3 = UnitInterval.new(1, 2)
        assert interval1 == interval2
        assert interval1 != interval3

    def test_hash(self):
        interval1 = UnitInterval.new(1, 4)
        interval2 = UnitInterval.new(1, 4)
        assert hash(interval1) == hash(interval2)

    def test_str(self):
        interval = UnitInterval.new(1, 4)
        assert str(interval) == "1/4"

    def test_repr(self):
        interval = UnitInterval.new(1, 4)
        assert repr(interval) == "UnitInterval(1/4)"

    def test_cbor_roundtrip(self):
        original = UnitInterval.new(1, 4)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = UnitInterval.from_cbor(reader)

        assert restored.numerator == original.numerator
        assert restored.denominator == original.denominator

    def test_context_manager(self):
        with UnitInterval.new(1, 4) as interval:
            assert interval.numerator == 1


class TestExUnits:
    """Tests for the ExUnits class."""

    def test_new(self):
        ex_units = ExUnits.new(1000000, 500000000)
        assert ex_units.memory == 1000000
        assert ex_units.cpu_steps == 500000000

    def test_setters(self):
        ex_units = ExUnits.new(1000, 2000)
        ex_units.memory = 3000
        ex_units.cpu_steps = 4000
        assert ex_units.memory == 3000
        assert ex_units.cpu_steps == 4000

    def test_equality(self):
        ex_units1 = ExUnits.new(1000, 2000)
        ex_units2 = ExUnits.new(1000, 2000)
        ex_units3 = ExUnits.new(1000, 3000)
        assert ex_units1 == ex_units2
        assert ex_units1 != ex_units3

    def test_hash(self):
        ex_units1 = ExUnits.new(1000, 2000)
        ex_units2 = ExUnits.new(1000, 2000)
        assert hash(ex_units1) == hash(ex_units2)

    def test_str(self):
        ex_units = ExUnits.new(1000, 2000)
        assert "mem: 1000" in str(ex_units)
        assert "steps: 2000" in str(ex_units)

    def test_repr(self):
        ex_units = ExUnits.new(1000, 2000)
        assert "memory=1000" in repr(ex_units)
        assert "cpu_steps=2000" in repr(ex_units)

    def test_cbor_roundtrip(self):
        original = ExUnits.new(1000000, 500000000)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = ExUnits.from_cbor(reader)

        assert restored.memory == original.memory
        assert restored.cpu_steps == original.cpu_steps

    def test_context_manager(self):
        with ExUnits.new(1000, 2000) as ex_units:
            assert ex_units.memory == 1000


class TestAnchor:
    """Tests for the Anchor class."""

    TEST_URL = "https://example.com/metadata.json"
    TEST_HASH = "00" * 32

    def test_from_hash_hex(self):
        anchor = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        assert anchor.url == self.TEST_URL
        assert anchor.hash_hex == self.TEST_HASH

    def test_from_hash_bytes(self):
        hash_bytes = bytes(32)
        anchor = Anchor.from_hash_bytes(self.TEST_URL, hash_bytes)
        assert anchor.url == self.TEST_URL
        assert anchor.hash_bytes == hash_bytes

    def test_new_with_blake2b_hash(self):
        hash_val = Blake2bHash.from_hex(self.TEST_HASH)
        anchor = Anchor.new(self.TEST_URL, hash_val)
        assert anchor.url == self.TEST_URL
        assert anchor.hash_hex == self.TEST_HASH

    def test_url_setter(self):
        anchor = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        new_url = "https://other.com/meta.json"
        anchor.url = new_url
        assert anchor.url == new_url

    def test_hash_setter(self):
        anchor = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        new_hash = Blake2bHash.from_hex("ff" * 32)
        anchor.hash = new_hash
        assert anchor.hash_hex == "ff" * 32

    def test_equality(self):
        anchor1 = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        anchor2 = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        anchor3 = Anchor.from_hash_hex("https://other.com", self.TEST_HASH)
        assert anchor1 == anchor2
        assert anchor1 != anchor3

    def test_hash_method(self):
        anchor1 = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        anchor2 = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        assert hash(anchor1) == hash(anchor2)

    def test_repr(self):
        anchor = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        assert self.TEST_URL in repr(anchor)

    def test_cbor_roundtrip(self):
        original = Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = Anchor.from_cbor(reader)

        assert restored.url == original.url
        assert restored.hash_hex == original.hash_hex

    def test_context_manager(self):
        with Anchor.from_hash_hex(self.TEST_URL, self.TEST_HASH) as anchor:
            assert anchor.url == self.TEST_URL


class TestDRep:
    """Tests for the DRep class."""

    TEST_KEY_HASH = "00" * 28

    def test_abstain(self):
        drep = DRep.abstain()
        assert drep.drep_type == DRepType.ABSTAIN
        assert drep.credential is None

    def test_no_confidence(self):
        drep = DRep.no_confidence()
        assert drep.drep_type == DRepType.NO_CONFIDENCE
        assert drep.credential is None

    def test_new_key_hash(self):
        cred = Credential.from_key_hash(self.TEST_KEY_HASH)
        drep = DRep.new(DRepType.KEY_HASH, cred)
        assert drep.drep_type == DRepType.KEY_HASH
        assert drep.credential is not None
        assert drep.credential.hash_hex == self.TEST_KEY_HASH

    def test_new_script_hash(self):
        cred = Credential.from_script_hash(self.TEST_KEY_HASH)
        drep = DRep.new(DRepType.SCRIPT_HASH, cred)
        assert drep.drep_type == DRepType.SCRIPT_HASH
        assert drep.credential is not None

    def test_drep_type_setter(self):
        drep = DRep.abstain()
        drep.drep_type = DRepType.NO_CONFIDENCE
        assert drep.drep_type == DRepType.NO_CONFIDENCE

    def test_equality_abstain(self):
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()
        assert drep1 == drep2

    def test_equality_no_confidence(self):
        drep1 = DRep.no_confidence()
        drep2 = DRep.no_confidence()
        assert drep1 == drep2

    def test_equality_different_types(self):
        drep1 = DRep.abstain()
        drep2 = DRep.no_confidence()
        assert drep1 != drep2

    def test_equality_with_credential(self):
        cred1 = Credential.from_key_hash(self.TEST_KEY_HASH)
        cred2 = Credential.from_key_hash(self.TEST_KEY_HASH)
        drep1 = DRep.new(DRepType.KEY_HASH, cred1)
        drep2 = DRep.new(DRepType.KEY_HASH, cred2)
        assert drep1 == drep2

    def test_hash_method(self):
        drep1 = DRep.abstain()
        drep2 = DRep.abstain()
        assert hash(drep1) == hash(drep2)

    def test_repr(self):
        drep = DRep.abstain()
        assert "ABSTAIN" in repr(drep)

    def test_str(self):
        cred = Credential.from_key_hash(self.TEST_KEY_HASH)
        drep = DRep.new(DRepType.KEY_HASH, cred)
        drep_str = str(drep)
        assert len(drep_str) > 0

    def test_cbor_roundtrip(self):
        cred = Credential.from_key_hash(self.TEST_KEY_HASH)
        original = DRep.new(DRepType.KEY_HASH, cred)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = DRep.from_cbor(reader)

        assert restored.drep_type == original.drep_type

    def test_context_manager(self):
        with DRep.abstain() as drep:
            assert drep.drep_type == DRepType.ABSTAIN


class TestGovernanceActionId:
    """Tests for the GovernanceActionId class."""

    TEST_TX_HASH = "00" * 32

    def test_from_hash_hex(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        assert gov_id.hash_hex == self.TEST_TX_HASH
        assert gov_id.index == 5

    def test_from_hash_bytes(self):
        hash_bytes = bytes(32)
        gov_id = GovernanceActionId.from_hash_bytes(hash_bytes, 3)
        assert gov_id.hash_bytes == hash_bytes
        assert gov_id.index == 3

    def test_new_with_blake2b_hash(self):
        tx_hash = Blake2bHash.from_hex(self.TEST_TX_HASH)
        gov_id = GovernanceActionId.new(tx_hash, 7)
        assert gov_id.hash_hex == self.TEST_TX_HASH
        assert gov_id.index == 7

    def test_index_setter(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 0)
        gov_id.index = 10
        assert gov_id.index == 10

    def test_transaction_hash_setter(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 0)
        new_hash = Blake2bHash.from_hex("ff" * 32)
        gov_id.transaction_hash = new_hash
        assert gov_id.hash_hex == "ff" * 32

    def test_to_bech32(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 11)
        bech32 = gov_id.to_bech32()
        assert bech32.startswith("gov_action")

    def test_from_bech32(self):
        original = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 11)
        bech32 = original.to_bech32()
        restored = GovernanceActionId.from_bech32(bech32)
        assert restored.index == original.index
        assert restored.hash_hex == original.hash_hex

    def test_equality(self):
        gov_id1 = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        gov_id2 = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        gov_id3 = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 6)
        assert gov_id1 == gov_id2
        assert gov_id1 != gov_id3

    def test_hash_method(self):
        gov_id1 = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        gov_id2 = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        assert hash(gov_id1) == hash(gov_id2)

    def test_repr(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        assert "index=5" in repr(gov_id)

    def test_str(self):
        gov_id = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        gov_str = str(gov_id)
        assert gov_str.startswith("gov_action")

    def test_cbor_roundtrip(self):
        original = GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 5)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = GovernanceActionId.from_cbor(reader)

        assert restored.hash_hex == original.hash_hex
        assert restored.index == original.index

    def test_context_manager(self):
        with GovernanceActionId.from_hash_hex(self.TEST_TX_HASH, 0) as gov_id:
            assert gov_id.index == 0


class TestDatum:
    """Tests for the Datum class."""

    TEST_HASH = "00" * 32

    def test_from_data_hash_hex(self):
        datum = Datum.from_data_hash_hex(self.TEST_HASH)
        assert datum.datum_type == DatumType.DATA_HASH
        assert datum.data_hash_hex == self.TEST_HASH

    def test_from_data_hash_bytes(self):
        hash_bytes = bytes(32)
        datum = Datum.from_data_hash_bytes(hash_bytes)
        assert datum.datum_type == DatumType.DATA_HASH
        assert datum.data_hash_bytes == hash_bytes

    def test_from_data_hash(self):
        hash_val = Blake2bHash.from_hex(self.TEST_HASH)
        datum = Datum.from_data_hash(hash_val)
        assert datum.datum_type == DatumType.DATA_HASH
        assert datum.data_hash_hex == self.TEST_HASH

    def test_data_hash_setter(self):
        datum = Datum.from_data_hash_hex(self.TEST_HASH)
        new_hash = Blake2bHash.from_hex("ff" * 32)
        datum.data_hash = new_hash
        assert datum.data_hash_hex == "ff" * 32

    def test_equality(self):
        datum1 = Datum.from_data_hash_hex(self.TEST_HASH)
        datum2 = Datum.from_data_hash_hex(self.TEST_HASH)
        datum3 = Datum.from_data_hash_hex("ff" * 32)
        assert datum1 == datum2
        assert datum1 != datum3

    def test_hash_method(self):
        datum1 = Datum.from_data_hash_hex(self.TEST_HASH)
        datum2 = Datum.from_data_hash_hex(self.TEST_HASH)
        assert hash(datum1) == hash(datum2)

    def test_repr(self):
        datum = Datum.from_data_hash_hex(self.TEST_HASH)
        assert "DATA_HASH" in repr(datum)

    def test_str(self):
        datum = Datum.from_data_hash_hex(self.TEST_HASH)
        datum_str = str(datum)
        assert "DatumHash" in datum_str

    def test_cbor_roundtrip(self):
        original = Datum.from_data_hash_hex(self.TEST_HASH)
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_bytes = writer.encode()

        reader = CborReader.from_bytes(cbor_bytes)
        restored = Datum.from_cbor(reader)

        assert restored.datum_type == original.datum_type
        assert restored.data_hash_hex == original.data_hash_hex

    def test_context_manager(self):
        with Datum.from_data_hash_hex(self.TEST_HASH) as datum:
            assert datum.datum_type == DatumType.DATA_HASH
