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
from cometa.witness_set.redeemer import Redeemer
from cometa.witness_set.redeemer_tag import RedeemerTag
from cometa.cbor.cbor_reader import CborReader
from cometa.cbor.cbor_writer import CborWriter
from cometa.json.json_writer import JsonWriter
from cometa.json.json_format import JsonFormat
from cometa.common.ex_units import ExUnits
from cometa.plutus_data.plutus_data import PlutusData
from cometa.errors import CardanoError


CBOR = "840000d8799f0102030405ff821821182c"
PLUTUS_DATA_CBOR = "d8799f0102030405ff"
EX_UNITS_CBOR = "821821182c"


@pytest.fixture
def default_redeemer():
    """Create a default redeemer from CBOR."""
    reader = CborReader.from_hex(CBOR)
    redeemer = Redeemer.from_cbor(reader)
    redeemer.clear_cbor_cache()
    return redeemer


@pytest.fixture
def default_plutus_data():
    """Create a default plutus data from CBOR."""
    reader = CborReader.from_hex(PLUTUS_DATA_CBOR)
    return PlutusData.from_cbor(reader)


@pytest.fixture
def default_ex_units():
    """Create a default ex_units from CBOR."""
    reader = CborReader.from_hex(EX_UNITS_CBOR)
    return ExUnits.from_cbor(reader)


class TestRedeemerNew:
    """Tests for Redeemer.new() factory method."""

    def test_new_creates_instance(self, default_plutus_data, default_ex_units):
        """Test that new() creates a Redeemer instance."""
        redeemer = Redeemer.new(
            RedeemerTag.SPEND,
            0,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer is not None
        assert isinstance(redeemer, Redeemer)

    def test_new_with_spend_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with SPEND tag."""
        redeemer = Redeemer.new(
            RedeemerTag.SPEND,
            0,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.SPEND

    def test_new_with_mint_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with MINT tag."""
        redeemer = Redeemer.new(
            RedeemerTag.MINT,
            1,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.MINT

    def test_new_with_certifying_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with CERTIFYING tag."""
        redeemer = Redeemer.new(
            RedeemerTag.CERTIFYING,
            2,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.CERTIFYING

    def test_new_with_reward_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with REWARD tag."""
        redeemer = Redeemer.new(
            RedeemerTag.REWARD,
            3,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.REWARD

    def test_new_with_voting_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with VOTING tag."""
        redeemer = Redeemer.new(
            RedeemerTag.VOTING,
            4,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.VOTING

    def test_new_with_proposing_tag(self, default_plutus_data, default_ex_units):
        """Test creating a redeemer with PROPOSING tag."""
        redeemer = Redeemer.new(
            RedeemerTag.PROPOSING,
            5,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.tag == RedeemerTag.PROPOSING

    def test_new_with_various_indices(self, default_plutus_data, default_ex_units):
        """Test creating redeemers with various indices."""
        for index in [0, 1, 10, 100, 1000]:
            redeemer = Redeemer.new(
                RedeemerTag.SPEND,
                index,
                default_plutus_data,
                default_ex_units
            )
            assert redeemer.index == index


class TestRedeemerFromCbor:
    """Tests for Redeemer.from_cbor() factory method."""

    def test_from_cbor_creates_instance(self):
        """Test that from_cbor() creates a Redeemer instance."""
        reader = CborReader.from_hex(CBOR)
        redeemer = Redeemer.from_cbor(reader)
        assert redeemer is not None
        assert isinstance(redeemer, Redeemer)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that from_cbor() with invalid CBOR raises CardanoError."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)

    def test_from_cbor_with_invalid_tag_raises_error(self):
        """Test that from_cbor() with invalid tag raises CardanoError."""
        invalid_cbor = "84ef00d8799f0102030405ff821821182c"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)

    def test_from_cbor_with_invalid_index_raises_error(self):
        """Test that from_cbor() with invalid index raises CardanoError."""
        invalid_cbor = "8400efd8799f0102030405ff821821182c"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)

    def test_from_cbor_with_invalid_plutus_data_raises_error(self):
        """Test that from_cbor() with invalid plutus data raises CardanoError."""
        invalid_cbor = "840000ef821821182c"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)

    def test_from_cbor_with_invalid_ex_units_raises_error(self):
        """Test that from_cbor() with invalid ex_units raises CardanoError."""
        invalid_cbor = "84000000ef"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)

    def test_from_cbor_with_non_array_raises_error(self):
        """Test that from_cbor() with non-array CBOR raises CardanoError."""
        reader = CborReader.from_hex("01")
        with pytest.raises(CardanoError):
            Redeemer.from_cbor(reader)


class TestRedeemerToCbor:
    """Tests for Redeemer.to_cbor() method."""

    def test_to_cbor_serializes_correctly(self, default_redeemer):
        """Test that to_cbor() serializes correctly."""
        writer = CborWriter()
        default_redeemer.to_cbor(writer)
        encoded = writer.encode()
        assert encoded.hex() == CBOR

    def test_to_cbor_with_cached_cbor(self):
        """Test that to_cbor() uses cached CBOR when available."""
        reader = CborReader.from_hex(CBOR)
        redeemer = Redeemer.from_cbor(reader)
        writer = CborWriter()
        redeemer.to_cbor(writer)
        encoded = writer.encode()
        assert encoded.hex() == CBOR

    def test_to_cbor_after_clear_cache(self, default_redeemer):
        """Test that to_cbor() works after clearing cache."""
        default_redeemer.clear_cbor_cache()
        writer = CborWriter()
        default_redeemer.to_cbor(writer)
        encoded = writer.encode()
        assert encoded.hex() == CBOR


class TestRedeemerTag:
    """Tests for Redeemer.tag property."""

    def test_tag_getter_returns_correct_value(self, default_redeemer):
        """Test that tag getter returns correct value."""
        assert default_redeemer.tag == RedeemerTag.SPEND

    def test_tag_setter_sets_value(self, default_redeemer):
        """Test that tag setter sets value correctly."""
        default_redeemer.tag = RedeemerTag.MINT
        assert default_redeemer.tag == RedeemerTag.MINT

    def test_tag_setter_with_all_valid_tags(self, default_redeemer):
        """Test that tag setter works with all valid tags."""
        for tag in RedeemerTag:
            default_redeemer.tag = tag
            assert default_redeemer.tag == tag


class TestRedeemerIndex:
    """Tests for Redeemer.index property."""

    def test_index_getter_returns_correct_value(self, default_redeemer):
        """Test that index getter returns correct value."""
        assert default_redeemer.index == 0

    def test_index_setter_sets_value(self, default_redeemer):
        """Test that index setter sets value correctly."""
        default_redeemer.index = 42
        assert default_redeemer.index == 42

    def test_index_setter_with_various_values(self, default_redeemer):
        """Test that index setter works with various values."""
        for index in [0, 1, 10, 100, 1000, 999999]:
            default_redeemer.index = index
            assert default_redeemer.index == index


class TestRedeemerData:
    """Tests for Redeemer.data property."""

    def test_data_getter_returns_plutus_data(self, default_redeemer):
        """Test that data getter returns PlutusData instance."""
        data = default_redeemer.data
        assert data is not None
        assert isinstance(data, PlutusData)

    def test_data_setter_sets_value(self, default_redeemer, default_plutus_data):
        """Test that data setter sets value correctly."""
        default_redeemer.data = default_plutus_data
        assert default_redeemer.data is not None

    def test_data_setter_updates_data(self, default_redeemer):
        """Test that data setter actually updates the data."""
        reader = CborReader.from_hex(PLUTUS_DATA_CBOR)
        new_data = PlutusData.from_cbor(reader)
        default_redeemer.data = new_data
        assert default_redeemer.data is not None


class TestRedeemerExUnits:
    """Tests for Redeemer.ex_units property."""

    def test_ex_units_getter_returns_ex_units(self, default_redeemer):
        """Test that ex_units getter returns ExUnits instance."""
        ex_units = default_redeemer.ex_units
        assert ex_units is not None
        assert isinstance(ex_units, ExUnits)

    def test_ex_units_setter_sets_value(self, default_redeemer, default_ex_units):
        """Test that ex_units setter sets value correctly."""
        default_redeemer.ex_units = default_ex_units
        assert default_redeemer.ex_units is not None

    def test_ex_units_setter_updates_ex_units(self, default_redeemer):
        """Test that ex_units setter actually updates the ex_units."""
        reader = CborReader.from_hex(EX_UNITS_CBOR)
        new_ex_units = ExUnits.from_cbor(reader)
        default_redeemer.ex_units = new_ex_units
        assert default_redeemer.ex_units is not None


class TestRedeemerClearCborCache:
    """Tests for Redeemer.clear_cbor_cache() method."""

    def test_clear_cbor_cache_clears_cache(self):
        """Test that clear_cbor_cache() clears the cached CBOR."""
        reader = CborReader.from_hex(CBOR)
        redeemer = Redeemer.from_cbor(reader)
        redeemer.clear_cbor_cache()
        writer = CborWriter()
        redeemer.to_cbor(writer)
        encoded = writer.encode()
        assert encoded.hex() == CBOR


class TestRedeemerToCip116Json:
    """Tests for Redeemer.to_cip116_json() method."""

    def test_to_cip116_json_with_spend_tag(self):
        """Test to_cip116_json() with SPEND tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.SPEND, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"spend","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_mint_tag(self):
        """Test to_cip116_json() with MINT tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.MINT, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"mint","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_certifying_tag(self):
        """Test to_cip116_json() with CERTIFYING tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.CERTIFYING, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"cert","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_reward_tag(self):
        """Test to_cip116_json() with REWARD tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.REWARD, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"reward","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_voting_tag(self):
        """Test to_cip116_json() with VOTING tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.VOTING, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"voting","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_proposing_tag(self):
        """Test to_cip116_json() with PROPOSING tag."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.PROPOSING, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        expected = '{"tag":"proposing","index":"0","data":{"tag":"bytes","value":"00"},"ex_units":{"mem":"10","steps":"10"}}'
        assert json_str == expected

    def test_to_cip116_json_with_invalid_writer_raises_error(self, default_redeemer):
        """Test that to_cip116_json() with invalid writer raises TypeError."""
        with pytest.raises(TypeError):
            default_redeemer.to_cip116_json("not a writer")


class TestRedeemerContextManager:
    """Tests for Redeemer context manager functionality."""

    def test_context_manager_works(self, default_plutus_data, default_ex_units):
        """Test that Redeemer works as a context manager."""
        with Redeemer.new(
            RedeemerTag.SPEND,
            0,
            default_plutus_data,
            default_ex_units
        ) as redeemer:
            assert redeemer is not None
            assert isinstance(redeemer, Redeemer)


class TestRedeemerRepr:
    """Tests for Redeemer.__repr__() method."""

    def test_repr_returns_string(self, default_redeemer):
        """Test that __repr__() returns a string."""
        repr_str = repr(default_redeemer)
        assert isinstance(repr_str, str)

    def test_repr_contains_tag_and_index(self, default_redeemer):
        """Test that __repr__() contains tag and index."""
        repr_str = repr(default_redeemer)
        assert "SPEND" in repr_str
        assert "0" in repr_str

    def test_repr_with_different_tags(self, default_plutus_data, default_ex_units):
        """Test __repr__() with different tags."""
        for tag in RedeemerTag:
            redeemer = Redeemer.new(tag, 0, default_plutus_data, default_ex_units)
            repr_str = repr(redeemer)
            assert tag.name in repr_str


class TestRedeemerInit:
    """Tests for Redeemer.__init__() method."""

    def test_init_with_null_ptr_raises_error(self):
        """Test that init with NULL pointer raises CardanoError."""
        from cometa._ffi import ffi
        with pytest.raises(CardanoError, match="Redeemer: invalid handle"):
            Redeemer(ffi.NULL)


class TestRedeemerRoundtrip:
    """Tests for serialization roundtrip."""

    def test_cbor_roundtrip(self, default_plutus_data, default_ex_units):
        """Test that CBOR serialization roundtrip preserves data."""
        original = Redeemer.new(
            RedeemerTag.SPEND,
            42,
            default_plutus_data,
            default_ex_units
        )
        original.clear_cbor_cache()
        writer = CborWriter()
        original.to_cbor(writer)
        encoded = writer.encode()
        reader = CborReader.from_bytes(encoded)
        decoded = Redeemer.from_cbor(reader)
        assert decoded.tag == original.tag
        assert decoded.index == original.index

    def test_json_roundtrip_format(self):
        """Test that JSON serialization produces valid format."""
        data = PlutusData.from_bytes(bytes([0x00]))
        ex_units = ExUnits.new(10, 10)
        redeemer = Redeemer.new(RedeemerTag.SPEND, 0, data, ex_units)
        writer = JsonWriter(JsonFormat.COMPACT)
        redeemer.to_cip116_json(writer)
        json_str = writer.encode()
        assert "tag" in json_str
        assert "index" in json_str
        assert "data" in json_str
        assert "ex_units" in json_str


class TestRedeemerEdgeCases:
    """Tests for edge cases."""

    def test_redeemer_with_max_index(self, default_plutus_data, default_ex_units):
        """Test redeemer with maximum index value."""
        max_index = 2**64 - 1
        redeemer = Redeemer.new(
            RedeemerTag.SPEND,
            max_index,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.index == max_index

    def test_redeemer_with_zero_index(self, default_plutus_data, default_ex_units):
        """Test redeemer with zero index."""
        redeemer = Redeemer.new(
            RedeemerTag.SPEND,
            0,
            default_plutus_data,
            default_ex_units
        )
        assert redeemer.index == 0

    def test_multiple_redeemers_independent(self, default_plutus_data, default_ex_units):
        """Test that multiple redeemer instances are independent."""
        redeemer1 = Redeemer.new(
            RedeemerTag.SPEND,
            0,
            default_plutus_data,
            default_ex_units
        )
        redeemer2 = Redeemer.new(
            RedeemerTag.MINT,
            1,
            default_plutus_data,
            default_ex_units
        )
        redeemer1.tag = RedeemerTag.CERTIFYING
        assert redeemer1.tag == RedeemerTag.CERTIFYING
        assert redeemer2.tag == RedeemerTag.MINT

    def test_redeemer_mutation_sequence(self, default_redeemer, default_ex_units):
        """Test a sequence of mutations on a redeemer."""
        original_tag = default_redeemer.tag
        original_index = default_redeemer.index
        default_redeemer.tag = RedeemerTag.MINT
        default_redeemer.index = 100
        default_redeemer.ex_units = default_ex_units
        assert default_redeemer.tag != original_tag
        assert default_redeemer.index != original_index
        assert default_redeemer.tag == RedeemerTag.MINT
        assert default_redeemer.index == 100
