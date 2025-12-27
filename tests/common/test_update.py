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
    Update,
    ProposedParamUpdates,
    CborReader,
    CborWriter,
    JsonWriter,
    CardanoError,
)


CBOR = "82a3581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000002b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000003b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba19020b"
PROPOSED_PARAM_CBOR = "a3581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000002b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000003b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba"


class TestUpdateNew:
    """Tests for Update.new() factory method."""

    def test_can_create_update(self):
        """Test that an Update can be created with valid epoch and proposed updates."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        assert update is not None

    def test_can_create_update_with_epoch_zero(self):
        """Test that an Update can be created with epoch 0."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=0, proposed_updates=proposed)
        assert update is not None
        assert update.epoch == 0

    def test_can_create_update_with_large_epoch(self):
        """Test that an Update can be created with a large epoch number."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        large_epoch = 999999
        update = Update.new(epoch=large_epoch, proposed_updates=proposed)
        assert update is not None
        assert update.epoch == large_epoch

    def test_new_raises_error_for_none_proposed_updates(self):
        """Test that Update.new raises error when proposed_updates is None."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Update.new(epoch=1, proposed_updates=None)

    def test_new_raises_error_for_invalid_epoch_type(self):
        """Test that Update.new raises error for invalid epoch type."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        with pytest.raises((CardanoError, TypeError)):
            Update.new(epoch="invalid", proposed_updates=proposed)

    def test_new_raises_error_for_negative_epoch(self):
        """Test that Update.new raises error for negative epoch."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            Update.new(epoch=-1, proposed_updates=proposed)


class TestUpdateCbor:
    """Tests for CBOR serialization/deserialization."""

    def test_can_serialize_to_cbor(self):
        """Test that Update can be serialized to CBOR."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=523, proposed_updates=proposed)

        writer = CborWriter()
        update.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_can_deserialize_from_cbor(self):
        """Test that Update can be deserialized from CBOR."""
        reader = CborReader.from_hex(CBOR)
        update = Update.from_cbor(reader)
        assert update is not None
        assert update.epoch == 523

    def test_roundtrip_cbor_serialization(self):
        """Test that CBOR serialization/deserialization roundtrip works."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        original = Update.new(epoch=100, proposed_updates=proposed)

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = Update.from_cbor(reader2)

        assert deserialized.epoch == original.epoch

    def test_from_cbor_raises_error_with_none_reader(self):
        """Test that from_cbor raises error with None reader."""
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Update.from_cbor(None)

    def test_to_cbor_raises_error_with_none_writer(self):
        """Test that to_cbor raises error with None writer."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            update.to_cbor(None)

    def test_from_cbor_raises_error_with_invalid_cbor_type(self):
        """Test that from_cbor raises error with invalid CBOR type (map instead of array)."""
        reader = CborReader.from_hex("a1")
        with pytest.raises(CardanoError):
            Update.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_proposed_update(self):
        """Test that from_cbor raises error with invalid proposed update CBOR."""
        invalid_cbor = "8283581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a20098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a0198af1a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a0011b22c1a0005fdde00021a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0223accc0a1a0374f693194a1f0a1a02515e841980b30a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b000000010000000019020b"
        reader = CborReader.from_hex(invalid_cbor)
        with pytest.raises(CardanoError):
            Update.from_cbor(reader)

    def test_from_cbor_raises_error_with_invalid_epoch(self):
        """Test that from_cbor raises error with invalid epoch encoding."""
        invalid_epoch_cbor = "82f6a0"
        reader = CborReader.from_hex(invalid_epoch_cbor)
        with pytest.raises(CardanoError):
            Update.from_cbor(reader)


class TestUpdateEpochProperty:
    """Tests for epoch property (getter and setter)."""

    def test_can_get_epoch(self):
        """Test that epoch can be retrieved."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=123, proposed_updates=proposed)
        assert update.epoch == 123

    def test_can_set_epoch(self):
        """Test that epoch can be set."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        update.epoch = 456
        assert update.epoch == 456

    def test_can_update_epoch_multiple_times(self):
        """Test that epoch can be updated multiple times."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        update.epoch = 100
        update.epoch = 200
        update.epoch = 300
        assert update.epoch == 300

    def test_can_set_epoch_to_zero(self):
        """Test that epoch can be set to zero."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=100, proposed_updates=proposed)
        update.epoch = 0
        assert update.epoch == 0

    def test_can_set_large_epoch_value(self):
        """Test that large epoch values can be set."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        large_value = 18446744073709551615
        update.epoch = large_value
        assert update.epoch == large_value

    def test_set_epoch_raises_error_for_negative(self):
        """Test that setting negative epoch raises an error."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        with pytest.raises((CardanoError, OverflowError, TypeError)):
            update.epoch = -1


class TestUpdateProposedParametersProperty:
    """Tests for proposed_parameters property (getter and setter)."""

    def test_can_get_proposed_parameters(self):
        """Test that proposed_parameters can be retrieved."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        result = update.proposed_parameters
        assert result is not None

    def test_can_set_proposed_parameters(self):
        """Test that proposed_parameters can be set."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)

        reader2 = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        new_proposed = ProposedParamUpdates.from_cbor(reader2)
        update.proposed_parameters = new_proposed

        result = update.proposed_parameters
        assert result is not None

    def test_set_proposed_parameters_raises_error_for_none(self):
        """Test that setting proposed_parameters to None raises error."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        with pytest.raises((CardanoError, TypeError, AttributeError)):
            update.proposed_parameters = None


class TestUpdateJson:
    """Tests for JSON serialization (CIP-116)."""

    def test_can_convert_to_cip116_json(self):
        """Test conversion to CIP-116 JSON format."""
        reader = CborReader.from_hex(CBOR)
        update = Update.from_cbor(reader)

        writer = JsonWriter()
        update.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0
        assert "epoch" in json_str
        assert "proposed_protocol_parameter_updates" in json_str

    def test_cip116_json_contains_correct_epoch(self):
        """Test that CIP-116 JSON contains the correct epoch value."""
        reader = CborReader.from_hex(CBOR)
        update = Update.from_cbor(reader)

        writer = JsonWriter()
        update.to_cip116_json(writer)
        json_str = writer.encode()

        assert '"epoch":523' in json_str or '"epoch": 523' in json_str

    def test_to_cip116_json_raises_error_with_none_writer(self):
        """Test that to_cip116_json raises error with None writer."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=100, proposed_updates=proposed)
        with pytest.raises((CardanoError, TypeError)):
            update.to_cip116_json(None)

    def test_to_cip116_json_raises_error_with_wrong_writer_type(self):
        """Test that to_cip116_json raises error with wrong writer type."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=100, proposed_updates=proposed)
        with pytest.raises((CardanoError, TypeError)):
            update.to_cip116_json("not a writer")


class TestUpdateMagicMethods:
    """Tests for magic methods (__repr__, __enter__, __exit__)."""

    def test_repr_returns_string(self):
        """Test that __repr__ returns a string."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=123, proposed_updates=proposed)
        repr_str = repr(update)
        assert "Update" in repr_str
        assert "123" in repr_str

    def test_repr_includes_epoch(self):
        """Test that __repr__ includes the epoch value."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=456, proposed_updates=proposed)
        repr_str = repr(update)
        assert "456" in repr_str

    def test_can_use_as_context_manager(self):
        """Test that Update can be used as a context manager."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        with Update.new(epoch=1, proposed_updates=proposed) as update:
            assert update is not None
            assert update.epoch == 1

    def test_context_manager_exit_doesnt_crash(self):
        """Test that context manager exit doesn't crash."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=1, proposed_updates=proposed)
        with update:
            pass


class TestUpdateComplexScenarios:
    """Tests for complex scenarios and edge cases."""

    def test_can_modify_epoch_and_serialize(self):
        """Test that epoch can be modified and then serialized."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=100, proposed_updates=proposed)
        update.epoch = 200

        writer = CborWriter()
        update.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = Update.from_cbor(reader2)
        assert deserialized.epoch == 200

    def test_can_serialize_both_cbor_and_json(self):
        """Test that Update can be serialized to both CBOR and JSON."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=123, proposed_updates=proposed)

        cbor_writer = CborWriter()
        update.to_cbor(cbor_writer)
        cbor_hex = cbor_writer.to_hex()

        json_writer = JsonWriter()
        update.to_cip116_json(json_writer)
        json_str = json_writer.encode()

        assert cbor_hex is not None
        assert json_str is not None
        assert len(cbor_hex) > 0
        assert len(json_str) > 0

    def test_full_roundtrip_preserves_data(self):
        """Test that full CBOR roundtrip preserves all data."""
        reader = CborReader.from_hex(CBOR)
        original = Update.from_cbor(reader)
        original_epoch = original.epoch

        writer = CborWriter()
        original.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = Update.from_cbor(reader2)

        assert deserialized.epoch == original_epoch

    def test_multiple_updates_independent(self):
        """Test that multiple Update instances are independent."""
        reader1 = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed1 = ProposedParamUpdates.from_cbor(reader1)
        update1 = Update.new(epoch=100, proposed_updates=proposed1)

        reader2 = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed2 = ProposedParamUpdates.from_cbor(reader2)
        update2 = Update.new(epoch=200, proposed_updates=proposed2)

        update1.epoch = 300

        assert update1.epoch == 300
        assert update2.epoch == 200


class TestUpdateEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_can_handle_max_uint64_epoch(self):
        """Test that maximum uint64 epoch value can be handled."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        max_uint64 = 18446744073709551615
        update = Update.new(epoch=max_uint64, proposed_updates=proposed)
        assert update.epoch == max_uint64

    def test_serialization_with_max_epoch(self):
        """Test serialization with maximum epoch value."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        max_uint64 = 18446744073709551615
        update = Update.new(epoch=max_uint64, proposed_updates=proposed)

        writer = CborWriter()
        update.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = Update.from_cbor(reader2)
        assert deserialized.epoch == max_uint64

    def test_can_handle_epoch_zero(self):
        """Test that epoch value of zero can be handled."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        update = Update.new(epoch=0, proposed_updates=proposed)
        assert update.epoch == 0

        writer = CborWriter()
        update.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        deserialized = Update.from_cbor(reader2)
        assert deserialized.epoch == 0

    def test_json_serialization_preserves_epoch(self):
        """Test that JSON serialization preserves epoch value."""
        reader = CborReader.from_hex(PROPOSED_PARAM_CBOR)
        proposed = ProposedParamUpdates.from_cbor(reader)
        test_epoch = 12345
        update = Update.new(epoch=test_epoch, proposed_updates=proposed)

        writer = JsonWriter()
        update.to_cip116_json(writer)
        json_str = writer.encode()

        assert str(test_epoch) in json_str
