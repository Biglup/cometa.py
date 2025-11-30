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
from cometa import Base58, Bech32, CardanoError


class TestBase58:
    """Tests for the Base58 encoding class."""

    def test_encode_produces_string(self):
        data = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
        encoded = Base58.encode(data)
        assert isinstance(encoded, str)
        assert len(encoded) > 0

    def test_decode_produces_bytes(self):
        # Use a known valid Base58 string
        encoded = "StV1DL6CwTryKyV"  # Known encoding
        decoded = Base58.decode(encoded)
        assert isinstance(decoded, bytes)
        assert len(decoded) > 0

    def test_encode_empty(self):
        encoded = Base58.encode(b"")
        assert encoded == ""

    def test_decode_empty(self):
        decoded = Base58.decode("")
        assert decoded == b""

    def test_encode_different_data_produces_different_output(self):
        data1 = b"hello"
        data2 = b"world"
        encoded1 = Base58.encode(data1)
        encoded2 = Base58.encode(data2)
        assert encoded1 != encoded2

    def test_decode_invalid_raises(self):
        # Characters not in Base58 alphabet
        with pytest.raises(CardanoError):
            Base58.decode("0OIl")  # 0, O, I, l are not in Base58


class TestBech32:
    """Tests for the Bech32 encoding class."""

    def test_encode_simple(self):
        hrp = "addr"
        data = bytes([0x01, 0x02, 0x03, 0x04])
        encoded = Bech32.encode(hrp, data)
        assert isinstance(encoded, str)
        assert encoded.startswith("addr1")

    def test_decode_simple(self):
        hrp = "addr"
        data = bytes([0x01, 0x02, 0x03, 0x04])
        encoded = Bech32.encode(hrp, data)
        decoded_hrp, decoded_data = Bech32.decode(encoded)
        assert decoded_hrp == hrp
        assert decoded_data == data

    def test_roundtrip_various_hrps(self):
        test_hrps = ["addr", "stake", "pool", "drep", "script"]
        data = bytes([0xde, 0xad, 0xbe, 0xef])
        for hrp in test_hrps:
            encoded = Bech32.encode(hrp, data)
            decoded_hrp, decoded_data = Bech32.decode(encoded)
            assert decoded_hrp == hrp
            assert decoded_data == data

    def test_roundtrip_various_data(self):
        hrp = "test"
        test_data = [
            bytes([0x00]),
            bytes([0xff]),
            bytes(range(20)),
            bytes(range(32)),
            b"\x00" * 28,  # Typical Cardano key hash size
        ]
        for data in test_data:
            encoded = Bech32.encode(hrp, data)
            decoded_hrp, decoded_data = Bech32.decode(encoded)
            assert decoded_hrp == hrp
            assert decoded_data == data

    def test_case_insensitivity(self):
        # Bech32 is case-insensitive
        hrp = "test"
        data = bytes([0x01, 0x02, 0x03])
        encoded = Bech32.encode(hrp, data)

        # Both uppercase and lowercase should decode the same
        decoded_hrp_lower, decoded_data_lower = Bech32.decode(encoded.lower())
        decoded_hrp_upper, decoded_data_upper = Bech32.decode(encoded.upper())

        assert decoded_data_lower == data
        assert decoded_data_upper == data

    def test_cardano_address_pattern(self):
        # Test with a pattern similar to Cardano addresses
        hrp = "addr_test"
        # 57 bytes is typical for Cardano addresses
        data = bytes([0x00] + list(range(28)) + list(range(28)))
        encoded = Bech32.encode(hrp, data)
        decoded_hrp, decoded_data = Bech32.decode(encoded)
        assert decoded_hrp == hrp
        assert decoded_data == data
