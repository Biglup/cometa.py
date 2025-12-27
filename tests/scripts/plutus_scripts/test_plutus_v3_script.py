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
from cometa import PlutusV3Script, CardanoError
from cometa.cbor import CborReader, CborWriter
from cometa.json import JsonWriter, JsonFormat


PLUTUS_V3_SCRIPT = "5908920100003233223232323232332232323232323232323232332232323232322223232533532323232325335001101d13357389211e77726f6e67207573616765206f66207265666572656e636520696e7075740001c3232533500221533500221333573466e1c00800408007c407854cd4004840784078d40900114cd4c8d400488888888888802d40044c08526221533500115333533550222350012222002350022200115024213355023320015021001232153353235001222222222222300e00250052133550253200150233355025200100115026320013550272253350011502722135002225335333573466e3c00801c0940904d40b00044c01800c884c09526135001220023333573466e1cd55cea80224000466442466002006004646464646464646464646464646666ae68cdc39aab9d500c480008cccccccccccc88888888888848cccccccccccc00403403002c02802402001c01801401000c008cd405c060d5d0a80619a80b80c1aba1500b33501701935742a014666aa036eb94068d5d0a804999aa80dbae501a35742a01066a02e0446ae85401cccd5406c08dd69aba150063232323333573466e1cd55cea801240004664424660020060046464646666ae68cdc39aab9d5002480008cc8848cc00400c008cd40b5d69aba15002302e357426ae8940088c98c80c0cd5ce01901a01709aab9e5001137540026ae854008c8c8c8cccd5cd19b8735573aa004900011991091980080180119a816bad35742a004605c6ae84d5d1280111931901819ab9c03203402e135573ca00226ea8004d5d09aba2500223263202c33573805c06005426aae7940044dd50009aba1500533501775c6ae854010ccd5406c07c8004d5d0a801999aa80dbae200135742a00460426ae84d5d1280111931901419ab9c02a02c026135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d55cf280089baa00135742a00860226ae84d5d1280211931900d19ab9c01c01e018375a00a6666ae68cdc39aab9d375400a9000100e11931900c19ab9c01a01c016101b132632017335738921035054350001b135573ca00226ea800448c88c008dd6000990009aa80d911999aab9f0012500a233500930043574200460066ae880080608c8c8cccd5cd19b8735573aa004900011991091980080180118061aba150023005357426ae8940088c98c8050cd5ce00b00c00909aab9e5001137540024646464646666ae68cdc39aab9d5004480008cccc888848cccc00401401000c008c8c8c8cccd5cd19b8735573aa0049000119910919800801801180a9aba1500233500f014357426ae8940088c98c8064cd5ce00d80e80b89aab9e5001137540026ae854010ccd54021d728039aba150033232323333573466e1d4005200423212223002004357426aae79400c8cccd5cd19b875002480088c84888c004010dd71aba135573ca00846666ae68cdc3a801a400042444006464c6403666ae7007407c06406005c4d55cea80089baa00135742a00466a016eb8d5d09aba2500223263201533573802e03202626ae8940044d5d1280089aab9e500113754002266aa002eb9d6889119118011bab00132001355018223233335573e0044a010466a00e66442466002006004600c6aae754008c014d55cf280118021aba200301613574200222440042442446600200800624464646666ae68cdc3a800a400046a02e600a6ae84d55cf280191999ab9a3370ea00490011280b91931900819ab9c01201400e00d135573aa00226ea80048c8c8cccd5cd19b875001480188c848888c010014c01cd5d09aab9e500323333573466e1d400920042321222230020053009357426aae7940108cccd5cd19b875003480088c848888c004014c01cd5d09aab9e500523333573466e1d40112000232122223003005375c6ae84d55cf280311931900819ab9c01201400e00d00c00b135573aa00226ea80048c8c8cccd5cd19b8735573aa004900011991091980080180118029aba15002375a6ae84d5d1280111931900619ab9c00e01000a135573ca00226ea80048c8cccd5cd19b8735573aa002900011bae357426aae7940088c98c8028cd5ce00600700409baa001232323232323333573466e1d4005200c21222222200323333573466e1d4009200a21222222200423333573466e1d400d2008233221222222233001009008375c6ae854014dd69aba135744a00a46666ae68cdc3a8022400c4664424444444660040120106eb8d5d0a8039bae357426ae89401c8cccd5cd19b875005480108cc8848888888cc018024020c030d5d0a8049bae357426ae8940248cccd5cd19b875006480088c848888888c01c020c034d5d09aab9e500b23333573466e1d401d2000232122222223005008300e357426aae7940308c98c804ccd5ce00a80b80880800780700680600589aab9d5004135573ca00626aae7940084d55cf280089baa0012323232323333573466e1d400520022333222122333001005004003375a6ae854010dd69aba15003375a6ae84d5d1280191999ab9a3370ea0049000119091180100198041aba135573ca00c464c6401866ae700380400280244d55cea80189aba25001135573ca00226ea80048c8c8cccd5cd19b875001480088c8488c00400cdd71aba135573ca00646666ae68cdc3a8012400046424460040066eb8d5d09aab9e500423263200933573801601a00e00c26aae7540044dd500089119191999ab9a3370ea00290021091100091999ab9a3370ea00490011190911180180218031aba135573ca00846666ae68cdc3a801a400042444004464c6401466ae7003003802001c0184d55cea80089baa0012323333573466e1d40052002200623333573466e1d40092000200623263200633573801001400800626aae74dd5000a4c244004244002921035054310012333333357480024a00c4a00c4a00c46a00e6eb400894018008480044488c0080049400848488c00800c4488004448c8c00400488cc00cc0080080041"
PLUTUS_V3_HASH = "16df94237e8e3abce4016304952b88720ec897b59a5b4b7ce4e1b6b4"
PLUTUS_V3_CBOR = "5908955908920100003233223232323232332232323232323232323232332232323232322223232533532323232325335001101d13357389211e77726f6e67207573616765206f66207265666572656e636520696e7075740001c3232533500221533500221333573466e1c00800408007c407854cd4004840784078d40900114cd4c8d400488888888888802d40044c08526221533500115333533550222350012222002350022200115024213355023320015021001232153353235001222222222222300e00250052133550253200150233355025200100115026320013550272253350011502722135002225335333573466e3c00801c0940904d40b00044c01800c884c09526135001220023333573466e1cd55cea80224000466442466002006004646464646464646464646464646666ae68cdc39aab9d500c480008cccccccccccc88888888888848cccccccccccc00403403002c02802402001c01801401000c008cd405c060d5d0a80619a80b80c1aba1500b33501701935742a014666aa036eb94068d5d0a804999aa80dbae501a35742a01066a02e0446ae85401cccd5406c08dd69aba150063232323333573466e1cd55cea801240004664424660020060046464646666ae68cdc39aab9d5002480008cc8848cc00400c008cd40b5d69aba15002302e357426ae8940088c98c80c0cd5ce01901a01709aab9e5001137540026ae854008c8c8c8cccd5cd19b8735573aa004900011991091980080180119a816bad35742a004605c6ae84d5d1280111931901819ab9c03203402e135573ca00226ea8004d5d09aba2500223263202c33573805c06005426aae7940044dd50009aba1500533501775c6ae854010ccd5406c07c8004d5d0a801999aa80dbae200135742a00460426ae84d5d1280111931901419ab9c02a02c026135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d5d1280089aba25001135744a00226ae8940044d55cf280089baa00135742a00860226ae84d5d1280211931900d19ab9c01c01e018375a00a6666ae68cdc39aab9d375400a9000100e11931900c19ab9c01a01c016101b132632017335738921035054350001b135573ca00226ea800448c88c008dd6000990009aa80d911999aab9f0012500a233500930043574200460066ae880080608c8c8cccd5cd19b8735573aa004900011991091980080180118061aba150023005357426ae8940088c98c8050cd5ce00b00c00909aab9e5001137540024646464646666ae68cdc39aab9d5004480008cccc888848cccc00401401000c008c8c8c8cccd5cd19b8735573aa0049000119910919800801801180a9aba1500233500f014357426ae8940088c98c8064cd5ce00d80e80b89aab9e5001137540026ae854010ccd54021d728039aba150033232323333573466e1d4005200423212223002004357426aae79400c8cccd5cd19b875002480088c84888c004010dd71aba135573ca00846666ae68cdc3a801a400042444006464c6403666ae7007407c06406005c4d55cea80089baa00135742a00466a016eb8d5d09aba2500223263201533573802e03202626ae8940044d5d1280089aab9e500113754002266aa002eb9d6889119118011bab00132001355018223233335573e0044a010466a00e66442466002006004600c6aae754008c014d55cf280118021aba200301613574200222440042442446600200800624464646666ae68cdc3a800a400046a02e600a6ae84d55cf280191999ab9a3370ea00490011280b91931900819ab9c01201400e00d135573aa00226ea80048c8c8cccd5cd19b875001480188c848888c010014c01cd5d09aab9e500323333573466e1d400920042321222230020053009357426aae7940108cccd5cd19b875003480088c848888c004014c01cd5d09aab9e500523333573466e1d40112000232122223003005375c6ae84d55cf280311931900819ab9c01201400e00d00c00b135573aa00226ea80048c8c8cccd5cd19b8735573aa004900011991091980080180118029aba15002375a6ae84d5d1280111931900619ab9c00e01000a135573ca00226ea80048c8cccd5cd19b8735573aa002900011bae357426aae7940088c98c8028cd5ce00600700409baa001232323232323333573466e1d4005200c21222222200323333573466e1d4009200a21222222200423333573466e1d400d2008233221222222233001009008375c6ae854014dd69aba135744a00a46666ae68cdc3a8022400c4664424444444660040120106eb8d5d0a8039bae357426ae89401c8cccd5cd19b875005480108cc8848888888cc018024020c030d5d0a8049bae357426ae8940248cccd5cd19b875006480088c848888888c01c020c034d5d09aab9e500b23333573466e1d401d2000232122222223005008300e357426aae7940308c98c804ccd5ce00a80b80880800780700680600589aab9d5004135573ca00626aae7940084d55cf280089baa0012323232323333573466e1d400520022333222122333001005004003375a6ae854010dd69aba15003375a6ae84d5d1280191999ab9a3370ea0049000119091180100198041aba135573ca00c464c6401866ae700380400280244d55cea80189aba25001135573ca00226ea80048c8c8cccd5cd19b875001480088c8488c00400cdd71aba135573ca00646666ae68cdc3a8012400046424460040066eb8d5d09aab9e500423263200933573801601a00e00c26aae7540044dd500089119191999ab9a3370ea00290021091100091999ab9a3370ea00490011190911180180218031aba135573ca00846666ae68cdc3a801a400042444004464c6401466ae7003003802001c0184d55cea80089baa0012323333573466e1d40052002200623333573466e1d40092000200623263200633573801001400800626aae74dd5000a4c244004244002921035054310012333333357480024a00c4a00c4a00c46a00e6eb400894018008480044488c0080049400848488c00800c4488004448c8c00400488cc00cc0080080041"


class TestPlutusV3Script:
    """Tests for the PlutusV3Script class."""

    def test_new_creates_script_from_bytes(self):
        """Test creating a PlutusV3Script from raw bytes."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)

        assert script is not None
        assert isinstance(script, PlutusV3Script)

    def test_new_with_empty_bytes_raises_error(self):
        """Test that creating a script with empty bytes raises CardanoError."""
        with pytest.raises(CardanoError):
            PlutusV3Script.new(b"")

    def test_new_with_invalid_bytes_type_raises_error(self):
        """Test that passing non-bytes to new raises TypeError."""
        with pytest.raises(TypeError):
            PlutusV3Script.new("not bytes")

        with pytest.raises(TypeError):
            PlutusV3Script.new(None)

        with pytest.raises(TypeError):
            PlutusV3Script.new(123)

    def test_from_hex_creates_script_from_hex_string(self):
        """Test creating a PlutusV3Script from hexadecimal string."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script is not None
        assert isinstance(script, PlutusV3Script)

    def test_from_hex_with_empty_string_raises_error(self):
        """Test that creating a script with empty hex string raises CardanoError."""
        with pytest.raises(CardanoError):
            PlutusV3Script.from_hex("")

    def test_from_hex_with_invalid_hex_creates_script(self):
        """Test that invalid hex characters are accepted by the C library."""
        script = PlutusV3Script.from_hex("zzzz")
        assert script is not None

    def test_from_hex_with_odd_length_hex_raises_error(self):
        """Test that odd-length hex string raises CardanoError."""
        with pytest.raises(CardanoError):
            PlutusV3Script.from_hex("abc")

    def test_from_hex_with_invalid_type_raises_error(self):
        """Test that passing non-string to from_hex raises TypeError."""
        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_hex(123)

        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_hex(None)

        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_hex(b"bytes")

    def test_from_cbor_deserializes_script(self):
        """Test deserializing a PlutusV3Script from CBOR."""
        cbor_hex = PLUTUS_V3_CBOR
        reader = CborReader.from_hex(cbor_hex)
        script = PlutusV3Script.from_cbor(reader)

        assert script is not None
        assert isinstance(script, PlutusV3Script)

    def test_from_cbor_with_invalid_cbor_raises_error(self):
        """Test that invalid CBOR data raises CardanoError."""
        reader = CborReader.from_hex("ff")
        with pytest.raises(CardanoError):
            PlutusV3Script.from_cbor(reader)

    def test_from_cbor_with_invalid_type_raises_error(self):
        """Test that passing non-CborReader to from_cbor raises error."""
        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_cbor("not a reader")

        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_cbor(None)

        with pytest.raises((TypeError, AttributeError)):
            PlutusV3Script.from_cbor(123)

    def test_to_cbor_serializes_script(self):
        """Test serializing a PlutusV3Script to CBOR."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)
        writer = CborWriter()

        script.to_cbor(writer)

        cbor_hex = writer.to_hex()
        assert cbor_hex == PLUTUS_V3_CBOR

    def test_to_cbor_with_invalid_type_raises_error(self):
        """Test that passing non-CborWriter to to_cbor raises error."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)

        with pytest.raises((TypeError, AttributeError)):
            script.to_cbor("not a writer")

        with pytest.raises((TypeError, AttributeError)):
            script.to_cbor(None)

        with pytest.raises((TypeError, AttributeError)):
            script.to_cbor(123)

    def test_cbor_roundtrip(self):
        """Test that serializing and deserializing preserves the script."""
        original_script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        writer = CborWriter()
        original_script.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader = CborReader.from_hex(cbor_hex)
        restored_script = PlutusV3Script.from_cbor(reader)

        assert original_script == restored_script

    def test_hash_returns_correct_hash(self):
        """Test that hash property returns the correct Blake2b hash."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script_hash = script.hash

        assert script_hash is not None
        assert isinstance(script_hash, bytes)
        assert len(script_hash) == 28
        assert script_hash.hex() == PLUTUS_V3_HASH

    def test_hash_is_consistent(self):
        """Test that calling hash multiple times returns the same value."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        hash1 = script.hash
        hash2 = script.hash

        assert hash1 == hash2

    def test_raw_bytes_returns_script_bytes(self):
        """Test that raw_bytes property returns the compiled script bytes."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)
        raw = script.raw_bytes

        assert raw is not None
        assert isinstance(raw, bytes)
        assert raw == script_bytes

    def test_raw_bytes_is_consistent(self):
        """Test that calling raw_bytes multiple times returns the same value."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)
        raw1 = script.raw_bytes
        raw2 = script.raw_bytes

        assert raw1 == raw2

    def test_equality_same_script(self):
        """Test that two scripts with the same content are equal."""
        script1 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script2 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script1 == script2

    def test_equality_different_scripts(self):
        """Test that two scripts with different content are not equal."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script1 = PlutusV3Script.new(script_bytes)
        script2 = PlutusV3Script.new(script_bytes[:-1])

        assert script1 != script2

    def test_equality_with_non_script_returns_not_implemented(self):
        """Test that equality with non-PlutusV3Script returns NotImplemented."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert (script == "not a script") is False
        assert (script == 123) is False
        assert (script == None) is False
        assert (script == b"bytes") is False

    def test_repr_contains_hash(self):
        """Test that repr includes the script hash."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        repr_str = repr(script)

        assert "PlutusV3Script" in repr_str
        assert "hash=" in repr_str
        assert PLUTUS_V3_HASH in repr_str

    def test_context_manager_protocol(self):
        """Test that PlutusV3Script can be used as a context manager."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)

        with PlutusV3Script.new(script_bytes) as script:
            assert script is not None
            assert isinstance(script, PlutusV3Script)
            script_hash = script.hash
            assert script_hash is not None

    def test_multiple_scripts_independence(self):
        """Test that multiple script instances are independent."""
        script1 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script2 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        hash1 = script1.hash
        hash2 = script2.hash

        assert hash1 == hash2
        assert script1 == script2

    def test_script_created_from_bytes_and_hex_are_equal(self):
        """Test that scripts created from bytes and hex are equal."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script_from_bytes = PlutusV3Script.new(script_bytes)
        script_from_hex = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script_from_bytes == script_from_hex
        assert script_from_bytes.hash == script_from_hex.hash
        assert script_from_bytes.raw_bytes == script_from_hex.raw_bytes

    def test_script_hash_length(self):
        """Test that script hash is always 28 bytes (224 bits)."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script_hash = script.hash

        assert len(script_hash) == 28

    def test_small_script_creation(self):
        """Test creating a small Plutus V3 script."""
        small_script_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        script = PlutusV3Script.new(small_script_bytes)

        assert script is not None
        assert script.raw_bytes == small_script_bytes

    def test_script_hash_is_deterministic(self):
        """Test that the same script always produces the same hash."""
        script1 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script2 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script1.hash == script2.hash

    def test_different_scripts_have_different_hashes(self):
        """Test that different scripts produce different hashes."""
        script_bytes1 = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script_bytes2 = script_bytes1[:-1]

        script1 = PlutusV3Script.new(script_bytes1)
        script2 = PlutusV3Script.new(script_bytes2)

        assert script1.hash != script2.hash

    def test_cbor_serialization_format(self):
        """Test that CBOR serialization produces valid CBOR."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        writer = CborWriter()

        script.to_cbor(writer)
        cbor_hex = writer.to_hex()

        assert cbor_hex.startswith("59")

    def test_script_from_cbor_creates_independent_instance(self):
        """Test that from_cbor creates a new independent instance."""
        reader = CborReader.from_hex(PLUTUS_V3_CBOR)
        script1 = PlutusV3Script.from_cbor(reader)

        reader = CborReader.from_hex(PLUTUS_V3_CBOR)
        script2 = PlutusV3Script.from_cbor(reader)

        assert script1 == script2
        assert script1 is not script2

    def test_inequality_operator(self):
        """Test the inequality operator works correctly."""
        script_bytes1 = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script_bytes2 = script_bytes1[:-1]

        script1 = PlutusV3Script.new(script_bytes1)
        script2 = PlutusV3Script.new(script_bytes2)

        assert script1 != script2
        assert not (script1 != script1)

    def test_script_hash_hex_format(self):
        """Test that script hash can be converted to hex format."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script_hash = script.hash
        hash_hex = script_hash.hex()

        assert hash_hex == PLUTUS_V3_HASH
        assert len(hash_hex) == 56

    def test_script_bytes_immutability(self):
        """Test that raw_bytes returns a copy, not a mutable reference."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)
        script = PlutusV3Script.new(script_bytes)
        raw1 = script.raw_bytes
        raw2 = script.raw_bytes

        assert raw1 == raw2

    def test_new_from_single_byte(self):
        """Test creating a script from a single byte."""
        script = PlutusV3Script.new(b"\x01")
        assert script is not None
        assert script.raw_bytes == b"\x01"

    def test_from_hex_lowercase(self):
        """Test from_hex accepts lowercase hex string."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT.lower())
        assert script is not None

    def test_from_hex_uppercase(self):
        """Test from_hex accepts uppercase hex string."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT.upper())
        assert script is not None

    def test_from_hex_mixed_case(self):
        """Test from_hex accepts mixed case hex string."""
        mixed_case = "aAbBcCdD"
        script = PlutusV3Script.from_hex(mixed_case)
        assert script is not None
        assert script.raw_bytes.hex() == mixed_case.lower()

    def test_equality_reflexive(self):
        """Test that equality is reflexive (a == a)."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        assert script == script

    def test_equality_symmetric(self):
        """Test that equality is symmetric (a == b implies b == a)."""
        script1 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script2 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script1 == script2
        assert script2 == script1

    def test_equality_transitive(self):
        """Test that equality is transitive (a == b and b == c implies a == c)."""
        script1 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script2 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        script3 = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        assert script1 == script2
        assert script2 == script3
        assert script1 == script3

    def test_hash_consistency_across_creation_methods(self):
        """Test that hash is consistent regardless of creation method."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)

        script_from_bytes = PlutusV3Script.new(script_bytes)
        script_from_hex = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        reader = CborReader.from_hex(PLUTUS_V3_CBOR)
        script_from_cbor = PlutusV3Script.from_cbor(reader)

        assert script_from_bytes.hash == script_from_hex.hash
        assert script_from_hex.hash == script_from_cbor.hash

    def test_raw_bytes_consistency_across_creation_methods(self):
        """Test that raw_bytes is consistent regardless of creation method."""
        script_bytes = bytes.fromhex(PLUTUS_V3_SCRIPT)

        script_from_bytes = PlutusV3Script.new(script_bytes)
        script_from_hex = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        reader = CborReader.from_hex(PLUTUS_V3_CBOR)
        script_from_cbor = PlutusV3Script.from_cbor(reader)

        assert script_from_bytes.raw_bytes == script_from_hex.raw_bytes
        assert script_from_hex.raw_bytes == script_from_cbor.raw_bytes

    def test_multiple_cbor_operations(self):
        """Test multiple serialization and deserialization operations."""
        original_script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)

        for _ in range(3):
            writer = CborWriter()
            original_script.to_cbor(writer)
            cbor_hex = writer.to_hex()

            reader = CborReader.from_hex(cbor_hex)
            restored_script = PlutusV3Script.from_cbor(reader)

            assert original_script == restored_script
            original_script = restored_script

    def test_script_with_all_zero_bytes(self):
        """Test creating a script with all zero bytes."""
        zero_bytes = bytes(32)
        script = PlutusV3Script.new(zero_bytes)

        assert script is not None
        assert script.raw_bytes == zero_bytes

    def test_script_with_all_ff_bytes(self):
        """Test creating a script with all 0xFF bytes."""
        ff_bytes = bytes([0xFF] * 32)
        script = PlutusV3Script.new(ff_bytes)

        assert script is not None
        assert script.raw_bytes == ff_bytes

    def test_large_script_handling(self):
        """Test that large scripts are handled correctly."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        raw = script.raw_bytes

        assert len(raw) > 1000
        assert len(raw) == len(bytes.fromhex(PLUTUS_V3_SCRIPT))

    def test_to_cip116_json_compact_format(self):
        """Test serializing a script to CIP-116 JSON in compact format."""
        script_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        script = PlutusV3Script.new(script_bytes)
        writer = JsonWriter(JsonFormat.COMPACT)

        script.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str == '{"language":"plutus_v3","bytes":"01020304"}'

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that passing non-JsonWriter to to_cip116_json raises error."""
        script_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        script = PlutusV3Script.new(script_bytes)

        with pytest.raises((TypeError, AttributeError)):
            script.to_cip116_json("not a writer")

        with pytest.raises((TypeError, AttributeError)):
            script.to_cip116_json(None)

        with pytest.raises((TypeError, AttributeError)):
            script.to_cip116_json(123)

    def test_to_cip116_json_contains_language_field(self):
        """Test that CIP-116 JSON output contains the language field."""
        script_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        script = PlutusV3Script.new(script_bytes)
        writer = JsonWriter()

        script.to_cip116_json(writer)
        json_dict = writer.to_dict()

        assert "language" in json_dict
        assert json_dict["language"] == "plutus_v3"

    def test_to_cip116_json_contains_bytes_field(self):
        """Test that CIP-116 JSON output contains the bytes field."""
        script_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        script = PlutusV3Script.new(script_bytes)
        writer = JsonWriter()

        script.to_cip116_json(writer)
        json_dict = writer.to_dict()

        assert "bytes" in json_dict
        assert json_dict["bytes"] == "01020304"

    def test_to_cip116_json_bytes_are_lowercase_hex(self):
        """Test that bytes in CIP-116 JSON are lowercase hex."""
        script_bytes = bytes([0xAB, 0xCD, 0xEF])
        script = PlutusV3Script.new(script_bytes)
        writer = JsonWriter()

        script.to_cip116_json(writer)
        json_dict = writer.to_dict()

        assert json_dict["bytes"] == "abcdef"

    def test_to_cip116_json_large_script(self):
        """Test CIP-116 JSON serialization with a large script."""
        script = PlutusV3Script.from_hex(PLUTUS_V3_SCRIPT)
        writer = JsonWriter()

        script.to_cip116_json(writer)
        json_dict = writer.to_dict()

        assert json_dict["language"] == "plutus_v3"
        assert json_dict["bytes"] == PLUTUS_V3_SCRIPT.lower()
