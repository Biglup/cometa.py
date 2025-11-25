import pytest
from biglup.cometa.common.protocol_version import ProtocolVersion
from biglup.cometa.cbor.cbor_writer import CborWriter
from biglup.cometa.cbor.cbor_reader import CborReader
from biglup.cometa.json.json_writer import JsonWriter

class TestProtocolVersion:
    def test_new(self):
        """Test creating a new ProtocolVersion."""
        pv = ProtocolVersion.new(8, 0)
        assert pv.major == 8
        assert pv.minor == 0
        assert pv.refcount >= 1

    def test_setters(self):
        """Test modifying major and minor versions."""
        pv = ProtocolVersion.new(1, 0)

        pv.major = 9
        assert pv.major == 9

        pv.minor = 2
        assert pv.minor == 2

    def test_equality(self):
        """Test equality comparison."""
        pv1 = ProtocolVersion.new(8, 0)
        pv2 = ProtocolVersion.new(8, 0)
        pv3 = ProtocolVersion.new(9, 0)
        pv4 = ProtocolVersion.new(8, 1)

        assert pv1 == pv2
        assert pv1 != pv3
        assert pv1 != pv4
        assert pv1 != "not a protocol version"

    def test_repr(self):
        """Test string representation."""
        pv = ProtocolVersion.new(8, 0)
        assert repr(pv) == "<ProtocolVersion major=8 minor=0>"

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization."""
        original = ProtocolVersion.new(8, 0)

        # Serialize
        writer = CborWriter()
        original.to_cbor(writer)
        cbor_data = writer.encode()

        # Deserialize
        reader = CborReader.from_bytes(cbor_data)
        decoded = ProtocolVersion.from_cbor(reader)

        assert original == decoded

    def test_json_serialization(self):
        """Test JSON serialization."""
        pv = ProtocolVersion.new(8, 2)
        writer = JsonWriter()

        pv.to_json(writer)
        json_str = writer.encode()

        assert '"major":8' in json_str.replace(" ", "")
        assert '"minor":2' in json_str.replace(" ", "")

    def test_context_manager(self):
        """Test usage as a context manager."""
        with ProtocolVersion.new(1, 1) as pv:
            assert pv.major == 1
            assert pv.minor == 1