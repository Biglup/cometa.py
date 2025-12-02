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

from __future__ import annotations
import typing

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError

if typing.TYPE_CHECKING:
    from ..cbor.cbor_reader import CborReader
    from ..cbor.cbor_writer import CborWriter
    from ..json.json_writer import JsonWriter


class ProtocolVersion:
    """
    Represents a version of the Cardano protocol.

    The protocol can be thought of as the set of rules that nodes in the network agree to follow.
    This versioning system helps nodes to keep track of which set of rules they are adhering to
    and allows for the decentralized updating of the protocol parameters without requiring a hard fork.
    """

    # --------------------------------------------------------------------------
    # Factories
    # --------------------------------------------------------------------------

    @classmethod
    def new(cls, major: int, minor: int) -> ProtocolVersion:
        """
        Creates and initializes a new instance of the Protocol Version.

        Args:
            major (int): The major version number.
            minor (int): The minor version number.
        """
        out = ffi.new("cardano_protocol_version_t**")
        err = lib.cardano_protocol_version_new(major, minor, out)
        check_error(err, lib.cardano_protocol_version_get_last_error, ffi.NULL)
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ProtocolVersion:
        """
        Creates a ProtocolVersion from a CBOR reader.

        Args:
            reader (CborReader): The CBOR reader instance.
        """
        out = ffi.new("cardano_protocol_version_t**")
        err = lib.cardano_protocol_version_from_cbor(reader._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, reader._ptr)
        return cls(out[0])

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def major(self) -> int:
        """The major version number."""
        return int(lib.cardano_protocol_version_get_major(self._ptr))

    @major.setter
    def major(self, value: int) -> None:
        """
        Sets the major version number.
        """
        err = lib.cardano_protocol_version_set_major(self._ptr, value)
        check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)

    @property
    def minor(self) -> int:
        """The minor version number."""
        return int(lib.cardano_protocol_version_get_minor(self._ptr))

    @minor.setter
    def minor(self, value: int) -> None:
        """
        Sets the minor version number.
        """
        err = lib.cardano_protocol_version_set_minor(self._ptr, value)
        check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Serialization
    # --------------------------------------------------------------------------

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes protocol version into CBOR format using a CBOR writer.

        Args:
            writer (CborWriter): The CBOR writer instance.
        """
        err = lib.cardano_protocol_version_to_cbor(self._ptr, writer._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, writer._ptr)

    def to_json(self, writer: JsonWriter) -> None:
        """
        Serializes a protocol version to CIP-116 JSON.

        Args:
            writer (JsonWriter): The JSON writer instance.
        """
        err = lib.cardano_protocol_version_to_cip116_json(self._ptr, writer._ptr)
        check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Internal State
    # --------------------------------------------------------------------------

    @property
    def refcount(self) -> int:
        """Returns the number of active references to the underlying C object."""
        return int(lib.cardano_protocol_version_refcount(self._ptr))

    @property
    def last_error(self) -> str:
        """Returns the last error message recorded for this object."""
        return ffi.string(lib.cardano_protocol_version_get_last_error(self._ptr)).decode("utf-8")

    @last_error.setter
    def last_error(self, message: str) -> None:
        """Manually sets the last error message."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_protocol_version_set_last_error(self._ptr, c_msg)

    def __init__(self, ptr) -> None:
        """
        Initializes the ProtocolVersion with a given C pointer.
        """
        if ptr == ffi.NULL:
            raise CardanoError("ProtocolVersion pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        """
        Cleans up the ProtocolVersion instance by decrementing the reference count
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_protocol_version_t**", self._ptr)
            lib.cardano_protocol_version_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProtocolVersion:
        """
        Enters the runtime context related to this object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exits the runtime context related to this object.
        """

    def __repr__(self) -> str:
        """
        Returns a string representation of the ProtocolVersion.
        """
        return f"<ProtocolVersion major={self.major} minor={self.minor}>"

    def __eq__(self, other: object) -> bool:
        """
        Compares two ProtocolVersion instances for equality.
        """
        if isinstance(other, ProtocolVersion):
            return self.major == other.major and self.minor == other.minor
        return False
