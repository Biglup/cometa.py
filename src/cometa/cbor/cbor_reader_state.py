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

from enum import IntEnum

from .._ffi import lib, ffi


class CborReaderState(IntEnum):
    """
    Specifies the state of a CborReader instance.

    This enumeration outlines the possible states of a CborReader as it processes
    CBOR data items.
    """

    UNDEFINED = 0
    """
    Indicates the undefined state.
    This state is used when the CborReader has not yet begun processing
    or the state is otherwise unknown.
    """

    UNSIGNED_INTEGER = 1
    """
    Indicates that the next CBOR data item is an unsigned integer (major type 0).
    """

    NEGATIVE_INTEGER = 2
    """
    Indicates that the next CBOR data item is a negative integer (major type 1).
    """

    BYTESTRING = 3
    """
    Indicates that the next CBOR data item is a byte string (major type 2).
    """

    START_INDEFINITE_LENGTH_BYTESTRING = 4
    """
    Indicates the start of an indefinite-length byte string (major type 2).
    """

    END_INDEFINITE_LENGTH_BYTESTRING = 5
    """
    Indicates the end of an indefinite-length byte string (major type 2).
    """

    TEXTSTRING = 6
    """
    Indicates that the next CBOR data item is a UTF-8 string (major type 3).
    """

    START_INDEFINITE_LENGTH_TEXTSTRING = 7
    """
    Indicates the start of an indefinite-length UTF-8 text string (major type 3).
    """

    END_INDEFINITE_LENGTH_TEXTSTRING = 8
    """
    Indicates the end of an indefinite-length UTF-8 text string (major type 3).
    """

    START_ARRAY = 9
    """
    Indicates the start of an array (major type 4).
    """

    END_ARRAY = 10
    """
    Indicates the end of an array (major type 4).
    """

    START_MAP = 11
    """
    Indicates the start of a map (major type 5).
    """

    END_MAP = 12
    """
    Indicates the end of a map (major type 5).
    """

    TAG = 13
    """
    Indicates that the next CBOR data item is a semantic reader_state (major type 6).
    """

    SIMPLE_VALUE = 14
    """
    Indicates that the next CBOR data item is a simple value (major type 7).
    """

    HALF_PRECISION_FLOAT = 15
    """
    Indicates an IEEE 754 Half-Precision float (major type 7).
    """

    SINGLE_PRECISION_FLOAT = 16
    """
    Indicates an IEEE 754 Single-Precision float (major type 7).
    """

    DOUBLE_PRECISION_FLOAT = 17
    """
    Indicates an IEEE 754 Double-Precision float (major type 7).
    """

    NULL = 18
    """
    Indicates a null literal (major type 7).
    """

    BOOLEAN = 19
    """
    Indicates a bool value (major type 7).
    """

    FINISHED = 20
    """
    Indicates the completion of reading a full CBOR document.
    This state is reached when the CborReader has successfully processed
    an entire CBOR document and there are no more data items to read.
    """

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this CBOR reader state.

        Returns:
            A string representation of the reader state.

        Example:
            >>> from cometa.cbor import CborReaderState
            >>> state = CborReaderState.UNSIGNED_INTEGER
            >>> state.to_string()
            'Unsigned Integer'
        """
        result = lib.cardano_cbor_reader_state_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
