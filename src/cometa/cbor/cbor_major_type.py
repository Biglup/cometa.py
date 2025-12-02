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


class CborMajorType(IntEnum):
    """
    Represents CBOR Major Types as defined in RFC 7049 section 2.1.

    These major types are used to identify the type of data in a CBOR data item.
    """

    UNSIGNED_INTEGER = 0
    """
    An unsigned integer.
    Range: 0 to 2^64-1 inclusive. The value of the encoded item is the argument itself.
    """

    NEGATIVE_INTEGER = 1
    """
    A negative integer.
    Range: -2^64 to -1 inclusive. The value of the item is -1 minus the argument.
    """

    BYTE_STRING = 2
    """
    A byte string.
    The number of bytes in the string is equal to the argument.
    """

    UTF8_STRING = 3
    """
    A text string encoded as UTF-8.
    Refer to Section 2 and RFC 3629. The number of bytes in the string is equal to the argument.
    """

    ARRAY = 4
    """
    An array of data items.
    The argument specifies the number of data items in the array.
    """

    MAP = 5
    """
    A map of pairs of data items.
    """

    TAG = 6
    """
    A tagged data item ("tag").
    Tag number ranges from 0 to 2^64-1 inclusive. The enclosed data item (tag content) follows the head.
    """

    SIMPLE = 7
    """
    Simple values, floating-point numbers, and the "break" stop code.
    """

    UNDEFINED = 0xFFFFFFFF
    """
    Undefined major type.
    """

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this CBOR major type.

        Returns:
            A string representation of the major type.

        Example:
            >>> from cometa.cbor import CborMajorType
            >>> major_type = CborMajorType.UNSIGNED_INTEGER
            >>> major_type.to_string()
            'Unsigned Integer'
        """
        result = lib.cardano_cbor_major_type_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
