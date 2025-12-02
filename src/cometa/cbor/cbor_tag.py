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


class CborTag(IntEnum):
    """
    Represents a CBOR semantic tag (major type 6).

    Semantic tags in CBOR (Concise Binary Object Representation) provide additional context
    to the data items that follow them, as defined in the CBOR standard (RFC 7049). These tags
    indicate how the subsequent data should be interpreted, ranging from date/time formats
    to various encoding schemes and specialized data types.
    """

    DATE_TIME_STRING = 0
    """
    Tag value for RFC3339 date/time strings.
    Indicates that the following string data item is formatted according
    to the RFC3339 specification for date and time.
    """

    UNIX_TIME_SECONDS = 1
    """
    Tag value for Epoch-based date/time in seconds.
    Denotes that the following integer data item represents a date and time as
    the number of seconds elapsed since the Unix epoch (1970-01-01T00:00Z).
    """

    UNSIGNED_BIG_NUM = 2
    """
    Tag value for unsigned bignum encodings.
    Used to encode arbitrarily large unsigned integers that cannot fit within
    the standard integer data item types.
    """

    NEGATIVE_BIG_NUM = 3
    """
    Tag value for negative bignum encodings.
    Represents arbitrarily large negative integers, complementing the unsigned
    bignum encoding for handling integers beyond the built-in integer types.
    """

    DECIMAL_FRACTION = 4
    """
    Tag value for decimal fraction encodings.
    Allows for the precise representation of decimal numbers using a base-10
    exponent notation. Followed by an array of two integers: the exponent and
    the significand.
    """

    BIG_FLOAT = 5
    """
    Tag value for big float encodings.
    Encodes floating-point numbers with arbitrary precision. Followed by an
    array of two integers representing the base-2 exponent and significand.
    """

    ENCODED_CBOR_DATA_ITEM = 24
    """
    Tag value for byte strings containing embedded CBOR data item encodings.
    """

    ENCODED_CBOR_RATIONAL_NUMBER = 30
    """
    Tag value for Rational numbers, as defined in http://peteroupc.github.io/CBOR/rational.html.
    """

    SET = 258
    """
    Tag value for `set<a> = #6.258([* a]) / [* a]`, `nonempty_set<a> = #6.258([+ a]) / [+ a]`, `nonempty_oset<a> = #6.258([+ a]) / [+ a]`
    """

    SELF_DESCRIBE_CBOR = 55799
    """
    Tag value for the Self-Describe CBOR header (0xd9d9f7).
    When placed at the beginning of a CBOR document, this tag signals that the
    document is encoded in CBOR, facilitating content type detection.
    """

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this CBOR tag.

        Returns:
            A string representation of the tag.

        Example:
            >>> from cometa.cbor import CborTag
            >>> tag = CborTag.DATE_TIME_STRING
            >>> tag.to_string()
            'Date Time String'
        """
        result = lib.cardano_cbor_tag_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
