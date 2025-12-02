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


class CborSimpleValue(IntEnum):
    """
    Represents a CBOR simple value (major type 7).

    These simple values are part of the CBOR data format as defined in RFC 7049, section 2.3,
    representing commonly used simple data items. This enumeration includes the simple values
    for 'false', 'true', 'null', and 'undefined', each of which has a specific role in the CBOR encoding
    and interpretation process.
    """

    FALSE = 20
    """
    Represents the value 'false'.
    This value is used to represent the boolean false in CBOR-encoded data.
    """

    TRUE = 21
    """
    Represents the value 'true'.
    This value is used to represent the boolean true in CBOR-encoded data.
    """

    NULL = 22
    """
    Represents the value 'null'.
    This value signifies a null reference or the absence of data in CBOR-encoded data.
    """

    UNDEFINED = 23
    """
    Represents an undefined value.
    This value is used by an encoder as a substitute for a data item with an encoding problem,
    indicating the absence of meaningful or correct data.
    """

    def to_string(self) -> str:
        """
        Returns a human-readable string representation of this CBOR simple value.

        Returns:
            A string representation of the simple value.

        Example:
            >>> from cometa.cbor import CborSimpleValue
            >>> value = CborSimpleValue.TRUE
            >>> value.to_string()
            'True'
        """
        result = lib.cardano_cbor_simple_value_to_string(self.value)
        if result == ffi.NULL:
            return f"Unknown({self.value})"
        return ffi.string(result).decode("utf-8")
