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

class ByteOrder(IntEnum):
    """
    Enumerates the possible byte order types for endianness interpretation.

    This enumeration is used to specify the byte order of data being processed,
    particularly when bytes need to be interpreted as numeric values.
    """

    LITTLE_ENDIAN = 0
    """
    Little-endian byte order.
    The least significant byte (LSB) is placed at the smallest address.
    """

    BIG_ENDIAN = 1
    """
    Big-endian byte order.
    The most significant byte (MSB) is placed at the smallest address.
    (Commonly known as network byte order).
    """
