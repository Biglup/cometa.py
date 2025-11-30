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

from typing import Union

from .._ffi import ffi, lib


def crc32(data: Union[bytes, bytearray]) -> int:
    """
    Computes the CRC32 checksum for the given data.

    CRC32 (Cyclic Redundancy Check) is used in Cardano for data integrity
    verification, particularly in Byron-era address encoding.

    Args:
        data: The data to compute the checksum for.

    Returns:
        The 32-bit CRC32 checksum.

    Example:
        >>> crc32(b"Hello, world!")
        3957769958
    """
    if not data:
        return 0
    c_data = ffi.from_buffer("byte_t[]", data)
    return int(lib.cardano_checksum_crc32(c_data, len(data)))
