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
from typing import Tuple

from .._ffi import ffi, lib
from ..errors import CardanoError


class Bech32:
    """
    Bech32 encoding and decoding utilities.

    Bech32 is an encoding scheme used in Cardano for addresses and other
    data. It consists of a human-readable part (HRP) followed by a separator
    and the data part.

    Example:
        >>> data = b"\\x01\\x02\\x03\\x04"
        >>> encoded = Bech32.encode("addr", data)
        >>> hrp, decoded = Bech32.decode(encoded)
        >>> hrp
        'addr'
        >>> decoded == data
        True
    """

    @staticmethod
    def encode(hrp: str, data: bytes) -> str:
        """
        Encodes binary data to a Bech32 string with the given HRP.

        Args:
            hrp: The human-readable part (e.g., "addr", "stake", "pool").
            data: The binary data to encode.

        Returns:
            The Bech32-encoded string.

        Raises:
            CardanoError: If encoding fails.

        Example:
            >>> Bech32.encode("addr", b"\\x01\\x02\\x03\\x04")
            'addr1qy...'
        """
        hrp_bytes = hrp.encode("utf-8")

        # Calculate required buffer size
        encoded_length = lib.cardano_encoding_bech32_get_encoded_length(
            hrp_bytes, len(hrp_bytes), data, len(data)
        )

        # Allocate output buffer
        output = ffi.new("char[]", encoded_length)

        # Encode
        err = lib.cardano_encoding_bech32_encode(
            hrp_bytes, len(hrp_bytes), data, len(data), output, encoded_length
        )
        if err != 0:
            raise CardanoError(f"Failed to encode Bech32 (error code: {err})")

        return ffi.string(output).decode("utf-8")

    @staticmethod
    def decode(encoded: str) -> Tuple[str, bytes]:
        """
        Decodes a Bech32 string to its HRP and binary data.

        Args:
            encoded: The Bech32-encoded string.

        Returns:
            A tuple of (hrp, data) where hrp is the human-readable part
            and data is the decoded binary data.

        Raises:
            CardanoError: If decoding fails (e.g., invalid Bech32 string).

        Example:
            >>> hrp, data = Bech32.decode("addr1qy...")
            >>> hrp
            'addr'
        """
        encoded_bytes = encoded.encode("utf-8")

        # Calculate required buffer sizes
        hrp_length_ptr = ffi.new("size_t*")
        decoded_length = lib.cardano_encoding_bech32_get_decoded_length(
            encoded_bytes, len(encoded_bytes), hrp_length_ptr
        )
        hrp_length = hrp_length_ptr[0]

        if decoded_length == 0 or hrp_length == 0:
            raise CardanoError("Invalid Bech32 string")

        # Allocate output buffers
        hrp_output = ffi.new("char[]", hrp_length)
        data_output = ffi.new("byte_t[]", decoded_length)

        # Decode
        err = lib.cardano_encoding_bech32_decode(
            encoded_bytes,
            len(encoded_bytes),
            hrp_output,
            hrp_length,
            data_output,
            decoded_length,
        )
        if err != 0:
            raise CardanoError(f"Failed to decode Bech32 (error code: {err})")

        hrp = ffi.string(hrp_output).decode("utf-8")
        data = bytes(ffi.buffer(data_output, decoded_length))

        return hrp, data
