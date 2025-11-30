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

from .._ffi import ffi, lib
from ..errors import CardanoError


class Base58:
    """
    Base58 encoding and decoding utilities.

    Base58 is a binary-to-text encoding scheme used in Bitcoin and other
    cryptocurrencies. It uses an alphabet that excludes easily confused
    characters (0, O, I, l) and non-alphanumeric characters.

    Example:
        >>> data = b"\\x01\\x02\\x03\\x04\\x05"
        >>> encoded = Base58.encode(data)
        >>> decoded = Base58.decode(encoded)
        >>> decoded == data
        True
    """

    @staticmethod
    def encode(data: bytes) -> str:
        """
        Encodes binary data to a Base58 string.

        Args:
            data: The binary data to encode.

        Returns:
            The Base58-encoded string.

        Raises:
            CardanoError: If encoding fails.

        Example:
            >>> Base58.encode(b"\\x01\\x02\\x03\\x04\\x05")
            '7bWpTW'
        """
        if not data:
            return ""

        # Calculate required buffer size
        encoded_length = lib.cardano_encoding_base58_get_encoded_length(data, len(data))

        # Allocate output buffer
        output = ffi.new("char[]", encoded_length)

        # Encode
        err = lib.cardano_encoding_base58_encode(data, len(data), output, encoded_length)
        if err != 0:
            raise CardanoError(f"Failed to encode Base58 (error code: {err})")

        return ffi.string(output).decode("utf-8")

    @staticmethod
    def decode(encoded: str) -> bytes:
        """
        Decodes a Base58 string to binary data.

        Args:
            encoded: The Base58-encoded string.

        Returns:
            The decoded binary data.

        Raises:
            CardanoError: If decoding fails (e.g., invalid Base58 string).

        Example:
            >>> Base58.decode("7bWpTW")
            b'\\x01\\x02\\x03\\x04\\x05'
        """
        if not encoded:
            return b""

        encoded_bytes = encoded.encode("utf-8")

        # Calculate required buffer size
        decoded_length = lib.cardano_encoding_base58_get_decoded_length(
            encoded_bytes, len(encoded_bytes)
        )

        if decoded_length == 0:
            raise CardanoError("Invalid Base58 string")

        # Allocate output buffer
        output = ffi.new("byte_t[]", decoded_length)

        # Decode
        err = lib.cardano_encoding_base58_decode(
            encoded_bytes, len(encoded_bytes), output, decoded_length
        )
        if err != 0:
            raise CardanoError(f"Failed to decode Base58 (error code: {err})")

        return bytes(ffi.buffer(output, decoded_length))
