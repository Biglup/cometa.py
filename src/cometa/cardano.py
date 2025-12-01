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

from ._ffi import lib, ffi


def get_lib_version() -> str:
    """
    Retrieves the version of the Cardano C library.

    This function returns a string representing the version of the underlying
    Cardano C library. The version string follows the Semantic Versioning (SemVer)
    format, which consists of three segments: MAJOR.MINOR.PATCH (e.g., "1.0.3").

    Returns:
        A string containing the library's version.

    Example:
        >>> from cometa import get_lib_version
        >>> version = get_lib_version()
        >>> print(f"Cardano C library version: {version}")
        Cardano C library version: 1.0.3
    """
    result = lib.cardano_get_lib_version()
    return ffi.string(result).decode("utf-8")


def memzero(buffer: bytearray) -> None:
    """
    Securely wipes the contents of a buffer from memory.

    This function is used to securely erase sensitive data stored in the provided
    buffer. This ensures that the data is no longer recoverable from memory after
    it has been used.

    After use, sensitive data should be overwritten. However, traditional approaches
    like simple zero-filling can be stripped away by optimizing compilers. This
    function guarantees that the memory is cleared, even in the presence of
    compiler optimizations.

    It is especially important to call this function before freeing memory that
    contains sensitive information, such as cryptographic keys or decrypted data,
    to prevent the data from remaining in memory.

    Args:
        buffer: A bytearray whose contents should be securely erased.
            The buffer will be modified in place.

    Example:
        >>> from cometa import memzero
        >>> sensitive_data = bytearray(b"secret_key_12345")
        >>> print(sensitive_data)
        bytearray(b'secret_key_12345')
        >>> memzero(sensitive_data)
        >>> print(sensitive_data)
        bytearray(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')

    Note:
        This function only works with mutable buffer types (bytearray).
        Immutable types like bytes cannot be modified.
    """
    if not isinstance(buffer, bytearray):
        raise TypeError("buffer must be a bytearray")

    if len(buffer) == 0:
        return

    # Get a pointer to the buffer data
    c_buffer = ffi.from_buffer(buffer)
    lib.cardano_memzero(c_buffer, len(buffer))
