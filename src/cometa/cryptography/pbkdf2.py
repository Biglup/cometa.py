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
from ..errors import CardanoError


def pbkdf2_hmac_sha512(
    password: Union[bytes, bytearray, str],
    salt: Union[bytes, bytearray],
    iterations: int,
    key_length: int
) -> bytes:
    """
    Derives a key using PBKDF2 with HMAC-SHA512.

    PBKDF2 (Password-Based Key Derivation Function 2) applies a pseudorandom
    function to the password along with a salt value, repeating the process
    multiple times to produce a derived key.

    Args:
        password: The input password or passphrase.
        salt: A cryptographic salt value.
        iterations: Number of iterations (higher = more secure but slower).
        key_length: Desired length of the derived key in bytes.

    Returns:
        The derived key as bytes.

    Raises:
        CardanoError: If key derivation fails.

    Example:
        >>> key = pbkdf2_hmac_sha512(b"password", b"salt", 10000, 32)
        >>> len(key)
        32
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    c_password = ffi.from_buffer("byte_t[]", password) if password else ffi.NULL
    c_salt = ffi.from_buffer("byte_t[]", salt)
    c_key = ffi.new("byte_t[]", key_length)

    err = lib.cardano_crypto_pbkdf2_hmac_sha512(
        c_password, len(password) if password else 0,
        c_salt, len(salt),
        iterations,
        c_key, key_length
    )
    if err != 0:
        raise CardanoError(f"PBKDF2 key derivation failed (error code: {err})")

    return bytes(ffi.buffer(c_key, key_length))
