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


def emip3_encrypt(
    data: Union[bytes, bytearray],
    passphrase: Union[bytes, bytearray, str]
) -> bytes:
    """
    Encrypts data using the EMIP-003 standard encryption format.

    EMIP-003 provides a standardized encryption scheme for sensitive data
    like cryptographic keys, suitable for secure storage on disk.

    The encryption uses:
    - PBKDF2 with HMAC-SHA512 for key derivation (19,162 iterations)
    - ChaCha20Poly1305 for authenticated encryption
    - Random 32-byte salt and 12-byte nonce

    Output format: salt (32 bytes) + nonce (12 bytes) + MAC (16 bytes) + ciphertext

    Args:
        data: The raw data to encrypt.
        passphrase: The passphrase for key derivation.

    Returns:
        The encrypted data with salt, nonce, and MAC prepended.

    Raises:
        CardanoError: If encryption fails.

    Example:
        >>> encrypted = emip3_encrypt(b"secret data", b"my-passphrase")
        >>> len(encrypted) > len(b"secret data")
        True

    See Also:
        EMIP-003: https://github.com/Emurgo/EmIPs/blob/master/specs/emip-003.md
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    c_data = ffi.from_buffer("byte_t[]", data)
    c_passphrase = ffi.from_buffer("byte_t[]", passphrase)
    out = ffi.new("cardano_buffer_t**")

    err = lib.cardano_crypto_emip3_encrypt(
        c_data, len(data),
        c_passphrase, len(passphrase),
        out
    )
    if err != 0:
        raise CardanoError(f"EMIP-003 encryption failed (error code: {err})")

    buffer_ptr = out[0]
    size = lib.cardano_buffer_get_size(buffer_ptr)
    data_ptr = lib.cardano_buffer_get_data(buffer_ptr)
    result = bytes(ffi.buffer(data_ptr, size))

    ptr_ptr = ffi.new("cardano_buffer_t**", buffer_ptr)
    lib.cardano_buffer_unref(ptr_ptr)

    return result


def emip3_decrypt(
    encrypted_data: Union[bytes, bytearray],
    passphrase: Union[bytes, bytearray, str]
) -> bytes:
    """
    Decrypts data that was encrypted using EMIP-003 format.

    Args:
        encrypted_data: The encrypted data (including salt, nonce, and MAC).
        passphrase: The passphrase used during encryption.

    Returns:
        The original decrypted data.

    Raises:
        CardanoError: If decryption fails (wrong passphrase, corrupted data, etc.).

    Example:
        >>> encrypted = emip3_encrypt(b"secret data", b"my-passphrase")
        >>> decrypted = emip3_decrypt(encrypted, b"my-passphrase")
        >>> decrypted
        b'secret data'

    See Also:
        EMIP-003: https://github.com/Emurgo/EmIPs/blob/master/specs/emip-003.md
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")

    c_data = ffi.from_buffer("byte_t[]", encrypted_data)
    c_passphrase = ffi.from_buffer("byte_t[]", passphrase)
    out = ffi.new("cardano_buffer_t**")

    err = lib.cardano_crypto_emip3_decrypt(
        c_data, len(encrypted_data),
        c_passphrase, len(passphrase),
        out
    )
    if err != 0:
        raise CardanoError(f"EMIP-003 decryption failed (error code: {err})")

    buffer_ptr = out[0]
    size = lib.cardano_buffer_get_size(buffer_ptr)
    data_ptr = lib.cardano_buffer_get_data(buffer_ptr)
    result = bytes(ffi.buffer(data_ptr, size))

    lib.cardano_buffer_memzero(buffer_ptr)
    ptr_ptr = ffi.new("cardano_buffer_t**", buffer_ptr)
    lib.cardano_buffer_unref(ptr_ptr)

    return result
