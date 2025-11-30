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
from typing import TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError

if TYPE_CHECKING:
    from ..address.address import Address
    from ..cryptography.blake2b_hash import Blake2bHash
    from ..cryptography.ed25519_private_key import Ed25519PrivateKey


class CIP8SignResult:
    """
    Result of a CIP-8 message signing operation.

    Contains the COSE_Sign1 and COSE_Key structures as CBOR-encoded bytes.

    Attributes:
        cose_sign1: The CBOR-encoded COSE_Sign1 structure containing the signature.
        cose_key: The CBOR-encoded COSE_Key structure containing the public key.
    """

    def __init__(self, cose_sign1: bytes, cose_key: bytes) -> None:
        self.cose_sign1 = cose_sign1
        self.cose_key = cose_key

    def __repr__(self) -> str:
        return f"CIP8SignResult(cose_sign1={len(self.cose_sign1)} bytes, cose_key={len(self.cose_key)} bytes)"


def sign(
    message: bytes,
    address: "Address",
    signing_key: "Ed25519PrivateKey",
) -> CIP8SignResult:
    """
    Signs arbitrary data using CIP-8 / COSE and binds the signature to a Cardano address.

    This function creates a COSE_Sign1 and COSE_Key structure compatible with CIP-8 and
    the CIP-30 `signData` API. The message is signed directly (no pre-hashing), with the
    CIP-8 "hashed" flag set to false and an empty external_aad.

    The protected headers include:
        - alg: EdDSA (-8)
        - address: raw bytes of the address

    Args:
        message: The message bytes to sign.
        address: Cardano address to bind the signature to.
        signing_key: Ed25519 private key used to produce the signature.

    Returns:
        A CIP8SignResult containing the CBOR-encoded COSE_Sign1 and COSE_Key structures.

    Raises:
        CardanoError: If signing fails.

    Example:
        >>> from cometa import Ed25519PrivateKey, Address
        >>> private_key = Ed25519PrivateKey.generate()
        >>> address = Address.from_bech32("addr1...")
        >>> result = sign(b"Hello, Cardano!", address, private_key)
        >>> result.cose_sign1  # CBOR-encoded COSE_Sign1
        b'...'
    """
    cose_sign1_out = ffi.new("cardano_buffer_t**")
    cose_key_out = ffi.new("cardano_buffer_t**")

    err = lib.cardano_cip8_sign(
        message,
        len(message),
        address._ptr,
        signing_key._ptr,
        cose_sign1_out,
        cose_key_out,
    )
    if err != 0:
        raise CardanoError(f"Failed to sign message with CIP-8 (error code: {err})")

    try:
        # Extract bytes from buffers
        sign1_ptr = cose_sign1_out[0]
        key_ptr = cose_key_out[0]

        sign1_data = lib.cardano_buffer_get_data(sign1_ptr)
        sign1_size = lib.cardano_buffer_get_size(sign1_ptr)
        cose_sign1 = bytes(ffi.buffer(sign1_data, sign1_size))

        key_data = lib.cardano_buffer_get_data(key_ptr)
        key_size = lib.cardano_buffer_get_size(key_ptr)
        cose_key = bytes(ffi.buffer(key_data, key_size))

        return CIP8SignResult(cose_sign1, cose_key)
    finally:
        # Clean up buffers
        lib.cardano_buffer_unref(cose_sign1_out)
        lib.cardano_buffer_unref(cose_key_out)


def sign_with_key_hash(
    message: bytes,
    key_hash: "Blake2bHash",
    signing_key: "Ed25519PrivateKey",
) -> CIP8SignResult:
    """
    Signs arbitrary data using CIP-8 / COSE and binds the signature to a key hash.

    This function creates a COSE_Sign1 and COSE_Key structure compatible with CIP-8 and
    the CIP-30 `signData` API, binding the signature to a key hash rather than a full
    Cardano address. The message is signed directly (no pre-hashing), with the CIP-8
    "hashed" flag set to false and an empty external_aad.

    The protected headers include:
        - alg: EdDSA (-8)
        - keyHash: raw bytes of the key hash

    Args:
        message: The message bytes to sign.
        key_hash: Key hash to bind the signature to (typically a Blake2b-224 hash
                  of a public key).
        signing_key: Ed25519 private key used to produce the signature.

    Returns:
        A CIP8SignResult containing the CBOR-encoded COSE_Sign1 and COSE_Key structures.

    Raises:
        CardanoError: If signing fails.

    Example:
        >>> from cometa import Ed25519PrivateKey, Blake2bHash
        >>> private_key = Ed25519PrivateKey.generate()
        >>> key_hash = private_key.get_public_key().to_hash()
        >>> result = sign_with_key_hash(b"Hello, dRep!", key_hash, private_key)
        >>> result.cose_sign1  # CBOR-encoded COSE_Sign1
        b'...'
    """
    cose_sign1_out = ffi.new("cardano_buffer_t**")
    cose_key_out = ffi.new("cardano_buffer_t**")

    err = lib.cardano_cip8_sign_ex(
        message,
        len(message),
        key_hash._ptr,
        signing_key._ptr,
        cose_sign1_out,
        cose_key_out,
    )
    if err != 0:
        raise CardanoError(f"Failed to sign message with CIP-8 (error code: {err})")

    try:
        # Extract bytes from buffers
        sign1_ptr = cose_sign1_out[0]
        key_ptr = cose_key_out[0]

        sign1_data = lib.cardano_buffer_get_data(sign1_ptr)
        sign1_size = lib.cardano_buffer_get_size(sign1_ptr)
        cose_sign1 = bytes(ffi.buffer(sign1_data, sign1_size))

        key_data = lib.cardano_buffer_get_data(key_ptr)
        key_size = lib.cardano_buffer_get_size(key_ptr)
        cose_key = bytes(ffi.buffer(key_data, key_size))

        return CIP8SignResult(cose_sign1, cose_key)
    finally:
        # Clean up buffers
        lib.cardano_buffer_unref(cose_sign1_out)
        lib.cardano_buffer_unref(cose_key_out)
