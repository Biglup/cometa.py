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

import struct
from typing import Callable

from .secure_key_handler import Ed25519SecureKeyHandler
from ..cardano import memzero
from ..cryptography.crc32 import crc32
from ..cryptography.ed25519_private_key import Ed25519PrivateKey
from ..cryptography.ed25519_public_key import Ed25519PublicKey
from ..cryptography.emip3 import emip3_encrypt, emip3_decrypt
from ..witness_set.vkey_witness import VkeyWitness
from ..witness_set.vkey_witness_set import VkeyWitnessSet
from ..transaction import Transaction


class SoftwareEd25519SecureKeyHandler(Ed25519SecureKeyHandler):
    """
    A software-based implementation of a secure key handler for single Ed25519 keys.

    This class securely manages a single private key by encrypting it with a passphrase.
    The passphrase is provided on-demand via a callback, and the decrypted
    key material only exists in memory for the brief moment it's needed for an operation,
    after which it is securely wiped.

    Example:
        >>> def get_passphrase():
        ...     return b"my-secure-passphrase"
        >>> private_key = Ed25519PrivateKey.from_extended_hex("...")
        >>> handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(
        ...     private_key=private_key,
        ...     passphrase=b"my-secure-passphrase",
        ...     get_passphrase=get_passphrase
        ... )
        >>> public_key = handler.get_public_key()
    """

    _MAGIC = 0x0A0A0A0A
    _VERSION = 0x01
    _ED25519_KEY_HANDLER = 0x00

    def __init__(
        self,
        encrypted_data: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> None:
        """
        Private constructor. Use the static factory methods to create an instance.

        Args:
            encrypted_data: The EMIP-003 encrypted private key.
            get_passphrase: An function called when the passphrase is needed.
        """
        self._encrypted_data = encrypted_data
        self._get_passphrase = get_passphrase

    def _get_decrypted_key(self) -> bytes:
        """
        A private helper method to securely get the decrypted key material on demand.
        It immediately wipes the provided passphrase after use.
        """
        passphrase = self._get_passphrase()
        try:
            return emip3_decrypt(self._encrypted_data, passphrase)
        finally:
            if isinstance(passphrase, bytearray):
                memzero(passphrase)

    @classmethod
    def from_ed25519_key(
        cls,
        private_key: Ed25519PrivateKey,
        passphrase: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> SoftwareEd25519SecureKeyHandler:
        """
        Creates a new Ed25519-based key handler from a raw private key and a passphrase.

        Args:
            private_key: The raw Ed25519 private key.
            passphrase: The passphrase to initially encrypt the key.
            get_passphrase: An function called when the passphrase is needed
                for cryptographic operations.

        Returns:
            A new instance of the key handler.

        Warning:
            For security, consider zeroing out the `passphrase` buffer after calling
            this function if it is a mutable bytearray.
        """
        private_key_bytes = private_key.to_bytes()
        try:
            encrypted_key = emip3_encrypt(private_key_bytes, passphrase)
            return cls(encrypted_key, get_passphrase)
        finally:
            if isinstance(private_key_bytes, bytearray):
                memzero(private_key_bytes)

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> SoftwareEd25519SecureKeyHandler:
        """
        Deserializes an encrypted Ed25519 key handler from a byte array.

        The binary format is:
        `[ 4-byte magic | 1-byte version | 1-byte type | 4-byte data_len | data | 4-byte crc32 checksum ]`

        Args:
            data: The serialized and encrypted key data.
            get_passphrase: An function called when the passphrase is needed.

        Returns:
            A new instance of the key handler.

        Raises:
            ValueError: If the data is invalid or corrupted.
        """
        min_length = 14  # 4 magic + 1 version + 1 type + 4 len + 4 checksum
        if len(data) < min_length:
            raise ValueError("Invalid serialized data: too short.")

        data_to_verify = data[:-4]
        received_checksum = struct.unpack(">I", data[-4:])[0]
        calculated_checksum = crc32(data_to_verify)

        if received_checksum != calculated_checksum:
            raise ValueError("Invalid serialized data: checksum mismatch.")

        magic = struct.unpack(">I", data[0:4])[0]
        if magic != cls._MAGIC:
            raise ValueError("Invalid serialized data: incorrect magic number.")

        version = data[4]
        if version != cls._VERSION:
            raise ValueError(
                f"Unsupported version: {version}. Expected {cls._VERSION}."
            )

        type_num = data[5]
        if type_num != cls._ED25519_KEY_HANDLER:
            raise ValueError(
                f"Unsupported key type: {type_num}. Expected {cls._ED25519_KEY_HANDLER}."
            )

        encrypted_data_size = struct.unpack(">I", data[6:10])[0]
        if len(data) != min_length + encrypted_data_size:
            raise ValueError("Invalid serialized data: length mismatch.")

        encrypted_data = data[10:10 + encrypted_data_size]
        return cls(bytes(encrypted_data), get_passphrase)

    def serialize(self) -> bytes:
        """
        Serializes the encrypted key data for secure storage into a binary format.

        The binary format is:
        `[ 4-byte magic | 1-byte version | 1-byte type | 4-byte data_len | data | 4-byte crc32 checksum ]`

        Returns:
            The serialized and encrypted key data.
        """
        header_size = 10
        footer_size = 4
        data_size = len(self._encrypted_data)
        total_size = header_size + data_size + footer_size

        buffer = bytearray(total_size)
        struct.pack_into(">I", buffer, 0, self._MAGIC)
        buffer[4] = self._VERSION
        buffer[5] = self._ED25519_KEY_HANDLER
        struct.pack_into(">I", buffer, 6, data_size)
        buffer[header_size:header_size + data_size] = self._encrypted_data

        data_to_checksum = buffer[:header_size + data_size]
        checksum = crc32(bytes(data_to_checksum))
        struct.pack_into(">I", buffer, header_size + data_size, checksum)

        return bytes(buffer)

    def sign_transaction(self, transaction: Transaction) -> VkeyWitnessSet:
        """
        Signs a transaction using the securely stored Ed25519 private key.

        Args:
            transaction: The transaction to sign.

        Returns:
            A VkeyWitnessSet containing the signature.

        Note:
            During this operation, the private key is temporarily decrypted in
            memory and then securely wiped immediately after use.
        """
        tx_body_hash = transaction.id.to_bytes()

        decrypted_key = self._get_decrypted_key()

        try:
            private_key = Ed25519PrivateKey.from_extended_bytes(decrypted_key)
            public_key = private_key.get_public_key()
            signature = private_key.sign(tx_body_hash)

            witness = VkeyWitness.new(
                vkey=public_key.to_bytes(),
                signature=signature.to_bytes()
            )

            witness_set = VkeyWitnessSet()
            witness_set.add(witness)
            return witness_set
        finally:
            if isinstance(decrypted_key, bytearray):
                memzero(decrypted_key)

    def sign_data(self, data: str) -> dict[str, str]:
        """
        Signs arbitrary data using the securely stored Ed25519 private key.

        Args:
            data: The hex-encoded data to be signed.

        Returns:
            A dict with 'signature' and 'key' (public key) as hex strings.
        """
        decrypted_key = self._get_decrypted_key()

        try:
            private_key = Ed25519PrivateKey.from_extended_bytes(decrypted_key)
            public_key = private_key.get_public_key()

            data_bytes = bytes.fromhex(data)
            signature = private_key.sign(data_bytes)

            return {
                "key": public_key.to_hex(),
                "signature": signature.to_hex()
            }
        finally:
            if isinstance(decrypted_key, bytearray):
                memzero(decrypted_key)

    def get_private_key(self) -> Ed25519PrivateKey:
        """
        Retrieves the securely stored private key.

        Returns:
            The Ed25519PrivateKey.

        Warning:
            This operation exposes the private key in memory and should be used
            with extreme caution. The caller is responsible for securely handling
            and wiping the key from memory after use.
        """
        decrypted_key = self._get_decrypted_key()
        private_key = Ed25519PrivateKey.from_extended_bytes(decrypted_key)

        if isinstance(decrypted_key, bytearray):
            memzero(decrypted_key)

        return private_key

    def get_public_key(self) -> Ed25519PublicKey:
        """
        Retrieves the public key corresponding to the securely stored private key.

        Returns:
            The corresponding Ed25519PublicKey.

        Note:
            This operation requires the private key, which is temporarily decrypted
            in memory and then securely wiped immediately after use.
        """
        decrypted_key = self._get_decrypted_key()

        try:
            private_key = Ed25519PrivateKey.from_extended_bytes(decrypted_key)
            return private_key.get_public_key()
        finally:
            if isinstance(decrypted_key, bytearray):
                memzero(decrypted_key)
