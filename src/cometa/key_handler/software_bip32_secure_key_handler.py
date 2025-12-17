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

from .secure_key_handler import (
    AccountDerivationPath,
    Bip32SecureKeyHandler,
    DerivationPath,
)
from ..cardano import memzero
from ..cryptography.bip32_private_key import Bip32PrivateKey
from ..cryptography.bip32_public_key import Bip32PublicKey
from ..cryptography.crc32 import crc32
from ..cryptography.ed25519_private_key import Ed25519PrivateKey
from ..cryptography.emip3 import emip3_encrypt, emip3_decrypt
from ..witness_set.vkey_witness import VkeyWitness
from ..witness_set.vkey_witness_set import VkeyWitnessSet
from ..transaction import Transaction


class SoftwareBip32SecureKeyHandler(Bip32SecureKeyHandler):
    """
    A software-based implementation of a secure key handler for BIP32
    hierarchical deterministic keys.

    This class securely manages a root key by encrypting it with a passphrase.
    The passphrase is provided on-demand via a callback, and the
    decrypted key material only exists in memory for the brief moment it's needed
    for an operation, after which it is securely wiped.

    Example:
        >>> def get_passphrase():
        ...     return b"my-secure-passphrase"
        >>> handler = SoftwareBip32SecureKeyHandler.from_entropy(
        ...     entropy=my_entropy,
        ...     passphrase=b"my-secure-passphrase",
        ...     get_passphrase=get_passphrase
        ... )
        >>> account_key = handler.get_account_public_key(account_path)
    """

    _MAGIC = 0x0A0A0A0A
    _VERSION = 0x01
    _BIP32_KEY_HANDLER = 0x01

    def __init__(
        self,
        encrypted_data: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> None:
        """
        Private constructor. Use the static factory methods to create an instance.

        Args:
            encrypted_data: The EMIP-003 encrypted entropy.
            get_passphrase: An function called when the passphrase is needed.
        """
        self._encrypted_data = encrypted_data
        self._get_passphrase = get_passphrase

    def _get_decrypted_seed(self) -> bytes:
        """
        A private helper method to securely get the decrypted seed on demand.
        It immediately wipes the provided passphrase after use.
        """
        passphrase = self._get_passphrase()
        try:
            return emip3_decrypt(self._encrypted_data, passphrase)
        finally:
            if isinstance(passphrase, bytearray):
                memzero(passphrase)

    @classmethod
    def from_entropy(
        cls,
        entropy: bytes,
        passphrase: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> SoftwareBip32SecureKeyHandler:
        """
        Creates a new BIP32-based key handler from entropy and a passphrase.

        Args:
            entropy: The entropy bytes for the root key.
            passphrase: The passphrase to initially encrypt the key.
            get_passphrase: An function called when the passphrase is needed
                for cryptographic operations.

        Returns:
            A new instance of the key handler.

        Warning:
            For security, consider zeroing out the `entropy` and `passphrase`
            buffers after calling this function if they are mutable bytearrays.
        """
        encrypted_entropy = emip3_encrypt(entropy, passphrase)
        return cls(encrypted_entropy, get_passphrase)

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        get_passphrase: Callable[[], bytes]
    ) -> SoftwareBip32SecureKeyHandler:
        """
        Deserializes an encrypted key handler from a byte array.

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
        if type_num != cls._BIP32_KEY_HANDLER:
            raise ValueError(
                f"Unsupported key type: {type_num}. Expected {cls._BIP32_KEY_HANDLER}."
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
        data_size = len(self._encrypted_data)

        part_to_checksum = bytearray(header_size + data_size)
        struct.pack_into(">I", part_to_checksum, 0, self._MAGIC)
        part_to_checksum[4] = self._VERSION
        part_to_checksum[5] = self._BIP32_KEY_HANDLER
        struct.pack_into(">I", part_to_checksum, 6, data_size)
        part_to_checksum[header_size:] = self._encrypted_data

        checksum = crc32(bytes(part_to_checksum))

        final_buffer = bytearray(len(part_to_checksum) + 4)
        final_buffer[:len(part_to_checksum)] = part_to_checksum
        struct.pack_into(">I", final_buffer, len(part_to_checksum), checksum)

        return bytes(final_buffer)

    def sign_transaction(  # pylint: disable=too-many-locals
        self,
        transaction: Transaction,
        derivation_paths: list[DerivationPath]
    ) -> VkeyWitnessSet:
        """
        Signs a transaction using BIP32-derived keys.

        Args:
            transaction: The transaction to sign.
            derivation_paths: The paths to the keys needed for signing.

        Returns:
            A VkeyWitnessSet containing the witnesses with signatures.

        Raises:
            ValueError: If derivation_paths is empty.

        Note:
            During this operation, the root key is temporarily decrypted in
            memory and then securely wiped immediately after use.
        """
        if not derivation_paths:
            raise ValueError(
                "Derivation paths are required for signing with a BIP32 key handler."
            )

        tx_body_hash = transaction.id.to_bytes()

        witness_set = VkeyWitnessSet()
        entropy = self._get_decrypted_seed()

        try:
            root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)

            for path in derivation_paths:
                path_indices = [
                    path.purpose,
                    path.coin_type,
                    path.account,
                    path.role,
                    path.index
                ]
                signing_key = root_key.derive(path_indices)
                public_key = signing_key.get_public_key()
                ed25519_key = signing_key.to_ed25519_key()
                signature = ed25519_key.sign(tx_body_hash)

                witness = VkeyWitness.new(
                    vkey=public_key.to_ed25519_key().to_bytes(),
                    signature=signature.to_bytes()
                )
                witness_set.add(witness)
        finally:
            if isinstance(entropy, bytearray):
                memzero(entropy)

        return witness_set

    def sign_data(
        self,
        data: str,
        derivation_path: DerivationPath
    ) -> dict[str, str]:
        """
        Signs arbitrary data using a BIP32-derived key.

        Args:
            data: The hex-encoded data to be signed.
            derivation_path: The derivation path specifying which key to use.

        Returns:
            A dict with 'signature' and 'key' (public key) as hex strings.
        """
        entropy = self._get_decrypted_seed()

        try:
            root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
            path_indices = [
                derivation_path.purpose,
                derivation_path.coin_type,
                derivation_path.account,
                derivation_path.role,
                derivation_path.index
            ]
            signing_key = root_key.derive(path_indices)
            public_key = signing_key.get_public_key()
            ed25519_key = signing_key.to_ed25519_key()

            data_bytes = bytes.fromhex(data)
            signature = ed25519_key.sign(data_bytes)

            return {
                "key": public_key.to_ed25519_key().to_hex(),
                "signature": signature.to_hex()
            }
        finally:
            if isinstance(entropy, bytearray):
                memzero(entropy)

    def get_private_key(
        self,
        derivation_path: DerivationPath
    ) -> Ed25519PrivateKey:
        """
        Retrieves the securely stored private key.

        Args:
            derivation_path: The derivation path specifying which key to retrieve.

        Returns:
            The Ed25519PrivateKey.

        Warning:
            This operation exposes the private key in memory and should be used
            with extreme caution. The caller is responsible for securely handling
            and wiping the key from memory after use.
        """
        entropy = self._get_decrypted_seed()

        try:
            root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
            path_indices = [
                derivation_path.purpose,
                derivation_path.coin_type,
                derivation_path.account,
                derivation_path.role,
                derivation_path.index
            ]
            signing_key = root_key.derive(path_indices)
            return signing_key.to_ed25519_key()
        finally:
            if isinstance(entropy, bytearray):
                memzero(entropy)

    def get_account_public_key(
        self,
        path: AccountDerivationPath
    ) -> Bip32PublicKey:
        """
        Derives and returns an extended account public key.

        Args:
            path: The derivation path for the account.

        Returns:
            The extended account public key.

        Note:
            This operation requires the root key, which is temporarily decrypted
            in memory and then securely wiped immediately after use.
        """
        entropy = self._get_decrypted_seed()

        try:
            root_key = Bip32PrivateKey.from_bip39_entropy(b"", entropy)
            account_key = root_key.derive([path.purpose, path.coin_type, path.account])
            return account_key.get_public_key()
        finally:
            if isinstance(entropy, bytearray):
                memzero(entropy)
