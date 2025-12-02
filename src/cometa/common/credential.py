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
from typing import Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..cryptography.blake2b_hash import Blake2bHash
from .credential_type import CredentialType


class Credential:
    """
    Represents a credential used in Cardano addresses.

    A credential identifies the owner of funds or staking rights. It can be either:
        - A key hash (hash of a public verification key)
        - A script hash (hash of a Plutus or native script)

    Credentials are used in:
        - Payment credentials (who can spend funds)
        - Staking credentials (who controls staking rights)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Credential: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_credential_t**", self._ptr)
            lib.cardano_credential_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Credential:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Credential(type={self.type.name}, hash={self.hash_hex})"

    @classmethod
    def from_hash(cls, hash_value: Blake2bHash, credential_type: CredentialType) -> Credential:
        """
        Creates a credential from a hash and credential type.

        Args:
            hash_value: The Blake2b hash (key hash or script hash).
            credential_type: The credential type (KEY_HASH or SCRIPT_HASH).

        Returns:
            A new Credential instance.

        Raises:
            CardanoError: If credential creation fails.

        Example:
            >>> h = Blake2bHash.from_hex("00" * 28)
            >>> cred = Credential.from_hash(h, CredentialType.KEY_HASH)
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_credential_new(hash_value._ptr, int(credential_type), out)
        if err != 0:
            raise CardanoError(f"Failed to create Credential (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_key_hash(cls, hash_value: Union[Blake2bHash, str, bytes]) -> Credential:
        """
        Creates a key hash credential.

        Args:
            hash_value: The key hash as a Blake2bHash, hex string, or bytes.

        Returns:
            A new Credential with type KEY_HASH.

        Raises:
            CardanoError: If credential creation fails.

        Example:
            >>> cred = Credential.from_key_hash("00" * 28)
        """
        if isinstance(hash_value, str):
            return cls.from_hex(hash_value, CredentialType.KEY_HASH)
        if isinstance(hash_value, bytes):
            return cls.from_bytes(hash_value, CredentialType.KEY_HASH)
        return cls.from_hash(hash_value, CredentialType.KEY_HASH)

    @classmethod
    def from_script_hash(cls, hash_value: Union[Blake2bHash, str, bytes]) -> Credential:
        """
        Creates a script hash credential.

        Args:
            hash_value: The script hash as a Blake2bHash, hex string, or bytes.

        Returns:
            A new Credential with type SCRIPT_HASH.

        Raises:
            CardanoError: If credential creation fails.

        Example:
            >>> cred = Credential.from_script_hash("00" * 28)
        """
        if isinstance(hash_value, str):
            return cls.from_hex(hash_value, CredentialType.SCRIPT_HASH)
        if isinstance(hash_value, bytes):
            return cls.from_bytes(hash_value, CredentialType.SCRIPT_HASH)
        return cls.from_hash(hash_value, CredentialType.SCRIPT_HASH)

    @classmethod
    def from_hex(cls, hex_string: str, credential_type: CredentialType) -> Credential:
        """
        Creates a credential from a hexadecimal hash string.

        Args:
            hex_string: The hexadecimal representation of the hash.
            credential_type: The credential type.

        Returns:
            A new Credential instance.

        Raises:
            CardanoError: If the hex string is invalid.

        Example:
            >>> cred = Credential.from_hex("00" * 28, CredentialType.KEY_HASH)
        """
        out = ffi.new("cardano_credential_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_credential_from_hash_hex(hex_bytes, len(hex_bytes), int(credential_type), out)
        if err != 0:
            raise CardanoError(f"Failed to create Credential from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray], credential_type: CredentialType) -> Credential:
        """
        Creates a credential from raw hash bytes.

        Args:
            data: The raw hash bytes.
            credential_type: The credential type.

        Returns:
            A new Credential instance.

        Raises:
            CardanoError: If credential creation fails.

        Example:
            >>> cred = Credential.from_bytes(bytes(28), CredentialType.KEY_HASH)
        """
        out = ffi.new("cardano_credential_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_credential_from_hash_bytes(c_data, len(data), int(credential_type), out)
        if err != 0:
            raise CardanoError(f"Failed to create Credential from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Credential:
        """
        Deserializes a Credential from CBOR data.

        Args:
            reader: A CborReader positioned at the credential data.

        Returns:
            A new Credential deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_credential_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Credential from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def type(self) -> CredentialType:
        """Returns the credential type (KEY_HASH or SCRIPT_HASH)."""
        type_out = ffi.new("cardano_credential_type_t*")
        err = lib.cardano_credential_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get credential type (error code: {err})")
        return CredentialType(type_out[0])

    @type.setter
    def type(self, value: CredentialType) -> None:
        """Sets the credential type."""
        err = lib.cardano_credential_set_type(self._ptr, int(value))
        if err != 0:
            raise CardanoError(f"Failed to set credential type (error code: {err})")

    @property
    def hash(self) -> Blake2bHash:
        """Returns the underlying hash as a Blake2bHash object."""
        ptr = lib.cardano_credential_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get credential hash")
        return Blake2bHash(ptr)

    @hash.setter
    def hash(self, value: Blake2bHash) -> None:
        """Sets the credential hash."""
        err = lib.cardano_credential_set_hash(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set credential hash (error code: {err})")

    @property
    def hash_bytes(self) -> bytes:
        """Returns the hash as raw bytes."""
        size = lib.cardano_credential_get_hash_bytes_size(self._ptr)
        if size == 0:
            return b""
        data = lib.cardano_credential_get_hash_bytes(self._ptr)
        if data == ffi.NULL:
            return b""
        return bytes(ffi.buffer(data, size))

    @property
    def hash_hex(self) -> str:
        """Returns the hash as a hexadecimal string."""
        hex_ptr = lib.cardano_credential_get_hash_hex(self._ptr)
        if hex_ptr == ffi.NULL:
            return ""
        return ffi.string(hex_ptr).decode("utf-8")

    @property
    def is_key_hash(self) -> bool:
        """Returns True if this is a key hash credential."""
        return self.type == CredentialType.KEY_HASH

    @property
    def is_script_hash(self) -> bool:
        """Returns True if this is a script hash credential."""
        return self.type == CredentialType.SCRIPT_HASH

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the credential to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_credential_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Credential to CBOR (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Converts this object to CIP-116 compliant JSON representation.

        CIP-116 defines a standard JSON format for Cardano data structures.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If conversion fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_credential_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def compare(self, other: Credential) -> int:
        """
        Compares this credential with another credential.

        Args:
            other: The credential to compare with.

        Returns:
            A negative value if this credential is less than other,
            zero if they are equal,
            a positive value if this credential is greater than other.
        """
        return int(lib.cardano_credential_compare(self._ptr, other._ptr))

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Credential."""
        if not isinstance(other, Credential):
            return False
        return bool(lib.cardano_credential_equals(self._ptr, other._ptr))

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.type, self.hash_bytes))

    def __lt__(self, other: Credential) -> bool:
        """Less than comparison."""
        return self.compare(other) < 0

    def __le__(self, other: Credential) -> bool:
        """Less than or equal comparison."""
        return self.compare(other) <= 0

    def __gt__(self, other: Credential) -> bool:
        """Greater than comparison."""
        return self.compare(other) > 0

    def __ge__(self, other: Credential) -> bool:
        """Greater than or equal comparison."""
        return self.compare(other) >= 0

    def __str__(self) -> str:
        """Returns a string representation of the credential."""
        return f"{self.type.name.lower()}:{self.hash_hex}"
