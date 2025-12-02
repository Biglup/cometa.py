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
from typing import Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from .drep_type import DRepType
from .credential import Credential
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter


class DRep:
    """
    Represents a Delegated Representative (DRep) for governance participation.

    In Voltaire, stake credentials can delegate their voting power to DReps for
    governance decisions. DReps can be identified by:

    - A verification key (Ed25519) - KEY_HASH type
    - A native or Plutus script - SCRIPT_HASH type

    Additionally, two pre-defined options are available:
    - ABSTAIN: Actively marks stake as not participating in governance
    - NO_CONFIDENCE: Votes "Yes" on No Confidence actions, "No" on all others

    Example:
        >>> cred = Credential.from_key_hash("00" * 28)
        >>> drep = DRep.new(DRepType.KEY_HASH, cred)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("DRep: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_drep_t**", self._ptr)
            lib.cardano_drep_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> DRep:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"DRep(type={self.drep_type.name})"

    @classmethod
    def new(cls, drep_type: DRepType, credential: Optional[Credential] = None) -> DRep:
        """
        Creates a new DRep with the specified type and optional credential.

        Args:
            drep_type: The type of DRep (KEY_HASH, SCRIPT_HASH, ABSTAIN, or NO_CONFIDENCE).
            credential: The credential for KEY_HASH or SCRIPT_HASH types. Must be None
                       for ABSTAIN and NO_CONFIDENCE types.

        Returns:
            A new DRep instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> cred = Credential.from_key_hash("00" * 28)
            >>> drep = DRep.new(DRepType.KEY_HASH, cred)
            >>> abstain = DRep.new(DRepType.ABSTAIN)
        """
        out = ffi.new("cardano_drep_t**")
        cred_ptr = credential._ptr if credential is not None else ffi.NULL
        err = lib.cardano_drep_new(int(drep_type), cred_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create DRep (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_string(cls, bech32_string: str) -> DRep:
        """
        Creates a DRep from a Bech32-encoded string (CIP-105 or CIP-129 format).

        Supports both:
        - CIP-105 format: Key hash directly as Bech32
        - CIP-129 format: Includes header byte with governance key type and credential type

        Args:
            bech32_string: The Bech32-encoded DRep string.

        Returns:
            A new DRep instance.

        Raises:
            CardanoError: If parsing fails.

        Example:
            >>> drep = DRep.from_string("drep1...")
        """
        out = ffi.new("cardano_drep_t**")
        data = bech32_string.encode("utf-8")
        err = lib.cardano_drep_from_string(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to parse DRep from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> DRep:
        """
        Deserializes a DRep from CBOR data.

        Args:
            reader: A CborReader positioned at the DRep data.

        Returns:
            A new DRep deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_drep_t**")
        err = lib.cardano_drep_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize DRep from CBOR (error code: {err})")
        return cls(out[0])

    @classmethod
    def abstain(cls) -> DRep:
        """
        Creates a DRep representing the Abstain voting option.

        Returns:
            A new DRep with type ABSTAIN.
        """
        return cls.new(DRepType.ABSTAIN, None)

    @classmethod
    def no_confidence(cls) -> DRep:
        """
        Creates a DRep representing the No Confidence voting option.

        Returns:
            A new DRep with type NO_CONFIDENCE.
        """
        return cls.new(DRepType.NO_CONFIDENCE, None)

    @property
    def drep_type(self) -> DRepType:
        """Returns the type of this DRep."""
        type_out = ffi.new("cardano_drep_type_t*")
        err = lib.cardano_drep_get_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get DRep type (error code: {err})")
        return DRepType(type_out[0])

    @drep_type.setter
    def drep_type(self, value: DRepType) -> None:
        """Sets the type of this DRep."""
        err = lib.cardano_drep_set_type(self._ptr, int(value))
        if err != 0:
            raise CardanoError(f"Failed to set DRep type (error code: {err})")

    @property
    def credential(self) -> Optional[Credential]:
        """
        Returns the credential associated with this DRep.

        Returns None for ABSTAIN and NO_CONFIDENCE types.
        """
        if self.drep_type in (DRepType.ABSTAIN, DRepType.NO_CONFIDENCE):
            return None
        out = ffi.new("cardano_credential_t**")
        err = lib.cardano_drep_get_credential(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get credential (error code: {err})")
        if out[0] == ffi.NULL:
            return None
        return Credential(out[0])

    @credential.setter
    def credential(self, value: Optional[Credential]) -> None:
        """Sets the credential for this DRep."""
        cred_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_drep_set_credential(self._ptr, cred_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set credential (error code: {err})")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the DRep to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_drep_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize DRep to CBOR (error code: {err})")

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
        err = lib.cardano_drep_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def to_cip129_string(self) -> str:
        """Returns the CIP-129 string representation of the DRep."""
        size = lib.cardano_drep_get_string_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_drep_to_string(self._ptr, buf, size)
        if err != 0:
            raise CardanoError(f"Failed to convert DRep to string (error code: {err})")
        return ffi.string(buf).decode("utf-8")

    def __str__(self) -> str:
        """Returns the CIP-129 string representation of the DRep."""
        return self.to_cip129_string()

    def __eq__(self, other: object) -> bool:
        """Checks equality with another DRep."""
        if not isinstance(other, DRep):
            return False
        if self.drep_type != other.drep_type:
            return False
        if self.drep_type in (DRepType.ABSTAIN, DRepType.NO_CONFIDENCE):
            return True
        self_cred = self.credential
        other_cred = other.credential
        if self_cred is None or other_cred is None:
            return self_cred is None and other_cred is None
        return self_cred == other_cred

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        drep_type = self.drep_type
        if drep_type in (DRepType.ABSTAIN, DRepType.NO_CONFIDENCE):
            return hash(drep_type)
        cred = self.credential
        if cred is None:
            return hash(drep_type)
        return hash((drep_type, cred.hash_hex))
