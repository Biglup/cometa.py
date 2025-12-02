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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.credential import Credential
from .voter_type import VoterType


class Voter:
    """
    Represents a voter in the Cardano governance system.

    A voter is any participant with an eligible role who either has a direct stake
    or has delegated their stake, and they exercise their rights by casting votes
    on governance actions. The weight or influence of their vote is determined by
    the amount of their active stake or the stake that's been delegated to them.

    Various roles in the Cardano ecosystem can participate in voting:
    - Constitutional committee members
    - DReps (Delegation Representatives)
    - SPOs (Stake Pool Operators)
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Voter: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_voter_t**", self._ptr)
            lib.cardano_voter_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Voter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        voter_type = self.voter_type
        cred = self.credential
        cred_hash = cred.hash.to_hex()[:16] if cred else "unknown"
        return f"Voter(type={voter_type.name}, credential={cred_hash}...)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Voter):
            return False
        return bool(lib.cardano_voter_equals(self._ptr, other._ptr))

    def __hash__(self) -> int:
        cred = self.credential
        if cred:
            return hash((self.voter_type, cred.hash.to_bytes()))
        return hash(self.voter_type)

    @classmethod
    def new(cls, voter_type: VoterType, credential: Credential) -> Voter:
        """
        Creates a new voter.

        Args:
            voter_type: The type of voter (CC, DRep, or SPO).
            credential: The credential identifying the voter.

        Returns:
            A new Voter instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> cred = Credential.from_key_hash(key_hash)
            >>> voter = Voter.new(VoterType.DREP_KEY_HASH, cred)
        """
        out = ffi.new("cardano_voter_t**")
        err = lib.cardano_voter_new(int(voter_type), credential._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Voter (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Voter:
        """
        Deserializes a Voter from CBOR data.

        Args:
            reader: A CborReader positioned at the voter data.

        Returns:
            A new Voter deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_voter_t**")
        err = lib.cardano_voter_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Voter from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the voter to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_voter_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Voter to CBOR (error code: {err})")

    @property
    def voter_type(self) -> VoterType:
        """Returns the type of this voter."""
        out = ffi.new("cardano_voter_type_t*")
        err = lib.cardano_voter_get_type(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get voter type (error code: {err})")
        return VoterType(out[0])

    @voter_type.setter
    def voter_type(self, value: VoterType) -> None:
        """Sets the type of this voter."""
        err = lib.cardano_voter_set_type(self._ptr, int(value))
        if err != 0:
            raise CardanoError(f"Failed to set voter type (error code: {err})")

    @property
    def credential(self) -> Credential:
        """Returns the credential associated with this voter."""
        cred_ptr = lib.cardano_voter_get_credential(self._ptr)
        if cred_ptr == ffi.NULL:
            raise CardanoError("Failed to get voter credential")
        return Credential(cred_ptr)

    @credential.setter
    def credential(self, value: Credential) -> None:
        """Sets the credential for this voter."""
        err = lib.cardano_voter_set_credential(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set voter credential (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json.json_writer import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_voter_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
