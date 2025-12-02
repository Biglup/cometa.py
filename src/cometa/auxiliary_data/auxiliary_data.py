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
from ..cryptography.blake2b_hash import Blake2bHash
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .transaction_metadata import TransactionMetadata


class AuxiliaryData:
    """
    Represents auxiliary data that can be attached to a Cardano transaction.

    Auxiliary data encapsulates optional information such as transaction
    metadata and scripts. The auxiliary data is hashed and referenced in
    the transaction body.

    Example:
        >>> aux_data = AuxiliaryData()
        >>> metadata = TransactionMetadata()
        >>> metadata.insert(721, nft_metadatum)
        >>> aux_data.set_metadata(metadata)
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_auxiliary_data_t**")
            err = lib.cardano_auxiliary_data_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create AuxiliaryData (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("AuxiliaryData: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_auxiliary_data_t**", self._ptr)
            lib.cardano_auxiliary_data_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> AuxiliaryData:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "AuxiliaryData()"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> AuxiliaryData:
        """
        Deserializes AuxiliaryData from CBOR data.

        Args:
            reader: A CborReader positioned at the auxiliary data.

        Returns:
            A new AuxiliaryData deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.

        Note:
            The original CBOR encoding is cached internally to ensure
            that re-serialization produces identical bytes, preserving
            the hash and any existing signatures.
        """
        out = ffi.new("cardano_auxiliary_data_t**")
        err = lib.cardano_auxiliary_data_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize AuxiliaryData from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def metadata(self) -> Optional[TransactionMetadata]:
        """
        Retrieves the transaction metadata from this auxiliary data.

        Returns:
            The TransactionMetadata, or None if no metadata is present.
        """
        ptr = lib.cardano_auxiliary_data_get_transaction_metadata(self._ptr)
        if ptr == ffi.NULL:
            return None
        return TransactionMetadata(ptr)

    def set_metadata(self, metadata: Optional[TransactionMetadata]) -> None:
        """
        Sets or removes the transaction metadata.

        Args:
            metadata: The TransactionMetadata to set, or None to remove
                existing metadata.

        Raises:
            CardanoError: If the operation fails.

        Example:
            >>> aux_data.set_metadata(TransactionMetadata())
        """
        meta_ptr = metadata._ptr if metadata is not None else ffi.NULL
        err = lib.cardano_auxiliary_data_set_transaction_metadata(self._ptr, meta_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set transaction metadata (error code: {err})")

    def to_hash(self) -> Blake2bHash:
        """
        Computes the hash of this auxiliary data.

        The hash is used in the transaction body to reference the
        auxiliary data.

        Returns:
            The Blake2b-256 hash of the auxiliary data.

        Raises:
            CardanoError: If hashing fails.
        """
        ptr = lib.cardano_auxiliary_data_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to hash AuxiliaryData")
        return Blake2bHash(ptr)

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the auxiliary data to CBOR format.

        If this object was created via from_cbor(), the original CBOR
        encoding is reused to preserve the hash.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_auxiliary_data_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize AuxiliaryData to CBOR (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR encoding.

        After calling this, to_cbor() will generate a new encoding based
        on the current state rather than reusing the original bytes.
        """
        lib.cardano_auxiliary_data_clear_cbor_cache(self._ptr)

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this auxiliary data to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_auxiliary_data_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
