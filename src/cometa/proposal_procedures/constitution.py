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
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.anchor import Anchor
from ..cryptography.blake2b_hash import Blake2bHash


class Constitution:
    """
    Represents a Cardano constitution.

    The constitution is a document that defines the rules and principles
    governing the Cardano blockchain. It includes an anchor (URL and hash)
    pointing to the constitution document and optionally a script hash for
    the constitution script.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Constitution: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_constitution_t**", self._ptr)
            lib.cardano_constitution_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Constitution:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        anchor = self.anchor
        return f"Constitution(url={anchor.url!r})"

    @classmethod
    def new(
        cls, anchor: Anchor, script_hash: Optional[Blake2bHash] = None
    ) -> Constitution:
        """
        Creates a new constitution.

        Args:
            anchor: The anchor pointing to the constitution document.
            script_hash: Optional script hash for the constitution script.

        Returns:
            A new Constitution instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_constitution_t**")
        script_ptr = script_hash._ptr if script_hash is not None else ffi.NULL
        err = lib.cardano_constitution_new(anchor._ptr, script_ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Constitution (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Constitution:
        """
        Deserializes a Constitution from CBOR data.

        Args:
            reader: A CborReader positioned at the constitution data.

        Returns:
            A new Constitution deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_constitution_t**")
        err = lib.cardano_constitution_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Constitution from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the constitution to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_constitution_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Constitution to CBOR (error code: {err})"
            )

    @property
    def anchor(self) -> Anchor:
        """
        The anchor pointing to the constitution document.

        Returns:
            The Anchor.
        """
        ptr = lib.cardano_constitution_get_anchor(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get anchor")
        lib.cardano_anchor_ref(ptr)
        return Anchor(ptr)

    @anchor.setter
    def anchor(self, value: Anchor) -> None:
        """
        Sets the anchor.

        Args:
            value: The Anchor to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_constitution_set_anchor(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set anchor (error code: {err})")

    @property
    def script_hash(self) -> Optional[Blake2bHash]:
        """
        The optional script hash for the constitution script.

        Returns:
            The Blake2bHash if present, None otherwise.
        """
        ptr = lib.cardano_constitution_get_script_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @script_hash.setter
    def script_hash(self, value: Optional[Blake2bHash]) -> None:
        """
        Sets the script hash.

        Args:
            value: The Blake2bHash to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        script_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_constitution_set_script_hash(self._ptr, script_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set script hash (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_constitution_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
