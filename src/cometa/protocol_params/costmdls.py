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
from ..buffer import Buffer
from ..scripts.plutus_scripts import PlutusLanguageVersion
from .cost_model import CostModel


class Costmdls:
    """
    A collection of cost models for different Plutus language versions.

    This class holds a map of Plutus language versions to their respective
    cost models. It provides methods to insert, retrieve, and check for
    cost models by language version.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Costmdls: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_costmdls_t**", self._ptr)
            lib.cardano_costmdls_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Costmdls:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        versions = []
        for version in PlutusLanguageVersion:
            if self.has(version):
                versions.append(version.name)
        return f"Costmdls(versions=[{', '.join(versions)}])"

    def __contains__(self, language: PlutusLanguageVersion) -> bool:
        """Checks if a cost model exists for the given language version."""
        return self.has(language)

    def __getitem__(self, language: PlutusLanguageVersion) -> CostModel:
        """
        Gets the cost model for a specific language version.

        Args:
            language: The Plutus language version.

        Returns:
            The CostModel for that version.

        Raises:
            KeyError: If no cost model exists for the language.
        """
        model = self.get(language)
        if model is None:
            raise KeyError(f"No cost model for {language.name}")
        return model

    def __setitem__(self, language: PlutusLanguageVersion, model: CostModel) -> None:
        """
        Sets the cost model for a language version.

        Note: The language version is determined by the model itself.

        Args:
            language: The Plutus language version (unused, for dict-like interface).
            model: The CostModel to insert.
        """
        self.insert(model)

    @classmethod
    def new(cls) -> Costmdls:
        """
        Creates a new empty Costmdls collection.

        Returns:
            A new empty Costmdls instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_costmdls_t**")
        err = lib.cardano_costmdls_new(out)
        if err != 0:
            raise CardanoError(f"Failed to create Costmdls (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Costmdls:
        """
        Deserializes Costmdls from CBOR data.

        Args:
            reader: A CborReader positioned at the costmdls data.

        Returns:
            A new Costmdls deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_costmdls_t**")
        err = lib.cardano_costmdls_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Costmdls from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the costmdls to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_costmdls_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Costmdls to CBOR (error code: {err})")

    def insert(self, cost_model: CostModel) -> None:
        """
        Inserts a cost model into the collection.

        The language version is determined by the cost model itself.

        Args:
            cost_model: The CostModel to insert.

        Raises:
            CardanoError: If insertion fails.
        """
        err = lib.cardano_costmdls_insert(self._ptr, cost_model._ptr)
        if err != 0:
            raise CardanoError(f"Failed to insert cost model (error code: {err})")

    def get(self, language: PlutusLanguageVersion) -> Optional[CostModel]:
        """
        Retrieves a cost model for a specific language version.

        Args:
            language: The Plutus language version.

        Returns:
            The CostModel if found, None otherwise.
        """
        out = ffi.new("cardano_cost_model_t**")
        err = lib.cardano_costmdls_get(self._ptr, int(language), out)
        if err != 0 or out[0] == ffi.NULL:
            return None
        return CostModel(out[0])

    def has(self, language: PlutusLanguageVersion) -> bool:
        """
        Checks if a cost model exists for a specific language version.

        Args:
            language: The Plutus language version to check.

        Returns:
            True if a cost model exists, False otherwise.
        """
        return bool(lib.cardano_costmdls_has(self._ptr, int(language)))

    def get_language_views_encoding(self) -> Buffer:
        """
        Gets the language views encoding for computing script data hash.

        This encodes the cost models following the CDDL specification,
        necessary for computing the script data hash of a transaction.

        Returns:
            A Buffer containing the encoded language views.

        Raises:
            CardanoError: If encoding fails.
        """
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_costmdls_get_language_views_encoding(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get language views encoding (error code: {err})")
        return Buffer(out[0])

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
        err = lib.cardano_costmdls_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
