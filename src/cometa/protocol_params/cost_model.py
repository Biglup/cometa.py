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
from typing import List, Iterator

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..scripts.plutus_scripts import PlutusLanguageVersion


class CostModel:
    """
    Represents a cost model for Plutus script execution.

    The execution of Plutus scripts consumes resources. Cost models provide
    predictable pricing for script execution by defining the computational
    cost of each operation in the Plutus language.

    A cost model is associated with a specific Plutus language version (V1, V2, V3)
    and contains an array of costs for each operation.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("CostModel: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_cost_model_t**", self._ptr)
            lib.cardano_cost_model_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CostModel:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"CostModel(language={self.language.name}, operations={len(self)})"

    def __len__(self) -> int:
        """Returns the number of operations in the cost model."""
        return int(lib.cardano_cost_model_get_costs_size(self._ptr))

    def __iter__(self) -> Iterator[int]:
        """Iterates over the costs in the model."""
        yield from self.get_costs()

    def __getitem__(self, operation: int) -> int:
        """
        Gets the cost for a specific operation index.

        Args:
            operation: The operation index.

        Returns:
            The cost for that operation.

        Raises:
            KeyError: If the operation index is out of range.
        """
        cost_out = ffi.new("int64_t*")
        err = lib.cardano_cost_model_get_cost(self._ptr, operation, cost_out)
        if err != 0:
            raise KeyError(f"Operation {operation} not found in cost model")
        return int(cost_out[0])

    def __setitem__(self, operation: int, cost: int) -> None:
        """
        Sets the cost for a specific operation index.

        Args:
            operation: The operation index.
            cost: The cost value.

        Raises:
            KeyError: If the operation index is out of range.
        """
        err = lib.cardano_cost_model_set_cost(self._ptr, operation, cost)
        if err != 0:
            raise KeyError(f"Failed to set cost for operation {operation}")

    @classmethod
    def new(
        cls, language: PlutusLanguageVersion, costs: List[int]
    ) -> CostModel:
        """
        Creates a new cost model for a specific Plutus language version.

        Args:
            language: The Plutus language version.
            costs: A list of costs for each operation.

        Returns:
            A new CostModel instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> costs = [100000, 200000, ...]  # Operation costs
            >>> model = CostModel.new(PlutusLanguageVersion.V1, costs)
        """
        costs_array = ffi.new("int64_t[]", costs)
        out = ffi.new("cardano_cost_model_t**")
        err = lib.cardano_cost_model_new(int(language), costs_array, len(costs), out)
        if err != 0:
            raise CardanoError(f"Failed to create CostModel (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> CostModel:
        """
        Deserializes a CostModel from CBOR data.

        Args:
            reader: A CborReader positioned at the cost model data.

        Returns:
            A new CostModel deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_cost_model_t**")
        err = lib.cardano_cost_model_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize CostModel from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the cost model to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_cost_model_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize CostModel to CBOR (error code: {err})")

    @property
    def language(self) -> PlutusLanguageVersion:
        """
        Returns the Plutus language version for this cost model.

        Returns:
            The PlutusLanguageVersion of this cost model.
        """
        lang_out = ffi.new("cardano_plutus_language_version_t*")
        err = lib.cardano_cost_model_get_language(self._ptr, lang_out)
        if err != 0:
            raise CardanoError(f"Failed to get language (error code: {err})")
        return PlutusLanguageVersion(lang_out[0])

    def get_cost(self, operation: int) -> int:
        """
        Gets the cost for a specific operation index.

        Args:
            operation: The operation index (0-based).

        Returns:
            The cost for that operation.

        Raises:
            CardanoError: If retrieval fails.
        """
        cost_out = ffi.new("int64_t*")
        err = lib.cardano_cost_model_get_cost(self._ptr, operation, cost_out)
        if err != 0:
            raise CardanoError(f"Failed to get cost for operation {operation} (error code: {err})")
        return int(cost_out[0])

    def set_cost(self, operation: int, cost: int) -> None:
        """
        Sets the cost for a specific operation index.

        Args:
            operation: The operation index (0-based).
            cost: The cost value to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_cost_model_set_cost(self._ptr, operation, cost)
        if err != 0:
            raise CardanoError(f"Failed to set cost for operation {operation} (error code: {err})")

    def get_costs(self) -> List[int]:
        """
        Returns all costs in the model as a list.

        Returns:
            A list of costs for all operations.
        """
        size = lib.cardano_cost_model_get_costs_size(self._ptr)
        costs_ptr = lib.cardano_cost_model_get_costs(self._ptr)
        if costs_ptr == ffi.NULL:
            return []
        return [int(costs_ptr[i]) for i in range(size)]

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this cost model to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_cost_model_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
