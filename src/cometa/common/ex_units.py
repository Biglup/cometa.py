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


class ExUnits:
    """
    Represents execution units for Plutus script execution.

    Execution units measure the computational resources required to run a Plutus
    script on the Cardano blockchain. They consist of two components:

    - Memory: The amount of memory the script is expected to consume
    - CPU steps: The number of CPU steps the script is expected to require

    These values are used to calculate transaction fees and ensure scripts
    don't overrun system resources.

    Example:
        >>> ex_units = ExUnits.new(memory=1000000, cpu_steps=500000000)
        >>> ex_units.memory
        1000000
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ExUnits: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ex_units_t**", self._ptr)
            lib.cardano_ex_units_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ExUnits:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ExUnits(memory={self.memory}, cpu_steps={self.cpu_steps})"

    @classmethod
    def new(cls, memory: int, cpu_steps: int) -> ExUnits:
        """
        Creates new execution units with the specified memory and CPU steps.

        Args:
            memory: The amount of memory (in units) for script execution.
            cpu_steps: The number of CPU steps for script execution.

        Returns:
            A new ExUnits instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> ex_units = ExUnits.new(1024, 500)
        """
        out = ffi.new("cardano_ex_units_t**")
        err = lib.cardano_ex_units_new(memory, cpu_steps, out)
        if err != 0:
            raise CardanoError(f"Failed to create ExUnits (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ExUnits:
        """
        Deserializes ExUnits from CBOR data.

        Args:
            reader: A CborReader positioned at the execution units data.

        Returns:
            A new ExUnits deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_ex_units_t**")
        err = lib.cardano_ex_units_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize ExUnits from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def memory(self) -> int:
        """Returns the memory component of the execution units."""
        return int(lib.cardano_ex_units_get_memory(self._ptr))

    @memory.setter
    def memory(self, value: int) -> None:
        """Sets the memory component of the execution units."""
        err = lib.cardano_ex_units_set_memory(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set memory (error code: {err})")

    @property
    def cpu_steps(self) -> int:
        """Returns the CPU steps component of the execution units."""
        return int(lib.cardano_ex_units_get_cpu_steps(self._ptr))

    @cpu_steps.setter
    def cpu_steps(self, value: int) -> None:
        """Sets the CPU steps component of the execution units."""
        err = lib.cardano_ex_units_set_cpu_steps(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set CPU steps (error code: {err})")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the execution units to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_ex_units_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize ExUnits to CBOR (error code: {err})")

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
        err = lib.cardano_ex_units_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another ExUnits."""
        if not isinstance(other, ExUnits):
            return False
        return self.memory == other.memory and self.cpu_steps == other.cpu_steps

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.memory, self.cpu_steps))

    def __str__(self) -> str:
        """Returns a string representation of the execution units."""
        return f"mem: {self.memory}, steps: {self.cpu_steps}"
