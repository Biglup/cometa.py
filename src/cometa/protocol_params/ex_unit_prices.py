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
from ..common.unit_interval import UnitInterval


class ExUnitPrices:
    """
    Specifies the cost (in Lovelace) of execution units.

    Execution unit prices set the "price" for the computational resources
    used by smart contracts. They are expressed as unit intervals representing
    the cost per unit of memory and CPU steps.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ExUnitPrices: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_ex_unit_prices_t**", self._ptr)
            lib.cardano_ex_unit_prices_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ExUnitPrices:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ExUnitPrices(memory={self.memory_prices}, steps={self.steps_prices})"

    @classmethod
    def new(cls, memory_prices: UnitInterval, steps_prices: UnitInterval) -> ExUnitPrices:
        """
        Creates a new ExUnitPrices instance.

        Args:
            memory_prices: The price per unit of memory consumption.
            steps_prices: The price per CPU step.

        Returns:
            A new ExUnitPrices instance.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> mem = UnitInterval.new(577, 10000)
            >>> cpu = UnitInterval.new(721, 10000000)
            >>> prices = ExUnitPrices.new(mem, cpu)
        """
        out = ffi.new("cardano_ex_unit_prices_t**")
        err = lib.cardano_ex_unit_prices_new(memory_prices._ptr, steps_prices._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create ExUnitPrices (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ExUnitPrices:
        """
        Deserializes ExUnitPrices from CBOR data.

        Args:
            reader: A CborReader positioned at the ex unit prices data.

        Returns:
            A new ExUnitPrices deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_ex_unit_prices_t**")
        err = lib.cardano_ex_unit_prices_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize ExUnitPrices from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the ex unit prices to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_ex_unit_prices_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize ExUnitPrices to CBOR (error code: {err})")

    @property
    def memory_prices(self) -> UnitInterval:
        """
        Returns the price for memory consumption.

        Returns:
            A UnitInterval representing the memory price.
        """
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_ex_unit_prices_get_memory_prices(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get memory prices (error code: {err})")
        return UnitInterval(out[0])

    @memory_prices.setter
    def memory_prices(self, value: UnitInterval) -> None:
        """
        Sets the price for memory consumption.

        Args:
            value: The memory price as a UnitInterval.
        """
        err = lib.cardano_ex_unit_prices_set_memory_prices(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set memory prices (error code: {err})")

    @property
    def steps_prices(self) -> UnitInterval:
        """
        Returns the price for CPU steps.

        Returns:
            A UnitInterval representing the CPU steps price.
        """
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_ex_unit_prices_get_steps_prices(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get steps prices (error code: {err})")
        return UnitInterval(out[0])

    @steps_prices.setter
    def steps_prices(self, value: UnitInterval) -> None:
        """
        Sets the price for CPU steps.

        Args:
            value: The CPU steps price as a UnitInterval.
        """
        err = lib.cardano_ex_unit_prices_set_steps_prices(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set steps prices (error code: {err})")

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
        err = lib.cardano_ex_unit_prices_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
