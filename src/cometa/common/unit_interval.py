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


class UnitInterval:
    """
    Represents a rational number as a ratio of two integers.

    Unit intervals are used throughout Cardano to represent fractional values
    such as protocol parameters (e.g., treasury cut, pool pledge influence).
    They are serialized as Rational Numbers (CBOR Tag 30).

    The value of a unit interval is the numerator divided by the denominator.

    Example:
        >>> interval = UnitInterval(1, 4)  # Represents 0.25
        >>> interval.to_float()
        0.25
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("UnitInterval: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_unit_interval_t**", self._ptr)
            lib.cardano_unit_interval_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> UnitInterval:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"UnitInterval({self.numerator}/{self.denominator})"

    @classmethod
    def new(cls, numerator: int, denominator: int) -> UnitInterval:
        """
        Creates a new unit interval from a numerator and denominator.

        Args:
            numerator: The numerator of the fraction.
            denominator: The denominator of the fraction (must not be zero).

        Returns:
            A new UnitInterval instance.

        Raises:
            CardanoError: If creation fails (e.g., zero denominator).

        Example:
            >>> interval = UnitInterval.new(3, 4)  # Represents 0.75
        """
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_unit_interval_new(numerator, denominator, out)
        if err != 0:
            raise CardanoError(f"Failed to create UnitInterval (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_float(cls, value: float) -> UnitInterval:
        """
        Creates a unit interval from a floating-point value.

        The float is converted to a rational approximation with appropriate
        numerator and denominator values.

        Args:
            value: The floating-point value to convert.

        Returns:
            A new UnitInterval approximating the given value.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> interval = UnitInterval.from_float(0.25)
            >>> interval.numerator
            1
            >>> interval.denominator
            4
        """
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_unit_interval_from_double(value, out)
        if err != 0:
            raise CardanoError(f"Failed to create UnitInterval from float (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> UnitInterval:
        """
        Deserializes a UnitInterval from CBOR data.

        Args:
            reader: A CborReader positioned at the unit interval data.

        Returns:
            A new UnitInterval deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_unit_interval_t**")
        err = lib.cardano_unit_interval_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize UnitInterval from CBOR (error code: {err})")
        return cls(out[0])

    @property
    def numerator(self) -> int:
        """Returns the numerator of the unit interval."""
        return int(lib.cardano_unit_interval_get_numerator(self._ptr))

    @numerator.setter
    def numerator(self, value: int) -> None:
        """Sets the numerator of the unit interval."""
        err = lib.cardano_unit_interval_set_numerator(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set numerator (error code: {err})")

    @property
    def denominator(self) -> int:
        """Returns the denominator of the unit interval."""
        return int(lib.cardano_unit_interval_get_denominator(self._ptr))

    @denominator.setter
    def denominator(self, value: int) -> None:
        """Sets the denominator of the unit interval."""
        err = lib.cardano_unit_interval_set_denominator(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set denominator (error code: {err})")

    def to_float(self) -> float:
        """
        Converts the unit interval to a floating-point value.

        Returns:
            The decimal value of the fraction (numerator / denominator).

        Example:
            >>> interval = UnitInterval.new(1, 4)
            >>> interval.to_float()
            0.25
        """
        return float(lib.cardano_unit_interval_to_double(self._ptr))

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the unit interval to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_unit_interval_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize UnitInterval to CBOR (error code: {err})")

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
        err = lib.cardano_unit_interval_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to convert to CIP-116 JSON (error code: {err})")

    def __float__(self) -> float:
        """Returns the floating-point representation."""
        return self.to_float()

    def __eq__(self, other: object) -> bool:
        """Checks equality with another UnitInterval."""
        if not isinstance(other, UnitInterval):
            return False
        return self.numerator == other.numerator and self.denominator == other.denominator

    def __hash__(self) -> int:
        """Returns a Python hash for use in sets and dicts."""
        return hash((self.numerator, self.denominator))

    def __str__(self) -> str:
        """Returns a string representation of the unit interval."""
        return f"{self.numerator}/{self.denominator}"
