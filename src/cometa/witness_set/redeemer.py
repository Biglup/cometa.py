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
from ..common.ex_units import ExUnits
from ..plutus_data.plutus_data import PlutusData
from .redeemer_tag import RedeemerTag


class Redeemer:
    """
    The Redeemer is an argument provided to a Plutus smart contract (script) when
    you are attempting to redeem a UTxO that's protected by that script.

    A redeemer includes a tag (indicating the type of action), an index,
    data (the actual argument to the script), and execution units (computational
    cost required for script execution).
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Redeemer: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_redeemer_t**", self._ptr)
            lib.cardano_redeemer_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Redeemer:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Redeemer(tag={self.tag.name}, index={self.index})"

    @classmethod
    def new(
        cls,
        tag: RedeemerTag,
        index: int,
        data: PlutusData,
        ex_units: ExUnits,
    ) -> Redeemer:
        """
        Creates a new redeemer.

        Args:
            tag: The type of action (spending, minting, etc.) this redeemer is for.
            index: The index of the transaction input this redeemer is intended for.
            data: The Plutus data to pass to the script.
            ex_units: The execution units allocated for this redeemer.

        Returns:
            A new Redeemer instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_redeemer_t**")
        err = lib.cardano_redeemer_new(int(tag), index, data._ptr, ex_units._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Redeemer (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Redeemer:
        """
        Deserializes a Redeemer from CBOR data.

        Args:
            reader: A CborReader positioned at the redeemer data.

        Returns:
            A new Redeemer deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_redeemer_t**")
        err = lib.cardano_redeemer_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize Redeemer from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the redeemer to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_redeemer_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize Redeemer to CBOR (error code: {err})"
            )

    @property
    def tag(self) -> RedeemerTag:
        """
        The tag indicating the type of action this redeemer is for.

        Returns:
            The RedeemerTag value.
        """
        return RedeemerTag(lib.cardano_redeemer_get_tag(self._ptr))

    @tag.setter
    def tag(self, value: RedeemerTag) -> None:
        """
        Sets the tag for this redeemer.

        Args:
            value: The RedeemerTag to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_redeemer_set_tag(self._ptr, int(value))
        if err != 0:
            raise CardanoError(f"Failed to set redeemer tag (error code: {err})")

    @property
    def index(self) -> int:
        """
        The index of the transaction input this redeemer applies to.

        Returns:
            The index value.
        """
        return int(lib.cardano_redeemer_get_index(self._ptr))

    @index.setter
    def index(self, value: int) -> None:
        """
        Sets the index for this redeemer.

        Args:
            value: The index to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_redeemer_set_index(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set redeemer index (error code: {err})")

    @property
    def data(self) -> PlutusData:
        """
        The Plutus data associated with this redeemer.

        Returns:
            The PlutusData object.
        """
        ptr = lib.cardano_redeemer_get_data(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get redeemer data")
        return PlutusData(ptr)

    @data.setter
    def data(self, value: PlutusData) -> None:
        """
        Sets the Plutus data for this redeemer.

        Args:
            value: The PlutusData to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_redeemer_set_data(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set redeemer data (error code: {err})")

    @property
    def ex_units(self) -> ExUnits:
        """
        The execution units allocated for this redeemer.

        Returns:
            The ExUnits object.
        """
        ptr = lib.cardano_redeemer_get_ex_units(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get redeemer ex_units")
        return ExUnits(ptr)

    @ex_units.setter
    def ex_units(self, value: ExUnits) -> None:
        """
        Sets the execution units for this redeemer.

        Args:
            value: The ExUnits to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_redeemer_set_ex_units(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set redeemer ex_units (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        This is useful when you have modified the redeemer after it was created
        from CBOR and you want to ensure that the next serialization reflects
        the current state rather than using the original cached CBOR.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can invalidate existing signatures.
        """
        lib.cardano_redeemer_clear_cbor_cache(self._ptr)

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
        err = lib.cardano_redeemer_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
