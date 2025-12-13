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
from typing import Union, List

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .plutus_list import PlutusList


class ConstrPlutusData:
    """
    Represents the nth constructor of a 'Sum Type' along with its arguments.

    In Plutus, data types are represented using constructors. This class
    represents a specific constructor (identified by its alternative index)
    and its arguments as a PlutusList.

    The encoding scheme is:
    - Alternatives 0-6 -> CBOR tags 121-127
    - Alternatives 7-127 -> CBOR tags 1280-1400
    - Other alternatives -> CBOR tag 102 with alternative as unsigned integer

    Example:
        >>> # Create a constructor with alternative 0 (e.g., for a "Just" value)
        >>> args = PlutusList()
        >>> args.append(42)
        >>> constr = ConstrPlutusData(0, args)
        >>> constr.alternative
        0
        >>> len(constr.data)
        1

        >>> # Create without initial data
        >>> constr = ConstrPlutusData(1)
        >>> constr.alternative
        1
        >>> len(constr.data)
        0
    """

    def __init__(
        self,
        alternative: int = None,
        data: Union[PlutusList, List[Union["PlutusData", int, str, bytes]]] = None,
        ptr=None
    ) -> None:
        """
        Creates a new ConstrPlutusData.

        Args:
            alternative: The constructor alternative number (nth constructor of Sum Type).
            data: The arguments as a PlutusList or a Python list. If None, an empty list is used.
            ptr: Internal pointer for wrapping existing C objects.

        Raises:
            CardanoError: If creation fails.
        """
        if ptr is not None:
            if ptr == ffi.NULL:
                raise CardanoError("ConstrPlutusData: invalid handle")
            self._ptr = ptr
        elif alternative is not None:
            if data is None:
                data = PlutusList()
            elif isinstance(data, list):
                data = PlutusList.from_list(data)
            out = ffi.new("cardano_constr_plutus_data_t**")
            err = lib.cardano_constr_plutus_data_new(alternative, data._ptr, out)
            if err != 0:
                raise CardanoError(f"Failed to create ConstrPlutusData (error code: {err})")
            self._ptr = out[0]
        else:
            raise CardanoError("ConstrPlutusData requires either alternative or ptr")

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_constr_plutus_data_t**", self._ptr)
            lib.cardano_constr_plutus_data_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ConstrPlutusData:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ConstrPlutusData(alternative={self.alternative}, args={len(self.data)})"

    def __eq__(self, other: object) -> bool:
        """Checks equality with another ConstrPlutusData."""
        if not isinstance(other, ConstrPlutusData):
            return False
        return bool(lib.cardano_constr_plutus_equals(self._ptr, other._ptr))

    @property
    def alternative(self) -> int:
        """
        Gets the constructor alternative number.

        Returns:
            The alternative number (nth constructor of Sum Type).
        """
        alt_ptr = ffi.new("uint64_t*")
        err = lib.cardano_constr_plutus_data_get_alternative(self._ptr, alt_ptr)
        if err != 0:
            raise CardanoError(f"Failed to get alternative (error code: {err})")
        return int(alt_ptr[0])

    @alternative.setter
    def alternative(self, value: int) -> None:
        """
        Sets the constructor alternative number.

        Args:
            value: The alternative number.
        """
        err = lib.cardano_constr_plutus_data_set_alternative(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set alternative (error code: {err})")

    @property
    def data(self) -> PlutusList:
        """
        Gets the arguments of this constructor.

        Returns:
            A PlutusList containing the constructor arguments.
        """
        out = ffi.new("cardano_plutus_list_t**")
        err = lib.cardano_constr_plutus_data_get_data(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get data (error code: {err})")
        return PlutusList(out[0])

    @data.setter
    def data(self, value: Union[PlutusList, List[Union["PlutusData", int, str, bytes]]]) -> None:
        """
        Sets the arguments of this constructor.

        Args:
            value: A PlutusList or a Python list containing the new arguments.
        """
        if isinstance(value, list):
            value = PlutusList.from_list(value)
        err = lib.cardano_constr_plutus_data_set_data(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set data (error code: {err})")

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ConstrPlutusData:
        """
        Deserializes a ConstrPlutusData from CBOR data.

        Args:
            reader: A CborReader positioned at the constructor data.

        Returns:
            A new ConstrPlutusData deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_constr_plutus_data_t**")
        err = lib.cardano_constr_plutus_data_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize ConstrPlutusData from CBOR (error code: {err})")
        return cls(ptr=out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the constructor to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_constr_plutus_data_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize ConstrPlutusData to CBOR (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can alter the data and invalidate existing signatures.
        """
        lib.cardano_constr_plutus_data_clear_cbor_cache(self._ptr)

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
        err = lib.cardano_constr_plutus_data_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
