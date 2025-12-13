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
from typing import TYPE_CHECKING, Union, List

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .plutus_data_kind import PlutusDataKind

if TYPE_CHECKING:
    from .plutus_list import PlutusList
    from .plutus_map import PlutusMap
    from .constr_plutus_data import ConstrPlutusData
    from ..common.bigint import BigInt

# Type alias for values that can be converted to PlutusData
PlutusDataLike = Union[
    "PlutusData",
    "PlutusList",
    "PlutusMap",
    "ConstrPlutusData",
    int,
    str,
    bytes,
]

class PlutusData:
    """
    A type corresponding to the Plutus Core Data datatype.

    The point of this type is to be opaque as to ensure that it is only used in ways
    that Plutus scripts can handle. Use this type to build any data structures that
    you want to be representable on-chain.

    PlutusData can represent:
    - Integers (arbitrary precision)
    - Byte strings
    - Lists of PlutusData
    - Maps of PlutusData to PlutusData
    - Constructor applications (for sum types)

    Example:
        >>> # Create from integer
        >>> data = PlutusData.from_int(42)
        >>> data.kind
        PlutusDataKind.INTEGER

        >>> # Create from bytes
        >>> data = PlutusData.from_bytes(b"hello")
        >>> data.kind
        PlutusDataKind.BYTES

        >>> # Create from string (UTF-8 encoded as bytes)
        >>> data = PlutusData.from_string("hello")
        >>> data.kind
        PlutusDataKind.BYTES
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            raise CardanoError("PlutusData cannot be created directly. Use factory methods.")
        if ptr == ffi.NULL:
            raise CardanoError("PlutusData: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_plutus_data_t**", self._ptr)
            lib.cardano_plutus_data_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> PlutusData:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"PlutusData(kind={self.kind.name})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PlutusData):
            return False
        return bool(lib.cardano_plutus_data_equals(self._ptr, other._ptr))

    @property
    def kind(self) -> PlutusDataKind:
        """
        Gets the kind of this PlutusData.

        Returns:
            The PlutusDataKind indicating what type of data this holds.
        """
        kind_ptr = ffi.new("cardano_plutus_data_kind_t*")
        err = lib.cardano_plutus_data_get_kind(self._ptr, kind_ptr)
        if err != 0:
            raise CardanoError(f"Failed to get PlutusData kind (error code: {err})")
        return PlutusDataKind(kind_ptr[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> PlutusData:
        """
        Deserializes PlutusData from CBOR.

        Args:
            reader: A CborReader positioned at the PlutusData.

        Returns:
            A new PlutusData instance.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize PlutusData from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the PlutusData to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_plutus_data_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize PlutusData to CBOR (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        This is useful when you have modified the PlutusData after it was created
        from CBOR and you want to ensure that the next serialization reflects the
        current state rather than using the original cached CBOR.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can alter the data and invalidate existing signatures.
        """
        lib.cardano_plutus_data_clear_cbor_cache(self._ptr)

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
        err = lib.cardano_plutus_data_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")

    @classmethod
    def from_int(cls, value: int) -> PlutusData:
        """
        Creates PlutusData from a Python integer.

        Args:
            value: The integer value (can be arbitrarily large).

        Returns:
            A new PlutusData containing the integer.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        # Use string-based creation for arbitrary precision
        value_str = str(value).encode("utf-8")
        err = lib.cardano_plutus_data_new_integer_from_string(value_str, len(value_str), 10, out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from int (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bigint(cls, bigint: BigInt) -> PlutusData:
        """
        Creates PlutusData from a BigInt.

        Args:
            bigint: The BigInt value.

        Returns:
            A new PlutusData containing the integer.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_new_integer(bigint._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from BigInt (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: bytes) -> PlutusData:
        """
        Creates PlutusData from bytes.

        Args:
            data: The byte data.

        Returns:
            A new PlutusData containing the bytes.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_new_bytes(data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> PlutusData:
        """
        Creates PlutusData from a hexadecimal string.

        Args:
            hex_string: The hexadecimal string (e.g., "deadbeef").

        Returns:
            A new PlutusData containing the bytes.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_plutus_data_new_bytes_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_string(cls, value: str) -> PlutusData:
        """
        Creates PlutusData from a string (UTF-8 encoded as bytes).

        Args:
            value: The string value.

        Returns:
            A new PlutusData containing the UTF-8 encoded bytes.

        Raises:
            CardanoError: If creation fails.
        """
        return cls.from_bytes(value.encode("utf-8"))

    @classmethod
    def from_list(cls, plutus_list: Union[PlutusList, List[Union["PlutusData", int, str, bytes]]]) -> PlutusData:
        """
        Creates PlutusData from a PlutusList or a Python list.

        Args:
            plutus_list: The PlutusList or a Python list of PlutusData/native values.

        Returns:
            A new PlutusData containing the list.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> # Using a Python list directly
            >>> data = PlutusData.from_list([42, "hello", b"bytes"])
        """
        from .plutus_list import PlutusList as PL
        if isinstance(plutus_list, list):
            plutus_list = PL.from_list(plutus_list)
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_new_list(plutus_list._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from list (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_map(cls, plutus_map: PlutusMap) -> PlutusData:
        """
        Creates PlutusData from a PlutusMap.

        Args:
            plutus_map: The PlutusMap.

        Returns:
            A new PlutusData containing the map.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_new_map(plutus_map._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from map (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_constr(cls, constr: ConstrPlutusData) -> PlutusData:
        """
        Creates PlutusData from a ConstrPlutusData.

        Args:
            constr: The ConstrPlutusData.

        Returns:
            A new PlutusData containing the constructor.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_plutus_data_t**")
        err = lib.cardano_plutus_data_new_constr(constr._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create PlutusData from constr (error code: {err})")
        return cls(out[0])

    def to_integer(self) -> BigInt:
        """
        Converts this PlutusData to a BigInt.

        Returns:
            The BigInt value if this is an integer.

        Raises:
            CardanoError: If conversion fails or this is not an integer.
        """
        from ..common.bigint import BigInt
        out = ffi.new("cardano_bigint_t**")
        err = lib.cardano_plutus_data_to_integer(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert PlutusData to integer (error code: {err})")
        return BigInt(out[0])

    def to_int(self) -> int:
        """
        Converts this PlutusData to a Python integer.

        Returns:
            The integer value if this is an integer.

        Raises:
            CardanoError: If conversion fails or this is not an integer.
        """
        bigint = self.to_integer()
        return int(bigint)

    def to_bytes(self) -> bytes:
        """
        Converts this PlutusData to bytes.

        Returns:
            The bytes value if this is a bytes type.

        Raises:
            CardanoError: If conversion fails or this is not bytes.
        """
        from ..buffer import Buffer
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_plutus_data_to_bounded_bytes(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert PlutusData to bytes (error code: {err})")
        buffer = Buffer(out[0])
        return bytes(buffer)

    def to_string(self) -> str:
        """
        Converts this PlutusData bytes to a UTF-8 string.

        Returns:
            The string value if this is a bytes type with valid UTF-8.

        Raises:
            CardanoError: If conversion fails or this is not bytes.
            UnicodeDecodeError: If the bytes are not valid UTF-8.
        """
        return self.to_bytes().decode("utf-8")

    def to_list(self) -> PlutusList:
        """
        Converts this PlutusData to a PlutusList.

        Returns:
            The PlutusList if this is a list type.

        Raises:
            CardanoError: If conversion fails or this is not a list.
        """
        from .plutus_list import PlutusList
        out = ffi.new("cardano_plutus_list_t**")
        err = lib.cardano_plutus_data_to_list(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert PlutusData to list (error code: {err})")
        return PlutusList(out[0])

    def to_map(self) -> PlutusMap:
        """
        Converts this PlutusData to a PlutusMap.

        Returns:
            The PlutusMap if this is a map type.

        Raises:
            CardanoError: If conversion fails or this is not a map.
        """
        from .plutus_map import PlutusMap
        out = ffi.new("cardano_plutus_map_t**")
        err = lib.cardano_plutus_data_to_map(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert PlutusData to map (error code: {err})")
        return PlutusMap(out[0])

    def to_constr(self) -> ConstrPlutusData:
        """
        Converts this PlutusData to a ConstrPlutusData.

        Returns:
            The ConstrPlutusData if this is a constructor type.

        Raises:
            CardanoError: If conversion fails or this is not a constructor.
        """
        from .constr_plutus_data import ConstrPlutusData
        out = ffi.new("cardano_constr_plutus_data_t**")
        err = lib.cardano_plutus_data_to_constr(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert PlutusData to constr (error code: {err})")
        return ConstrPlutusData(ptr=out[0])

    @staticmethod
    def to_plutus_data(value: PlutusDataLike) -> "PlutusData":
        """
        Converts a native Python value or Plutus container to PlutusData.

        Supports:
        - PlutusData
        - PlutusList
        - PlutusMap
        - ConstrPlutusData
        - int
        - str (UTF-8)
        - bytes
        """
        from .plutus_list import PlutusList
        from .plutus_map import PlutusMap
        from .constr_plutus_data import ConstrPlutusData

        if isinstance(value, PlutusData):
            return value
        if isinstance(value, int):
            return PlutusData.from_int(value)
        if isinstance(value, str):
            return PlutusData.from_string(value)
        if isinstance(value, bytes):
            return PlutusData.from_bytes(value)
        if isinstance(value, PlutusList):
            return PlutusData.from_list(value)
        if isinstance(value, PlutusMap):
            return PlutusData.from_map(value)
        if isinstance(value, ConstrPlutusData):
            return PlutusData.from_constr(value)

        raise TypeError(f"Cannot convert {type(value).__name__} to PlutusData")
