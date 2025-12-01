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
from typing import Union, List, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..json.json_writer import JsonWriter
from ..common.bigint import BigInt
from .metadatum_kind import MetadatumKind

if TYPE_CHECKING:
    from .metadatum_list import MetadatumList, MetadatumLike
    from .metadatum_map import MetadatumMap


class Metadatum:
    """
    Represents a transaction metadatum in Cardano.

    Metadatum can be one of five types: map, list, integer, bytes, or text.
    This is used to attach arbitrary data to transactions.

    Example:
        >>> # Integer metadatum
        >>> meta = Metadatum.from_int(42)
        >>> meta.kind
        <MetadatumKind.INTEGER: 2>

        >>> # Text metadatum
        >>> meta = Metadatum.from_string("Hello")
        >>> meta.to_str()
        'Hello'
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Metadatum: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_metadatum_t**", self._ptr)
            lib.cardano_metadatum_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Metadatum:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Metadatum(kind={self.kind.name})"

    @classmethod
    def from_int(cls, value: int) -> Metadatum:
        """
        Creates a metadatum from a signed integer.

        Args:
            value: The integer value.

        Returns:
            A new Metadatum containing the integer.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta = Metadatum.from_int(42)
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_new_integer_from_int(value, out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from int (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_uint(cls, value: int) -> Metadatum:
        """
        Creates a metadatum from an unsigned integer.

        Args:
            value: The unsigned integer value.

        Returns:
            A new Metadatum containing the integer.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_new_integer_from_uint(value, out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from uint (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_integer_string(cls, string: str, base: int = 10) -> Metadatum:
        """
        Creates a metadatum from a string representation of an integer.

        This is useful for large integers that don't fit in int64/uint64.

        Args:
            string: The string representation of the integer.
            base: The numeric base (2-36). Defaults to 10.

        Returns:
            A new Metadatum containing the integer.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta = Metadatum.from_integer_string("12345678901234567890")
        """
        out = ffi.new("cardano_metadatum_t**")
        string_bytes = string.encode("utf-8")
        err = lib.cardano_metadatum_new_integer_from_string(
            string_bytes, len(string_bytes), base, out
        )
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bigint(cls, value: BigInt) -> Metadatum:
        """
        Creates a metadatum from a BigInt.

        Args:
            value: The BigInt value.

        Returns:
            A new Metadatum containing the integer.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_new_integer(value._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from BigInt (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]) -> Metadatum:
        """
        Creates a metadatum from bytes.

        Args:
            data: The byte data (max 64 bytes per chunk).

        Returns:
            A new Metadatum containing the bytes.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta = Metadatum.from_bytes(b"\\xde\\xad\\xbe\\xef")
        """
        out = ffi.new("cardano_metadatum_t**")
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_metadatum_new_bytes(c_data, len(data), out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from bytes (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_hex(cls, hex_string: str) -> Metadatum:
        """
        Creates a metadatum from a hexadecimal string.

        Args:
            hex_string: The hex-encoded bytes.

        Returns:
            A new Metadatum containing the bytes.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta = Metadatum.from_hex("deadbeef")
        """
        out = ffi.new("cardano_metadatum_t**")
        hex_bytes = hex_string.encode("utf-8")
        err = lib.cardano_metadatum_new_bytes_from_hex(hex_bytes, len(hex_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from hex (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_string(cls, text: str) -> Metadatum:
        """
        Creates a metadatum from a text string.

        Args:
            text: The text string (max 64 bytes when UTF-8 encoded).

        Returns:
            A new Metadatum containing the text.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta = Metadatum.from_string("Hello, Cardano!")
        """
        out = ffi.new("cardano_metadatum_t**")
        text_bytes = text.encode("utf-8")
        err = lib.cardano_metadatum_new_string(text_bytes, len(text_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from string (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Metadatum:
        """
        Deserializes a Metadatum from CBOR data.

        Args:
            reader: A CborReader positioned at the metadatum data.

        Returns:
            A new Metadatum deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Metadatum from CBOR (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_json(cls, json: str) -> Metadatum:
        """
        Creates a metadatum from a JSON string.

        Args:
            json: The JSON-encoded metadatum.

        Returns:
            A new Metadatum deserialized from the JSON data.

        Raises:
            CardanoError: If parsing fails.

        Example:
            >>> meta = Metadatum.from_json('{"int": 42}')
        """
        out = ffi.new("cardano_metadatum_t**")
        json_bytes = json.encode("utf-8")
        err = lib.cardano_metadatum_from_json(json_bytes, len(json_bytes), out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from JSON (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_map(cls, metadatum_map: MetadatumMap) -> Metadatum:
        """
        Creates a metadatum from a MetadatumMap.

        Args:
            metadatum_map: The MetadatumMap to convert.

        Returns:
            A new Metadatum containing the map.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta_map = MetadatumMap()
            >>> meta_map.insert(Metadatum.from_string("key"), Metadatum.from_int(42))
            >>> meta = Metadatum.from_map(meta_map)
            >>> meta.kind
            <MetadatumKind.MAP: 0>
        """
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_new_map(metadatum_map._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from map (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_list(cls, metadatum_list: Union[MetadatumList, List[MetadatumLike]]) -> Metadatum:
        """
        Creates a metadatum from a MetadatumList or a Python list.

        Args:
            metadatum_list: The MetadatumList or a Python list of metadatum values to convert.

        Returns:
            A new Metadatum containing the list.

        Raises:
            CardanoError: If creation fails.

        Example:
            >>> meta_list = MetadatumList()
            >>> meta_list.add(Metadatum.from_int(1))
            >>> meta_list.add(Metadatum.from_int(2))
            >>> meta = Metadatum.from_list(meta_list)
            >>> meta.kind
            <MetadatumKind.LIST: 1>

            >>> # Or using a Python list directly
            >>> meta = Metadatum.from_list([1, "hello", b"bytes"])
        """
        from .metadatum_list import MetadatumList as ML
        if isinstance(metadatum_list, list):
            metadatum_list = ML.from_list(metadatum_list)
        out = ffi.new("cardano_metadatum_t**")
        err = lib.cardano_metadatum_new_list(metadatum_list._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Metadatum from list (error code: {err})")
        return cls(out[0])

    @property
    def kind(self) -> MetadatumKind:
        """
        Returns the kind of this metadatum.

        Returns:
            The MetadatumKind enum value.
        """
        kind = ffi.new("cardano_metadatum_kind_t*")
        err = lib.cardano_metadatum_get_kind(self._ptr, kind)
        if err != 0:
            raise CardanoError(f"Failed to get metadatum kind (error code: {err})")
        return MetadatumKind(kind[0])

    def to_integer(self) -> BigInt:
        """
        Converts this metadatum to a BigInt.

        Returns:
            The BigInt value.

        Raises:
            CardanoError: If this metadatum is not an integer type.
        """
        out = ffi.new("cardano_bigint_t**")
        err = lib.cardano_metadatum_to_integer(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to integer (error code: {err})")
        return BigInt(out[0])

    def to_bytes(self) -> bytes:
        """
        Converts this metadatum to bytes.

        Returns:
            The byte data.

        Raises:
            CardanoError: If this metadatum is not a bytes type.
        """
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_metadatum_to_bounded_bytes(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to bytes (error code: {err})")
        buffer_ptr = out[0]
        size = lib.cardano_buffer_get_size(buffer_ptr)
        data_ptr = lib.cardano_buffer_get_data(buffer_ptr)
        result = bytes(ffi.buffer(data_ptr, size))
        ptr_ptr = ffi.new("cardano_buffer_t**", buffer_ptr)
        lib.cardano_buffer_unref(ptr_ptr)
        return result

    def to_str(self) -> str:
        """
        Converts this metadatum to a string.

        Returns:
            The text string.

        Raises:
            CardanoError: If this metadatum is not a text type.
        """
        size = lib.cardano_metadatum_get_string_size(self._ptr)
        if size == 0:
            return ""
        buffer = ffi.new(f"char[{size}]")
        err = lib.cardano_metadatum_to_string(self._ptr, buffer, size)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to string (error code: {err})")
        return ffi.string(buffer).decode("utf-8")

    def to_json(self) -> str:
        """
        Converts this metadatum to a JSON string.

        Returns:
            The JSON representation.
        """
        size = lib.cardano_metadatum_get_json_size(self._ptr)
        if size == 0:
            return ""
        buffer = ffi.new(f"char[{size}]")
        err = lib.cardano_metadatum_to_json(self._ptr, buffer, size)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to JSON (error code: {err})")
        return ffi.string(buffer).decode("utf-8")

    def to_map(self) -> MetadatumMap:
        """
        Converts this metadatum to a MetadatumMap.

        Returns:
            The MetadatumMap representation.

        Raises:
            CardanoError: If this metadatum is not a map type.

        Example:
            >>> meta = Metadatum.from_map(some_map)
            >>> retrieved_map = meta.to_map()
        """
        # Import here to avoid circular import
        from .metadatum_map import MetadatumMap
        out = ffi.new("cardano_metadatum_map_t**")
        err = lib.cardano_metadatum_to_map(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to map (error code: {err})")
        return MetadatumMap(out[0])

    def to_list(self) -> MetadatumList:
        """
        Converts this metadatum to a MetadatumList.

        Returns:
            The MetadatumList representation.

        Raises:
            CardanoError: If this metadatum is not a list type.

        Example:
            >>> meta = Metadatum.from_list(some_list)
            >>> retrieved_list = meta.to_list()
        """
        # Import here to avoid circular import
        from .metadatum_list import MetadatumList
        out = ffi.new("cardano_metadatum_list_t**")
        err = lib.cardano_metadatum_to_list(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert Metadatum to list (error code: {err})")
        return MetadatumList(out[0])

    def to_cip116_json(self, writer: JsonWriter) -> None:
        """
        Serializes this metadatum to CIP-116 JSON format.

        CIP-116 defines a standard JSON representation for transaction metadata.

        Args:
            writer: A JsonWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Example:
            >>> meta = Metadatum.from_int(42)
            >>> writer = JsonWriter()
            >>> meta.to_cip116_json(writer)
            >>> json_str = writer.encode()
        """
        err = lib.cardano_metadatum_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Metadatum to CIP-116 JSON (error code: {err})")

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the metadatum to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_metadatum_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Metadatum to CBOR (error code: {err})")

    def __eq__(self, other: object) -> bool:
        """Checks equality with another Metadatum."""
        if not isinstance(other, Metadatum):
            return False
        return bool(lib.cardano_metadatum_equals(self._ptr, other._ptr))

    def __hash__(self) -> int:
        """Returns a hash based on JSON representation."""
        return hash(self.to_json())
