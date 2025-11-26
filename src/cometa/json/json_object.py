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
from typing import Union, Optional, Iterator, Tuple

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError
from .json_object_type import JsonObjectType
from .json_format import JsonFormat

class JsonObject:
    """
    Represents a parsed JSON object, array, or value.

    This class serves as the primary data type for interacting with JSON data.
    It can represent any valid JSON value, including objects, arrays, strings,
    numbers, booleans, or null.

    JSON objects are immutable once created in this context.
    """

    # --------------------------------------------------------------------------
    # Factories
    # --------------------------------------------------------------------------

    @classmethod
    def parse(cls, json_string: str) -> JsonObject:
        """
        Parses a JSON string into a JsonObject.

        Args:
            json_string (str): The JSON string to parse.

        Returns:
            JsonObject: The parsed object.
        """
        b_json = json_string.encode("utf-8")
        ptr = lib.cardano_json_object_parse(b_json, len(b_json))

        if ptr == ffi.NULL:
            raise CardanoError("Failed to parse JSON data")

        c_msg = ffi.new("char[]", b"")
        lib.cardano_json_object_set_last_error(ptr, c_msg)

        return cls(ptr)

    # --------------------------------------------------------------------------
    # Properties & State
    # --------------------------------------------------------------------------

    @property
    def type(self) -> JsonObjectType:
        """Retrieves the type of the JSON object."""
        return JsonObjectType(lib.cardano_json_object_get_type(self._ptr))

    @property
    def refcount(self) -> int:
        """Returns the number of active references to the underlying C object."""
        return int(lib.cardano_json_object_refcount(self._ptr))

    @property
    def last_error(self) -> str:
        """Returns the last error message recorded for this object."""
        ptr = lib.cardano_json_object_get_last_error(self._ptr)
        if ptr == ffi.NULL:
            return ""
        # errors='replace' handles cases where C lib might return uninitialized garbage
        return ffi.string(ptr).decode("utf-8", errors='replace')

    @last_error.setter
    def last_error(self, message: str) -> None:
        """Manually sets the last error message."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_json_object_set_last_error(self._ptr, c_msg)

    # --------------------------------------------------------------------------
    # Serialization
    # --------------------------------------------------------------------------

    def to_json(self, json_format: JsonFormat = JsonFormat.COMPACT) -> str:
        """
        Serializes the JSON object into a string.

        Args:
            json_format (JsonFormat): The output format (COMPACT or PRETTY).

        Returns:
            str: The JSON string.
        """
        length = ffi.new("size_t*")
        c_str = lib.cardano_json_object_to_json_string(self._ptr, json_format, length)

        if c_str == ffi.NULL:
            raise CardanoError("Failed to serialize JSON object")

        # The string belongs to the object, we copy it to python string
        return ffi.string(c_str).decode("utf-8")

    # --------------------------------------------------------------------------
    # Container Protocols (Array & Object Access)
    # --------------------------------------------------------------------------

    def __len__(self) -> int:
        """
        Returns the number of items in the array or keys in the object.
        Returns 0 for other types.
        """
        obj_type = self.type
        if obj_type == JsonObjectType.OBJECT:
            return int(lib.cardano_json_object_get_property_count(self._ptr))
        if obj_type == JsonObjectType.ARRAY:
            return int(lib.cardano_json_object_array_get_length(self._ptr))
        return 0

    def __getitem__(self, key: Union[int, str]) -> JsonObject:
        """
        Retrieves a value from the JSON object or array.

        Args:
            key (int | str): Index for arrays, key string for objects.

        Returns:
            JsonObject: The value wrapper.

        Raises:
            TypeError: If the key type doesn't match the container type.
            IndexError: If array index is out of bounds.
            KeyError: If object key is missing.
        """
        obj_type = self.type

        if isinstance(key, int):
            if obj_type != JsonObjectType.ARRAY:
                raise TypeError(f"Cannot index JSON {obj_type.name} with integer")

            # Handle negative indexing
            length = len(self)
            if key < 0:
                key += length

            if key < 0 or key >= length:
                raise IndexError("JSON array index out of range")

            # cardano_json_object_array_get increments refcount
            ptr = lib.cardano_json_object_array_get(self._ptr, key)
            if ptr == ffi.NULL:
                raise CardanoError("Failed to retrieve array element")
            return JsonObject(ptr)

        if isinstance(key, str):
            if obj_type != JsonObjectType.OBJECT:
                raise TypeError(f"Cannot access JSON {obj_type.name} with string key")

            b_key = key.encode("utf-8")
            val_ptr = ffi.new("cardano_json_object_t**")

            found = lib.cardano_json_object_get(self._ptr, b_key, len(b_key), val_ptr)

            if not found:
                raise KeyError(f"Key '{key}' not found in JSON object")

            # val_ptr[0] has refcount incremented by C API
            return JsonObject(val_ptr[0])

        raise TypeError(f"Invalid key type: {type(key)}")

    def __contains__(self, key: str) -> bool:
        """Checks if a key exists in a JSON object."""
        if self.type != JsonObjectType.OBJECT:
            return False

        b_key = key.encode("utf-8")
        return bool(lib.cardano_json_object_has_property(self._ptr, b_key, len(b_key)))

    # --------------------------------------------------------------------------
    # Iteration (Object specific)
    # --------------------------------------------------------------------------

    def keys(self) -> Iterator[str]:
        """Iterates over keys if this is a JSON object."""
        if self.type != JsonObjectType.OBJECT:
            return

        count = len(self)
        for i in range(count):
            key_len = ffi.new("size_t*")
            c_key = lib.cardano_json_object_get_key_at(self._ptr, i, key_len)
            if c_key != ffi.NULL:
                yield ffi.string(c_key, key_len[0]).decode("utf-8")

    def values(self) -> Iterator[JsonObject]:
        """Iterates over values if this is a JSON object."""
        if self.type != JsonObjectType.OBJECT:
            return

        count = len(self)
        for i in range(count):
            # get_value_at increments refcount
            ptr = lib.cardano_json_object_get_value_at(self._ptr, i)
            if ptr != ffi.NULL:
                yield JsonObject(ptr)

    def items(self) -> Iterator[Tuple[str, JsonObject]]:
        """Iterates over (key, value) pairs if this is a JSON object."""
        if self.type != JsonObjectType.OBJECT:
            return

        count = len(self)
        for i in range(count):
            # Key
            key_len = ffi.new("size_t*")
            c_key = lib.cardano_json_object_get_key_at(self._ptr, i, key_len)
            key_str = ffi.string(c_key, key_len[0]).decode("utf-8") if c_key != ffi.NULL else ""

            # Value
            ptr = lib.cardano_json_object_get_value_at(self._ptr, i)
            if ptr != ffi.NULL:
                yield key_str, JsonObject(ptr)

    # --------------------------------------------------------------------------
    # Type Conversions
    # --------------------------------------------------------------------------

    def is_null(self) -> bool:
        """Checks if the JSON object represents a null value."""
        return self.type == JsonObjectType.NULL

    def as_bool(self) -> Optional[bool]:
        """
        Returns the boolean value if the type is BOOLEAN, else None.
        """
        if self.type != JsonObjectType.BOOLEAN:
            return None
        val = ffi.new("bool*")
        err = lib.cardano_json_object_get_boolean(self._ptr, val)
        check_error(err, lib.cardano_json_object_get_last_error, self._ptr)
        return bool(val[0])

    def as_str(self) -> Optional[str]:
        """
        Returns the string value if the type is STRING, else None.
        """
        if self.type != JsonObjectType.STRING:
            return None

        length = ffi.new("size_t*")
        c_str = lib.cardano_json_object_get_string(self._ptr, length)
        if c_str == ffi.NULL:
            return None
        return ffi.string(c_str, length[0]).decode("utf-8")

    def as_int(self) -> Optional[int]:
        """
        Returns the integer value if the type is NUMBER.

        This method intelligently handles signed vs unsigned 64-bit integers
        supported by the underlying library.
        """
        if self.type != JsonObjectType.NUMBER:
            return None

        # Check sign to decide which accessor to use
        if lib.cardano_json_object_get_is_negative_number(self._ptr):
            val = ffi.new("int64_t*")
            err = lib.cardano_json_object_get_signed_int(self._ptr, val)
            check_error(err, lib.cardano_json_object_get_last_error, self._ptr)
            return int(val[0])

        val = ffi.new("uint64_t*")
        err = lib.cardano_json_object_get_uint(self._ptr, val)
        check_error(err, lib.cardano_json_object_get_last_error, self._ptr)
        return int(val[0])

    def as_float(self) -> Optional[float]:
        """
        Returns the floating point value if the type is NUMBER.
        """
        if self.type != JsonObjectType.NUMBER:
            return None

        val = ffi.new("double*")
        err = lib.cardano_json_object_get_double(self._ptr, val)
        check_error(err, lib.cardano_json_object_get_last_error, self._ptr)
        return float(val[0])

    def __bool__(self) -> bool:
        """
        Pythonic truthiness:
        - Null -> False
        - False -> False
        - 0 -> False
        - Empty String -> False
        - Empty Array/Object -> False
        - Everything else -> True
        """
        json_type = self.type
        if json_type == JsonObjectType.NULL:
            return False
        if json_type == JsonObjectType.BOOLEAN:
            return bool(self.as_bool())
        if json_type == JsonObjectType.NUMBER:
            if lib.cardano_json_object_get_is_real_number(self._ptr):
                return self.as_float() != 0.0

            return self.as_int() != 0
        if json_type == JsonObjectType.STRING:
            return len(self.as_str() or "") > 0
        if json_type in (JsonObjectType.ARRAY, JsonObjectType.OBJECT):
            return len(self) > 0
        return True

    def __init__(self, ptr) -> None:
        """
        Internal constructor. Use factories like `parse` instead.
        """
        if ptr == ffi.NULL:
            raise CardanoError("JsonObject pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        """
        Destructor to release the underlying C object.
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_json_object_t**", self._ptr)
            lib.cardano_json_object_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> JsonObject:
        """
        Context manager entry (no-op).
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Context manager exit (no-op).
        """

    def __repr__(self) -> str:
        """
        Returns a detailed string representation for debugging.
        """
        return f"<JsonObject type={self.type.name} value={str(self)}>"

    def __str__(self) -> str:
        """Returns the compact JSON string representation."""
        return self.to_json(JsonFormat.COMPACT)
