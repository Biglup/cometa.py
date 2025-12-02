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

import json
import typing
from typing import Union

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError
from .json_format import JsonFormat
from .json_context import JsonContext
from ..common.bigint import BigInt
from ..buffer import Buffer

if typing.TYPE_CHECKING:
    from .json_object import JsonObject


class JsonWriter:
    """
    Provides a API for forward-only, non-cached writing of UTF-8 encoded JSON text.

    This class allows for the incremental creation of JSON documents. It manages
    internal state to ensure syntactically valid JSON output.
    """

    def __init__(self, json_format: JsonFormat = JsonFormat.COMPACT) -> None:
        """
        Creates a new JSON writer instance.

        Args:
            json_format (JsonFormat): The desired output format (COMPACT or PRETTY).
                                 Defaults to COMPACT.
        """
        self._ptr = lib.cardano_json_writer_new(int(json_format))
        if self._ptr == ffi.NULL:
            raise CardanoError("Failed to create JSON writer")

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def refcount(self) -> int:
        """Returns the number of active references to the underlying C object."""
        return int(lib.cardano_json_writer_refcount(self._ptr))

    @property
    def encoded_size(self) -> int:
        """Returns the current size of the encoded data in bytes."""
        return int(lib.cardano_json_writer_get_encoded_size(self._ptr))

    @property
    def context(self) -> JsonContext:
        """Returns the current context (ROOT, OBJECT, or ARRAY)."""
        return JsonContext(lib.cardano_json_writer_get_context(self._ptr))

    @property
    def last_error(self) -> str:
        """Returns the last error message recorded for this writer."""
        ptr = lib.cardano_json_writer_get_last_error(self._ptr)
        if ptr == ffi.NULL:
            return ""
        return ffi.string(ptr).decode("utf-8", errors='replace')

    @last_error.setter
    def last_error(self, message: str) -> None:
        """Manually sets the last error message."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_json_writer_set_last_error(self._ptr, c_msg)

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------

    def reset(self) -> None:
        """
        Resets the writer, clearing all written data.
        The writer can be reused for new data without creating a new instance.
        """
        err = lib.cardano_json_writer_reset(self._ptr)
        check_error(err, lib.cardano_json_writer_get_last_error, self._ptr)

    def encode(self) -> str:
        """
        Finalizes the JSON encoding and returns the resulting string.

        Returns:
            str: The generated JSON text.
        """
        # Use encode_in_buffer to handle allocation safely
        buf_ptr = ffi.new("cardano_buffer_t**")
        err = lib.cardano_json_writer_encode_in_buffer(self._ptr, buf_ptr)
        check_error(err, lib.cardano_json_writer_get_last_error, self._ptr)

        buffer = buf_ptr[0]

        if buffer == ffi.NULL:
            return ""

        try:
            size = lib.cardano_buffer_get_size(buffer)
            if size == 0:
                return ""

            raw_data = lib.cardano_buffer_get_data(buffer)
            if raw_data == ffi.NULL:
                return ""

            return ffi.string(raw_data, size).decode("utf-8")
        finally:
            lib.cardano_buffer_unref(buf_ptr)

    def to_dict(self) -> dict:
        """Parses the JSON into a Python dictionary for inspection."""
        json_str = self.encode()
        if not json_str:
            return {}
        return json.loads(json_str)

    # --------------------------------------------------------------------------
    # Structure
    # --------------------------------------------------------------------------

    def write_start_object(self) -> None:
        """Begins a JSON object ('{') in the output."""
        lib.cardano_json_writer_write_start_object(self._ptr)

    def write_end_object(self) -> None:
        """Ends a JSON object ('}') in the output."""
        lib.cardano_json_writer_write_end_object(self._ptr)

    def write_start_array(self) -> None:
        """Begins a JSON array ('[') in the output."""
        lib.cardano_json_writer_write_start_array(self._ptr)

    def write_end_array(self) -> None:
        """Ends a JSON array ('[') in the output."""
        lib.cardano_json_writer_write_end_array(self._ptr)

    def write_property_name(self, name: str) -> None:
        """
        Writes a property name. Must be called within an Object context.

        Args:
            name (str): The property key.
        """
        b_name = name.encode("utf-8")
        lib.cardano_json_writer_write_property_name(self._ptr, b_name, len(b_name))

    # --------------------------------------------------------------------------
    # Values
    # --------------------------------------------------------------------------

    def write_null(self) -> None:
        """Writes a JSON `null` value."""
        lib.cardano_json_writer_write_null(self._ptr)

    def write_bool(self, value: bool) -> None:
        """Writes a boolean value (`true` or `false`)."""
        lib.cardano_json_writer_write_bool(self._ptr, value)

    def write_str(self, value: str) -> None:
        """
        Writes a string value. The writer handles escaping automatically.

        Args:
            value (str): The string content.
        """
        b_val = value.encode("utf-8")
        lib.cardano_json_writer_write_string(self._ptr, b_val, len(b_val))

    def write_int(self, value: Union[int, BigInt], as_string: bool = False) -> None:
        """
        Writes an integer value.

        Args:
            value (int | BigInt): The integer to write.
            as_string (bool): If True, writes the number as a string (e.g. "123").
                              Note: Very large integers (BigInts) are *always* written
                              as strings by the underlying library to preserve precision.
        """
        # Case 1: BigInt wrapper
        if isinstance(value, BigInt):
            # C API cardano_json_writer_write_bigint always writes as string
            lib.cardano_json_writer_write_bigint(self._ptr, value._ptr)
            return

        if not isinstance(value, int):
            raise TypeError(f"Expected int or BigInt, got {type(value)}")

        # Case 2: Standard 64-bit range
        # uint64 max: 18446744073709551615
        # int64 min: -9223372036854775808
        if 0 <= value <= 18446744073709551615:
            if as_string:
                lib.cardano_json_writer_write_uint_as_string(self._ptr, value)
            else:
                lib.cardano_json_writer_write_uint(self._ptr, value)
        elif -9223372036854775808 <= value < 0:
            if as_string:
                lib.cardano_json_writer_write_signed_int_as_string(self._ptr, value)
            else:
                lib.cardano_json_writer_write_signed_int(self._ptr, value)
        else:
            # Case 3: Large Python int -> Convert to BigInt -> Write
            # Note: This will implicitly be written as a string due to C API behavior
            big_int = BigInt.from_int(value)
            lib.cardano_json_writer_write_bigint(self._ptr, big_int._ptr)

    def write_float(self, value: float, as_string: bool = False) -> None:
        """
        Writes a floating point number.

        Args:
            value (float): The number to write.
            as_string (bool): If True, writes the number as a quoted string.
        """
        if as_string:
            lib.cardano_json_writer_write_double_as_string(self._ptr, value)
        else:
            lib.cardano_json_writer_write_double(self._ptr, value)

    def write_raw_value(self, value: str) -> None:
        """
        Writes a raw JSON fragment directly to the output.

        Warning: The caller must ensure `value` is valid JSON.

        Args:
            value (str): The raw JSON string (e.g., "[1, 2]").
        """
        b_val = value.encode("utf-8")
        lib.cardano_json_writer_write_raw_value(self._ptr, b_val, len(b_val))

    # --------------------------------------------------------------------------
    # Complex / Binary
    # --------------------------------------------------------------------------

    def write_json_object(self, obj: JsonObject) -> None:
        """
        Writes an existing JsonObject to the stream.

        Args:
            obj (JsonObject): The parsed JSON object to write.
        """
        lib.cardano_json_writer_write_object(self._ptr, obj._ptr)

    def write_bytes(self, data: Union[bytes, Buffer]) -> None:
        """
        Writes binary data as a hexadecimal string.

        Args:
            data (bytes | Buffer): The data to write.
        """
        if isinstance(data, bytes):
            c_data = ffi.from_buffer("byte_t[]", data)
            lib.cardano_json_writer_write_bytes_as_hex(self._ptr, c_data, len(data))
        elif isinstance(data, Buffer):
            lib.cardano_json_writer_write_buffer_as_hex(self._ptr, data._ptr)
        else:
            raise TypeError(f"Expected bytes or Buffer, got {type(data)}")

    def write_bech32(self, hrp: str, data: Union[bytes, Buffer]) -> None:
        """
        Writes binary data encoded as a Bech32 string.

        Args:
            hrp (str): The human-readable part (prefix).
            data (bytes | Buffer): The binary payload.
        """
        b_hrp = hrp.encode("utf-8")

        if isinstance(data, bytes):
            c_data = ffi.from_buffer("byte_t[]", data)
            lib.cardano_json_writer_write_bytes_as_bech32(
                self._ptr, b_hrp, len(b_hrp), c_data, len(data)
            )
        elif isinstance(data, Buffer):
            lib.cardano_json_writer_write_buffer_as_bech32(
                self._ptr, b_hrp, len(b_hrp), data._ptr
            )
        else:
            raise TypeError(f"Expected bytes or Buffer, got {type(data)}")

    def __del__(self) -> None:
        """
        Cleans up the underlying C resources when the JsonWriter is garbage collected.
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_json_writer_t**", self._ptr)
            lib.cardano_json_writer_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> JsonWriter:
        """
        Context manager entry. Returns self.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Context manager exit. Cleans up resources.
        """

    def __repr__(self) -> str:
        """
        Returns a string representation of the JsonWriter.
        """
        return f"<JsonWriter encoded_size={self.encoded_size} context={self.context.name}>"
