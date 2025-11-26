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
from typing import Optional

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError
from .cbor_reader_state import CborReaderState
from ..buffer import Buffer
from ..common.bigint import BigInt

class CborReader:
    """
    Represents a reader for parsing Concise Binary Object Representation (CBOR) encoded data.

    This class provides a stream-like interface to decode CBOR data items sequentially.
    """

    @property
    def refcount(self) -> int:
        """Returns the number of active references to the underlying C object."""
        return int(lib.cardano_cbor_reader_refcount(self._ptr))

    @property
    def remaining_bytes(self) -> int:
        """Returns the number of unread bytes remaining in the buffer."""
        remaining = ffi.new("size_t*")
        err = lib.cardano_cbor_reader_get_bytes_remaining(self._ptr, remaining)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(remaining[0])

    @property
    def last_error(self) -> str:
        """Returns the last error message recorded for this reader."""
        return ffi.string(lib.cardano_cbor_reader_get_last_error(self._ptr)).decode("utf-8")

    @last_error.setter
    def last_error(self, message: str) -> None:
        """Manually sets the last error message."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_cbor_reader_set_last_error(self._ptr, c_msg)

    # --------------------------------------------------------------------------
    # Factories
    # --------------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes) -> CborReader:
        """
        Creates a CborReader from raw bytes.

        Args:
            data (bytes): The CBOR encoded data.
        """
        buf = ffi.from_buffer("unsigned char[]", data)
        ptr = lib.cardano_cbor_reader_new(buf, len(data))
        if ptr == ffi.NULL:
            # Retrieve generic error if creation fails
            msg = ffi.string(
                lib.cardano_cbor_reader_get_last_error(ffi.NULL)
            ).decode("utf-8")
            raise CardanoError(msg)
        return cls(ptr)

    @classmethod
    def from_hex(cls, hex_string: str) -> CborReader:
        """
        Creates a CborReader from a hexadecimal string.

        Args:
            hex_string (str): The hex-encoded CBOR data.
        """
        input_bytes = hex_string.encode("utf-8")
        ptr = lib.cardano_cbor_reader_from_hex(input_bytes, len(input_bytes))
        if ptr == ffi.NULL:
            msg = ffi.string(
                lib.cardano_cbor_reader_get_last_error(ffi.NULL)
            ).decode("utf-8")
            raise CardanoError(msg)
        return cls(ptr)

    # --------------------------------------------------------------------------
    # State
    # --------------------------------------------------------------------------
    def peek_state(self) -> CborReaderState:
        """
        Inspects the type of the next CBOR token without consuming it.

        Returns:
            CborReaderState: The state enum indicating the next token type.
        """
        state = ffi.new("cardano_cbor_reader_state_t*")
        err = lib.cardano_cbor_reader_peek_state(self._ptr, state)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return CborReaderState(state[0])

    def clone(self) -> CborReader:
        """Creates a deep copy of the reader with its own independent cursor."""
        out = ffi.new("cardano_cbor_reader_t**")
        err = lib.cardano_cbor_reader_clone(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return CborReader(out[0])

    # --------------------------------------------------------------------------
    # Reading Methods
    # --------------------------------------------------------------------------

    def read_remainder(self) -> bytes:
        """Reads all remaining unparsed bytes."""
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_cbor_reader_get_remainder_bytes(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return bytes(Buffer(out[0]))

    def skip_value(self) -> None:
        """Skips the next CBOR data item completely (including nested items)."""
        err = lib.cardano_cbor_reader_skip_value(self._ptr)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

    def read_encoded_value(self) -> bytes:
        """Reads the next CBOR data item as-is and returns the raw bytes."""
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_cbor_reader_read_encoded_value(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return bytes(Buffer(out[0]))

    def read_array_len(self) -> Optional[int]:
        """
        Reads the start of an array.

        Returns:
            int | None: The number of elements in the array, or None if it is indefinite-length.
        """
        size = ffi.new("int64_t*")
        err = lib.cardano_cbor_reader_read_start_array(self._ptr, size)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

        val = int(size[0])
        return None if val < 0 else val

    def read_array_end(self) -> None:
        """Consumes the 'break' code ending an indefinite-length array."""
        err = lib.cardano_cbor_reader_read_end_array(self._ptr)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

    def read_map_len(self) -> Optional[int]:
        """
        Reads the start of a map.

        Returns:
            int | None: The number of pairs in the map, or None if it is indefinite-length.
        """
        size = ffi.new("int64_t*")
        err = lib.cardano_cbor_reader_read_start_map(self._ptr, size)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

        val = int(size[0])
        return None if val < 0 else val

    def read_map_end(self) -> None:
        """Consumes the 'break' code ending an indefinite-length map."""
        err = lib.cardano_cbor_reader_read_end_map(self._ptr)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Primitive Readers
    # --------------------------------------------------------------------------

    def read_int(self) -> int:
        """Reads a signed integer (Major type 0 or 1)."""
        value = ffi.new("int64_t*")
        err = lib.cardano_cbor_reader_read_int(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(value[0])

    def read_uint(self) -> int:
        """Reads an unsigned integer (Major type 0)."""
        value = ffi.new("uint64_t*")
        err = lib.cardano_cbor_reader_read_uint(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(value[0])

    def read_bigint(self) -> int:
        """Reads a bignum (Major type 6, tag 2 or 3)."""
        out = ffi.new("cardano_bigint_t**")
        err = lib.cardano_cbor_reader_read_bigint(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        # Wrap in BigInt to manage memory via __del__, then convert to Python int
        return int(BigInt(out[0]))

    def read_float(self) -> float:
        """Reads a double-precision float (Major type 7)."""
        value = ffi.new("double*")
        err = lib.cardano_cbor_reader_read_double(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return float(value[0])

    def read_simple_value(self) -> int:
        """
        Reads a simple value (e.g., boolean, null, or undefined).

        Returns:
            int: The simple value.
        """
        value = ffi.new("cardano_cbor_simple_value_t*")
        err = lib.cardano_cbor_reader_read_simple_value(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(value[0])

    def read_bool(self) -> bool:
        """Reads a boolean value."""
        value = ffi.new("bool*")
        err = lib.cardano_cbor_reader_read_bool(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return bool(value[0])

    def read_null(self) -> None:
        """Consumes a null value."""
        err = lib.cardano_cbor_reader_read_null(self._ptr)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

    def read_bytes(self) -> bytes:
        """Reads a byte string (Major type 2)."""
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_cbor_reader_read_bytestring(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return bytes(Buffer(out[0]))

    def read_str(self) -> str:
        """
        Reads a text string (Major type 3).
        Returns a string (decoded UTF-8).
        """
        out = ffi.new("cardano_buffer_t**")
        err = lib.cardano_cbor_reader_read_textstring(self._ptr, out)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return Buffer(out[0]).to_str()

    def read_tag(self) -> int:
        """
        Reads a semantic tag (Major type 6).

        Returns:
            int: The tag value.
        """
        tag = ffi.new("cardano_cbor_tag_t*")
        err = lib.cardano_cbor_reader_read_tag(self._ptr, tag)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(tag[0])

    def peek_tag(self) -> int:
        """
        Peeks at the next semantic tag without consuming it.

        Returns:
            int: The tag value if present.
        """
        tag = ffi.new("cardano_cbor_tag_t*")
        err = lib.cardano_cbor_reader_peek_tag(self._ptr, tag)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(tag[0])

    def __init__(self, ptr) -> None:
        """Internal constructor. Use factories like `from_bytes` or `from_hex`."""
        if ptr == ffi.NULL:
            raise CardanoError("CBOR reader pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        """Cleans up the underlying C object when the Python object is garbage collected."""
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_cbor_reader_t**", self._ptr)
            lib.cardano_cbor_reader_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CborReader:
        """Enables use as a context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cleans up when exiting a context manager."""

    def __repr__(self) -> str:
        """Returns a string representation of the CborReader."""
        try:
            remaining = self.remaining_bytes
        except CardanoError:
            remaining = "?"
        return f"<CborReader at 0x{id(self):x}, remaining={remaining}>"
