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
from typing import Optional, Union

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError
from .cbor_tag import CborTag
from ..common.bigint import BigInt

class CborWriter:
    """
    A simple writer for Concise Binary Object Representation (CBOR) encoded data.

    This class facilitates encoding data into the CBOR format. It abstracts the complexities
    involved in CBOR encoding, providing a simple interface for creating CBOR data streams.
    """

    def __init__(self, ptr=None) -> None:
        """
        Creates and initializes a new instance of a CBOR writer.
        """
        if ptr is None:
            self._ptr = lib.cardano_cbor_writer_new()
            if self._ptr == ffi.NULL:
                raise CardanoError("Failed to create CBOR writer")
        else:
            self._ptr = ptr

    # --------------------------------------------------------------------------
    # Properties & State
    # --------------------------------------------------------------------------

    @property
    def refcount(self) -> int:
        """Returns the number of active references to the underlying C object."""
        return int(lib.cardano_cbor_writer_refcount(self._ptr))

    @property
    def encoded_size(self) -> int:
        """Returns the current size of the encoded data in bytes."""
        return int(lib.cardano_cbor_writer_get_encode_size(self._ptr))

    @property
    def last_error(self) -> str:
        """Returns the last error message recorded for this writer."""
        return ffi.string(lib.cardano_cbor_writer_get_last_error(self._ptr)).decode("utf-8")

    @last_error.setter
    def last_error(self, message: str) -> None:
        """Manually sets the last error message."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_cbor_writer_set_last_error(self._ptr, c_msg)

    def reset(self) -> None:
        """
        Resets the writer, clearing all written data.
        The writer can be reused for new data without creating a new instance.
        """
        err = lib.cardano_cbor_writer_reset(self._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Encoding Output
    # --------------------------------------------------------------------------

    def encode(self) -> bytes:
        """
        Finalizes the CBOR encoding and returns the data as bytes.
        """
        # Method 1: Use encode_in_buffer to handle allocation automatically
        buf_ptr = ffi.new("cardano_buffer_t**")
        err = lib.cardano_cbor_writer_encode_in_buffer(self._ptr, buf_ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

        buffer = buf_ptr[0]
        try:
            # Extract raw bytes from the buffer
            size = lib.cardano_buffer_get_size(buffer)
            if size == 0:
                return b""

            raw_data = lib.cardano_buffer_get_data(buffer)
            return bytes(ffi.buffer(raw_data, size))
        finally:
            # We must release the buffer created by the C library
            lib.cardano_buffer_unref(buf_ptr)

    def to_hex(self) -> str:
        """
        Returns the encoded data as a hexadecimal string.
        """
        size = lib.cardano_cbor_writer_get_hex_size(self._ptr)
        if size == 0:
            return ""

        buf = ffi.new("char[]", size)
        err = lib.cardano_cbor_writer_encode_hex(self._ptr, buf, size)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

        return ffi.string(buf).decode("utf-8")

    # --------------------------------------------------------------------------
    # Write Methods
    # --------------------------------------------------------------------------

    def write_int(self, value: Union[int, BigInt]) -> None:
        """
        Encodes and writes an integer value.

        This method automatically selects the appropriate CBOR encoding:
        - Major type 0 for positive integers fitting in uint64.
        - Major type 1 for negative integers fitting in int64.
        - Major type 6 (Tag 2/3) for arbitrary precision integers (BigInts).

        Args:
            value (int | BigInt): The integer to write.
        """
        # Handle BigInt object
        if isinstance(value, BigInt):
            err = lib.cardano_cbor_writer_write_bigint(self._ptr, value._ptr)
            check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)
            return

        # Handle Python int
        if not isinstance(value, int):
            raise TypeError(f"Expected int or BigInt, got {type(value)}")

        # Check if it fits in standard 64-bit types
        if 0 <= value <= 18446744073709551615:
            err = lib.cardano_cbor_writer_write_uint(self._ptr, value)
        elif -9223372036854775808 <= value < 0:
            err = lib.cardano_cbor_writer_write_signed_int(self._ptr, value)
        else:
            # Too big for primitive types, convert to BigInt and write
            # This handles both large positive and large negative numbers
            big_int = BigInt.from_int(value)
            err = lib.cardano_cbor_writer_write_bigint(self._ptr, big_int._ptr)

        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_bool(self, value: bool) -> None:
        """Writes a boolean value."""
        err = lib.cardano_cbor_writer_write_bool(self._ptr, value)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_bytes(self, data: bytes) -> None:
        """
        Writes a byte string (major type 2).

        Args:
            data (bytes): The raw bytes to encode.
        """
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_cbor_writer_write_bytestring(self._ptr, c_data, len(data))
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_str(self, text: str) -> None:
        """
        Writes a UTF-8 text string (major type 3).

        Args:
            text (str): The string to encode.
        """
        b_text = text.encode("utf-8")
        c_data = ffi.from_buffer("char[]", b_text)
        err = lib.cardano_cbor_writer_write_textstring(self._ptr, c_data, len(b_text))
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_start_array(self, length: Optional[int] = None) -> None:
        """
        Initiates the writing of an array.

        Args:
            length (int, optional): The number of elements. If None, starts an
                                    indefinite-length array.
        """
        size = -1 if length is None else length
        err = lib.cardano_cbor_writer_write_start_array(self._ptr, size)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_end_array(self) -> None:
        """Concludes an indefinite-length array."""
        err = lib.cardano_cbor_writer_write_end_array(self._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_start_map(self, length: Optional[int] = None) -> None:
        """
        Initiates the writing of a map.

        Args:
            length (int, optional): The number of key-value pairs. If None, starts an
                                    indefinite-length map.
        """
        size = -1 if length is None else length
        err = lib.cardano_cbor_writer_write_start_map(self._ptr, size)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_end_map(self) -> None:
        """Concludes an indefinite-length map."""
        err = lib.cardano_cbor_writer_write_end_map(self._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_tag(self, tag: Union[int, CborTag]) -> None:
        """
        Assigns a semantic tag (major type 6) to the next data item.

        Args:
            tag (int | CborTag): The tag value.
        """
        err = lib.cardano_cbor_writer_write_tag(self._ptr, int(tag))
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_null(self) -> None:
        """Writes a null value (major type 7)."""
        err = lib.cardano_cbor_writer_write_null(self._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_undefined(self) -> None:
        """Writes an undefined value (major type 7)."""
        err = lib.cardano_cbor_writer_write_undefined(self._ptr)
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def write_encoded(self, data: bytes) -> None:
        """
        Writes pre-encoded CBOR data directly to the stream.

        This is useful if you already have a valid CBOR byte fragment and want
        to embed it without re-encoding.

        Args:
            data (bytes): The pre-encoded CBOR bytes.
        """
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_cbor_writer_write_encoded(self._ptr, c_data, len(data))
        check_error(err, lib.cardano_cbor_writer_get_last_error, self._ptr)

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_cbor_writer_t**", self._ptr)
            lib.cardano_cbor_writer_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> CborWriter:
        """
        Enters the runtime context related to this object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exits the runtime context related to this object.
        """

    def __repr__(self) -> str:
        """
        Returns a string representation of the CborWriter.
        """
        return f"<CborWriter size={self.encoded_size}>"
