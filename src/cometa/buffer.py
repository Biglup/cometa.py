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
from typing import Union, Iterator, overload

from ._ffi import ffi, lib
from .errors import check_error, CardanoError
from .common.byte_order import ByteOrder

class Buffer:
    """
    A dynamic, reference-counted byte buffer with configurable exponential growth.

    This class wraps the C `cardano_buffer_t` type. It behaves similarly to a
    mutable Python `bytearray`, offering automatic resizing, slicing, and
    binary data manipulation.
    """

    # --------------------------------------------------------------------------
    # Factories
    # --------------------------------------------------------------------------

    @classmethod
    def new(cls, capacity: int) -> Buffer:
        """
        Creates a new dynamic buffer with the specified initial capacity.

        Args:
            capacity (int): The initial allocation size in bytes.

        Returns:
            Buffer: An empty buffer with the reserved capacity.
        """
        ptr = lib.cardano_buffer_new(capacity)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to create buffer (invalid capacity or OOM)")
        return cls(ptr)

    @classmethod
    def from_bytes(cls, data: bytes) -> Buffer:
        """
        Creates a new buffer initialized with a copy of the given data.

        Args:
            data (bytes): The raw bytes to copy into the buffer.

        Returns:
            Buffer: A new buffer containing the data.
        """
        c_data = ffi.from_buffer("byte_t[]", data)
        ptr = lib.cardano_buffer_new_from(c_data, len(data))
        if ptr == ffi.NULL:
            raise CardanoError("Failed to create buffer from bytes")
        return cls(ptr)

    @classmethod
    def from_hex(cls, hex_string: str) -> Buffer:
        """
        Creates a new buffer by decoding a given hex string.

        Args:
            hex_string (str): A hexadecimal string (e.g., "deadbeef").

        Returns:
            Buffer: A new buffer containing the decoded bytes.
        """
        s_bytes = hex_string.encode("utf-8")
        ptr = lib.cardano_buffer_from_hex(s_bytes, len(s_bytes))
        if ptr == ffi.NULL:
            raise CardanoError("Failed to create buffer from hex string")
        return cls(ptr)

    # --------------------------------------------------------------------------
    # Python Protocols & Magic Methods
    # --------------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Returns the current number of used bytes in the buffer."""
        return int(lib.cardano_buffer_get_size(self._ptr))

    @property
    def capacity(self) -> int:
        """Returns the total allocated memory capacity of the buffer."""
        return int(lib.cardano_buffer_get_capacity(self._ptr))

    def compare(self, other: Buffer) -> int:
        """
        Compares two buffer objects lexicographically.

        Returns:
            int: < 0 if self < other, 0 if equal, > 0 if self > other.
        """
        return int(lib.cardano_buffer_compare(self._ptr, other._ptr))

    # --------------------------------------------------------------------------
    # Utility Methods
    # --------------------------------------------------------------------------

    def clone(self) -> Buffer:
        """Creates a deep copy of the buffer."""
        # Slicing the entire range creates a copy
        return self[0:self.size]

    def copy_bytes(self) -> bytes:
        """Returns a copy of the raw bytes (alias for to_bytes)."""
        return self.to_bytes()

    def to_bytes(self) -> bytes:
        """Converts the internal data to a Python bytes object."""
        size = self.size
        if size == 0:
            return b""

        raw_ptr = lib.cardano_buffer_get_data(self._ptr)
        if raw_ptr == ffi.NULL:
            return b""
        return bytes(ffi.buffer(raw_ptr, size))

    def to_hex(self) -> str:
        """Returns the hexadecimal string representation (e.g., 'deadbeef')."""
        size = lib.cardano_buffer_get_hex_size(self._ptr)
        buf = ffi.new("char[]", size)
        err = lib.cardano_buffer_to_hex(self._ptr, buf, size)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return ffi.string(buf).decode("utf-8")

    def to_str(self) -> str:
        """
        Converts the buffer content to a UTF-8 string.
        Assumes the buffer contains valid UTF-8 encoded text.
        """
        size = lib.cardano_buffer_get_str_size(self._ptr)
        if size == 0:
            return ""
        buf = ffi.new("char[]", size)
        err = lib.cardano_buffer_to_str(self._ptr, buf, size)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return ffi.string(buf).decode("utf-8")

    def set_size(self, size: int) -> None:
        """
        Sets the logical size of the buffer.

        Warning: This does not allocate new memory; it only updates the internal
        usage marker. The new size must not exceed the current capacity.

        Args:
            size (int): The new size.
        """
        err = lib.cardano_buffer_set_size(self._ptr, size)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def memzero(self) -> None:
        """
        Securely wipes the contents of the buffer from memory.
        Useful for clearing sensitive data like private keys.
        """
        lib.cardano_buffer_memzero(self._ptr)

    # --------------------------------------------------------------------------
    # Raw I/O
    # --------------------------------------------------------------------------

    def write(self, data: bytes) -> None:
        """
        Appends raw bytes to the end of the buffer.
        The buffer will automatically resize if necessary.
        """
        c_data = ffi.from_buffer("byte_t[]", data)
        err = lib.cardano_buffer_write(self._ptr, c_data, len(data))
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def read(self, length: int) -> bytes:
        """
        Reads a specified amount of data from the current cursor position.

        Args:
            length (int): Number of bytes to read.

        Returns:
            bytes: The data read.
        """
        buf = ffi.new("byte_t[]", length)
        err = lib.cardano_buffer_read(self._ptr, buf, length)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return bytes(buf)

    def seek(self, position: int) -> None:
        """
        Repositions the internal cursor within the buffer.

        Args:
            position (int): The offset to seek to.
        """
        err = lib.cardano_buffer_seek(self._ptr, position)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Typed Write Operations
    # --------------------------------------------------------------------------

    def write_uint16(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 16-bit unsigned integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_uint16_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_uint16_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_uint32(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 32-bit unsigned integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_uint32_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_uint32_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_uint64(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 64-bit unsigned integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_uint64_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_uint64_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_int16(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 16-bit signed integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_int16_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_int16_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_int32(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 32-bit signed integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_int32_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_int32_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_int64(self, value: int, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 64-bit signed integer to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_int64_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_int64_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_float(self, value: float, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 32-bit floating point number to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_float_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_float_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    def write_double(self, value: float, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> None:
        """Writes a 64-bit floating point number (double) to the buffer."""
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_write_double_le(self._ptr, value)
        else:
            err = lib.cardano_buffer_write_double_be(self._ptr, value)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)

    # --------------------------------------------------------------------------
    # Typed Read Operations
    # --------------------------------------------------------------------------

    def read_uint16(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 16-bit unsigned integer from the current position."""
        val = ffi.new("uint16_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_uint16_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_uint16_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_uint32(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 32-bit unsigned integer from the current position."""
        val = ffi.new("uint32_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_uint32_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_uint32_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_uint64(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 64-bit unsigned integer from the current position."""
        val = ffi.new("uint64_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_uint64_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_uint64_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_int16(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 16-bit signed integer from the current position."""
        val = ffi.new("int16_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_int16_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_int16_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_int32(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 32-bit signed integer from the current position."""
        val = ffi.new("int32_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_int32_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_int32_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_int64(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> int:
        """Reads a 64-bit signed integer from the current position."""
        val = ffi.new("int64_t*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_int64_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_int64_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return int(val[0])

    def read_float(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> float:
        """Reads a 32-bit floating point number from the current position."""
        val = ffi.new("float*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_float_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_float_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return float(val[0])

    def read_double(self, order: ByteOrder = ByteOrder.LITTLE_ENDIAN) -> float:
        """Reads a 64-bit floating point number from the current position."""
        val = ffi.new("double*")
        if order == ByteOrder.LITTLE_ENDIAN:
            err = lib.cardano_buffer_read_double_le(self._ptr, val)
        else:
            err = lib.cardano_buffer_read_double_be(self._ptr, val)
        check_error(err, lib.cardano_buffer_get_last_error, self._ptr)
        return float(val[0])

    # --------------------------------------------------------------------------
    # Error Handling
    # --------------------------------------------------------------------------

    def set_last_error(self, message: str) -> None:
        """Records an error message in the buffer's error register."""
        c_msg = ffi.new("char[]", message.encode("utf-8"))
        lib.cardano_buffer_set_last_error(self._ptr, c_msg)

    def get_last_error(self) -> str:
        """Retrieves the last error message recorded for this buffer."""
        return ffi.string(lib.cardano_buffer_get_last_error(self._ptr)).decode("utf-8")

    def __init__(self, ptr) -> None:
        """
        Internal constructor.

        Use factories like `Buffer.new()`, `Buffer.from_bytes()`, etc. instead.
        """
        if ptr == ffi.NULL:
            raise CardanoError("Buffer pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        """
        Destructor to release the underlying C buffer.
        """
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_buffer_t**", self._ptr)
            lib.cardano_buffer_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Buffer:
        """
        Context manager entry (no-op).
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Context manager exit (no-op).
        """

    def __len__(self) -> int:
        """Returns the number of bytes in the buffer."""
        return self.size

    def __bool__(self) -> bool:
        """Returns True if the buffer is not empty, False otherwise."""
        return self.size > 0

    def __bytes__(self) -> bytes:
        """Converts the buffer content to a Python immutable `bytes` object."""
        return self.to_bytes()

    @overload
    def __getitem__(self, key: int) -> int:
        ...

    @overload
    def __getitem__(self, key: slice) -> Buffer:
        ...

    def __getitem__(self, key: Union[int, slice]) -> Union[int, Buffer]:
        """
        Retrieve a byte or a slice of the buffer.

        Args:
            key (int | slice): The index or slice range.

        Returns:
            int: If key is an int, returns the byte value (0-255).
            Buffer: If key is a slice, returns a new Buffer containing the slice.
        """
        length = self.size

        if isinstance(key, int):
            if key < 0:
                key += length
            if not 0 <= key < length:
                raise IndexError("Buffer index out of range")

            raw_ptr = lib.cardano_buffer_get_data(self._ptr)
            return raw_ptr[key]

        if isinstance(key, slice):
            start, stop, stride = key.indices(length)
            if stride != 1:
                raise ValueError("Buffer slicing does not support strides")

            # Use the underlying C slice function for efficiency
            ptr = lib.cardano_buffer_slice(self._ptr, start, stop)
            if ptr == ffi.NULL:
                raise CardanoError("Failed to slice buffer")
            return Buffer(ptr)

        raise TypeError(f"Invalid argument type: {type(key)}")

    def __setitem__(self, key: int, value: int) -> None:
        """
        Modifies a byte at the specified index.

        Args:
            key (int): The index to modify.
            value (int): The new byte value (0-255).
        """
        if not isinstance(key, int):
            raise TypeError("Buffer assignment only supports integer indices")

        length = self.size
        if key < 0:
            key += length
        if not 0 <= key < length:
            raise IndexError("Buffer assignment index out of range")

        if not 0 <= value <= 255:
            raise ValueError("Byte value must be in range(0, 256)")

        raw_ptr = lib.cardano_buffer_get_data(self._ptr)
        raw_ptr[key] = value

    def __iter__(self) -> Iterator[int]:
        """Iterates over the bytes in the buffer."""
        raw_ptr = lib.cardano_buffer_get_data(self._ptr)
        length = self.size
        for i in range(length):
            yield raw_ptr[i]

    def __eq__(self, other: object) -> bool:
        """Checks if two buffers contain identical data."""
        if not isinstance(other, Buffer):
            return False
        return bool(lib.cardano_buffer_equals(self._ptr, other._ptr))

    def __add__(self, other: Buffer) -> Buffer:
        """Concatenates two buffers (lhs + rhs) into a new Buffer."""
        if not isinstance(other, Buffer):
            raise TypeError(f"Cannot concatenate Buffer with {type(other)}")
        ptr = lib.cardano_buffer_concat(self._ptr, other._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to concatenate buffers")
        return Buffer(ptr)

    def __repr__(self) -> str:
        """
        Returns a string representation of the buffer.
        """
        return f"<Buffer size={self.size} capacity={self.capacity}>"

    def __lt__(self, other: Buffer) -> bool:
        """
        Returns True if this buffer is lexicographically less than the other.
        """
        return self.compare(other) < 0

    def __le__(self, other: Buffer) -> bool:
        """
        Returns True if this buffer is lexicographically less than or equal to the other.
        """
        return self.compare(other) <= 0

    def __gt__(self, other: Buffer) -> bool:
        """
        Returns True if this buffer is lexicographically greater than the other.
        """
        return self.compare(other) > 0

    def __ge__(self, other: Buffer) -> bool:
        """
        Returns True if this buffer is lexicographically greater than or equal to the other.
        """
        return self.compare(other) >= 0
