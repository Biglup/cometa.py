from __future__ import annotations

from .._ffi import ffi, lib
from .._errors import check_error, CardanoError


class CborReader:
    """Python wrapper for cardano_cbor_reader_t."""

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            # we can try to fetch a generic message, but spec says NULL => error
            raise CardanoError("CBOR reader pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_cbor_reader_t**", self._ptr)
            lib.cardano_cbor_reader_unref(ptr_ptr)
            self._ptr = ffi.NULL

    @classmethod
    def from_bytes(cls, data: bytes) -> "CborReader":
        """Create a reader from raw CBOR bytes."""
        buf = ffi.from_buffer("unsigned char[]", data)
        ptr = lib.cardano_cbor_reader_new(buf, len(data))
        if ptr == ffi.NULL:
            # cardano_cbor_reader_get_last_error(NULL) returns generic message
            msg = ffi.string(
                lib.cardano_cbor_reader_get_last_error(ffi.NULL)
            ).decode("utf-8")
            raise CardanoError(msg)
        return cls(ptr)

    @classmethod
    def from_hex(cls, hex_string: str) -> "CborReader":
        """Create a reader from a hex-encoded CBOR string (without 0x prefix)."""
        bs = hex_string.encode("utf-8")
        ptr = lib.cardano_cbor_reader_from_hex(bs, len(bs))
        if ptr == ffi.NULL:
            msg = ffi.string(
                lib.cardano_cbor_reader_get_last_error(ffi.NULL)
            ).decode("utf-8")
            raise CardanoError(msg)
        return cls(ptr)

    def clone(self) -> "CborReader":
        """Clone the reader (new C object, separate lifetime)."""
        out = ffi.new("cardano_cbor_reader_t**")
        err = lib.cardano_cbor_reader_clone(self._ptr, out)
        ctx = out[0] if out[0] != ffi.NULL else self._ptr
        check_error(err, lib.cardano_cbor_reader_get_last_error, ctx)
        return CborReader(out[0])

    def refcount(self) -> int:
        """Return the current reference count (for debugging/testing)."""
        return int(lib.cardano_cbor_reader_refcount(self._ptr))

    def get_bytes_remaining(self) -> int:
        """Return the number of unread bytes remaining in the reader."""
        remaining = ffi.new("size_t*")
        err = lib.cardano_cbor_reader_get_bytes_remaining(self._ptr, remaining)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(remaining[0])

    def read_uint(self) -> int:
        """Read next CBOR item as unsigned integer."""
        value = ffi.new("uint64_t*")
        err = lib.cardano_cbor_reader_read_uint(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(value[0])

    def read_int(self) -> int:
        """Read next CBOR item as signed integer."""
        value = ffi.new("int64_t*")
        err = lib.cardano_cbor_reader_read_int(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return int(value[0])

    def read_bool(self) -> bool:
        """Read next CBOR item as boolean."""
        value = ffi.new("bool*")
        err = lib.cardano_cbor_reader_read_bool(self._ptr, value)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)
        return bool(value[0])

    def read_null(self) -> None:
        """Read next CBOR item as null (just advances the reader)."""
        err = lib.cardano_cbor_reader_read_null(self._ptr)
        check_error(err, lib.cardano_cbor_reader_get_last_error, self._ptr)

    def __repr__(self) -> str:
        try:
            remaining = self.get_bytes_remaining()
        except Exception:
            remaining = "?"
        return f"<CborReader at 0x{id(self):x}, remaining={remaining}>"
