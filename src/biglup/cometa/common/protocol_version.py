from __future__ import annotations

from .._ffi import ffi, lib
from .._errors import check_error


class ProtocolVersion:
    """Python wrapper for cardano_protocol_version_t."""

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise ValueError("ProtocolVersion pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_protocol_version_t**", self._ptr)
            lib.cardano_protocol_version_unref(ptr_ptr)
            self._ptr = ffi.NULL

    # ---- Constructors -----------------------------------------------------

    @classmethod
    def from_numbers(cls, major: int, minor: int) -> "ProtocolVersion":
        """Create a ProtocolVersion from major/minor integers."""
        out = ffi.new("cardano_protocol_version_t**")
        err = lib.cardano_protocol_version_new(
            int(major),
            int(minor),
            out,
        )
        # On error, ctx_ptr is out[0] but may be NULL; that's OK for get_last_error.
        ctx = out[0] if out[0] != ffi.NULL else ffi.NULL
        check_error(err, lib.cardano_protocol_version_get_last_error, ctx)
        return cls(out[0])

    # ---- Reference counting ----------------------------------------------

    def clone(self) -> "ProtocolVersion":
        """Increase refcount and wrap in a new Python object."""
        lib.cardano_protocol_version_ref(self._ptr)
        return ProtocolVersion(self._ptr)

    def refcount(self) -> int:
        """Return the current reference count (debugging helper)."""
        return int(lib.cardano_protocol_version_refcount(self._ptr))

    # ---- Properties -------------------------------------------------------

    @property
    def major(self) -> int:
        return int(lib.cardano_protocol_version_get_major(self._ptr))

    @major.setter
    def major(self, value: int) -> None:
        err = lib.cardano_protocol_version_set_major(self._ptr, int(value))
        check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)

    @property
    def minor(self) -> int:
        return int(lib.cardano_protocol_version_get_minor(self._ptr))

    @minor.setter
    def minor(self, value: int) -> None:
        err = lib.cardano_protocol_version_set_minor(self._ptr, int(value))
        check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)

    # def to_cbor(self, writer: CborWriter) -> None:
    #     err = lib.cardano_protocol_version_to_cbor(self._ptr, writer._ptr)
    #     check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)
    #
    # def to_cip116_json(self, writer: JsonWriter) -> None:
    #     err = lib.cardano_protocol_version_to_cip116_json(self._ptr, writer._ptr)
    #     check_error(err, lib.cardano_protocol_version_get_last_error, self._ptr)
