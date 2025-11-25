from __future__ import annotations
from typing import Union, Optional

from .._ffi import ffi, lib
from ..errors import check_error, CardanoError
from .byte_order import ByteOrder

BigIntLike = Union["BigInt", int, str]

class BigInt:
    """
    Represents a large numeric value (arbitrary precision integer).

    This class wraps the C `cardano_bigint_t` type. It implements standard
    Python math operators (`+`, `-`, `*`, `/`, etc.), enabling it to be used
    interchangeably with native Python integers in most contexts.
    """

    def __init__(self, ptr) -> None:
        """
        Internal constructor.
        Use class methods like `from_int`, `from_string`, or `from_bytes` instead.
        """
        if ptr == ffi.NULL:
            raise CardanoError("BigInt pointer is NULL")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_bigint_t**", self._ptr)
            lib.cardano_bigint_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> BigInt:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    # --------------------------------------------------------------------------
    # Factories
    # --------------------------------------------------------------------------

    @classmethod
    def from_int(cls, value: int) -> BigInt:
        """
        Creates a BigInt from a Python integer.

        Args:
            value (int): The integer value.
        """
        out = ffi.new("cardano_bigint_t**")

        # Optimization: If it fits in standard C types, use direct constructors
        if -9223372036854775808 <= value <= 9223372036854775807:
            err = lib.cardano_bigint_from_int(value, out)
        elif 0 <= value <= 18446744073709551615:
            err = lib.cardano_bigint_from_unsigned_int(value, out)
        else:
            # Fallback for massive integers: go via string (base 10)
            s_val = str(value).encode('utf-8')
            err = lib.cardano_bigint_from_string(s_val, len(s_val), 10, out)

        if err != 0:
            raise CardanoError(f"Failed to create BigInt from {value}")

        return cls(out[0])

    @classmethod
    def from_string(cls, string: str, base: int = 10) -> BigInt:
        """
        Creates a BigInt from a string representation.

        Args:
            string (str): The string representation.
            base (int): The numerical base (e.g., 10, 16).
        """
        b_str = string.encode("utf-8")
        out = ffi.new("cardano_bigint_t**")
        err = lib.cardano_bigint_from_string(b_str, len(b_str), base, out)

        if err != 0:
            raise CardanoError(f"Failed to parse BigInt from string (base {base})")

        return cls(out[0])

    @classmethod
    def from_bytes(cls, data: bytes, order: ByteOrder = ByteOrder.BIG_ENDIAN) -> BigInt:
        """
        Creates a BigInt from a byte array.

        Args:
            data (bytes): The raw byte data.
            order (ByteOrder): The byte order (Endianness).
        """
        out = ffi.new("cardano_bigint_t**")
        c_data = ffi.from_buffer("byte_t[]", data)

        err = lib.cardano_bigint_from_bytes(c_data, len(data), order, out)

        if err != 0:
            raise CardanoError("Failed to create BigInt from bytes")

        return cls(out[0])

    # --------------------------------------------------------------------------
    # Python Protocols
    # --------------------------------------------------------------------------

    def __int__(self) -> int:
        """Converts the BigInt to a Python int."""
        return int(self.to_string(base=10))

    def __index__(self) -> int:
        """
        Allows BigInt to be used as a list index or in functions like hex(), bin().
        Example: `my_list[big_int]` or `hex(big_int)`
        """
        return int(self)

    def __str__(self) -> str:
        """Returns the decimal string representation."""
        return self.to_string(base=10)

    def __repr__(self) -> str:
        return f"BigInt({self})"

    def __format__(self, format_spec: str) -> str:
        """
        Allows BigInt to be formatted in f-strings.
        Example: f"{big_int:x}" -> hexadecimal
        """
        return int(self).__format__(format_spec)

    @property
    def is_zero(self) -> bool:
        """Returns True if the value is 0."""
        return bool(lib.cardano_bigint_is_zero(self._ptr))

    @property
    def sign(self) -> int:
        """Returns -1 for negative, 0 for zero, 1 for positive."""
        return int(lib.cardano_bigint_signum(self._ptr))

    # --------------------------------------------------------------------------
    # Core Methods
    # --------------------------------------------------------------------------

    def clone(self) -> BigInt:
        """Creates a deep copy of the BigInt object."""
        out = ffi.new("cardano_bigint_t**")
        err = lib.cardano_bigint_clone(self._ptr, out)
        check_error(err, lib.cardano_bigint_get_last_error, self._ptr)
        return BigInt(out[0])

    def to_string(self, base: int = 10) -> str:
        """Converts the BigInt to a string in the specified base."""
        size = lib.cardano_bigint_get_string_size(self._ptr, base)
        if size == 0:
            return ""

        buf = ffi.new("char[]", size)
        err = lib.cardano_bigint_to_string(self._ptr, buf, size, base)
        check_error(err, lib.cardano_bigint_get_last_error, self._ptr)

        return ffi.string(buf).decode("utf-8")

    def to_bytes(self, order: ByteOrder = ByteOrder.BIG_ENDIAN) -> bytes:
        """Converts the BigInt to a byte array."""
        size = lib.cardano_bigint_get_bytes_size(self._ptr)
        if size == 0:
            return b""

        buf = ffi.new("byte_t[]", size)
        err = lib.cardano_bigint_to_bytes(self._ptr, order, buf, size)
        check_error(err, lib.cardano_bigint_get_last_error, self._ptr)

        return bytes(buf)

    # --------------------------------------------------------------------------
    # Math Magic Methods
    # --------------------------------------------------------------------------

    def _ensure_bigint(self, other: BigIntLike) -> BigInt:
        if isinstance(other, BigInt):
            return other
        if isinstance(other, int):
            return BigInt.from_int(other)
        if isinstance(other, str):
            return BigInt.from_string(other)
        raise TypeError(f"Unsupported type for BigInt operation: {type(other)}")

    def _new_res(self) -> BigInt:
        return BigInt.from_int(0)

    def __add__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_add(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __sub__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_subtract(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __mul__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_multiply(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __truediv__(self, other: BigIntLike) -> BigInt:
        """Integer division (same as floordiv for BigInt)."""
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_divide(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __floordiv__(self, other: BigIntLike) -> BigInt:
        return self.__truediv__(other)

    def __mod__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_mod(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __divmod__(self, other: BigIntLike) -> tuple[BigInt, BigInt]:
        other_bi = self._ensure_bigint(other)
        quo = self._new_res()
        rem = self._new_res()
        lib.cardano_bigint_divide_and_reminder(self._ptr, other_bi._ptr, quo._ptr, rem._ptr)
        return (quo, rem)

    def __pow__(self, exponent: int, modulus: Optional[BigIntLike] = None) -> BigInt:
        if modulus is not None:
            return self.mod_pow(exponent, modulus)
        return self.pow(exponent)

    def __abs__(self) -> BigInt:
        res = self._new_res()
        lib.cardano_bigint_abs(self._ptr, res._ptr)
        return res

    def __neg__(self) -> BigInt:
        res = self._new_res()
        lib.cardano_bigint_negate(self._ptr, res._ptr)
        return res

    def pow(self, exponent: int) -> BigInt:
        """Raises BigInt to a positive integer power."""
        if exponent < 0:
            raise ValueError("BigInt.pow only supports positive exponents")
        res = self._new_res()
        lib.cardano_bigint_pow(self._ptr, exponent, res._ptr)
        return res

    def mod_pow(self, exponent: BigIntLike, modulus: BigIntLike) -> BigInt:
        """Modular exponentiation: (self ** exponent) % modulus."""
        exp_bi = self._ensure_bigint(exponent)
        mod_bi = self._ensure_bigint(modulus)
        res = self._new_res()
        lib.cardano_bigint_mod_pow(self._ptr, exp_bi._ptr, mod_bi._ptr, res._ptr)
        return res

    def mod_inverse(self, modulus: BigIntLike) -> BigInt:
        """Computes the modular multiplicative inverse."""
        mod_bi = self._ensure_bigint(modulus)
        res = self._new_res()
        lib.cardano_bigint_mod_inverse(self._ptr, mod_bi._ptr, res._ptr)
        return res

    def gcd(self, other: BigIntLike) -> BigInt:
        """Computes the Greatest Common Divisor."""
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_gcd(self._ptr, other_bi._ptr, res._ptr)
        return res

    # --------------------------------------------------------------------------
    # Bitwise Operations
    # --------------------------------------------------------------------------

    def __and__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_and(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __or__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_or(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __xor__(self, other: BigIntLike) -> BigInt:
        other_bi = self._ensure_bigint(other)
        res = self._new_res()
        lib.cardano_bigint_xor(self._ptr, other_bi._ptr, res._ptr)
        return res

    def __invert__(self) -> BigInt:
        res = self._new_res()
        lib.cardano_bigint_not(self._ptr, res._ptr)
        return res

    def __lshift__(self, bits: int) -> BigInt:
        res = self._new_res()
        lib.cardano_bigint_shift_left(self._ptr, bits, res._ptr)
        return res

    def __rshift__(self, bits: int) -> BigInt:
        res = self._new_res()
        lib.cardano_bigint_shift_right(self._ptr, bits, res._ptr)
        return res

    # --------------------------------------------------------------------------
    # Bit Manipulation
    # --------------------------------------------------------------------------

    def test_bit(self, n: int) -> bool:
        """Checks if the N-th bit is set."""
        return bool(lib.cardano_bigint_test_bit(self._ptr, n))

    def set_bit(self, n: int) -> None:
        """Sets the N-th bit in-place."""
        lib.cardano_bigint_set_bit(self._ptr, n)

    def clear_bit(self, n: int) -> None:
        """Clears the N-th bit in-place."""
        lib.cardano_bigint_clear_bit(self._ptr, n)

    def flip_bit(self, n: int) -> None:
        """Flips the N-th bit in-place."""
        lib.cardano_bigint_flip_bit(self._ptr, n)

    @property
    def bit_count(self) -> int:
        """Returns number of bits differing from sign bit."""
        return int(lib.cardano_bigint_bit_count(self._ptr))

    @property
    def bit_length(self) -> int:
        """Returns number of bits required to represent the integer."""
        return int(lib.cardano_bigint_bit_length(self._ptr))

    # --------------------------------------------------------------------------
    # Comparison
    # --------------------------------------------------------------------------

    def compare(self, other: BigIntLike) -> int:
        other_bi = self._ensure_bigint(other)
        return int(lib.cardano_bigint_compare(self._ptr, other_bi._ptr))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (BigInt, int, str)):
            other_bi = self._ensure_bigint(other)
            return bool(lib.cardano_bigint_equals(self._ptr, other_bi._ptr))
        return False

    def __lt__(self, other: BigIntLike) -> bool:
        return self.compare(other) < 0

    def __le__(self, other: BigIntLike) -> bool:
        return self.compare(other) <= 0

    def __gt__(self, other: BigIntLike) -> bool:
        return self.compare(other) > 0

    def __ge__(self, other: BigIntLike) -> bool:
        return self.compare(other) >= 0