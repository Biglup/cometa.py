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

import pytest
from cometa import BigInt, ByteOrder, CardanoError


class TestBigIntCreation:
    """Tests for BigInt factory methods and initialization."""

    def test_from_int_small_positive(self):
        """Test from_int with small positive integer (int64 range)."""
        val = 123456789
        bi = BigInt.from_int(val)
        assert int(bi) == val
        assert not bi.is_zero
        assert bi.sign == 1

    def test_from_int_small_negative(self):
        """Test from_int with small negative integer (int64 range)."""
        val = -123456789
        bi = BigInt.from_int(val)
        assert int(bi) == val
        assert bi.sign == -1

    def test_from_int_zero(self):
        """Test from_int with zero."""
        bi = BigInt.from_int(0)
        assert int(bi) == 0
        assert bi.is_zero
        assert bi.sign == 0

    def test_from_int_large_unsigned(self):
        """Test from_int with large unsigned (fits in uint64 but not int64)."""
        val = 2**63 + 10
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_from_int_massive(self):
        """Test from_int with massive integer (requires string fallback)."""
        val = 2**128 + 123456789
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_from_int_max_int64(self):
        """Test from_int with max int64 value."""
        val = 9223372036854775807
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_from_int_min_int64(self):
        """Test from_int with min int64 value."""
        val = -9223372036854775808
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_from_int_max_uint64(self):
        """Test from_int with max uint64 value."""
        val = 18446744073709551615
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_from_string_decimal(self):
        """Test from_string with decimal base."""
        s = "12345678901234567890"
        bi = BigInt.from_string(s, base=10)
        assert str(bi) == s

    def test_from_string_large_number(self):
        """Test from_string with large number (from C test)."""
        s = "340199290171201906221318119490500689920"
        bi = BigInt.from_string(s, base=10)
        assert str(bi) == s

    def test_from_string_negative(self):
        """Test from_string with negative number (from C test)."""
        s = "-1234567890000000000000000000000000000000000000000000"
        bi = BigInt.from_string(s, base=10)
        assert str(bi) == s

    def test_from_string_hexadecimal(self):
        """Test from_string with hexadecimal base."""
        s_hex = "deadbeef"
        bi = BigInt.from_string(s_hex, base=16)
        assert int(bi) == 0xdeadbeef

    def test_from_string_empty(self):
        """Test from_string with empty string (should fail)."""
        with pytest.raises(CardanoError):
            BigInt.from_string("", base=10)

    def test_from_string_invalid(self):
        """Test from_string with invalid characters (from C test)."""
        with pytest.raises(CardanoError):
            BigInt.from_string("123456789a", base=10)

    def test_from_string_invalid_zzzz(self):
        """Test from_string with invalid string."""
        with pytest.raises(CardanoError):
            BigInt.from_string("zzzz", base=10)

    def test_from_bytes_big_endian(self):
        """Test from_bytes with big endian (from C test)."""
        data = bytes([0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        bi = BigInt.from_bytes(data, ByteOrder.BIG_ENDIAN)
        assert str(bi) == "340199290171201906221318119490500689920"

    def test_from_bytes_little_endian(self):
        """Test from_bytes with little endian (from C test)."""
        data = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0xFF])
        bi = BigInt.from_bytes(data, ByteOrder.LITTLE_ENDIAN)
        assert str(bi) == "340199290171201906221318119490500689920"

    def test_from_bytes_simple_big_endian(self):
        """Test from_bytes with simple value big endian."""
        data = b"\x01\x02"
        bi = BigInt.from_bytes(data, ByteOrder.BIG_ENDIAN)
        assert int(bi) == 258

    def test_from_bytes_simple_little_endian(self):
        """Test from_bytes with simple value little endian."""
        data = b"\x01\x02"
        bi = BigInt.from_bytes(data, ByteOrder.LITTLE_ENDIAN)
        assert int(bi) == 0x0201


class TestBigIntConversion:
    """Tests for BigInt conversion methods."""

    def test_to_string_decimal(self):
        """Test to_string with decimal base."""
        bi = BigInt.from_int(123456789)
        assert bi.to_string(10) == "123456789"

    def test_to_string_hexadecimal(self):
        """Test to_string with hexadecimal base."""
        bi = BigInt.from_int(0xdeadbeef)
        assert bi.to_string(16) == "deadbeef"

    def test_to_string_negative(self):
        """Test to_string with negative number."""
        bi = BigInt.from_int(-123456789)
        assert bi.to_string(10) == "-123456789"

    def test_to_bytes_big_endian(self):
        """Test to_bytes with big endian (from C test)."""
        s = "340199290171201906221318119490500689920"
        bi = BigInt.from_string(s, base=10)
        result = bi.to_bytes(ByteOrder.BIG_ENDIAN)
        expected = bytes([0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        assert result == expected

    def test_to_bytes_simple(self):
        """Test to_bytes with simple value."""
        val = 0x010203
        bi = BigInt.from_int(val)
        b_be = bi.to_bytes(ByteOrder.BIG_ENDIAN)
        assert b_be.endswith(b"\x01\x02\x03")

    def test_to_int(self):
        """Test to_int conversion (from C test)."""
        bi = BigInt.from_int(123456789)
        assert bi.to_int() == 123456789

    def test_to_unsigned_int(self):
        """Test to_unsigned_int conversion (from C test)."""
        bi = BigInt.from_int(123456789)
        assert bi.to_unsigned_int() == 123456789

    def test_dunder_int(self):
        """Test __int__ conversion."""
        val = 255
        bi = BigInt.from_int(val)
        assert int(bi) == val

    def test_dunder_str(self):
        """Test __str__ conversion."""
        bi = BigInt.from_int(255)
        assert str(bi) == "255"

    def test_dunder_repr(self):
        """Test __repr__ conversion."""
        bi = BigInt.from_int(255)
        assert repr(bi) == "BigInt(255)"

    def test_dunder_format(self):
        """Test __format__ conversion."""
        bi = BigInt.from_int(255)
        assert f"{bi:04x}" == "00ff"


class TestBigIntProperties:
    """Tests for BigInt properties."""

    def test_is_zero_true(self):
        """Test is_zero property with zero value."""
        bi = BigInt.from_int(0)
        assert bi.is_zero is True

    def test_is_zero_false(self):
        """Test is_zero property with non-zero value."""
        bi = BigInt.from_int(1)
        assert bi.is_zero is False

    def test_sign_positive(self):
        """Test sign property with positive value."""
        bi = BigInt.from_int(42)
        assert bi.sign == 1

    def test_sign_negative(self):
        """Test sign property with negative value."""
        bi = BigInt.from_int(-42)
        assert bi.sign == -1

    def test_sign_zero(self):
        """Test sign property with zero value."""
        bi = BigInt.from_int(0)
        assert bi.sign == 0

    def test_bit_count(self):
        """Test bit_count property."""
        bi = BigInt.from_int(5)
        assert bi.bit_count == 2

    def test_bit_length(self):
        """Test bit_length property."""
        bi = BigInt.from_int(5)
        assert bi.bit_length == 3


class TestBigIntArithmetic:
    """Tests for BigInt arithmetic operations."""

    def test_add_two_bigints(self):
        """Test addition of two BigInt values (from C test)."""
        a = BigInt.from_int(123456789)
        b = BigInt.from_int(987654321)
        result = a + b
        assert int(result) == 1111111110

    def test_add_bigint_and_int(self):
        """Test addition of BigInt and int."""
        a = BigInt.from_int(10)
        assert int(a + 5) == 15

    def test_add_bigint_and_string(self):
        """Test addition of BigInt and string."""
        a = BigInt.from_int(10)
        assert int(a + "5") == 15

    def test_subtract_two_bigints(self):
        """Test subtraction of two BigInt values."""
        a = BigInt.from_int(987654321)
        b = BigInt.from_int(123456789)
        result = a - b
        assert int(result) == 864197532

    def test_subtract_bigint_and_int(self):
        """Test subtraction of BigInt and int."""
        a = BigInt.from_int(30)
        assert int(a - 5) == 25

    def test_multiply_two_bigints(self):
        """Test multiplication of two BigInt values (from C test)."""
        lhs = BigInt.from_string("-1234567890000000000000000000000000000000000000000000")
        rhs = BigInt.from_int(2)
        result = lhs * rhs
        assert str(result) == "-2469135780000000000000000000000000000000000000000000"

    def test_multiply_simple(self):
        """Test multiplication with simple values."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert int(a * b) == 200

    def test_divide_two_bigints(self):
        """Test division of two BigInt values."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(3)
        assert int(a / b) == 33

    def test_floordiv(self):
        """Test floor division."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(3)
        assert int(a // b) == 33

    def test_mod_two_bigints(self):
        """Test modulus of two BigInt values."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(30)
        assert int(a % b) == 10

    def test_remainder(self):
        """Test remainder method."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(30)
        assert int(a.remainder(b)) == 10

    def test_divmod(self):
        """Test divmod operation."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(30)
        q, r = divmod(a, b)
        assert int(q) == 3
        assert int(r) == 10

    def test_pow_positive(self):
        """Test power with positive exponent."""
        a = BigInt.from_int(2)
        assert int(a ** 10) == 1024
        assert int(a.pow(10)) == 1024

    def test_pow_zero(self):
        """Test power with zero exponent."""
        a = BigInt.from_int(5)
        assert int(a ** 0) == 1

    def test_pow_negative_raises(self):
        """Test power with negative exponent raises ValueError."""
        a = BigInt.from_int(2)
        with pytest.raises(ValueError):
            a.pow(-1)

    def test_mod_pow(self):
        """Test modular exponentiation."""
        base = BigInt.from_int(2)
        exp = BigInt.from_int(10)
        mod = BigInt.from_int(1000)
        assert int(pow(base, 10, mod)) == 24
        assert int(base.mod_pow(exp, mod)) == 24

    def test_mod_inverse(self):
        """Test modular multiplicative inverse."""
        a = BigInt.from_int(3)
        mod = BigInt.from_int(11)
        inv = a.mod_inverse(mod)
        assert int((a * inv) % mod) == 1

    def test_abs_positive(self):
        """Test absolute value of positive number."""
        a = BigInt.from_int(10)
        assert int(abs(a)) == 10

    def test_abs_negative(self):
        """Test absolute value of negative number."""
        a = BigInt.from_int(-50)
        assert int(abs(a)) == 50

    def test_neg(self):
        """Test negation."""
        a = BigInt.from_int(10)
        assert int(-a) == -10

    def test_gcd(self):
        """Test greatest common divisor."""
        a = BigInt.from_int(48)
        b = BigInt.from_int(18)
        assert int(a.gcd(b)) == 6


class TestBigIntBitwise:
    """Tests for BigInt bitwise operations."""

    def test_and(self):
        """Test bitwise AND."""
        a = BigInt.from_int(12)
        b = BigInt.from_int(10)
        assert int(a & b) == 8

    def test_or(self):
        """Test bitwise OR."""
        a = BigInt.from_int(12)
        b = BigInt.from_int(10)
        assert int(a | b) == 14

    def test_xor(self):
        """Test bitwise XOR."""
        a = BigInt.from_int(12)
        b = BigInt.from_int(10)
        assert int(a ^ b) == 6

    def test_not(self):
        """Test bitwise NOT."""
        a = BigInt.from_int(0)
        assert int(~a) == -1

    def test_lshift(self):
        """Test left shift."""
        a = BigInt.from_int(12)
        assert int(a << 2) == 48

    def test_rshift(self):
        """Test right shift."""
        a = BigInt.from_int(12)
        assert int(a >> 2) == 3

    def test_test_bit_set(self):
        """Test test_bit when bit is set."""
        a = BigInt.from_int(4)
        assert a.test_bit(2) is True

    def test_test_bit_clear(self):
        """Test test_bit when bit is clear."""
        a = BigInt.from_int(4)
        assert a.test_bit(0) is False

    def test_set_bit(self):
        """Test set_bit operation."""
        a = BigInt.from_int(0)
        a.set_bit(2)
        assert int(a) == 4
        assert a.test_bit(2) is True

    def test_clear_bit(self):
        """Test clear_bit operation."""
        a = BigInt.from_int(5)
        a.clear_bit(2)
        assert int(a) == 1

    def test_flip_bit(self):
        """Test flip_bit operation."""
        a = BigInt.from_int(4)
        a.flip_bit(0)
        assert int(a) == 5


class TestBigIntComparison:
    """Tests for BigInt comparison operations."""

    def test_eq_same_value(self):
        """Test equality with same value."""
        a = BigInt.from_int(10)
        c = BigInt.from_int(10)
        assert a == c

    def test_eq_different_value(self):
        """Test equality with different value."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert not (a == b)

    def test_eq_with_int(self):
        """Test equality with int."""
        a = BigInt.from_int(10)
        assert a == 10

    def test_eq_with_string(self):
        """Test equality with string."""
        a = BigInt.from_int(10)
        assert a == "10"

    def test_ne(self):
        """Test not equal."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert a != b

    def test_lt(self):
        """Test less than."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert a < b

    def test_lt_with_int(self):
        """Test less than with int."""
        a = BigInt.from_int(10)
        assert a < 20

    def test_lt_with_string(self):
        """Test less than with string."""
        a = BigInt.from_int(10)
        assert a < "20"

    def test_le(self):
        """Test less than or equal."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert a <= b
        assert a <= BigInt.from_int(10)

    def test_gt(self):
        """Test greater than."""
        a = BigInt.from_int(20)
        b = BigInt.from_int(10)
        assert a > b

    def test_gt_with_string(self):
        """Test greater than with string."""
        a = BigInt.from_int(20)
        assert a > "10"

    def test_ge(self):
        """Test greater than or equal."""
        a = BigInt.from_int(20)
        b = BigInt.from_int(10)
        assert a >= b
        assert a >= BigInt.from_int(20)

    def test_compare_equal(self):
        """Test compare method with equal values."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(10)
        assert a.compare(b) == 0

    def test_compare_less(self):
        """Test compare method with less than."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        assert a.compare(b) < 0

    def test_compare_greater(self):
        """Test compare method with greater than."""
        a = BigInt.from_int(20)
        b = BigInt.from_int(10)
        assert a.compare(b) > 0


class TestBigIntInPlace:
    """Tests for BigInt in-place operations."""

    def test_assign(self):
        """Test assign method (from C test)."""
        a = BigInt.from_int(100)
        b = BigInt.from_int(200)
        a.assign(b)
        assert int(a) == 200

    def test_assign_with_int(self):
        """Test assign with int."""
        a = BigInt.from_int(100)
        a.assign(200)
        assert int(a) == 200

    def test_assign_with_string(self):
        """Test assign with string."""
        a = BigInt.from_int(100)
        a.assign("200")
        assert int(a) == 200

    def test_increment(self):
        """Test increment method."""
        a = BigInt.from_int(99)
        a.increment()
        assert int(a) == 100

    def test_decrement(self):
        """Test decrement method."""
        a = BigInt.from_int(100)
        a.decrement()
        assert int(a) == 99


class TestBigIntStaticMethods:
    """Tests for BigInt static methods."""

    def test_min_lhs_smaller(self):
        """Test min when left is smaller."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        result = BigInt.min(a, b)
        assert int(result) == 10

    def test_min_rhs_smaller(self):
        """Test min when right is smaller."""
        a = BigInt.from_int(20)
        b = BigInt.from_int(10)
        result = BigInt.min(a, b)
        assert int(result) == 10

    def test_min_with_int(self):
        """Test min with int values."""
        result = BigInt.min(20, 10)
        assert int(result) == 10

    def test_max_lhs_larger(self):
        """Test max when left is larger."""
        a = BigInt.from_int(20)
        b = BigInt.from_int(10)
        result = BigInt.max(a, b)
        assert int(result) == 20

    def test_max_rhs_larger(self):
        """Test max when right is larger."""
        a = BigInt.from_int(10)
        b = BigInt.from_int(20)
        result = BigInt.max(a, b)
        assert int(result) == 20

    def test_max_with_int(self):
        """Test max with int values."""
        result = BigInt.max(10, 20)
        assert int(result) == 20


class TestBigIntClone:
    """Tests for BigInt clone operation."""

    def test_clone(self):
        """Test clone creates independent copy (from C test)."""
        bi1 = BigInt.from_string("123456789")
        bi2 = bi1.clone()
        assert str(bi2) == "123456789"
        assert bi1 == bi2

    def test_clone_independence(self):
        """Test that clone creates deep copy."""
        bi1 = BigInt.from_int(100)
        bi2 = bi1.clone()
        bi2 = bi2 + 1
        assert bi1 != bi2
        assert int(bi1) == 100
        assert int(bi2) == 101


class TestBigIntProtocols:
    """Tests for BigInt protocol methods."""

    def test_index_hex(self):
        """Test __index__ with hex()."""
        val = 255
        bi = BigInt.from_int(val)
        assert hex(bi) == "0xff"

    def test_index_bin(self):
        """Test __index__ with bin()."""
        val = 255
        bi = BigInt.from_int(val)
        assert bin(bi) == "0b11111111"

    def test_index_list(self):
        """Test __index__ as list index."""
        lst = [10, 20, 30]
        idx = BigInt.from_int(1)
        assert lst[idx] == 20

    def test_context_manager(self):
        """Test context manager protocol."""
        with BigInt.from_int(100) as bi:
            assert int(bi) == 100


class TestBigIntEdgeCases:
    """Tests for BigInt edge cases and error handling."""

    def test_ensure_bigint_with_bigint(self):
        """Test _ensure_bigint with BigInt input."""
        from cometa.common.bigint import _ensure_bigint
        bi = BigInt.from_int(10)
        result = _ensure_bigint(bi)
        assert result == bi

    def test_ensure_bigint_with_int(self):
        """Test _ensure_bigint with int input."""
        from cometa.common.bigint import _ensure_bigint
        result = _ensure_bigint(10)
        assert int(result) == 10

    def test_ensure_bigint_with_string(self):
        """Test _ensure_bigint with string input."""
        from cometa.common.bigint import _ensure_bigint
        result = _ensure_bigint("10")
        assert int(result) == 10

    def test_ensure_bigint_with_invalid_type(self):
        """Test _ensure_bigint with invalid type."""
        from cometa.common.bigint import _ensure_bigint
        with pytest.raises(TypeError, match="Unsupported type"):
            _ensure_bigint([1, 2, 3])

    def test_eq_with_invalid_type(self):
        """Test equality with invalid type returns False."""
        bi = BigInt.from_int(10)
        assert not (bi == [1, 2, 3])

    def test_new_res(self):
        """Test _new_res creates zero BigInt."""
        from cometa.common.bigint import _new_res
        result = _new_res()
        assert int(result) == 0
        assert result.is_zero


class TestBigIntLargeNumbers:
    """Tests for BigInt with very large numbers."""

    def test_large_multiplication(self):
        """Test multiplication with large numbers."""
        a = BigInt.from_string("99999999999999999999999999999999")
        b = BigInt.from_int(2)
        result = a * b
        assert str(result) == "199999999999999999999999999999998"

    def test_large_addition(self):
        """Test addition with large numbers."""
        a = BigInt.from_string("99999999999999999999999999999999")
        b = BigInt.from_int(1)
        result = a + b
        assert str(result) == "100000000000000000000000000000000"

    def test_large_power(self):
        """Test power with moderately large result."""
        a = BigInt.from_int(10)
        result = a ** 30
        assert int(result) == 10**30


class TestBigIntNegativeNumbers:
    """Tests for BigInt with negative numbers."""

    def test_negative_addition(self):
        """Test addition with negative numbers."""
        a = BigInt.from_int(-10)
        b = BigInt.from_int(-20)
        assert int(a + b) == -30

    def test_negative_subtraction(self):
        """Test subtraction with negative numbers."""
        a = BigInt.from_int(-10)
        b = BigInt.from_int(-20)
        assert int(a - b) == 10

    def test_negative_multiplication(self):
        """Test multiplication with negative numbers."""
        a = BigInt.from_int(-10)
        b = BigInt.from_int(20)
        assert int(a * b) == -200

    def test_negative_division(self):
        """Test division with negative numbers."""
        a = BigInt.from_int(-100)
        b = BigInt.from_int(3)
        assert int(a / b) == -33


class TestBigIntSpecialBases:
    """Tests for BigInt with different numeric bases."""

    def test_from_string_base_2(self):
        """Test from_string with binary base."""
        bi = BigInt.from_string("1010", base=2)
        assert int(bi) == 10

    def test_from_string_base_8(self):
        """Test from_string with octal base."""
        bi = BigInt.from_string("12", base=8)
        assert int(bi) == 10

    def test_from_string_base_16(self):
        """Test from_string with hexadecimal base."""
        bi = BigInt.from_string("A", base=16)
        assert int(bi) == 10

    def test_to_string_base_2(self):
        """Test to_string with binary base."""
        bi = BigInt.from_int(10)
        assert bi.to_string(2) == "1010"

    def test_to_string_base_8(self):
        """Test to_string with octal base."""
        bi = BigInt.from_int(10)
        assert bi.to_string(8) == "12"

    def test_to_string_base_16(self):
        """Test to_string with hexadecimal base."""
        bi = BigInt.from_int(10)
        assert bi.to_string(16) == "a"
