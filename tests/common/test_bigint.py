import pytest
from cometa import BigInt
from cometa import ByteOrder
from cometa import CardanoError

# ------------------------------------------------------------------------------
# Factories & Initialization
# ------------------------------------------------------------------------------

def test_bigint_from_int():
    # Small positive (fits in int64)
    val = 42
    bi = BigInt.from_int(val)
    assert int(bi) == val
    assert not bi.is_zero
    assert bi.sign == 1

    # Small negative (fits in int64)
    val = -42
    bi = BigInt.from_int(val)
    assert int(bi) == val
    assert bi.sign == -1

    # Large unsigned (fits in uint64 but not int64)
    val = 2 ** 63 + 10
    bi = BigInt.from_int(val)
    assert int(bi) == val

    # Massive integer (requires string fallback)
    val = 2 ** 128 + 123456789
    bi = BigInt.from_int(val)
    assert int(bi) == val

    # Zero
    bi = BigInt.from_int(0)
    assert int(bi) == 0
    assert bi.is_zero
    assert bi.sign == 0


def test_bigint_from_string():
    # Decimal
    s = "12345678901234567890"
    bi = BigInt.from_string(s, base=10)
    assert str(bi) == s

    # Hexadecimal
    s_hex = "deadbeef"
    bi = BigInt.from_string(s_hex, base=16)
    assert int(bi) == 0xdeadbeef

    # Invalid
    with pytest.raises(CardanoError):
        BigInt.from_string("zzzz", base=10)


def test_bigint_from_bytes():
    # Big Endian
    data = b"\x01\x02"  # 256 + 2 = 258
    bi = BigInt.from_bytes(data, ByteOrder.BIG_ENDIAN)
    assert int(bi) == 258

    # Little Endian
    bi = BigInt.from_bytes(data, ByteOrder.LITTLE_ENDIAN)
    assert int(bi) == 0x0201  # 513


def test_bigint_clone():
    bi1 = BigInt.from_int(100)
    bi2 = bi1.clone()
    assert bi1 == bi2
    # Ensure deep copy behavior (modify bi2, check bi1)
    bi2 = bi2 + 1
    assert bi1 != bi2


# ------------------------------------------------------------------------------
# Arithmetic Operations
# ------------------------------------------------------------------------------

def test_arithmetic_add():
    a = BigInt.from_int(10)
    b = BigInt.from_int(20)
    assert int(a + b) == 30
    assert int(a + 5) == 15
    assert int(a + "5") == 15


def test_arithmetic_sub():
    a = BigInt.from_int(30)
    b = BigInt.from_int(10)
    assert int(a - b) == 20
    assert int(a - 5) == 25


def test_arithmetic_mul():
    a = BigInt.from_int(10)
    b = BigInt.from_int(20)
    assert int(a * b) == 200


def test_arithmetic_div():
    a = BigInt.from_int(100)
    b = BigInt.from_int(3)
    # Integer division
    assert int(a / b) == 33
    assert int(a // b) == 33


def test_arithmetic_mod():
    a = BigInt.from_int(100)
    b = BigInt.from_int(30)
    assert int(a % b) == 10


def test_arithmetic_divmod():
    a = BigInt.from_int(100)
    b = BigInt.from_int(30)
    q, r = divmod(a, b)
    assert int(q) == 3
    assert int(r) == 10


def test_arithmetic_pow():
    a = BigInt.from_int(2)
    assert int(a ** 10) == 1024
    assert int(a.pow(10)) == 1024

    with pytest.raises(ValueError):
        a.pow(-1)


def test_arithmetic_mod_pow():
    base = BigInt.from_int(2)
    exp = BigInt.from_int(10)
    mod = BigInt.from_int(1000)

    # 2^10 = 1024, 1024 % 1000 = 24
    assert int(pow(base, 10, mod)) == 24
    assert int(base.mod_pow(exp, mod)) == 24


def test_arithmetic_unary():
    a = BigInt.from_int(10)
    assert int(-a) == -10
    assert int(abs(BigInt.from_int(-50))) == 50


def test_gcd():
    a = BigInt.from_int(48)
    b = BigInt.from_int(18)
    assert int(a.gcd(b)) == 6


# ------------------------------------------------------------------------------
# Bitwise Operations
# ------------------------------------------------------------------------------

def test_bitwise_ops():
    # 12 = 1100, 10 = 1010
    a = BigInt.from_int(12)
    b = BigInt.from_int(10)

    assert int(a & b) == 8  # 1000
    assert int(a | b) == 14  # 1110
    assert int(a ^ b) == 6  # 0110
    assert int(a << 2) == 48
    assert int(a >> 2) == 3
    assert int(~BigInt.from_int(0)) == -1


def test_bit_manipulation():
    # In-place modifications
    a = BigInt.from_int(0)

    a.set_bit(2)  # 4 (100)
    assert int(a) == 4
    assert a.test_bit(2) is True
    assert a.test_bit(0) is False

    a.flip_bit(0)  # 5 (101)
    assert int(a) == 5

    a.clear_bit(2)  # 1 (001)
    assert int(a) == 1

    assert a.bit_length == 1
    assert a.bit_count == 1


# ------------------------------------------------------------------------------
# Protocols & formatting
# ------------------------------------------------------------------------------

def test_protocols():
    val = 255
    bi = BigInt.from_int(val)

    # __int__
    assert int(bi) == val

    # __index__ (hex, bin, list index)
    assert hex(bi) == "0xff"
    assert bin(bi) == "0b11111111"
    lst = [10, 20]
    idx = BigInt.from_int(1)
    assert lst[idx] == 20

    # __str__
    assert str(bi) == "255"

    # __format__
    assert f"{bi:04x}" == "00ff"


def test_comparisons():
    a = BigInt.from_int(10)
    b = BigInt.from_int(20)
    c = BigInt.from_int(10)

    assert a < b
    assert a <= b
    assert b > a
    assert b >= a
    assert a == c
    assert a != b

    # Cross-type
    assert a == 10
    assert a < 20
    assert a > "5"


def test_to_bytes():
    val = 0x010203
    bi = BigInt.from_int(val)

    b_be = bi.to_bytes(ByteOrder.BIG_ENDIAN)
    # BigInt usually returns minimum bytes needed
    assert b_be.endswith(b"\x01\x02\x03")

    b_le = bi.to_bytes(ByteOrder.LITTLE_ENDIAN)
    assert b_le.startswith(b"\x03\x02\x01")