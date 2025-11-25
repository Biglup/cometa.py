from enum import IntEnum


class CborMajorType(IntEnum):
    """
    Represents CBOR Major Types as defined in RFC 7049 section 2.1.

    These major types are used to identify the type of data in a CBOR data item.
    """

    # An unsigned integer.
    # Range: 0 to 2^64-1 inclusive. The value of the encoded item is the argument itself.
    UNSIGNED_INTEGER = 0

    # A negative integer.
    # Range: -2^64 to -1 inclusive. The value of the item is -1 minus the argument.
    NEGATIVE_INTEGER = 1

    # A byte string.
    # The number of bytes in the string is equal to the argument.
    BYTE_STRING = 2

    # A text string encoded as UTF-8.
    # Refer to Section 2 and RFC 3629. The number of bytes in the string is equal to the argument.
    UTF8_STRING = 3

    # An array of data items.
    # The argument specifies the number of data items in the array.
    ARRAY = 4

    # A map of pairs of data items.
    MAP = 5

    # A tagged data item ("tag").
    # Tag number ranges from 0 to 2^64-1 inclusive. The enclosed data item (tag content) follows the head.
    TAG = 6

    # Simple values, floating-point numbers, and the "break" stop code.
    SIMPLE = 7

    # Undefined major type.
    UNDEFINED = 0xFFFFFFFF