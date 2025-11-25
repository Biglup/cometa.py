from enum import IntEnum

class ByteOrder(IntEnum):
    """
    Enumerates the possible byte order types for endianness interpretation.

    This enumeration is used to specify the byte order of data being processed,
    particularly when bytes need to be interpreted as numeric values.
    """

    # Little-endian byte order.
    # The least significant byte (LSB) is placed at the smallest address.
    LITTLE_ENDIAN = 0

    # Big-endian byte order.
    # The most significant byte (MSB) is placed at the smallest address.
    # (Commonly known as network byte order).
    BIG_ENDIAN = 1