from enum import IntEnum

class CborSimpleValue(IntEnum):
    """
    Represents a CBOR simple value (major type 7).

    These simple values are part of the CBOR data format as defined in RFC 7049, section 2.3,
    representing commonly used simple data items. This enumeration includes the simple values
    for 'false', 'true', 'null', and 'undefined', each of which has a specific role in the CBOR encoding
    and interpretation process.
    """

    # Represents the value 'false'.
    # This value is used to represent the boolean false in CBOR-encoded data.
    FALSE = 20

    # Represents the value 'true'.
    # This value is used to represent the boolean true in CBOR-encoded data.
    TRUE = 21

    # Represents the value 'null'.
    # This value signifies a null reference or the absence of data in CBOR-encoded data.
    NULL = 22

    # Represents an undefined value.
    # This value is used by an encoder as a substitute for a data item with an encoding problem,
    # indicating the absence of meaningful or correct data.
    UNDEFINED = 23