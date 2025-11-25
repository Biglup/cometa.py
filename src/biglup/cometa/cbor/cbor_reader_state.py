from enum import IntEnum

class CborReaderState(IntEnum):
    """
    Specifies the state of a CborReader instance.

    This enumeration outlines the possible states of a CborReader as it processes
    CBOR data items.
    """

    # Indicates the undefined state.
    # This state is used when the CborReader has not yet begun processing
    # or the state is otherwise unknown.
    UNDEFINED = 0

    # Indicates that the next CBOR data item is an unsigned integer (major type 0).
    UNSIGNED_INTEGER = 1

    # Indicates that the next CBOR data item is a negative integer (major type 1).
    NEGATIVE_INTEGER = 2

    # Indicates that the next CBOR data item is a byte string (major type 2).
    BYTESTRING = 3

    # Indicates the start of an indefinite-length byte string (major type 2).
    START_INDEFINITE_LENGTH_BYTESTRING = 4

    # Indicates the end of an indefinite-length byte string (major type 2).
    END_INDEFINITE_LENGTH_BYTESTRING = 5

    # Indicates that the next CBOR data item is a UTF-8 string (major type 3).
    TEXTSTRING = 6

    # Indicates the start of an indefinite-length UTF-8 text string (major type 3).
    START_INDEFINITE_LENGTH_TEXTSTRING = 7

    # Indicates the end of an indefinite-length UTF-8 text string (major type 3).
    END_INDEFINITE_LENGTH_TEXTSTRING = 8

    # Indicates the start of an array (major type 4).
    START_ARRAY = 9

    # Indicates the end of an array (major type 4).
    END_ARRAY = 10

    # Indicates the start of a map (major type 5).
    START_MAP = 11

    # Indicates the end of a map (major type 5).
    END_MAP = 12

    # Indicates that the next CBOR data item is a semantic reader_state (major type 6).
    TAG = 13

    # Indicates that the next CBOR data item is a simple value (major type 7).
    SIMPLE_VALUE = 14

    # Indicates an IEEE 754 Half-Precision float (major type 7).
    HALF_PRECISION_FLOAT = 15

    # Indicates an IEEE 754 Single-Precision float (major type 7).
    SINGLE_PRECISION_FLOAT = 16

    # Indicates an IEEE 754 Double-Precision float (major type 7).
    DOUBLE_PRECISION_FLOAT = 17

    # Indicates a null literal (major type 7).
    NULL = 18

    # Indicates a bool value (major type 7).
    BOOLEAN = 19

    # Indicates the completion of reading a full CBOR document.
    # This state is reached when the CborReader has successfully processed
    # an entire CBOR document and there are no more data items to read.
    FINISHED = 20