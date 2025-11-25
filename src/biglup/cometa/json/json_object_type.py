from enum import IntEnum

class JsonObjectType(IntEnum):
    """
    Enumerates the possible types of a JSON object.

    This enumeration defines the various types a JSON object can represent.
    """

    # Represents a JSON object (key-value pairs).
    OBJECT = 0

    # Represents a JSON array (ordered list).
    ARRAY = 1

    # Represents a JSON string.
    STRING = 2

    # Represents a JSON number (integer or floating-point).
    NUMBER = 3

    # Represents a JSON boolean (`true` or `false`).
    BOOLEAN = 4

    # Represents a JSON null value.
    NULL = 5