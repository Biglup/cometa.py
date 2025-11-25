from enum import IntEnum

class JsonContext(IntEnum):
    """
    Enum representing the current context of the JSON writer.

    This enum defines the possible states of the JSON writer, indicating
    whether it is at the root level, inside an object, or inside an array.
    """

    # The writer is at the root level (no context set).
    ROOT = 0

    # The writer is inside an object context.
    OBJECT = 1

    # The writer is inside an array context.
    ARRAY = 2