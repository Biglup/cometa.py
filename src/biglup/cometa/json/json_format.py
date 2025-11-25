from enum import IntEnum

class JsonFormat(IntEnum):
    """
    Enum representing the format of the JSON output.

    This enum defines the possible formats for the JSON output, indicating
    whether it should be compact (no extra spaces or line breaks) or pretty
    (extra spaces and line breaks for readability).
    """

    # Compact JSON format (no extra spaces or line breaks).
    COMPACT = 0

    # Pretty JSON format (extra spaces and line breaks for readability).
    PRETTY = 1