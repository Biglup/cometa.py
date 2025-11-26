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

from enum import IntEnum

class JsonFormat(IntEnum):
    """
    Enum representing the format of the JSON output.

    This enum defines the possible formats for the JSON output, indicating
    whether it should be compact (no extra spaces or line breaks) or pretty
    (extra spaces and line breaks for readability).
    """

    COMPACT = 0
    """
    Compact JSON format (no extra spaces or line breaks).
    """

    PRETTY = 1
    """
    Pretty JSON format (extra spaces and line breaks for readability).
    """
