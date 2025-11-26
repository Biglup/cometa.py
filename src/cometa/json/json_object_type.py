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

class JsonObjectType(IntEnum):
    """
    Enumerates the possible types of a JSON object.

    This enumeration defines the various types a JSON object can represent.
    """

    OBJECT = 0
    """
    Represents a JSON object (key-value pairs).
    """

    ARRAY = 1
    """
    Represents a JSON array (ordered list).
    """

    STRING = 2
    """
    Represents a JSON string.
    """

    NUMBER = 3
    """
    Represents a JSON number (integer or floating-point).
    """

    BOOLEAN = 4
    """
    Represents a JSON boolean (`true` or `false`).
    """

    NULL = 5
    """
    Represents a JSON null value.
    """
