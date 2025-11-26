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

class JsonContext(IntEnum):
    """
    Enum representing the current context of the JSON writer.

    This enum defines the possible states of the JSON writer, indicating
    whether it is at the root level, inside an object, or inside an array.
    """

    ROOT = 0
    """
    The writer is at the root level (no context set).
    """

    OBJECT = 1
    """
    The writer is inside an object context.
    """

    ARRAY = 2
    """
    The writer is inside an array context.
    """
