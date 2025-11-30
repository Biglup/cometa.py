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


class MetadatumKind(IntEnum):
    """
    Represents the type of transaction metadatum.

    Transaction metadata in Cardano can be one of five types:
    maps, lists, integers, byte strings, or text strings.
    """

    MAP = 0
    """A map with metadatum keys and values."""

    LIST = 1
    """A list of metadatum values."""

    INTEGER = 2
    """An arbitrary-precision integer."""

    BYTES = 3
    """A bounded byte string (max 64 bytes)."""

    TEXT = 4
    """A text string (max 64 bytes when UTF-8 encoded)."""
