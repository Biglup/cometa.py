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


class PlutusDataKind(IntEnum):
    """
    The Plutus data type kind.

    Plutus data can be one of five types: constructor, map, list, integer, or bytes.
    """

    CONSTR = 0
    """Represents a specific constructor of a 'Sum Type' along with its arguments."""

    MAP = 1
    """A map of PlutusData as both key and values."""

    LIST = 2
    """A list of PlutusData."""

    INTEGER = 3
    """An integer (BigInt)."""

    BYTES = 4
    """Bounded bytes."""
