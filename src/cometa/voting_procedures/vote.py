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


class Vote(IntEnum):
    """
    Represents possible voting choices in a Cardano voting procedure.

    In the Cardano governance system, participants can cast votes on proposals
    using one of three options: No, Yes, or Abstain.
    """

    NO = 0
    """Represents a 'No' vote - the voter is against the proposal."""

    YES = 1
    """Represents a 'Yes' vote - the voter supports the proposal."""

    ABSTAIN = 2
    """Represents an 'Abstain' vote - the voter neither supports nor opposes."""
