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

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class StakePointer:
    """
    Pointer to a stake key registration location on the blockchain.

    Used in pointer addresses to indirectly reference a stake key through its
    registration certificate location rather than embedding the key directly.
    """

    slot: int
    """The slot number of the stake key registration certificate."""
    tx_index: int
    """The transaction index within the slot."""
    cert_index: int
    """The certificate index within the transaction."""

    def __post_init__(self) -> None:
        """
        Validates that all fields are non-negative after initialization.

        Raises:
            ValueError: If any field (slot, tx_index, cert_index) is negative.
        """
        if self.slot < 0:
            raise ValueError("slot must be non-negative")
        if self.tx_index < 0:
            raise ValueError("tx_index must be non-negative")
        if self.cert_index < 0:
            raise ValueError("cert_index must be non-negative")
