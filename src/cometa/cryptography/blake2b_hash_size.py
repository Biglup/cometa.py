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


class Blake2bHashSize(IntEnum):
    """
    Represents the types of BLAKE2b hash functions distinguished by their output size.

    These hash types are utilized in various contexts throughout Cardano, including
    verification keys, multi-signature scripts, and key derivation processes.
    """

    HASH_224 = 28
    """
    BLAKE2b-224 (28 bytes / 224 bits).
    Used for hashing verification keys and multi-signature scripts.
    """

    HASH_256 = 32
    """
    BLAKE2b-256 (32 bytes / 256 bits).
    Standard hash variant used for transaction IDs, address hashing, and more.
    """

    HASH_512 = 64
    """
    BLAKE2b-512 (64 bytes / 512 bits).
    Used for key derivation functions.
    """
