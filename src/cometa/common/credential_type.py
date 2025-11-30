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


class CredentialType(IntEnum):
    """
    Types of credentials used in Cardano addresses.

    A credential identifies the owner of funds or staking rights, either
    through a public key hash or a script hash.
    """

    KEY_HASH = 0
    """Credential is a hash of a public key."""

    SCRIPT_HASH = 1
    """Credential is a hash of a script."""
