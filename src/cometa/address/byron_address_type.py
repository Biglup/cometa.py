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


class ByronAddressType(IntEnum):
    """
    Types of spending data associated with Byron-era addresses.

    Each type corresponds to a different method of controlling the spending of funds.
    """

    PUBKEY = 0
    """Address controlled by a public key."""

    SCRIPT = 1
    """Address controlled by a script."""

    REDEEM = 2
    """Redeem address used during the initial ADA distribution phase."""
