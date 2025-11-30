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


class GovernanceKeyType(IntEnum):
    """
    Enumerates the types of governance keys used in Cardano's CIP-1852 governance system.

    These key types are used to identify the role of credentials in governance
    actions, particularly for constitutional committee operations and DRep activities.
    """

    CC_HOT = 0
    """Constitutional committee hot verification signing key."""

    CC_COLD = 1
    """Constitutional committee cold verification key hash (cold credential)."""

    DREP = 2
    """Delegated Representative (DRep) verification key hash."""
