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


class PlutusLanguageVersion(IntEnum):
    """
    Plutus script language version.

    The Cardano ledger tags scripts with a language that determines what the ledger
    will do with the script. These versions correspond to different Plutus language
    versions introduced in different hard forks.
    """

    V1 = 0
    """V1 was the initial version of Plutus, introduced in the Alonzo hard fork."""

    V2 = 1
    """V2 was introduced in the Vasil hard fork with extended ScriptContext."""

    V3 = 2
    """V3 was introduced in the Conway hard fork with governance features."""
