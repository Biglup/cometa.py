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


class ScriptLanguage(IntEnum):
    """
    Enumerates the types of scripting languages supported by Cardano.

    Cardano supports different scripting languages for defining spending conditions
    and smart contracts. This enumeration categorizes the available script types
    into native scripts and Plutus scripts (V1, V2, V3).
    """

    NATIVE = 0
    """
    Native scripts use a simple expression language to define spending conditions.

    They support basic operations like requiring specific signatures, time-locks,
    and boolean combinations (all, any, n-of-k). Native scripts are evaluated
    directly by the ledger without requiring a smart contract runtime.
    """

    PLUTUS_V1 = 1
    """
    Plutus V1 scripts introduced in the Alonzo hard fork.

    Plutus V1 was the initial version of Plutus smart contracts, enabling
    complex spending logic through Haskell-based smart contracts compiled
    to Untyped Plutus Core (UPLC).
    """

    PLUTUS_V2 = 2
    """
    Plutus V2 scripts introduced in the Vasil hard fork.

    V2 extended the ScriptContext to include:
    - Full redeemers structure
    - Reference inputs (CIP-31)
    - Inline datums (CIP-32)
    - Reference scripts (CIP-33)
    """

    PLUTUS_V3 = 3
    """
    Plutus V3 scripts introduced in the Conway hard fork.

    V3 extended the ScriptContext to include governance features:
    - Map with all votes in the transaction
    - List of governance proposals
    - Optional treasury amount checking
    - Optional treasury donations
    """
