"""
Cardano BIP-039 Example

This example demonstrates how to create a software secure key handler
from a mnemonic phrase and derive a Cardano address.

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

from cometa import (
    mnemonic_to_entropy,
    SoftwareBip32SecureKeyHandler,
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    AccountDerivationPath,
    BaseAddress,
    NetworkId,
    Credential
)

# Constants
MNEMONICS = (
    "antenna whale clutch cushion narrow chronic matrix alarm raise much "
    "stove beach mimic daughter review build dinner twelve orbit soap "
    "decorate bachelor athlete close"
)

def get_password() -> bytes:
    """Callback that returns the passphrase for decryption."""
    return input("Enter password: ").encode("utf-8")

def main() -> None:
    """Example of creating a software secure key handler from a mnemonic phrase."""
    print("=" * 60)
    print("Cardano BIP-039 Example")
    print("=" * 60)
    print(
        "This example demonstrates how to create a software secure "
        "key handler from a mnemonic phrase."
    )
    print()

    print("Converting mnemonic words to entropy...")
    entropy = mnemonic_to_entropy(MNEMONICS.split())

    print("Create secure key handler")
    password = get_password()
    secure_key_handler = SoftwareBip32SecureKeyHandler.from_entropy(
        entropy, password, get_password
    )

    print("Get account public key")
    extended_public_key = secure_key_handler.get_account_public_key(
        AccountDerivationPath(
            purpose=harden(KeyDerivationPurpose.STANDARD),
            coin_type=harden(CoinType.CARDANO),
            account=harden(0)
        )
    )

    print("Deriving address at: m / 1852' / 1815' / 0' / 0 / 0 ...")

    payment_key = extended_public_key.derive([KeyDerivationRole.EXTERNAL, 0])
    staking_key = extended_public_key.derive([KeyDerivationRole.STAKING, 0])

    payment_credential = Credential.from_key_hash(
        payment_key.to_ed25519_key().to_hash(),
    )
    staking_credential = Credential.from_key_hash(
        staking_key.to_ed25519_key().to_hash()
    )

    base_address = BaseAddress.from_credentials(
        NetworkId.TESTNET,
        payment_credential,
        staking_credential
    )

    print(f"Base address: {base_address.to_bech32()}")


if __name__ == "__main__":
    main()
