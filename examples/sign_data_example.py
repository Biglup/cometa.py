"""
Sign Data Example

This example demonstrates how to sign data using CIP-008 standard
with the SingleAddressWallet.

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

from cometa import NetworkMagic
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

# Constants
MNEMONICS = (
    "antenna whale clutch cushion narrow chronic matrix alarm raise much "
    "stove beach mimic daughter review build dinner twelve orbit soap "
    "decorate bachelor athlete close"
)


def utf8_to_hex(text: str) -> str:
    """Converts a UTF-8 string to its hex representation."""
    return text.encode("utf-8").hex()


def get_password() -> bytes:
    """Callback that returns the passphrase for decryption."""
    return bytes([0x00])


class MockProvider:
    """
    A mock provider for demonstration purposes.
    In a real scenario, you would use BlockfrostProvider or similar.
    """

    def get_network_magic(self):
        """Returns the network magic for preprod."""
        return NetworkMagic.PREPROD

    def get_unspent_outputs(self, address: str):
        """Returns empty UTxO list (mock)."""
        return []

    def get_parameters(self):
        """Returns None (mock)."""
        return None

    def submit_transaction(self, tx_cbor: str) -> str:
        """Mock transaction submission."""
        raise NotImplementedError("Mock provider cannot submit transactions")

    def confirm_transaction(self, tx_hash: str, timeout_ms: int) -> bool:
        """Mock transaction confirmation."""
        return False

    def get_rewards_balance(self, reward_address) -> int:
        """Returns 0 (mock)."""
        return 0


def main() -> None:
    """Sign data with CIP-008 using Cometa."""
    print("=" * 60)
    print("Sign Data Example")
    print("=" * 60)
    print("This example will sign some data with CIP-008 standard.")
    print()

    provider = MockProvider()

    print("[INFO] Creating wallet from mnemonics...")
    wallet = SingleAddressWallet.create_from_mnemonics(
        mnemonics=MNEMONICS.split(),
        provider=provider,
        credentials_config=SingleAddressCredentialsConfig(
            account=0,
            payment_index=0,
            staking_index=0
        ),
        get_password=get_password
    )

    reward_addresses = wallet.get_reward_addresses()
    address = reward_addresses[0]

    print(f"[INFO] Signing data with {address.to_bech32()}")

    message = "Hello, Cometa!"
    result = wallet.sign_data(address.to_address(), utf8_to_hex(message))

    print("[INFO] Data signed successfully!")
    print(f"[INFO] Cose Key: {result['key']}")
    print(f"[INFO] Cose Sign1: {result['signature']}")


if __name__ == "__main__":
    main()
