"""
Reward Account Pubkey Example

This example demonstrates how to register a stake key, delegate it to a pool,
and then deregister it.

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

import os

from cometa import BlockfrostProvider, NetworkMagic
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

POOL_ID = "pool1pzdqdxrv0k74p4q33y98f2u7vzaz95et7mjeedjcfy0jcgk754f"  # SMAUG Pool
MNEMONICS = (
    "antenna whale clutch cushion narrow chronic matrix alarm raise much "
    "stove beach mimic daughter review build dinner twelve orbit soap "
    "decorate bachelor athlete close"
)


def get_blockfrost_project_id() -> str:
    """Reads the Blockfrost project ID from environment variable."""
    project_id = os.environ.get("BLOCKFROST_PROJECT_ID", "")
    if not project_id:
        raise ValueError(
            "BLOCKFROST_PROJECT_ID environment variable is not set. "
            "Please set it to your Blockfrost project ID."
        )
    return project_id


def get_password() -> bytes:
    """Callback that returns the passphrase for decryption."""
    return input("Enter password: ").encode("utf-8")


def sign_and_submit(wallet, provider, transaction) -> None:
    """Signs and submits a transaction using Cometa."""
    print("Signing transaction...")
    witness_set = wallet.sign_transaction(transaction)
    transaction.apply_vkey_witnesses(witness_set)

    print("Signed transaction:")
    print(transaction.serialize_to_json())

    print("Submitting transaction...")
    tx_id = wallet.submit_transaction(transaction.serialize_to_cbor())
    print(f"Transaction submitted successfully with ID: {tx_id}")

    print("Confirming transaction...")
    confirmed = provider.confirm_transaction(tx_id, 90000)
    if confirmed:
        print("Transaction confirmed successfully.")
    else:
        print("[FAIL] Transaction confirmation failed.")


def register_and_delegate_stake_key(wallet, provider, pool_id: str) -> None:
    """Registers a stake key and delegates to a pool."""
    print("Registering and delegating stake to pool...")
    builder = wallet.create_transaction_builder()

    reward_addresses = wallet.get_reward_addresses()
    reward_address = reward_addresses[0]

    transaction = builder \
        .register_reward_address(reward_address=reward_address) \
        .delegate_stake(reward_address=reward_address, pool_id=pool_id) \
        .build()

    print("Register and delegating transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def deregister_and_withdraw_rewards(wallet, provider) -> None:
    """Deregisters the stake key and withdraws rewards."""
    print("Deregister stake key and withdrawing rewards...")
    builder = wallet.create_transaction_builder()

    reward_addresses = wallet.get_reward_addresses()
    reward_address = reward_addresses[0]

    transaction = builder \
        .deregister_reward_address(reward_address=reward_address) \
        .build()

    print("Deregister and withdraw rewards transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def main() -> None:
    """
    Example of registering a stake key, delegating it to a pool,
    and withdrawing rewards.
    """
    print("=" * 60)
    print("Delegate and Withdraw Example (Pubkey Hash)")
    print("=" * 60)
    print(
        "This example registers and delegates a stake key to a pool, "
        "and finally withdraws and deregisters it."
    )
    print()

    provider = BlockfrostProvider(
        network=NetworkMagic.PREPROD,
        project_id=get_blockfrost_project_id()
    )

    print("Creating wallet from mnemonics...")
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

    register_and_delegate_stake_key(wallet, provider, POOL_ID)
    deregister_and_withdraw_rewards(wallet, provider)


if __name__ == "__main__":
    main()
