"""
DRep Public Key Example

This example demonstrates how to register a DRep (Delegated Representative),
delegate voting power, and deregister both the DRep and stake key.

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

from cometa import (
    BlockfrostProvider,
    NetworkMagic,
    Anchor,
    Blake2bHash,
    Credential,
    DRep,
    DRepType,
    Ed25519PublicKey,
)
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

# Constants
ANCHOR = Anchor.new(
    url="https://storage.googleapis.com/biglup/Angel_Castillo.jsonld",
    hash_value=Blake2bHash.from_hex(
        "26ce09df4e6f64fe5cf248968ab78f4b8a0092580c234d78f68c079c0fce34f0"
    )
)

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


def register_drep(wallet, provider, drep: DRep) -> None:
    """Registers a DRep using Cometa."""
    print("Registering DRep...")
    builder = wallet.create_transaction_builder()

    transaction = builder \
        .register_drep(drep=drep, anchor=ANCHOR) \
        .build()

    print("Register DRep transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def deregister_drep(wallet, provider, drep: DRep) -> None:
    """Deregisters a DRep using Cometa."""
    print("Deregistering DRep...")
    builder = wallet.create_transaction_builder()

    transaction = builder \
        .deregister_drep(drep=drep) \
        .build()

    print("Deregistering DRep transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def register_and_delegate_stake_key(wallet, provider, drep: DRep) -> None:
    """Registers a stake key and delegates voting power to a DRep."""
    print("Registering and delegating voting power to DRep...")
    builder = wallet.create_transaction_builder()

    reward_addresses = wallet.get_reward_addresses()
    reward_address = reward_addresses[0]

    transaction = builder \
        .register_reward_address(reward_address=reward_address) \
        .delegate_voting_power(drep=drep, reward_address=reward_address) \
        .build()

    print("Register and delegating transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def deregister_and_withdraw_rewards(wallet, provider) -> None:
    """Deregisters the stake key and withdraws rewards."""
    print("Deregister stake key and withdrawing rewards...")
    builder = wallet.create_transaction_builder()

    reward_addresses = wallet.get_reward_addresses()
    reward_address = reward_addresses[0]
    amount = provider.get_rewards_balance(reward_address)

    transaction = builder \
        .withdraw_rewards(amount=amount, reward_address=reward_address) \
        .deregister_reward_address(reward_address=reward_address) \
        .build()

    print("Deregister and withdraw rewards transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def main() -> None:
    """
    Example of registering a DRep, delegating voting power, and
    deregistering both the DRep and stake key.
    """
    print("=" * 60)
    print("Registers DRep and Delegate Voting Power (Pubkey Hash)")
    print("=" * 60)
    print(
        "This example registers ourselves as DReps, delegate our voting power "
        "to our DRep credential, and finally unregisters both the DRep and stake key."
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

    cred_hash = Ed25519PublicKey.from_hex(wallet.get_pub_drep_key()).to_hash()
    drep = DRep.new(drep_type=DRepType.KEY_HASH, credential=Credential.from_key_hash(cred_hash))
    print(drep.to_cip129_string())

    register_drep(wallet, provider, drep)
    register_and_delegate_stake_key(wallet, provider, drep)
    deregister_and_withdraw_rewards(wallet, provider)
    deregister_drep(wallet, provider, drep)

if __name__ == "__main__":
    main()
