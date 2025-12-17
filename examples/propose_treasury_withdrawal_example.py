"""
Propose Treasury Withdrawal Example

This example demonstrates how to propose a treasury withdrawal using the
governance action system in Conway era.

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
    TransactionInput, WithdrawalMap,
)
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

HOUR_IN_SECONDS = 3600
MNEMONICS = (
    "antenna whale clutch cushion narrow chronic matrix alarm raise much "
    "stove beach mimic daughter review build dinner twelve orbit soap "
    "decorate bachelor athlete close"
)

ANCHOR = Anchor.new(
    url="https://raw.githubusercontent.com/IntersectMBO/governance-actions/refs/heads/main/mainnet/2024-11-19-infohf/metadata.jsonld",
    hash_value=Blake2bHash.from_hex(
        "93106d082a93e94df5aff74f678438bae3a647dac63465fbfcde6a3058f41a1e"
    )
)

CONSTITUTION_SCRIPT_HASH = "fa24fb305126805cf2164c161d852a0e7330cf988f1fe558cf7d4a64"
WITHDRAWAL_AMOUNT = 1_000_000_000_000  # 1 million ADA


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


def main() -> None:
    """Proposes a treasury withdrawal transaction using Cometa."""
    print("=" * 60)
    print("Propose Treasury Withdrawal Example")
    print("=" * 60)
    print(
        f"This example will issue a withdrawal proposal to withdraw "
        f"{WITHDRAWAL_AMOUNT} lovelace from treasury."
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

    print("Building transaction...")
    builder = wallet.create_transaction_builder()

    reward_addresses = wallet.get_reward_addresses()
    reward_address = reward_addresses[0]

    reference_input = provider.resolve_unspent_outputs([
        TransactionInput.from_hex("9aabbac24d1e39cb3e677981c84998a4210bae8d56b0f60908eedb9f59efffc8",0)
    ])[0]

    withdrawals = WithdrawalMap.from_dict({
        reward_address.to_bech32(): WITHDRAWAL_AMOUNT
    })

    transaction = builder \
        .add_reference_input(reference_input) \
        .propose_treasury_withdrawals(
            reward_address=reward_address,
            anchor=ANCHOR,
            withdrawals=withdrawals,
            policy_hash=Blake2bHash.from_hex(CONSTITUTION_SCRIPT_HASH)
        ) \
        .expires_in(HOUR_IN_SECONDS * 2) \
        .build()

    print("Transaction built successfully.")

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


if __name__ == "__main__":
    main()
