"""
Spend from Native Script Example

This example demonstrates how to fund a native script address and then
spend from it.

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
    EnterpriseAddress,
    NetworkId,
    Credential,
    ScriptAll,
    ScriptInvalidAfter,
)
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

LOVELACE_TO_SEND = 2_000_000  # 2 ADA
RECEIVING_ADDRESS = (
    "addr_test1qpjhcqawjma79scw4d9fjudwcu0sww9kv9x8f30fer3rmpu2qn0kv3udaf5"
    "pmf94ts27ul2w7q3sepupwccez2u2lu5s7aa8rv"
)
HOUR_IN_SECONDS = 3600
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


def main() -> None:
    """Spend from Native Script Example."""
    print("=" * 60)
    print("Spend from Native Script Example")
    print("=" * 60)
    print("This example will spend balance from a native script.")
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

    always_succeeds_native_script = ScriptAll.new([
        ScriptInvalidAfter.new(1001655683199)  # Invalid after year 33658
    ])

    script_hash = always_succeeds_native_script.hash
    script_credential = Credential.from_script_hash(script_hash)
    script_address = EnterpriseAddress.from_credentials(
        NetworkId.TESTNET,
        script_credential
    ).to_address()

    builder = wallet.create_transaction_builder()
    fund_script_tx = builder \
        .send_lovelace(address=script_address, amount=12_000_000) \
        .expires_in(HOUR_IN_SECONDS) \
        .build()

    print("Transaction built successfully.")
    sign_and_submit(wallet, provider, fund_script_tx)

    print(f"Script funded at: {script_address}")
    print("Spending from native script...")

    script_utxos = provider.get_unspent_outputs(str(script_address))
    builder = wallet.create_transaction_builder()

    spend_from_script_tx = builder \
        .add_input(utxo=script_utxos[0]) \
        .send_lovelace(address=RECEIVING_ADDRESS, amount=LOVELACE_TO_SEND) \
        .add_script(always_succeeds_native_script) \
        .expires_in(HOUR_IN_SECONDS * 2) \
        .build()

    print("Transaction built successfully.")
    sign_and_submit(wallet, provider, spend_from_script_tx)

    print(
        f"Transaction sent to: {RECEIVING_ADDRESS[:50]}... "
        f"from script address: {script_address}"
    )


if __name__ == "__main__":
    main()
