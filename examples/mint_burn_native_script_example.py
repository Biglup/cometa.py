"""
Mint & Burn with Native Scripts Example

This example demonstrates how to mint two CIP-025 tokens using native scripts
and then burn them afterwards.

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
    ScriptAll,
    ScriptInvalidAfter,
    Value,
    NativeScriptLike,
)
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

# Example CIP-25 metadata
EXAMPLE_CIP_25_METADATA = {
    "eb7e6282971727598462d39d7627bfa6fbbbf56496cb91b76840affb": {
        "BerryOnyx": {
            "color": "#0F0F0F",
            "image": "ipfs://ipfs/QmS7w3Q5oVL9NE1gJnsMVPp6fcxia1e38cRT5pE5mmxawL",
            "name": "Berry Onyx"
        },
        "BerryRaspberry": {
            "color": "#E30B5D",
            "image": "ipfs://ipfs/QmXjegt568JqSUpAz9phxbXq5noWE3AeymZMUP43Ej2DRZ",
            "name": "Berry Raspberry"
        }
    }
}

MNEMONICS = (
    "antenna whale clutch cushion narrow chronic matrix alarm raise much "
    "stove beach mimic daughter review build dinner twelve orbit soap "
    "decorate bachelor athlete close"
)


def utf8_to_bytes(text: str) -> bytes:
    """Converts a UTF-8 string to its byte representation."""
    return text.encode("utf-8")


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


def mint(
    wallet, provider, native_script: NativeScriptLike, asset_id1: bytes, asset_id2: bytes
) -> None:
    """Mints two tokens using Cometa's transaction builder and sends them to the wallet's address."""
    print("Minting tokens...")
    builder = wallet.create_transaction_builder()
    addresses = wallet.get_used_addresses()
    address = addresses[0]

    # Parse asset IDs
    policy1 = asset_id1[:28]
    name1 = asset_id1[28:]
    policy2 = asset_id2[:28]
    name2 = asset_id2[28:]

    value = Value.from_dict([
            2000000,
            {
                policy1: {
                    name1: 1,
                    name2: 1
                }
            }
        ])

    transaction = builder \
        .set_metadata(metadata=EXAMPLE_CIP_25_METADATA, tag=721) \
        .expires_in(3600) \
        .mint_token(amount=1, policy_id=policy1, asset_name=name1) \
        .mint_token(amount=1, policy_id=policy2, asset_name=name2) \
        .add_script(native_script) \
        .send_value(address=str(address), value=value) \
        .build()

    print("Mint transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def burn(
    wallet, provider, native_script: NativeScriptLike, asset_id1: bytes, asset_id2: bytes
) -> None:
    """Burns two tokens using Cometa's transaction builder."""
    print("Burning tokens...")
    builder = wallet.create_transaction_builder()

    transaction = builder \
        .expires_in(3600) \
        .mint_token_with_id(amount=-1, asset_id=asset_id1) \
        .mint_token_with_id(amount=-1, asset_id=asset_id2) \
        .add_script(native_script) \
        .build()

    print("Burn transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def main() -> None:
    """Example of minting and burning tokens with a native script using Cometa."""
    print("=" * 60)
    print("Mint & Burn with Native Scripts Example")
    print("=" * 60)
    print("This example mints two CIP-025 tokens and burn them afterwards.")
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

    # Create the native script and compute its policy ID
    always_succeeds_script = ScriptAll.new([
        ScriptInvalidAfter.new(1001655683199)
    ])

    policy_id = always_succeeds_script.hash

    # Create asset IDs
    asset_id1 = policy_id + utf8_to_bytes("BerryOnyx")
    asset_id2 = policy_id + utf8_to_bytes("BerryRaspberry")

    print(f"Policy ID: {policy_id.hex()}")
    print(f"Asset ID 1: {asset_id1.hex()}")
    print(f"Asset ID 2: {asset_id2.hex()}")

    mint(wallet, provider, always_succeeds_script, asset_id1, asset_id2)
    burn(wallet, provider, always_succeeds_script, asset_id1, asset_id2)


if __name__ == "__main__":
    main()
