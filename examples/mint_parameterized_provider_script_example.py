"""
Mint with Parameterized Aiken Script Example (Provider Evaluator)

This example demonstrates how to:
1. Apply parameters to a parameterized Aiken script (Gift Card contract)
2. Use the ProviderTxEvaluator for transaction evaluation
3. Mint an NFT using the parameterized script

This is the same Gift Card contract as mint_parameterized_aiken_script_example.py
but uses the provider's evaluation API instead of the local Aiken evaluator.

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

from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

from cometa import (
    BlockfrostProvider,
    ProviderTxEvaluator,
    NetworkMagic,
    Script,
    PlutusV2Script,
    Value,
    ConstrPlutusData,
    PlutusData,
    PlutusList,
)
from cometa.aiken import apply_params_to_script

GIFT_CARD_AIKEN_COMPILED_CODE = (
    "590221010000323232323232323232323223222232533300b32323232533300f3370e900018070008"
    "9919191919191919191919299980e98100010991919299980e99b87480000044c94ccc078cdc3a40"
    "00603a002264a66603e66e1c011200213371e00a0322940c07000458c8cc004004030894ccc08800"
    "4530103d87a80001323253330213375e6603a603e004900000d099ba548000cc0940092f5c026600"
    "8008002604c00460480022a66603a66e1c009200113371e00602e2940c06c050dd6980e8011bae30"
    "1b00116301e001323232533301b3370e90010008a5eb7bdb1804c8dd59810800980c801180c8009"
    "91980080080111299980f0008a6103d87a8000132323232533301f3371e01e004266e9520003302"
    "3374c00297ae0133006006003375660400066eb8c078008c088008c080004c8cc004004008894cc"
    "c07400452f5bded8c0264646464a66603c66e3d221000021003133022337606ea4008dd3000998030"
    "030019bab301f003375c603a0046042004603e0026eacc070004c070004c06c004c068004c06400"
    "8dd6180b80098078029bae3015001300d001163013001301300230110013009002149858c94ccc0"
    "2ccdc3a40000022a66601c60120062930b0a99980599b874800800454ccc038c02400c52616163"
    "009002375c0026600200290001111199980399b8700100300c233330050053370000890011807000"
    "801001118029baa001230033754002ae6955ceaab9e5573eae815d0aba201"
)

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
    return "password".encode("utf-8")


def build_output_reference(tx_hash: str, output_index: int) -> ConstrPlutusData:
    """
    Builds an OutputReference as Plutus Data.

    Defined as:
        type OutputReference {
            transaction_id: TransactionId,
            output_index: Int,
        }

        type TransactionId {
            hash: Hash<Blake2b_256, Transaction>,
        }

    This translates to:
        Constr(0, [Constr(0, [tx_hash_bytes]), output_index])
    """
    transaction_id = ConstrPlutusData(0, [PlutusData.from_hex(tx_hash)])
    output_ref = ConstrPlutusData(0, [
        PlutusData.from_constr(transaction_id),
        PlutusData.from_int(output_index)
    ])
    return output_ref


def create_provider_evaluator(provider) -> ProviderTxEvaluator:
    """Creates a ProviderTxEvaluator from the provider."""
    return ProviderTxEvaluator(provider)


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


def mint_gift_card(wallet, provider, script, redeemer, asset_id: bytes, param_utxo) -> None:
    """
    Mints a Gift Card NFT using Cometa's transaction builder with the
    ProviderTxEvaluator for Plutus script evaluation.
    """
    print("Minting Gift Card NFT...")

    builder = wallet.create_transaction_builder()
    builder.set_evaluator(create_provider_evaluator(provider))

    addresses = wallet.get_used_addresses()
    address = addresses[0]

    policy_id = asset_id[:28]
    asset_name = asset_id[28:]

    value = Value.from_dict([
        2_000_000,
        {
            policy_id: {
                asset_name: 1,
            }
        }
    ])

    transaction = builder \
        .add_input(param_utxo) \
        .expires_in(3600) \
        .mint_token(policy_id=policy_id, asset_name=asset_name, amount=1, redeemer=redeemer) \
        .add_script(script) \
        .send_value(address=str(address), value=value) \
        .build()

    print("Mint transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def burn_gift_card(wallet, provider, script, asset_id: bytes) -> None:
    """Burns a Gift Card NFT using Cometa's transaction builder."""
    print("Burning Gift Card NFT...")

    builder = wallet.create_transaction_builder()
    builder.set_evaluator(create_provider_evaluator(provider))

    redeemer = ConstrPlutusData(1)

    transaction = builder \
        .expires_in(3600) \
        .mint_token_with_id(asset_id=asset_id, amount=-1, redeemer=redeemer) \
        .add_script(script) \
        .build()

    print("Burn transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def main() -> None:
    """Example of minting with a parameterized Aiken script using a provider evaluator."""
    print("=" * 60)
    print("Mint with Parameterized Aiken Script (Provider Evaluator)")
    print("=" * 60)
    print("This example demonstrates applying parameters to an Aiken script")
    print("and minting an NFT using the ProviderTxEvaluator.")
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

    sender_address = wallet.get_address()
    print(f"Sender Address: {sender_address}")

    utxos = wallet.get_unspent_outputs()
    if not utxos:
        raise ValueError("No UTXOs available at the sender address")

    suitable_utxo = None
    for utxo in utxos:
        if utxo.output.value.coin >= 2_000_000:
            suitable_utxo = utxo
            break

    if not suitable_utxo:
        raise ValueError("No UTXO with at least 2 ADA found")

    print(f"Selected UTXO: {suitable_utxo.input.transaction_id.hex()}#{suitable_utxo.input.index}")

    token_name = "BlockfrostGift"

    output_ref = build_output_reference(
        tx_hash=suitable_utxo.input.transaction_id.hex(),
        output_index=suitable_utxo.input.index
    )

    params = PlutusList.from_list([
        PlutusData.from_string(token_name),
        PlutusData.from_constr(output_ref)
    ])

    print("Applying parameters to the Gift Card script...")
    compiled_code = apply_params_to_script(params, GIFT_CARD_AIKEN_COMPILED_CODE)
    print(f"Parameterized script compiled (length: {len(compiled_code)} hex chars)")

    plutus_v2_script = PlutusV2Script.from_hex(compiled_code)
    script = Script.from_plutus_v2(plutus_v2_script)

    mint_redeemer = ConstrPlutusData(0)

    policy_id = script.hash
    asset_id = policy_id + utf8_to_bytes(token_name)

    print(f"Policy ID: {policy_id.hex()}")
    print(f"Asset ID: {asset_id.hex()}")
    print(f"Token Name: {token_name}")

    mint_gift_card(wallet, provider, script, mint_redeemer, asset_id, suitable_utxo)

    print()
    print("Waiting before burning...")
    print()

    burn_gift_card(wallet, provider, script, asset_id)


if __name__ == "__main__":
    main()
