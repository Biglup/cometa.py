"""
DRep Script Example

This example demonstrates how to register a PlutusV3 script as a DRep,
delegate voting power to it, and deregister both the DRep and stake key.

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
    Script,
    PlutusV3Script,
    ConstrPlutusData,
)
from single_address_wallet import SingleAddressWallet, SingleAddressCredentialsConfig

ALWAYS_SUCCEEDS_SCRIPT_V3 = (
    "590dff010000323232332232323232332232323232323232232498c8c8c94cd4ccd5cd19b874800000804c0484c8c8c8c8c8ccc88848ccc00401000c008c8c8c94cd4ccd5cd19b874800000806c0684c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8cccccccccccc8ccc8cc8cc888888888888888848cccccccccccccccc00404404003c03803403002c02802402001c01801401000c008c004d5d080a18009aba1013302123232325335333573466e1d2000002031030133221233001003002301d35742002600a6ae84d5d1000898192481035054310035573c0046aae74004dd5000998108009aba101123232325335333573466e1d200000203002f13232333322221233330010050040030023232325335333573466e1d2000002035034133221233001003002302a35742002660564646464a66a666ae68cdc3a40000040720702642446004006605c6ae8400454cd4ccd5cd19b87480080080e40e04c8ccc888488ccc00401401000cdd69aba1002375a6ae84004dd69aba1357440026ae880044c0e92401035054310035573c0046aae74004dd50009aba1357440022606c9201035054310035573c0046aae74004dd51aba1003300735742004646464a66a666ae68cdc3a400000406a068224440062a66a666ae68cdc3a400400406a068264244460020086eb8d5d08008a99a999ab9a3370e900200101a81a099091118010021aba1001130364901035054310035573c0046aae74004dd51aba10013302875c6ae84d5d10009aba200135744002260629201035054310035573c0046aae74004dd50009bad3574201e60026ae84038c008c009d69980f80a9aba100c33302202075a6ae8402cc8c8c94cd4ccd5cd19b87480000080b80b44cc8848cc00400c008c8c8c94cd4ccd5cd19b87480000080c40c04cc8848cc00400c008cc0b9d69aba1001302d357426ae880044c0c9241035054310035573c0046aae74004dd51aba10013232325335333573466e1d20000020310301332212330010030023302e75a6ae84004c0b4d5d09aba200113032491035054310035573c0046aae74004dd51aba1357440022605e921035054310035573c0046aae74004dd51aba100a3301f75c6ae84024ccc0888c8c8c94cd4ccd5cd19b87480000080bc0b84c84888888c01401cdd71aba100115335333573466e1d200200202f02e13212222223002007301b357420022a66a666ae68cdc3a400800405e05c2642444444600600e60486ae8400454cd4ccd5cd19b87480180080bc0b84cc884888888cc01802001cdd69aba10013019357426ae8800454cd4ccd5cd19b87480200080bc0b84c84888888c00401cc068d5d08008a99a999ab9a3370e9005001017817099910911111198020040039bad3574200260306ae84d5d1000898182481035054310035573c0046aae74004dd50008131aba1008330020263574200e6eb8d5d080319981100b198110149191919299a999ab9a3370e9000001017817089110010a99a999ab9a3370e9001001017817089110008a99a999ab9a3370e900200101781708911001898182481035054310035573c0046aae74004dd50009aba10053301f0143574200860026ae8400cc004d5d09aba2003302075a6040eb8d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba2001357440026ae88004d5d10009aba20011301c491035054310035573c0046aae74004dd51aba10063574200a646464a66a666ae68cdc3a40000040360342642444444600a00e6eb8d5d08008a99a999ab9a3370e900100100d80d0999109111111980100400398039aba100133011016357426ae8800454cd4ccd5cd19b874801000806c0684c84888888c00c01cc040d5d08008a99a999ab9a3370e900300100d80d099910911111198030040039bad35742002600a6ae84d5d10008a99a999ab9a3370e900400100d80d0990911111180080398031aba100115335333573466e1d200a00201b01a13322122222233004008007375a6ae84004c010d5d09aba20011301c4901035054310035573c0046aae74004dd51aba13574400a4646464a66a666ae68cdc3a4000004036034264666444246660020080060046eb4d5d080118089aba10013232325335333573466e1d200000201f01e1323332221222222233300300a0090083301601e357420046ae84004cc059d71aba1357440026ae8800454cd4ccd5cd19b874800800807c0784cc8848888888cc01c024020cc054074d5d0800991919299a999ab9a3370e90000010110108999109198008018011bad357420026eb4d5d09aba200113023491035054310035573c0046aae74004dd51aba1357440022a66a666ae68cdc3a400800403e03c26644244444446600401201066602c028eb4d5d08009980abae357426ae8800454cd4ccd5cd19b874801800807c0784c848888888c010020cc054074d5d08008a99a999ab9a3370e900400100f80f09919199991110911111119998008058050048041980b80f9aba1003330150163574200466603002ceb4d5d08009a991919299a999ab9a3370e900000101201189980e1bad357420026eb4d5d09aba2001130254901035054310035573c0046aae74004dd51aba135744002446602a0040026ae88004d5d10008a99a999ab9a3370e900500100f80f0999109111111198028048041980a80e9aba10013232325335333573466e1d200000202202113301875c6ae840044c08d241035054310035573c0046aae74004dd51aba1357440022a66a666ae68cdc3a401800403e03c22444444400c26040921035054310035573c0046aae74004dd51aba1357440026ae880044c071241035054310035573c0046aae74004dd50009191919299a999ab9a3370e900000100d00c899910911111111111980280680618079aba10013301075a6ae84d5d10008a99a999ab9a3370e900100100d00c899910911111111111980100680618079aba10013301075a6ae84d5d10008a9919a999ab9a3370e900200180d80d099910911111111111980500680618081aba10023001357426ae8800854cd4ccd5cd19b874801800c06c0684c8ccc888488888888888ccc018038034030c044d5d080198011aba1001375a6ae84d5d10009aba200215335333573466e1d200800301b01a133221222222222223300700d00c3010357420046eb4d5d09aba200215335333573466e1d200a00301b01a132122222222122300100c3010357420042a66a666ae68cdc3a4018006036034266442444444444446600601a01860206ae84008dd69aba1357440042a66a666ae68cdc3a401c006036034266442444444444446601201a0186eb8d5d08011bae357426ae8800854cd4ccd5cd19b874804000c06c0684cc88488888888888cc020034030dd71aba1002375a6ae84d5d10010a99a999ab9a3370e900900180d80d099910911111111111980580680618081aba10023010357426ae8800854cd4ccd5cd19b874805000c06c0684c8488888888888c010030c040d5d08010980e2481035054310023232325335333573466e1d200000201e01d13212223003004375c6ae8400454c8cd4ccd5cd19b874800800c07c0784c84888c004010c004d5d08010a99a999ab9a3370e900200180f80f099910911198010028021bae3574200460026ae84d5d1001098102481035054310023232325335333573466e1d2000002022021132122230030043017357420022a66a666ae68cdc3a4004004044042224440042a66a666ae68cdc3a40080040440422244400226046921035054310035573c0046aae74004dd50009aab9e00235573a0026ea8004d55cf0011aab9d00137540024646464a66a666ae68cdc3a400000403203026424446006008601c6ae8400454cd4ccd5cd19b87480080080640604c84888c008010c038d5d08008a99a999ab9a3370e900200100c80c099091118008021bae3574200226034921035054310035573c0046aae74004dd50009191919299a999ab9a3370e900000100c00b8999109198008018011bae357420026eb4d5d09aba200113019491035054310035573c0046aae74004dd50009aba200113014491035054310035573c0046aae74004dd50009808911299a999ab9a3370e900000080880809809249035054330015335333573466e20005200001101013300333702900000119b81480000044c8cc8848cc00400c008cdc200180099b840020013300400200130102225335333573466e1d200000101000f10021330030013370c004002464460046eb0004c04088cccd55cf8009005119a80498021aba10023003357440040224646464a66a666ae68cdc3a400000401e01c26424460040066eb8d5d08008a99a999ab9a3370e900100100780709909118008019bae3574200226020921035054310035573c0046aae74004dd500091191919299a999ab9a3370e900100100780708910008a99a999ab9a3370e9000001007807099091180100198029aba1001130104901035054310035573c0046aae74004dd50009119118011bab001300e2233335573e002401046466a0106600e600c6aae74004c014d55cf00098021aba20033574200401e4424660020060042440042442446600200800640024646464a66a666ae68cdc3a400000401000e200e2a66a666ae68cdc3a400400401000e201026012921035054310035573c0046aae74004dd500091191919299a999ab9a3370e9000001004003889110010a99a999ab9a3370e90010010040038990911180180218029aba100115335333573466e1d200400200800711222001130094901035054310035573c0046aae74004dd50009191919299a999ab9a3370e90000010030028999109198008018011bae357420026eb4d5d09aba200113007491035054310035573c0046aae74004dd5000891001091000919319ab9c0010021200123230010012300223300200200101"
)

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


def register_drep(wallet, provider, script, redeemer, drep: DRep) -> None:
    """Registers a DRep using Cometa."""
    print("Registering DRep...")
    builder = wallet.create_transaction_builder()

    transaction = builder \
        .register_drep(drep=drep, anchor=ANCHOR, redeemer=redeemer) \
        .add_script(script) \
        .build()

    print("Register DRep transaction built successfully.")
    sign_and_submit(wallet, provider, transaction)


def deregister_drep(wallet, provider, script, redeemer, drep: DRep) -> None:
    """Deregisters a DRep using Cometa."""
    print("Deregistering DRep...")
    builder = wallet.create_transaction_builder()

    transaction = builder \
        .deregister_drep(drep=drep, redeemer=redeemer) \
        .add_script(script) \
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
    print("Registers DRep and Delegate Voting Power (Script Hash)")
    print("=" * 60)
    print(
        "This example registers a PlutusV3 as DRep, delegates our voting power "
        "to the DRep credential, and finally unregisters both the DRep and stake key."
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

    plutus_v3_script = PlutusV3Script.from_hex(ALWAYS_SUCCEEDS_SCRIPT_V3)
    script = Script.from_plutus_v3(plutus_v3_script)

    redeemer = ConstrPlutusData(0)

    script_hash = script.hash
    script_credential = Credential.from_script_hash(script_hash)
    drep = DRep.new(drep_type=DRepType.SCRIPT_HASH, credential=script_credential)

    print(f"DRep ID: {drep.to_cip129_string()}")

    register_drep(wallet, provider, script, redeemer, drep)
    register_and_delegate_stake_key(wallet, provider, drep)
    deregister_and_withdraw_rewards(wallet, provider)
    deregister_drep(wallet, provider, script, redeemer, drep)


if __name__ == "__main__":
    main()
