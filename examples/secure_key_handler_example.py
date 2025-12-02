"""
Cardano Secure Key Handler Example

This example demonstrates how to create a software secure key handler
from serialized data and use it to sign transactions.

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
    SoftwareBip32SecureKeyHandler,
    harden,
    CoinType,
    KeyDerivationPurpose,
    KeyDerivationRole,
    AccountDerivationPath,
    DerivationPath,
    Transaction,
    CborReader,
)

# Constants
SERIALIZED_BIP32_KEY_HANDLER = (
    "0a0a0a0a01010000005c97db5e09b3a4919ec75ed1126056241a1e5278731c2e0b"
    "01bea0a5f42c22db4131e0a4bbe75633677eb0e60e2ecd3520178f85c7e0d4be77"
    "a449087fe9674ee52f946b07c1b56d228c496ec0d36dd44212ba8af0f6eed1a821"
    "94dd69f479c603"
)

TX_CBOR = (
    "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9"
    "232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84f"
    "aedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c73"
    "84942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437"
    "b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b0"
    "00b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b5820"
    "88e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a1"
    "0481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c7121"
    "3dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799f"
    "d8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13"
    "ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd879"
    "9fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168"
    "c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898"
    "d88da20ef73964b8cf6f8f08ddfbffffffffffd8799fd87980d8799fd8799f581c"
    "aa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8"
    "799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08"
    "ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9f"
    "d8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1"
    "d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4"
    "b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff"
    "9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001"
    "884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1f"
    "b1c0d87980fffff5f6"
)


def get_password() -> bytes:
    """Callback that returns the passphrase for decryption."""
    return b"password"


def main() -> None:
    """Example of using a secure key handler to manage Cardano keys securely."""
    print("=" * 60)
    print("Cardano Secure Key Handler Example")
    print("=" * 60)
    print("This example demonstrates how to create a software secure key handler")
    print()

    # The SoftwareBip32SecureKeyHandler keeps the root private key encrypted,
    # and only decrypts it when needed for a short time. It will then wipe
    # from memory the decrypted private key and the given password.
    # The SoftwareBip32SecureKeyHandler can be created from a serialized
    # version, which is useful for storing it in a database or a file,
    # or directly from BIP-39 mnemonics or entropy.
    # You can then securely store it for future use with serialize().

    print("[INFO] Use passphrase: 'password'")
    print("[INFO] Deserializing secure key handler from stored data...")

    secure_key_handler = SoftwareBip32SecureKeyHandler.deserialize(
        bytes.fromhex(SERIALIZED_BIP32_KEY_HANDLER),
        get_password
    )

    print("[INFO] Requesting extended account public key...")

    root_account_pub_key = secure_key_handler.get_account_public_key(
        AccountDerivationPath(
            account=harden(0),
            coin_type=harden(CoinType.CARDANO),
            purpose=harden(KeyDerivationPurpose.STANDARD)
        )
    )

    print(f"[INFO] Extended account public key: {root_account_pub_key.to_hex()}")

    # The secure key handler can be used to sign transaction with more than
    # one key at a time.
    print("[INFO] Signing transaction...")

    reader = CborReader.from_hex(TX_CBOR)
    transaction = Transaction.from_cbor(reader)

    witness_set = secure_key_handler.sign_transaction(
        transaction,
        [
            DerivationPath(
                account=harden(0),
                coin_type=harden(CoinType.CARDANO),
                index=0,
                purpose=harden(KeyDerivationPurpose.STANDARD),
                role=KeyDerivationRole.EXTERNAL
            )
        ]
    )

    print("[INFO] Transaction signed successfully.")
    print(f"[INFO] Witness set has {len(witness_set)} witnesses")

    for i, witness in enumerate(witness_set):
        print(f"  Witness {i}:")
        print(f"    vkey: {witness.vkey.to_hex()}")
        print(f"    signature: {witness.signature.to_hex()}")


if __name__ == "__main__":
    main()
