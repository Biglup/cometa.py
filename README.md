<div align="center">
  <a href="" target="_blank">
    <img align="center" width="300" src="https://raw.githubusercontent.com/Biglup/cometa.py/main/assets/cometa_py.png">
  </a>
</div>

<br>

<div align="center">

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Post-Integration](https://github.com/Biglup/cometa.py/actions/workflows/ci.yml/badge.svg)
[![Documentation Status](https://app.readthedocs.org/projects/cometapy/badge/?version=latest)](https://cometapy.readthedocs.io/en/latest/?badge=latest)
[![Twitter Follow](https://img.shields.io/twitter/follow/BiglupLabs?style=social)](https://x.com/BiglupLabs)
[![PyPI version](https://img.shields.io/pypi/v/biglup-cometa)](https://pypi.org/project/biglup-cometa/)

</div>

<hr>

- [Official Website](https://cometa.dev/)
- [Installation](#installation)
- [Documentation](https://cometapy.readthedocs.io/en/latest/)

<hr>

Cometa.py is a lightweight, high-performance Python library binding for the [libcardano-c](https://github.com/Biglup/cardano-c) library, designed to simplify blockchain development on Cardano.

Cometa.py packages [libcardano-c](https://github.com/Biglup/cardano-c) using CFFI bindings, providing a fully documented, developer-friendly Pythonic API with type hints for excellent IDE support.

Example:

```python
from cometa import TxBuilder, SlotConfig

builder = TxBuilder(protocol_params, SlotConfig.mainnet())

unsigned_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .send_lovelace(recipient_address, 12_000_000)
    .expires_in(3600)
    .build()
)
```

<hr>

## **Conway Era Support**

Cometa.py supports all features up to the Conway era, which is the current era of the Cardano blockchain. Conway era brought decentralized governance to Cardano, including:

- [Register as DRep (PubKey)](examples/drep_pubkey_example.py)
-  [Register as DRep (Script)](examples/drep_script_example.py)
-  [Submit governance action proposal (Withdrawing from treasury)](examples/propose_treasury_withdrawal_example.py)
-  [Vote for proposal (PubKey DRep)](examples/vote_for_proposal_drep_pubkey_example.py)
-  [Vote for proposal (Script DRep)](examples/vote_for_proposal_drep_script_example.py)

These are some of the examples illustrated in the [examples](examples/) directory. However, you should
be able to build any valid transaction for the current era. See the [Documentation](https://cometapy.readthedocs.io/) for more information.


<hr>

## **Installation**

You can install Cometa.py using pip:

```bash
pip install biglup-cometa
```

Once installed, you can import it into your application:

```python
import cometa

version = cometa.get_lib_version()
print(f"Library version: {version}")
```

<hr>

## **Getting Started**

The primary component for creating transactions is the `TxBuilder`. It provides a fluent (chainable) API that simplifies the complex process of assembling inputs, outputs, and calculating fees.

The `TxBuilder` requires protocol parameters and a `SlotConfig` for slot/time calculations:

```python
from cometa import TxBuilder, SlotConfig, ProtocolParameters

# SlotConfig provides network timing configuration
# Use the appropriate factory method for your network:
slot_config = SlotConfig.mainnet()   # For mainnet
slot_config = SlotConfig.preprod()   # For preprod testnet
slot_config = SlotConfig.preview()   # For preview testnet

# Create the builder
builder = TxBuilder(protocol_params, slot_config)
```

> **Note:** The `TxBuilder` uses `AikenTxEvaluator` by default for local Plutus script evaluation. You can override this with a custom evaluator using `builder.set_evaluator()`.

First, establish a connection to the Cardano network using a Provider:

```python
from cometa import BlockfrostProvider, NetworkMagic

provider = BlockfrostProvider(
    network=NetworkMagic.PREPROD,
    project_id="YOUR_BLOCKFROST_PROJECT_ID"
)
```

> **Tip:** You can create your own providers by implementing the `Provider` protocol.

Create your addresses and fetch UTxOs:

```python
from cometa import Address

sender_address = Address.from_bech32("addr_test1...")
recipient_address = Address.from_bech32("addr_test1...")

# Fetch UTxOs from the provider
utxos = provider.get_unspent_outputs(sender_address)
protocol_params = provider.get_parameters()
```

Build your transaction using the fluent API:

```python
from cometa import TxBuilder, SlotConfig

builder = TxBuilder(protocol_params, SlotConfig.preprod())

unsigned_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .send_lovelace(recipient_address, 2_000_000)  # Send 2 ADA
    .expires_in(7200)  # Valid for 2 hours
    .build()
)
```

Sign and submit the transaction:

```python
tx_hash = provider.submit_transaction(signed_tx)
print(f"Transaction submitted! TxHash: {tx_hash}")
```

<hr>

## **Transaction Builder Examples**

The `TxBuilder` supports a wide range of transaction types. Here are some common patterns.

All examples below assume you have already created the builder:

```python
from cometa import TxBuilder, SlotConfig

builder = TxBuilder(protocol_params, SlotConfig.preprod())
```

### Sending Multiple Outputs

```python
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .send_lovelace("addr_test1qz...", 5_000_000)   # Send 5 ADA
    .send_lovelace("addr_test1qp...", 10_000_000)  # Send 10 ADA
    .send_lovelace("addr_test1qr...", 2_000_000)   # Send 2 ADA
    .expires_in(7200)  # Expires in 2 hours
    .build()
)
```

### Minting Tokens with Native Scripts

```python
from cometa import ScriptAll, ScriptPubkey, Value

# Create a native script policy
pub_key_hash = payment_key.to_hash()
native_script = ScriptAll.new([
    ScriptPubkey.new(pub_key_hash)
])
policy_id = native_script.hash

# Mint tokens
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .mint_token(amount=100, policy_id=policy_id, asset_name=b"MyToken")
    .add_script(native_script)
    .send_value(
        address=str(sender_address),
        value=Value.from_dict([2_000_000, {policy_id: {b"MyToken": 100}}])
    )
    .expires_in(3600)
    .build()
)
```

### Burning Tokens

```python
# Burn tokens (negative amount)
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .mint_token(amount=-50, policy_id=policy_id, asset_name=b"MyToken")
    .add_script(native_script)
    .expires_in(3600)
    .build()
)
```

### Attaching Metadata (CIP-25 NFTs)

```python
# CIP-25 NFT metadata
nft_metadata = {
    policy_id.hex(): {
        "MyNFT": {
            "name": "My Awesome NFT",
            "image": "ipfs://QmXyz...",
            "description": "A unique digital artwork"
        }
    }
}

tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .mint_token(amount=1, policy_id=policy_id, asset_name=b"MyNFT")
    .add_script(native_script)
    .set_metadata(metadata=nft_metadata, tag=721)  # CIP-25 uses tag 721
    .send_value(
        address=recipient_address,
        value=Value.from_dict([2_000_000, {policy_id: {b"MyNFT": 1}}])
    )
    .expires_in(3600)
    .build()
)
```

### Staking Operations

```python
from cometa import DRep

# Delegate stake to a pool
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .delegate_stake(
        reward_address=reward_address,
        pool_id="pool1..."
    )
    .build()
)

# Delegate voting power to a DRep (Conway era)
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .delegate_voting_power(
        reward_address=reward_address,
        drep=DRep.from_key_hash("drep_key_hash_hex...")
    )
    .build()
)
```

### Treasury Donation

```python
# Donate to the Cardano treasury
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .donate(1_000_000_000)  # Donate 1000 ADA
    .build()
)
```

<hr>

## **Plutus Smart Contracts**

Cometa.py supports Plutus V1, V2, and V3 scripts for smart contract interactions. Plutus scripts can be used for spending validation, minting policies, and staking operations.

### Loading Plutus Scripts

```python
from cometa import PlutusV3Script, PlutusV2Script, PlutusV1Script, Script

# Load a Plutus V3 script from CBOR hex
plutus_v3 = PlutusV3Script.from_hex("590dff010000323232...")
script = Script.from_plutus_v3(plutus_v3)

# Load Plutus V2 or V1 similarly
plutus_v2 = PlutusV2Script.from_hex("...")
script_v2 = Script.from_plutus_v2(plutus_v2)

# Get the script hash (used as policy ID for minting)
script_hash = script.hash
print(f"Script hash: {script_hash.hex()}")
```

### Creating Script Addresses

```python
from cometa import EnterpriseAddress, Credential, NetworkId

# Create a credential from the script hash
script_credential = Credential.from_script_hash(script_hash)

# Create an enterprise address (no staking) for the script
script_address = EnterpriseAddress.from_credentials(
    NetworkId.TESTNET,
    script_credential
).to_address()

print(f"Script address: {script_address}")
```

### Spending from a Plutus Script

```python
from cometa import ConstrPlutusData

# Get UTXOs locked at the script address
script_utxos = provider.get_unspent_outputs(str(script_address))

# Create a redeemer (argument to the script)
# ConstrPlutusData(0) is a simple constructor - your script defines the format
redeemer = ConstrPlutusData(0)

# Build transaction to spend from the script
spend_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .add_input(utxo=script_utxos[0], redeemer=redeemer)  # Script input with redeemer
    .send_lovelace(address=recipient_address, amount=5_000_000)
    .add_script(script)  # Include the script for validation
    .expires_in(3600)
    .build()
)
```

### Working with Plutus Data

```python
from cometa import ConstrPlutusData, PlutusList, PlutusMap
# Constructor with fields (most common pattern)
# Represents: data MyDatum = MyDatum { owner: PubKeyHash, amount: Integer }
datum = ConstrPlutusData(
    0,  # Constructor index
    [
        b"pubkey_hash_here", # owner
        1000000              # amount
    ]
)

# List of integers
int_list = PlutusList.from_list([
    1,
    2,
    3
])

# Map (key-value pairs)
plutus_map = PlutusMap()
plutus_map[b"key1"] = 100
plutus_map[b"key2"] = 200
```


### Working with Scripts

Cometa.py provides some utilities to parameterize scripts and local transaction evaluation using the Aiken UPLC evaluator.

#### Applying Parameters to Scripts

Many contracts are parameterized, they require configuration data to be applied before deployment. Use `apply_params_to_script` to apply parameters to compiled scripts:

```python
from cometa import apply_params_to_script, PlutusV2Script, Script, PlutusList, PlutusData, ConstrPlutusData

# Load your compiled script
compiled_code = "590221010000323232..."

# Build parameters as Plutus Data
# Example: Gift Card contract requires token_name and utxo_ref
token_name = "MyToken"
output_ref = ConstrPlutusData(0, [
    ConstrPlutusData(0, [PlutusData.from_hex(utxo.input.transaction_id.hex())]),
    PlutusData.from_int(utxo.input.index)
])

params = PlutusList.from_list([
    PlutusData.from_string(token_name),
    PlutusData.from_constr(output_ref)
])

# Apply parameters to get the final script
parameterized_code = apply_params_to_script(params, compiled_code)

# Create the script object
plutus_script = PlutusV2Script.from_hex(parameterized_code)
script = Script.from_plutus_v2(plutus_script)

# Get the policy ID (script hash)
policy_id = script.hash
print(f"Policy ID: {policy_id.hex()}")
```

#### Example: Minting with Parameterized Script

```python
from cometa import (
    BlockfrostProvider, NetworkMagic, TxBuilder, SlotConfig,
    PlutusV2Script, Script, Value,
    PlutusList, PlutusData, ConstrPlutusData, apply_params_to_script
)

# Setup provider
provider = BlockfrostProvider(
    network=NetworkMagic.PREPROD,
    project_id="YOUR_PROJECT_ID"
)

# Get protocol parameters and UTXOs
protocol_params = provider.get_parameters()
utxos = provider.get_unspent_outputs(sender_address)

# Select a UTXO to use as parameter (ensures script uniqueness)
param_utxo = utxos[0]

# Build script parameters
token_name = "MyNFT"
output_ref = ConstrPlutusData(0, [
    ConstrPlutusData(0, [PlutusData.from_hex(param_utxo.input.transaction_id.hex())]),
    PlutusData.from_int(param_utxo.input.index)
])

params = PlutusList.from_list([
    PlutusData.from_string(token_name),
    PlutusData.from_constr(output_ref)
])

# Apply parameters and create script
compiled_code = "590221010000323232..."
parameterized = apply_params_to_script(params, compiled_code)
script = Script.from_plutus_v2(PlutusV2Script.from_hex(parameterized))

# Build mint transaction
# Note: TxBuilder uses AikenTxEvaluator by default for local Plutus evaluation
policy_id = script.hash
asset_name = token_name.encode("utf-8")
mint_redeemer = ConstrPlutusData(0)  # Mint action

builder = TxBuilder(protocol_params, SlotConfig.preprod())

tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .add_input(param_utxo)  # Must spend the referenced UTXO
    .mint_token(policy_id=policy_id, asset_name=asset_name, amount=1, redeemer=mint_redeemer)
    .add_script(script)
    .send_value(
        address=str(recipient_address),
        value=Value.from_dict([2_000_000, {policy_id: {asset_name: 1}}])
    )
    .expires_in(3600)
    .build()
)

# Sign and submit
signed_tx = sign_transaction(tx, private_key)
tx_hash = provider.submit_transaction(signed_tx.serialize_to_cbor())
print(f"Transaction submitted: {tx_hash}")
```

<hr>

## **Conway Governance**

Cardano's Conway era introduced decentralized governance. Cometa.py supports all governance features including DRep registration, voting, and proposal submission.

### Registering as a DRep

Delegated Representatives (DReps) vote on governance proposals on behalf of delegators:

```python
from cometa import DRep, DRepType, Credential, Anchor, Blake2bHash, Ed25519PublicKey

# Create DRep credential from your DRep key
drep_pub_key = Ed25519PublicKey.from_hex("your_drep_public_key_hex")
drep_credential = Credential.from_key_hash(drep_pub_key.to_hash())

# Create the DRep object
drep = DRep.new(drep_type=DRepType.KEY_HASH, credential=drep_credential)
print(f"DRep ID: {drep.to_cip129_string()}")

# Create an anchor (metadata URL + hash)
anchor = Anchor.new(
    url="https://example.com/drep-metadata.jsonld",
    hash_value=Blake2bHash.from_hex("metadata_hash_hex...")
)

# Register as a DRep
register_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .register_drep(drep=drep, anchor=anchor)
    .build()
)
```

### Delegating Voting Power

ADA holders can delegate their voting power to a DRep:

```python
from cometa import DRep

# Delegate to a specific DRep
drep = DRep.from_string("drep1...")  # DRep ID in CIP-129 format

# First register your stake key (if not already registered)
register_stake_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .register_reward_address(reward_address=reward_address)
    .build()
)

# Then delegate voting power
delegate_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .delegate_voting_power(
        drep=drep,
        reward_address=reward_address
    )
    .build()
)

# You can also delegate to special DReps
from cometa import DRep

# Delegate to "Abstain" (participate in quorum but don't vote)
abstain_drep = DRep.new_abstain()

# Delegate to "No Confidence" (vote no on everything)
no_confidence_drep = DRep.new_no_confidence()
```

### Voting on Proposals

DReps can vote on governance proposals:

```python
from cometa import (
    Voter, VoterType, Vote, VotingProcedure,
    GovernanceActionId, Anchor, Blake2bHash
)

# Create the voter (DRep credential)
voter = Voter.new(VoterType.DREP_KEY_HASH, drep_credential)

# Reference the governance action to vote on
action_id = GovernanceActionId.from_bech32(
    "gov_action1u8gafgcskj6sqvgwqse7adc0h9438m535lg97czcvxntscvw7f5sqgf2n7j"
)

# Create voting procedure with rationale anchor
rationale_anchor = Anchor.new(
    url="https://example.com/vote-rationale.jsonld",
    hash_value=Blake2bHash.from_hex("rationale_hash...")
)
voting_procedure = VotingProcedure.new(Vote.YES, rationale_anchor)

# Cast the vote
vote_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .vote(
        voter=voter,
        action_id=action_id,
        voting_procedure=voting_procedure
    )
    .build()
)
```

### Proposing Governance Actions

Submit proposals for on-chain governance:

```python
from cometa import Anchor, Blake2bHash

# All proposals require an anchor with metadata
proposal_anchor = Anchor.new(
    url="https://example.com/proposal-metadata.jsonld",
    hash_value=Blake2bHash.from_hex("metadata_hash...")
)

# Info action (non-binding poll)
info_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .propose_info(
        reward_address=reward_address,  # Deposit refund address
        anchor=proposal_anchor
    )
    .build()
)
```

### Deregistering a DRep

```python
# Deregister and reclaim your deposit
deregister_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .deregister_drep(drep=drep)
    .build()
)
```

### Withdrawing Staking Rewards

```python
# Get current rewards balance
rewards_balance = provider.get_rewards_balance(reward_address)

# Withdraw all rewards
withdraw_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .withdraw_rewards(
        amount=rewards_balance,
        reward_address=reward_address
    )
    .build()
)

# Optionally deregister stake key to reclaim deposit
deregister_stake_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .withdraw_rewards(amount=rewards_balance, reward_address=reward_address)
    .deregister_reward_address(reward_address=reward_address)
    .build()
)
```

You can see the full capabilities of the transaction builder in the [TxBuilder API documentation](https://cometapy.readthedocs.io/en/latest/api/transaction_builder/tx_builder.html).

<hr>

## **Working with CBOR**

Cardano uses [CBOR (Concise Binary Object Representation)](https://cbor.io/) for serialization. Cometa.py provides `CborReader` and `CborWriter` for encoding and decoding CBOR data.

### Writing CBOR Data

```python
from cometa import CborWriter

# Create a writer
writer = CborWriter()

# Write primitive values
writer.write_int(42)
writer.write_str("Hello, Cardano!")
writer.write_bytes(b"\x01\x02\x03")
writer.write_bool(True)
writer.write_null()

# Get the encoded bytes
cbor_bytes = writer.encode()
cbor_hex = writer.to_hex()
```

### Reading CBOR Data

```python
from cometa import CborReader, CborReaderState

# Create a reader from hex or bytes
reader = CborReader.from_hex("83010203")  # Array [1, 2, 3]

# Check what type of data is next
state = reader.peek_state()
if state == CborReaderState.START_ARRAY:
    length = reader.read_array_len()
    for _ in range(length):
        value = reader.read_uint()
        print(value)
    reader.read_array_end()
```

<hr>

## **Cryptography**

Cometa.py provides comprehensive cryptographic primitives for Cardano development, including Ed25519 key pairs, BIP32 hierarchical deterministic keys, and BIP39 mnemonic support.

### Working with Mnemonics (BIP39)

BIP39 mnemonics are human-readable word sequences that encode cryptographic entropy:

```python
from cometa import mnemonic_to_entropy, entropy_to_mnemonic

# Convert a mnemonic phrase to entropy
mnemonic_words = [
    "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "abandon",
    "abandon", "abandon", "abandon", "about"
]
entropy = mnemonic_to_entropy(mnemonic_words)
print(f"Entropy: {entropy.hex()}")
```

### Deriving Keys from Mnemonics (CIP-1852)

Cardano uses CIP-1852 for HD wallet key derivation:

```python
from cometa import (
    mnemonic_to_entropy,
    Bip32PrivateKey,
    harden,
    BaseAddress,
    NetworkId,
    Credential
)

# Convert mnemonic to entropy
mnemonic = "your 24 word mnemonic phrase here...".split()
entropy = mnemonic_to_entropy(mnemonic)

# Create root key from entropy
root_key = Bip32PrivateKey.from_bip39_entropy(b"optional-passphrase", entropy)

# Derive account key using CIP-1852 path: m/1852'/1815'/0'
# 1852' = Cardano purpose, 1815' = ADA coin type, 0' = account 0
account_key = root_key.derive([
    harden(1852),  # Purpose
    harden(1815),  # Coin type (ADA)
    harden(0)      # Account index
])

# Get account public key (can be shared safely)
account_pub_key = account_key.get_public_key()

# Derive payment key: m/1852'/1815'/0'/0/0
payment_key = account_pub_key.derive([0, 0])  # External chain, address 0

# Derive staking key: m/1852'/1815'/0'/2/0
staking_key = account_pub_key.derive([2, 0])  # Staking chain, index 0

# Create credentials from key hashes
payment_credential = Credential.from_key_hash(
    payment_key.to_ed25519_key().to_hash()
)
staking_credential = Credential.from_key_hash(
    staking_key.to_ed25519_key().to_hash()
)

# Create a base address
address = BaseAddress.from_credentials(
    NetworkId.MAINNET,
    payment_credential,
    staking_credential
)
print(f"Address: {address.to_bech32()}")
```

### Signing and Verifying Messages

Ed25519 signatures are used for transaction signing and message authentication:

```python
from cometa import Ed25519PrivateKey, Ed25519PublicKey

# Create a private key (in practice, derive from HD wallet)
private_key = Ed25519PrivateKey.from_normal_bytes(bytes(32))

# Get the corresponding public key
public_key = private_key.get_public_key()
print(f"Public key hash: {public_key.to_hash().to_hex()}")

# Sign a message
message = b"Hello, Cardano!"
signature = private_key.sign(message)
print(f"Signature: {signature.to_hex()}")

# Verify the signature
is_valid = public_key.verify(signature, message)
print(f"Signature valid: {is_valid}")

# Verification fails with wrong message
is_valid = public_key.verify(signature, b"Wrong message")
print(f"Wrong message valid: {is_valid}")  # False
```

<hr>

## **Extending the Transaction Builder**

The `TxBuilder` API allows you to override its core logic for coin selection and transaction evaluation. If these custom implementations are not provided, the builder uses the following defaults:

- **Coin Selection**: A "Largest First" strategy via `LargeFirstCoinSelector`
- **Transaction Evaluation**: Local evaluation via `AikenTxEvaluator` (uses the Aiken UPLC evaluator)

### Implementing a Custom CoinSelector

The coin selector is responsible for choosing which UTxOs to spend to cover the value required by the transaction's outputs. You can provide your own strategy by implementing the `CoinSelector` protocol:

```python
from typing import List, Tuple
from cometa import Utxo, Value

class MyCoinSelector:
    """Custom coin selection strategy."""

    def get_name(self) -> str:
        return "MyCustomSelector"

    def select(
        self,
        pre_selected_utxo: List[Utxo],
        available_utxo: List[Utxo],
        target: Value,
    ) -> Tuple[List[Utxo], List[Utxo]]:
        # Your custom selection logic here
        # Return: (selected_utxos, remaining_utxos)
        ...
```

Attach your custom selector to the builder:

```python
my_selector = MyCoinSelector()
builder.set_coin_selector(my_selector)
```

### Transaction Evaluators

The transaction evaluator calculates execution units (ExUnits) for Plutus scripts.

**Default: Local Evaluation with AikenTxEvaluator**

By default, `TxBuilder` uses `AikenTxEvaluator` for local Plutus script evaluation. This is configured automatically based on the `SlotConfig` and protocol parameters you provide:

```python
from cometa import TxBuilder, SlotConfig

# AikenTxEvaluator is used automatically
builder = TxBuilder(protocol_params, SlotConfig.preprod())

# Build transaction with Plutus scripts - evaluation happens locally
tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .add_input(script_utxo, redeemer=redeemer)
    .add_script(script)
    .build()
)
```

**Custom AikenTxEvaluator Configuration**

If you need to customize the evaluator settings, you can create your own instance:

```python
from cometa import TxBuilder, SlotConfig
from cometa.aiken import AikenTxEvaluator

# Create custom evaluator with specific settings
evaluator = AikenTxEvaluator(
    cost_models=protocol_params.cost_models,
    slot_config=SlotConfig.preprod(),
    max_tx_ex_units=protocol_params.max_tx_ex_units,
)

# Override the default evaluator
builder = TxBuilder(protocol_params, SlotConfig.preprod())
builder.set_evaluator(evaluator)
```

**Custom Evaluator**

You can also implement your own evaluator by following the `TxEvaluator` protocol:

```python
from typing import List, Optional
from cometa import Transaction, Utxo, Redeemer

class MyTxEvaluator:
    """Custom transaction evaluator."""

    def get_name(self) -> str:
        return "MyCustomEvaluator"

    def evaluate(
        self,
        transaction: Transaction,
        additional_utxos: Optional[List[Utxo]] = None,
    ) -> List[Redeemer]:
        # Your custom evaluation logic here
        ...
```

Attach your custom evaluator to the builder:

```python
my_evaluator = MyTxEvaluator()
builder.set_evaluator(my_evaluator)
```

<hr>

## **Building and Testing**

While the underlying [libcardano-c](https://github.com/Biglup/cardano-c) library has its own comprehensive test suite, Cometa.py maintains a separate, dedicated suite of tests. These binding-level tests verify the correctness of the Python-to-C interface and ensure the high-level API functions as expected.

To build and run the tests, use the following commands:

```bash
pip install -e ".[dev]"
pytest
```

To run the linter:

```bash
pylint src/cometa
```

<hr>

## **License**

Cometa.py is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for more information.
