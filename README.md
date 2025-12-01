<div align="center">
  <a href="" target="_blank">
    <img align="center" width="300" src="assets/cometa_py.png">
  </a>
</div>

<br>

<div align="center">

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Post-Integration](https://github.com/Biglup/cometa.py/actions/workflows/ci.yml/badge.svg)
[![Documentation Status](https://app.readthedocs.org/projects/cometapy/badge/?version=latest)](https://cometapy.readthedocs.io/en/latest/?badge=latest)
[![Twitter Follow](https://img.shields.io/twitter/follow/BiglupLabs?style=social)](https://x.com/BiglupLabs)

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
builder = TxBuilder(protocol_params, provider)

unsigned_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .send_lovelace(recipient_address, 12_000_000)
    .set_valid_until(current_time + 3600)
    .build()
)
```

<hr>

## **Conway Era Support**

Cometa.py supports all features up to the Conway era, which is the current era of the Cardano blockchain. Conway era brought decentralized governance to Cardano, including:

- **DRep Registration**: Register as a Delegated Representative (DRep) using public keys or scripts
- **Voting**: Vote on governance proposals as a DRep, SPO, or Constitutional Committee member
- **Governance Actions**: Submit proposals for treasury withdrawals, parameter changes, hard forks, and more
- **Stake Delegation**: Delegate voting power to DReps

See the [Documentation](https://cometapy.readthedocs.io/) for more information on governance features.

<hr>

## **Installation**

You can install Cometa.py using pip:

```bash
pip install cometa-py
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

First, establish a connection to the Cardano network using a Provider:

```python
from cometa import BlockfrostProvider, NetworkMagic

provider = BlockfrostProvider(
    network=NetworkMagic.Preprod,
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
utxos = provider.get_utxos(sender_address)
protocol_params = provider.get_protocol_parameters()
```

Build your transaction using the fluent API:

```python
from cometa import TxBuilder

builder = TxBuilder(protocol_params, provider)

unsigned_tx = (
    builder
    .set_change_address(sender_address)
    .set_utxos(utxos)
    .send_lovelace(recipient_address, 2_000_000)  # Send 2 ADA
    .set_valid_until(current_time + 7200)  # Set TTL
    .build()
)
```

Sign the transaction with your private key:

```python

```

Submit the signed transaction:

```python
tx_hash = provider.submit_transaction(signed_tx)
print(f"Transaction submitted! TxHash: {tx_hash}")
```

You can see the full capabilities of the transaction builder in the [TxBuilder API documentation](https://cometapy.readthedocs.io/).

<hr>

## **Extending the Transaction Builder**

The `TxBuilder` API allows you to override its core logic for coin selection and transaction evaluation. If these custom implementations are not provided, the builder uses the following defaults:

- **Coin Selection**: A "Largest First" strategy via `LargeFirstCoinSelector`
- **Transaction Evaluation**: A remote service via the configured Provider (e.g., Blockfrost)

### Implementing a Custom CoinSelector

The coin selector is responsible for choosing which UTxOs to spend to cover the value required by the transaction's outputs. You can provide your own strategy by implementing the `CoinSelector` protocol:

```python
from typing import List
from cometa import Utxo, TransactionOutput, Value

class MyCoinSelector:
    """Custom coin selection strategy."""

    @property
    def name(self) -> str:
        return "MyCustomSelector"

    def select(
        self,
        pre_selected_utxo: List[Utxo],
        available_utxo: List[Utxo],
        target: Value,
    ) -> Tuple[List[Utxo], List[Utxo]]:
        # Your custom selection logic here
        ...
```

Attach your custom selector to the builder:

```python
my_selector = MyCoinSelector()
builder.set_coin_selector(my_selector)
```

### Implementing a Custom TxEvaluator

The transaction evaluator is responsible for calculating the execution units (ExUnits) for any Plutus scripts in a transaction. You can provide a custom implementation:

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
        # Could use a local evaluator or different service
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
