"""Regression tests for the wallet used by the runnable examples."""

import runpy
from pathlib import Path
from types import SimpleNamespace

from cometa import (
    Credential, EnterpriseAddress, NetworkId, NetworkMagic, ProtocolParameters,
    ScriptAll, TransactionInput, TransactionOutput, UnitInterval, Utxo,
)
from cometa.transaction_builder import compute_transaction_fee


def test_script_only_transaction_budgets_the_wallet_payment_witness():
    namespace = runpy.run_path(str(Path(__file__).parents[1] / 'examples/single_address_wallet.py'))
    params = ProtocolParameters.new()
    params.min_fee_a = 44
    params.min_fee_b = 155381
    params.coins_per_utxo_byte = 4310
    params.max_tx_size = 16384
    params.max_value_size = 5000
    params.ref_script_cost_per_byte = UnitInterval.new(15, 1)
    provider = SimpleNamespace(
        get_network_magic=lambda: NetworkMagic.PREPROD,
        get_parameters=lambda: params,
        get_unspent_outputs=lambda _address: [],
    )
    wallet = namespace['SingleAddressWallet'].create_from_mnemonics(
        mnemonics=('antenna whale clutch cushion narrow chronic matrix alarm raise much '
                   'stove beach mimic daughter review build dinner twelve orbit soap '
                   'decorate bachelor athlete close').split(),
        provider=provider,
        credentials_config=namespace['SingleAddressCredentialsConfig'](
            account=0, payment_index=0, staking_index=0),
        get_password=lambda: b'wallet-regression-test',
    )
    script = ScriptAll.new([])
    address = EnterpriseAddress.from_credentials(
        NetworkId.TESTNET, Credential.from_script_hash(script.hash)).to_address()
    utxo = Utxo.new(TransactionInput.from_hex('ab' * 32, 0),
                   TransactionOutput.new(address, 12_000_000))
    tx = (wallet.create_transaction_builder().add_input(utxo).add_script(script)
          .send_lovelace(wallet.get_address(), 2_000_000).build())
    assert len(tx.body.inputs) == 1
    assert len(tx.body.required_signers) == 1
    tx.apply_vkey_witnesses(wallet.sign_transaction(tx))
    assert tx.body.fee >= compute_transaction_fee(tx, [utxo], params)
