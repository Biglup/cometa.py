"""Native Plutus evaluation, protocol gating and reference ownership."""

import gc

import pytest

from cometa import (
    CardanoError, Credential, EnterpriseAddress, ExUnits, NativeTxEvaluator,
    NetworkId, PlutusData, PlutusV3Script, Redeemer, RedeemerTag, SlotConfig,
    Transaction, TransactionBody, TransactionInput, TransactionOutput, Utxo, WitnessSet,
)
from cometa._ffi import ffi, lib


def spending_transaction(script_hex="450100002499"):
    # (program 1.0.0 (lam ctx (con unit ())))
    script = PlutusV3Script.from_hex(script_hex)
    address = EnterpriseAddress.from_credentials(
        NetworkId.TESTNET, Credential.from_script_hash(script.hash)).to_address()
    tx_input = TransactionInput.from_hex("00" * 32, 0)
    utxo = Utxo.new(tx_input, TransactionOutput.new(address, 10_000_000))
    witnesses = WitnessSet()
    witnesses.plutus_v3_scripts = [script]
    witnesses.redeemers = [Redeemer.new(
        RedeemerTag.SPEND, 0, PlutusData.from_int(0), ExUnits.new(0, 0))]
    body = TransactionBody.new(
        [tx_input], [TransactionOutput.new(address, 9_000_000)], 1_000_000)
    return Transaction.new(body, witnesses), utxo


def test_native_evaluation_returns_actual_units_and_preserves_inputs():
    tx, utxo = spending_transaction()
    evaluator = NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=10)
    for _ in range(20):
        result = evaluator.evaluate(tx, [utxo])
        assert len(result) == 1
        assert result[0].tag == RedeemerTag.SPEND
        assert result[0].ex_units.memory == 500
        assert result[0].ex_units.cpu_steps == 64100
    assert tx.witness_set.redeemers[0].ex_units.memory == 0
    assert lib.cardano_transaction_refcount(tx._ptr) == 1
    assert lib.cardano_utxo_refcount(utxo._ptr) == 1


def test_native_evaluation_rejects_unresolved_input():
    tx, _ = spending_transaction()
    evaluator = NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=10)
    with pytest.raises(CardanoError, match="Transaction evaluation failed"):
        evaluator.evaluate(tx, [])


def test_native_evaluation_gates_plutus_v3():
    tx, utxo = spending_transaction()
    evaluator = NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=8)
    with pytest.raises(CardanoError, match="Transaction evaluation failed"):
        evaluator.evaluate(tx, [utxo])


def test_native_evaluator_releases_its_reference():
    evaluator = NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=10)
    ptr = evaluator.ptr
    lib.cardano_tx_evaluator_ref(ptr)
    assert lib.cardano_tx_evaluator_refcount(ptr) == 2
    del evaluator
    gc.collect()
    try:
        assert lib.cardano_tx_evaluator_refcount(ptr) == 1
    finally:
        lib.cardano_tx_evaluator_unref(ffi.new("cardano_tx_evaluator_t **", ptr))


def test_plutus_v4_execution_and_protocol_gate():
    from cometa import PlutusV4Script, Script, ScriptLanguage
    script = PlutusV4Script.from_hex("450100002499")
    assert Script.from_plutus_v4(script).language == ScriptLanguage.PLUTUS_V4
    address = EnterpriseAddress.from_credentials(
        NetworkId.TESTNET, Credential.from_script_hash(script.hash)).to_address()
    tx_input = TransactionInput.from_hex("00" * 32, 0)
    utxo = Utxo.new(tx_input, TransactionOutput.new(address, 10_000_000))
    witnesses = WitnessSet()
    witnesses.plutus_v4_scripts = [script]
    witnesses.redeemers = [Redeemer.new(
        RedeemerTag.SPEND, 0, PlutusData.from_int(0), ExUnits.new(0, 0))]
    tx = Transaction.new(TransactionBody.new([tx_input], [], 0), witnesses)
    result = NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=12).evaluate(tx, [utxo])
    assert result[0].ex_units.cpu_steps == 64100
    assert result[0].ex_units.memory == 500
    with pytest.raises(CardanoError, match="Transaction evaluation failed"):
        NativeTxEvaluator(SlotConfig.mainnet(), protocol_major=10).evaluate(tx, [utxo])
