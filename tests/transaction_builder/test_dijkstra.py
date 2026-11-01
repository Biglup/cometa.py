"""Dijkstra transaction flows through the public Python API and native evaluator."""

import gc

import pytest

from cometa import (
    AccountBalanceInterval, Address, CardanoError, CborReader, CborWriter,
    CostModel, Costmdls, Credential, Ed25519PrivateKey, Ed25519Signature, EnterpriseAddress,
    ExUnitPrices, ExUnits, NativeScript, NativeScriptType, NativeTxEvaluator,
    NetworkId, PlutusV4Script, PlutusLanguageVersion, ProtocolVersion,
    Script, ScriptRequireGuard, SlotConfig, SoftwareEd25519SecureKeyHandler,
    SubTransaction, SubTransactionBuilder, Transaction, TransactionInput,
    TransactionOutput, TxBuilder, UnitInterval, Utxo,
)
from cometa._ffi import ffi, lib
from .test_tx_builder import (
    create_protocol_params, create_test_utxo, DIJKSTRA_COSTS,
    TEST_ADDRESS, TEST_ADDRESS_2, STAKE_ADDRESS,
)


@pytest.fixture
def params():
    value = create_protocol_params()
    value.protocol_version = ProtocolVersion.new(12, 0)
    value.execution_costs = ExUnitPrices.new(UnitInterval.new(577, 10000), UnitInterval.new(721, 10000000))
    value.ref_script_cost_per_byte = UnitInterval.new(15, 1)
    value.max_tx_ex_units = ExUnits.new(14_000_000, 10_000_000_000)
    costs = Costmdls.new()
    costs.insert(CostModel.new(PlutusLanguageVersion.V4, DIJKSTRA_COSTS))
    value.cost_models = costs
    return value


def batcher(params):
    return (TxBuilder(params, SlotConfig.preprod())
            .set_utxos([create_test_utxo(index=10, lovelace=50_000_000)])
            .set_change_address(TEST_ADDRESS)
            .set_collateral_utxos([create_test_utxo(index=11, lovelace=10_000_000)])
            .set_collateral_change_address(TEST_ADDRESS))


def script_input():
    script = PlutusV4Script.from_hex("450100002499")
    address = EnterpriseAddress.from_credentials(
        NetworkId.TESTNET, Credential.from_script_hash(script.hash)).to_address()
    utxo = Utxo.new(TransactionInput.from_hex("aa" * 32, 0), TransactionOutput.new(address, 20_000_000))
    return script, utxo


def key_handler():
    key = Ed25519PrivateKey.from_extended_hex("10" * 64)
    handler = SoftwareEd25519SecureKeyHandler.from_ed25519_key(key, b"test", lambda: b"test")
    return handler


def test_direct_deposits_and_balance_constraints(params):
    interval = AccountBalanceInterval.new(1_000_000, 10_000_000)
    exact = AccountBalanceInterval.new_exact(2_000_000)
    tx = (batcher(params).add_direct_deposit(STAKE_ADDRESS, 2_000_000)
          .add_direct_deposit(STAKE_ADDRESS, 3_000_000)
          .add_account_balance_interval(STAKE_ADDRESS, interval)
          .add_starting_account_balance_interval(STAKE_ADDRESS, exact).build())
    tx = Transaction.from_cbor(CborReader.from_hex(tx.serialize_to_cbor()))
    assert tx.body.direct_deposits == {STAKE_ADDRESS: 5_000_000}
    assert tx.body.account_balance_intervals[STAKE_ADDRESS].inclusive_lower_bound == 1_000_000
    assert tx.body.account_balance_intervals[STAKE_ADDRESS].exclusive_upper_bound == 10_000_000
    assert tx.body.starting_account_balance_intervals[STAKE_ADDRESS].exact_balance == 2_000_000
    assert sum(output.value.coin for output in tx.body.outputs) + tx.body.fee + 5_000_000 == 50_000_000


@pytest.mark.parametrize("amount", [0, -1, 2**63, 1.5, True])
def test_invalid_deposit_amount(params, amount):
    with pytest.raises(ValueError):
        batcher(params).add_direct_deposit(STAKE_ADDRESS, amount)


@pytest.mark.parametrize("exact,lower,upper", [(0, None, None), (2**64-1, None, None), (None, 3, 9), (None, None, 9), (None, 3, None)])
def test_interval_encoding(exact, lower, upper):
    interval = AccountBalanceInterval.new_exact(exact) if exact is not None else AccountBalanceInterval.new(lower, upper)
    writer = CborWriter()
    interval.to_cbor(writer)
    decoded = AccountBalanceInterval.from_cbor(CborReader.from_hex(writer.to_hex()))
    assert decoded.exact_balance == exact
    assert decoded.is_exact == (exact is not None)
    assert decoded.inclusive_lower_bound == lower
    assert decoded.exclusive_upper_bound == upper


def test_signed_intent_roundtrip_and_batch_value_conservation(params):
    handler = key_handler()
    credential = Credential.from_key_hash(handler.get_public_key().to_hash())
    address = EnterpriseAddress.from_credentials(NetworkId.TESTNET, credential).to_address()
    party = create_test_utxo(index=0, address=str(address), lovelace=10_000_000)
    sub = (SubTransactionBuilder(params, SlotConfig.preprod()).add_input(party)
           .send_lovelace(TEST_ADDRESS_2, 15_000_000).require_top_level_guard(credential, 42).build())
    original_id = sub.id.to_hex()
    witnesses = handler.sign_sub_transaction(sub)
    sub.apply_vkey_witnesses(witnesses)
    encoded = sub.serialize_to_cbor()
    sub = SubTransaction.from_cbor(CborReader.from_hex(encoded))
    assert sub.serialize_to_cbor() == encoded
    assert sub.id.to_hex() == original_id
    assert sub.body.required_top_level_guards[0][1].to_int() == 42
    tx = batcher(params).add_guard(credential).add_sub_transaction(sub, [party]).build()
    included = tx.body.sub_transactions[0]
    assert included.serialize_to_cbor() == encoded
    witness = included.witness_set.vkeys[0]
    assert handler.get_public_key().verify(Ed25519Signature.from_bytes(witness.signature), included.id.to_bytes())
    assert sum(o.value.coin for o in tx.body.outputs) + tx.body.fee == 45_000_000
    assert len(tx.body.guards) == 1


def test_sub_transaction_has_no_top_level_configuration(params):
    builder = SubTransactionBuilder(params, SlotConfig.preprod())
    for method in ('set_utxos', 'set_change_address', 'set_collateral_utxos', 'set_evaluator', 'add_sub_transaction'):
        assert not hasattr(builder, method)


def test_sub_transaction_deposits_and_intervals(params):
    sub = (SubTransactionBuilder(params, SlotConfig.preprod())
           .add_direct_deposit(STAKE_ADDRESS, 3_000_000)
           .add_account_balance_interval(STAKE_ADDRESS, AccountBalanceInterval.new_exact(1))
           .build())
    assert sub.body.direct_deposits == {STAKE_ADDRESS: 3_000_000}
    assert sub.body.account_balance_intervals[STAKE_ADDRESS].exact_balance == 1
    tx = batcher(params).add_sub_transaction(sub, []).build()
    assert sum(o.value.coin for o in tx.body.outputs) + tx.body.fee == 47_000_000


def test_v4_sub_transaction_deferred_spend_and_evaluation(params):
    script, utxo = script_input()
    calls = []
    def redeemer(draft, inputs):
        calls.append((draft, inputs))
        return 7
    sub = (SubTransactionBuilder(params, SlotConfig.preprod()).add_script(script)
           .add_input(utxo, redeemer=redeemer).send_lovelace(TEST_ADDRESS, 20_000_000).build())
    assert len(calls) == 1
    assert calls[0][0].body.inputs[0] == utxo.input
    assert sub.witness_set.redeemers[0].data.to_int() == 7
    assert sub.witness_set.redeemers[0].ex_units.cpu_steps > 0
    tx = batcher(params).add_sub_transaction(sub, [utxo]).build()
    evaluator = NativeTxEvaluator.from_parameters(params, SlotConfig.preprod(), sub_transaction_index=0)
    result = evaluator.evaluate(tx, [utxo, create_test_utxo(index=10, lovelace=50_000_000)])
    assert len(result) == 1
    assert result[0].ex_units.cpu_steps > 0
    assert tx.body.total_collateral > 0


def test_sub_callback_exception_preserves_cause(params):
    script, utxo = script_input()
    def fail(_draft, _inputs):
        raise ValueError('broken redeemer')
    builder = SubTransactionBuilder(params, SlotConfig.preprod()).add_script(script).add_input(utxo, redeemer=fail)
    with pytest.raises(CardanoError) as caught:
        builder.build()
    assert isinstance(caught.value.__cause__, ValueError)


def test_guard_native_script_roundtrip_and_build(params):
    credential = Credential.from_key_hash(key_handler().get_public_key().to_hash())
    required = ScriptRequireGuard.new(credential)
    native = NativeScript.from_require_guard(required)
    assert native.script_type == NativeScriptType.REQUIRE_GUARD
    assert native.to_require_guard().credential == credential
    script = Script.from_native(required)
    address = EnterpriseAddress.from_credentials(NetworkId.TESTNET, Credential.from_script_hash(script.hash)).to_address()
    utxo = create_test_utxo(address=str(address), lovelace=10_000_000)
    tx = batcher(params).add_input(utxo).add_script(required).add_guard(credential).build()
    assert len(tx.body.guards) == 1


@pytest.mark.parametrize('sub_level', [False, True])
def test_v4_guard_evaluation(params, sub_level):
    script, _ = script_input()
    credential = Credential.from_script_hash(script.hash)
    if sub_level:
        sub = (SubTransactionBuilder(params, SlotConfig.preprod()).add_script(script)
               .add_guard(credential, redeemer=0).build())
        tx = batcher(params).add_sub_transaction(sub, []).build()
    else:
        tx = batcher(params).add_script(script).add_guard(credential, redeemer=0).build()
    redeemers = tx.body.sub_transactions[0].witness_set.redeemers if sub_level else tx.witness_set.redeemers
    assert redeemers[0].ex_units.cpu_steps > 0


def test_repeated_reads_release_native_references(params):
    guard = Credential.from_key_hash(key_handler().get_public_key().to_hash())
    interval = AccountBalanceInterval.new_exact(0)
    sub = (SubTransactionBuilder(params, SlotConfig.preprod()).require_top_level_guard(guard)
           .add_direct_deposit(STAKE_ADDRESS, 1).add_account_balance_interval(STAKE_ADDRESS, interval).build())
    tx = batcher(params).add_guard(guard).add_sub_transaction(sub, []).build()
    base_refs = lib.cardano_sub_transaction_refcount(sub._ptr)
    for _ in range(100):
        assert tx.body.sub_transactions[0].body.direct_deposits[STAKE_ADDRESS] == 1
        assert tx.body.sub_transactions[0].body.account_balance_intervals[STAKE_ADDRESS].exact_balance == 0
        assert tx.body.sub_transactions[0].body.required_top_level_guards[0][0] == guard
        assert tx.body.guards[0] == guard
    gc.collect()
    assert lib.cardano_sub_transaction_refcount(sub._ptr) == base_refs


def test_bip32_sub_transaction_signature(params):
    from cometa import SoftwareBip32SecureKeyHandler, DerivationPath, KeyDerivationRole, Ed25519PublicKey, harden
    handler = SoftwareBip32SecureKeyHandler.from_entropy(b'\x01' * 32, b'test', lambda: b'test')
    path = DerivationPath(harden(1852), harden(1815), harden(0), KeyDerivationRole.EXTERNAL, 0)
    sub = SubTransactionBuilder(params, SlotConfig.preprod()).send_lovelace(TEST_ADDRESS, 2_000_000).build()
    witnesses = handler.sign_sub_transaction(sub, [path])
    witness = witnesses[0]
    assert Ed25519PublicKey.from_bytes(witness.vkey).verify(
        Ed25519Signature.from_bytes(witness.signature), sub.id.to_bytes())
    sub.apply_vkey_witnesses(witnesses)
    assert SubTransaction.from_cbor(CborReader.from_hex(sub.serialize_to_cbor())).id == sub.id


def test_missing_required_guard_is_rejected(params):
    credential = Credential.from_key_hash(key_handler().get_public_key().to_hash())
    sub = (SubTransactionBuilder(params, SlotConfig.preprod()).require_top_level_guard(credential)
           .send_lovelace(TEST_ADDRESS, 2_000_000).build())
    with pytest.raises(CardanoError):
        batcher(params).add_sub_transaction(sub, []).build()


@pytest.mark.parametrize('bounds', [(10, 5), (-1, None), (None, 2**64)])
def test_invalid_interval(bounds):
    with pytest.raises((ValueError, CardanoError)):
        AccountBalanceInterval.new(*bounds)


def test_sub_body_fields_and_cbor(params):
    sub = (SubTransactionBuilder(params, SlotConfig.preprod()).set_network_id(NetworkId.TESTNET)
           .set_valid_from(slot=10).set_valid_until(slot=100)
           .send_lovelace(TEST_ADDRESS, 2_000_000).build())
    body = sub.body
    assert body.invalid_before == 10
    assert body.invalid_after == 100
    assert body.network_id == NetworkId.TESTNET
    assert body.hash == sub.id
    for field in ('certificates', 'withdrawals', 'aux_data_hash', 'mint', 'script_data_hash',
                  'reference_inputs', 'voting_procedures', 'proposal_procedures', 'treasury_value', 'donation'):
        assert getattr(body, field) is None
    assert body.guards == []
    assert body.required_top_level_guards == []
    assert body.direct_deposits == {}
    assert body.account_balance_intervals == {}


def test_native_guard_composition(params):
    from cometa import ScriptAll
    credential = Credential.from_key_hash(key_handler().get_public_key().to_hash())
    required = ScriptRequireGuard.new(credential)
    composed = Script.from_native(ScriptAll.new([required]))
    address = EnterpriseAddress.from_credentials(NetworkId.TESTNET, Credential.from_script_hash(composed.hash)).to_address()
    utxo = create_test_utxo(address=str(address), lovelace=10_000_000)
    tx = batcher(params).add_script(composed).add_input(utxo).add_guard(credential).build()
    assert tx.body.guards[0] == credential


def test_guard_script_in_witness_set():
    from cometa import WitnessSet
    credential = Credential.from_key_hash(key_handler().get_public_key().to_hash())
    witness_set = WitnessSet()
    witness_set.native_scripts = [ScriptRequireGuard.new(credential)]
    assert witness_set.native_scripts[0].to_require_guard().credential == credential
