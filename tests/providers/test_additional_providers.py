"""Provider contracts, malformed responses, and real HTTP request boundaries."""

import copy
import hashlib
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock

import pytest

from cometa import KoiosProvider, KupmiosProvider, HydraProvider, CardanoError, TransactionInput
from cometa.providers._http import Http, ProviderHttpError, ProviderTimeoutError, decode_json
from cometa.providers._hydra import hydra_outputs
from cometa.providers._outputs import koios_output, ogmios_output
from cometa.providers._protocol import parameters
from cometa.providers._values import cbor, hash_text, transaction

ROOT = Path(__file__).parent / 'fixtures'
KOIOS = decode_json((ROOT / 'koios-utxos.json').read_bytes())
PARAMS = decode_json((ROOT / 'ogmios-parameters.json').read_bytes())['result']
HYDRA_PARAMS = decode_json((ROOT / 'hydra-parameters.json').read_bytes())
HYDRA = decode_json((ROOT / 'hydra-utxos.json').read_bytes())
ADDRESS = KOIOS[0]['address']
STAKE = 'stake_test1uppy2gm2hqzkwc80em4mlat73j4jyqvzhclrvsu72g9xg4q2yweet'
TX = '84a3008001800200a0f5f6'
TX_ID = hash_text(transaction(TX).id)
DATUM = '1801'
DATUM_HASH = hashlib.blake2b(bytes.fromhex(DATUM), digest_size=32).hexdigest()
POLICY = 'ab' * 28


def provider(name):
    if name == 'Koios':
        return KoiosProvider(1, base_url='http://koios.test', poll_interval_ms=1)
    if name == 'Kupmios':
        return KupmiosProvider(1, 'http://kupo.test', 'http://ogmios.test', poll_interval_ms=1)
    return HydraProvider(1, 'http://hydra.test', poll_interval_ms=1)


def rpc(value):
    return {'jsonrpc': '2.0', 'id': 'cometa', 'result': value}


def wire_output(name, quantity=1):
    if name == 'Koios':
        return {'tx_hash': TX_ID, 'tx_index': 0, 'address': ADDRESS, 'value': '3000000', 'is_spent': False,
                'asset_list': [{'policy_id': POLICY, 'asset_name': '', 'quantity': str(quantity)}],
                'inline_datum': {'bytes': DATUM}, 'datum_hash': DATUM_HASH, 'reference_script': None}
    if name == 'Kupmios':
        return {'transaction_id': TX_ID, 'output_index': 0, 'address': ADDRESS, 'spent_at': None,
                'value': {'coins': 3000000, 'assets': {POLICY + '.': quantity}}, 'datum_hash': DATUM_HASH,
                'datum_type': 'inline', 'script_hash': None, 'created_at': {'slot_no': 1, 'header_hash': 'aa' * 32}}
    return {f'{TX_ID}#0': {'address': ADDRESS, 'value': {'lovelace': 3000000, POLICY: {'': quantity}},
                          'inlineDatumRaw': DATUM, 'inlineDatumhash': DATUM_HASH, 'datumhash': None, 'referenceScript': None}}


def install_outputs(instance, name, quantity=1):
    row = wire_output(name, quantity)
    def query(path, *args, **kwargs):
        if path[0] == 'datums':
            return {'datum': DATUM}
        if path[0] == 'datum_info':
            return [{'datum_hash': DATUM_HASH, 'bytes': DATUM}]
        return row if name == 'Hydra' else [row]
    transport = instance._kupo if name == 'Kupmios' else instance._http
    transport.json = Mock(side_effect=query)
    return transport


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_names_network_and_complete_parameters(name):
    instance = provider(name)
    if name == 'Hydra':
        instance._http.json = Mock(return_value=HYDRA_PARAMS)
    else:
        instance._node.json = Mock(return_value=rpc(PARAMS))
    result = instance.get_parameters()
    assert instance.get_name() == name
    assert instance.get_network_magic() == 1
    assert result.ref_script_cost_stride == 25600
    assert result.ref_script_cost_multiplier.numerator == 6
    assert result.ref_script_cost_multiplier.denominator == 5
    assert result.protocol_version.major in (9, 11)
    assert result.drep_voting_thresholds is not None
    assert result.pool_voting_thresholds is not None
    if name != 'Hydra':
        assert result.execution_costs.steps_prices.numerator == 721
        assert result.execution_costs.steps_prices.denominator == 10000000
        assert result.min_fee_a == 44


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_every_output_query_and_original_datum_bytes(name):
    instance = provider(name)
    transport = install_outputs(instance, name)
    outputs = instance.get_unspent_outputs(ADDRESS)
    assert len(outputs) == 1
    assert cbor(outputs[0].output.datum.get_inline_data()) == DATUM
    assert len(instance.get_unspent_outputs_with_asset(ADDRESS, POLICY)) == 1
    assert instance.get_unspent_outputs_with_asset(ADDRESS, 'cd' * 28) == []
    assert instance.get_unspent_output_by_nft(POLICY).input == outputs[0].input
    assert len(instance.resolve_unspent_outputs([outputs[0].input, outputs[0].input])) == 1
    assert instance.resolve_datum(DATUM_HASH) == DATUM
    if name == 'Kupmios':
        match_calls = [call for call in transport.json.call_args_list if call.args[0][0] == 'matches']
        assert all(call.args[1]['unspent'] is None for call in match_calls)
        assert any(call.args[1].get('asset_name') == '' for call in match_calls)


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_fungible_quantity_cannot_pass_nft_lookup(name):
    instance = provider(name)
    install_outputs(instance, name, quantity=2)
    with pytest.raises(ValueError, match='exactly one'):
        instance.get_unspent_output_by_nft(POLICY)


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_zero_deadline_does_not_send_request(name):
    instance = provider(name)
    instance._confirmed = Mock(side_effect=AssertionError('Unexpected request'))
    assert instance.confirm_transaction(TX_ID, 0) is False


@pytest.mark.parametrize('name', ['Koios', 'Kupmios'])
def test_rewards_submission_and_evaluation(name):
    instance = provider(name)
    if name == 'Koios':
        instance._http.json = Mock(return_value=[{'stake_address': STAKE, 'rewards_available': '123456789'}])
    else:
        from cometa import RewardAddress
        expected = RewardAddress.from_bech32(STAKE).credential.hash_hex
        instance._node.json = Mock(return_value=rpc([{'credential': expected, 'from': 'verificationKey', 'rewards': {'ada': {'lovelace': 123456789}}}]))
    assert instance.get_rewards_balance(STAKE) == 123456789
    instance._node.json = Mock(return_value=rpc({'transaction': {'id': TX_ID}}))
    assert instance.submit_transaction(TX) == TX_ID
    assert instance._node.json.call_count == 1
    instance._node.json = Mock(return_value=rpc([]))
    assert instance.evaluate_transaction(TX) == []
    additional = koios_output(KOIOS[0])
    assert instance.evaluate_transaction(TX, [additional]) == []
    sent = instance._node.json.call_args.kwargs['body']['params']['additionalUtxo']
    assert sent == [ogmios_output(additional)]


@pytest.mark.parametrize('name', ['Koios', 'Kupmios'])
def test_rejects_rpc_identity_and_submission_mismatch(name):
    instance = provider(name)
    for reply in [{'jsonrpc': '1.0', 'id': 'cometa', 'result': PARAMS},
                  {'jsonrpc': '2.0', 'id': 'wrong', 'result': PARAMS},
                  {'jsonrpc': '2.0', 'id': 'cometa', 'error': {'message': 'secret'}},
                  {'jsonrpc': '2.0', 'id': 'cometa', 'result': {'transaction': {'id': 'bb' * 32}}}]:
        instance._node.json = Mock(return_value=reply)
        with pytest.raises(CardanoError) as error:
            instance.submit_transaction(TX)
        assert 'secret' not in str(error.value)
        assert instance._node.json.call_count == 1


@pytest.mark.parametrize('name', ['Koios', 'Kupmios'])
def test_confirmation_checks_identity(name):
    instance = provider(name)
    transport = instance._http if name == 'Koios' else instance._kupo
    row = {'tx_hash': TX_ID, 'num_confirmations': 1} if name == 'Koios' else wire_output(name)
    transport.json = Mock(return_value=[row])
    assert instance.confirm_transaction(TX_ID, 100)
    row['tx_hash' if name == 'Koios' else 'transaction_id'] = 'bb' * 32
    with pytest.raises(CardanoError):
        instance.confirm_transaction(TX_ID, 100)


def test_hydra_l2_submission_and_confirmation_contract():
    instance = provider('Hydra')
    instance._http.request = Mock(return_value=(202, {'tag': 'SubmitTxSubmitted'}))
    assert instance.submit_transaction(TX) == TX_ID
    assert instance._http.request.call_args.args == (['transaction'],)
    instance._http.json = Mock(return_value={'tag': 'InitialSnapshot'})
    assert not instance.confirm_transaction(TX_ID, 2)
    instance._http.json = Mock(return_value={'tag': 'ConfirmedSnapshot', 'snapshot': {'number': 1, 'confirmed': [{'cborHex': TX, 'txId': TX_ID}]}})
    assert instance.confirm_transaction(TX_ID, 100)
    instance._http.json = Mock(return_value={'tag': 'ConfirmedSnapshot', 'snapshot': {'number': 1, 'confirmed': [{'cborHex': TX, 'txId': 'aa' * 32}]}})
    with pytest.raises(CardanoError):
        instance.confirm_transaction(TX_ID, 100)
    with pytest.raises(NotImplementedError):
        instance.get_rewards_balance(STAKE)
    with pytest.raises(NotImplementedError):
        instance.evaluate_transaction(TX)


def test_koios_pagination_rejects_duplicates():
    instance = provider('Koios')
    row = wire_output('Koios')
    instance._http.json = Mock(return_value=[row, row])
    with pytest.raises(CardanoError):
        instance.get_unspent_outputs(ADDRESS)


def test_codec_fixtures_include_scripts_and_exact_integers():
    outputs = [koios_output(row) for row in KOIOS]
    assert any(output.output.script_ref is not None for output in outputs)
    for output in outputs:
        encoded = ogmios_output(output)
        assert isinstance(encoded['value']['ada']['lovelace'], int)
    assert len(hydra_outputs(HYDRA)) == 2
    row = wire_output('Koios')
    row['value'] = '9007199254740993'
    assert koios_output(row).output.value.coin == 9007199254740993


@pytest.mark.parametrize('mutation', ['negative', 'duplicate_asset', 'datum_hash', 'script_hash', 'spent_flag'])
def test_rejects_malformed_koios_outputs(mutation):
    row = wire_output('Koios')
    if mutation == 'negative':
        row['value'] = '-1'
    elif mutation == 'duplicate_asset':
        row['asset_list'].append({'policy_id': POLICY.upper(), 'asset_name': '', 'quantity': '1'})
    elif mutation == 'datum_hash':
        row['datum_hash'] = '00' * 32
    elif mutation == 'script_hash':
        row['reference_script'] = {'type': 'plutusV3', 'bytes': '0102', 'hash': '00' * 28}
    else:
        row['is_spent'] = 'false'
    with pytest.raises(CardanoError):
        koios_output(row)


def test_protocol_fee_tiers_and_governance_bounds():
    data = copy.deepcopy(PARAMS)
    data['maxReferenceScriptsSizePerTransaction'] = {'bytes': 12345}
    data['maxReferenceScriptsSizePerBlock'] = {'bytes': 54321}
    result = parameters(data)
    assert result.max_ref_script_size_per_tx == 12345
    assert result.max_ref_script_size_per_block == 54321
    data['monetaryExpansion'] = '2/1'
    with pytest.raises(CardanoError):
        parameters(data)


@contextmanager
def server(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            handler(self)
        def do_POST(self):
            handler(self)
        def log_message(self, *args):
            pass
    service = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{service.server_port}'
    finally:
        service.shutdown()
        service.server_close()
        thread.join()


def reply(request, status, body):
    request.send_response(status)
    request.send_header('Content-Length', str(len(body)))
    request.end_headers()
    request.wfile.write(body)


def test_http_bare_flags_empty_values_and_rpc_exact_numbers():
    received = []
    def handler(request):
        received.append(request.path)
        reply(request, 200, b'{"quantity":9007199254740993,"price":0.0000721}')
    with server(handler) as endpoint:
        client = Http(endpoint + '/api?unspent=wrong&tenant=fixture')
        result = client.json(['matches', 'space / value'], {'unspent': None, 'asset_name': ''})
        assert received == ['/api/matches/space%20%2F%20value?tenant=fixture&unspent&asset_name=']
        assert result['quantity'] == 9007199254740993
        assert str(result['price']) == '0.0000721'


@pytest.mark.parametrize('status', [301, 400, 401, 403, 429, 500])
def test_http_statuses_do_not_retry_or_leak_credentials(status):
    calls = []
    def handler(request):
        calls.append(request.path)
        reply(request, status, b'private-server-secret')
    with server(handler) as endpoint:
        with pytest.raises(ProviderHttpError) as error:
            Http(endpoint, token='private-token').json()
        assert error.value.status == status
        assert 'private' not in str(error.value)
        assert len(calls) == 1


def test_http_deadline_covers_body_read_and_recovers():
    started = threading.Event()
    def handler(request):
        request.send_response(200)
        request.send_header('Content-Length', '2')
        request.end_headers()
        started.set()
        time.sleep(0.15)
        try:
            request.wfile.write(b'[]')
        except (BrokenPipeError, ConnectionResetError):
            pass
    with server(handler) as endpoint:
        client = Http(endpoint, timeout_ms=30)
        before = time.monotonic()
        with pytest.raises(ProviderTimeoutError):
            client.json()
        assert time.monotonic() - before < 0.14
        assert started.is_set()


@pytest.mark.parametrize('url', ['ftp://example.com', 'http://user:password@example.com', 'http://localhost/#secret', 'http://localhost:99999'])
def test_invalid_endpoints_hide_secrets(url):
    with pytest.raises(ValueError) as error:
        Http(url)
    assert 'password' not in str(error.value)
    assert 'secret' not in str(error.value)


@pytest.mark.parametrize('name', ['Koios', 'Kupmios'])
def test_evaluation_matches_all_redeemer_purposes_and_preserves_data(name):
    from cometa import Redeemer, RedeemerTag, PlutusData, ExUnits
    instance = provider(name)
    tx = transaction(TX)
    purposes = ['spend', 'mint', 'publish', 'withdraw', 'vote', 'propose']
    original = [Redeemer.new(RedeemerTag(index), index, PlutusData.from_int(index + 42), ExUnits.new(0, 0)) for index in range(6)]
    witnesses = tx.witness_set
    witnesses.redeemers = original
    tx.witness_set = witnesses
    tx.clear_cbor_cache()
    budgets = [{'validator': {'purpose': purpose, 'index': index}, 'budget': {'memory': index + 1, 'cpu': index + 100}}
               for index, purpose in enumerate(purposes)]
    instance._node.json = Mock(return_value=rpc(list(reversed(budgets))))
    result = instance.evaluate_transaction(cbor(tx))
    assert [(item.tag, item.index, item.data.to_int(), item.ex_units.memory, item.ex_units.cpu_steps) for item in result] == [
        (RedeemerTag(index), index, index + 42, index + 1, index + 100) for index in range(6)]
    for invalid_budgets in [budgets[:-1], budgets + [budgets[0]], budgets + [{'validator': {'purpose': 'other', 'index': 0}, 'budget': {'memory': 1, 'cpu': 1}}]]:
        instance._node.json = Mock(return_value=rpc(invalid_budgets))
        with pytest.raises(CardanoError):
            instance.evaluate_transaction(cbor(tx))


@pytest.mark.parametrize('language', [1, 2, 3, 4])
def test_reference_script_roundtrip(language):
    from cometa import Script, CborReader, CborWriter
    from cometa.providers._outputs import script_bytes
    raw = '01020304'
    writer = CborWriter()
    writer.write_bytes(bytes.fromhex(raw))
    expected = Script.from_cbor(CborReader.from_hex(f'820{language}' + writer.to_hex()))
    actual = script_bytes(f'plutus:v{language}', raw, expected.hash.hex())
    assert actual.hash == expected.hash
    row = wire_output('Koios')
    row['reference_script'] = {'type': f'plutusV{language}', 'bytes': raw, 'hash': expected.hash.hex()}
    encoded = ogmios_output(koios_output(row))
    assert encoded['script'] == {'language': f'plutus:v{language}', 'cbor': raw}


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_missing_datum_and_wrong_hash_never_return_unverified_bytes(name):
    instance = provider(name)
    install_outputs(instance, name)
    with pytest.raises(CardanoError):
        instance.resolve_datum('00' * 32)


@pytest.mark.parametrize('name', ['Koios', 'Kupmios', 'Hydra'])
def test_output_resolution_preserves_order_and_rejects_extra_rows(name):
    instance = provider(name)
    install_outputs(instance, name)
    unknown = TransactionInput.from_hex('dd' * 32, 0)
    if name == 'Hydra':
        assert instance.resolve_unspent_outputs([unknown]) == []
    else:
        with pytest.raises(CardanoError):
            instance.resolve_unspent_outputs([unknown])


def test_response_size_limit(monkeypatch):
    import cometa.providers._http as transport
    monkeypatch.setattr(transport, 'MAX_RESPONSE_BYTES', 16)
    with server(lambda request: reply(request, 200, b'[' + b' ' * 32 + b']')) as endpoint:
        with pytest.raises(CardanoError, match='size limit'):
            Http(endpoint).json()


@pytest.mark.parametrize('payload', [b'{"a":NaN}', b'{"a":Infinity}', b'not json'])
def test_invalid_json(payload):
    with pytest.raises(CardanoError):
        decode_json(payload)


def test_koios_pagination_advances_and_retains_first_request_order():
    instance = provider('Koios')
    rows = []
    for index in range(101):
        row = wire_output('Koios')
        row['tx_index'] = index
        rows.append(row)
    instance._http.json = Mock(side_effect=[rows[:100], rows[100:]])
    outputs = instance.get_unspent_outputs(ADDRESS)
    assert [item.input.index for item in outputs] == list(range(101))
    calls = instance._http.json.call_args_list
    assert [call.args[1]['offset'] for call in calls] == ['0', '100']
    assert all(call.args[1]['order'] == 'tx_hash.asc,tx_index.asc' for call in calls)
    instance._http.json = Mock(return_value=[rows[1], rows[0]])
    requested = [outputs[0].input, outputs[1].input, outputs[0].input]
    assert [item.input.index for item in instance.resolve_unspent_outputs(requested)] == [0, 1]


def test_koios_repeated_page_is_rejected():
    instance = provider('Koios')
    rows = []
    for index in range(100):
        row = wire_output('Koios')
        row['tx_index'] = index
        rows.append(row)
    instance._http.json = Mock(side_effect=[rows, rows])
    with pytest.raises(CardanoError):
        instance.get_unspent_outputs(ADDRESS)
    assert instance._http.json.call_count == 2
