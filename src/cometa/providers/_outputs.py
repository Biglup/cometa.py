"""UTxO codecs authenticate datums and reference scripts before returning them."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

import json

from ..address import Address
from ..cbor import CborReader, CborWriter
from ..common import Datum
from ..common.utxo import Utxo
from ..plutus_data import PlutusData
from ..scripts import Script
from ..scripts.native_scripts import NativeScript
from ..transaction_body import TransactionInput, TransactionOutput, Value
from ._values import obj, array, integer, hex_text, address_text, datum_bytes, cbor, invalid, hash_text


def inline_datum(encoded, expected=None):
    """Create an inline datum after validating its original encoding and hash."""
    return Datum.from_inline_data(PlutusData.from_cbor(CborReader.from_hex(datum_bytes(encoded, expected))))


def output(tx_id, index, address, coins, assets):
    """Construct a typed UTxO with bounded indices and nonnegative quantities."""
    reference = TransactionInput.from_hex(hex_text(tx_id, 32), integer(index, 0, 65535))
    result = TransactionOutput.new(Address.from_string(address_text(address)), integer(coins))
    policies = {}
    for unit, quantity in assets.items():
        policies.setdefault(bytes.fromhex(unit[:56]), {})[bytes.fromhex(unit[56:])] = integer(quantity, 1)
    result.value = Value.from_dict([integer(coins), policies])
    return Utxo.new(reference, result)


def script_bytes(language, encoded, expected):
    """Decode unwrapped script bytes and verify the script's ledger hash."""
    encoded = hex_text(encoded)
    if language in ("native", "timelock"):
        script = Script.from_cbor(CborReader.from_hex("8200" + encoded))
    else:
        languages = {f"plutus:v{index}": index for index in range(1, 5)}
        languages.update({f"plutusV{index}": index for index in range(1, 5)})
        if language not in languages:
            invalid()
        writer = CborWriter()
        writer.write_bytes(bytes.fromhex(encoded))
        script = Script.from_cbor(CborReader.from_hex(f"820{languages[language]}" + writer.to_hex()))
    if script.hash.hex() != hex_text(expected, 28):
        invalid()
    return script


def _native_json(value, depth=0):
    if depth > 64:
        invalid()
    value = obj(value)
    kind = value.get("type")
    if kind == "sig":
        return {"type": kind, "keyHash": hex_text(value.get("keyHash"), 28)}
    if kind in ("before", "after"):
        return {"type": kind, "slot": integer(value.get("slot"))}
    if kind in ("all", "any", "atLeast"):
        result = {"type": kind, "scripts": [_native_json(child, depth + 1) for child in array(value.get("scripts"))]}
        if kind == "atLeast":
            result["required"] = integer(value.get("required"))
        return result
    return invalid()


def koios_output(raw):
    """Decode one extended Koios output, including spent-row validation."""
    row = obj(raw)
    if not isinstance(row.get("is_spent"), bool):
        invalid()
    assets = {}
    for item in array(row.get("asset_list") or []):
        item = obj(item)
        unit = hex_text(item.get("policy_id"), 28) + _asset_name(item.get("asset_name"))
        if unit in assets:
            invalid()
        assets[unit] = integer(item.get("quantity"), 1)
    result = output(row.get("tx_hash"), row.get("tx_index"), row.get("address"), row.get("value"), assets)
    tx_out = result.output
    if row.get("inline_datum") is not None:
        tx_out.datum = inline_datum(obj(row["inline_datum"]).get("bytes"), hex_text(row.get("datum_hash"), 32))
    elif row.get("datum_hash") is not None:
        tx_out.datum = Datum.from_data_hash_hex(hex_text(row["datum_hash"], 32))
    if row.get("reference_script") is not None:
        ref = obj(row["reference_script"])
        if ref.get("type") == "timelock" and ref.get("bytes") is None:
            script = Script.from_native(NativeScript.from_json(json.dumps(_native_json(ref.get("value")))))
            if script.hash.hex() != hex_text(ref.get("hash"), 28):
                invalid()
            tx_out.script_ref = script
        else:
            tx_out.script_ref = script_bytes(ref.get("type"), ref.get("bytes"), ref.get("hash"))
    return result


def _asset_name(value):
    value = hex_text(value, empty=True)
    if len(value) > 64:
        invalid()
    return value


def kupo_output(raw, lookup):
    """Resolve inline datums and reference scripts from the same Kupo index."""
    row = obj(raw)
    if "spent_at" not in row or row["spent_at"] is not None:
        invalid()
    value = obj(row.get("value"))
    assets = {}
    for unit, quantity in obj(value.get("assets")).items():
        parts = unit.split(".")
        if len(parts) > 2:
            invalid()
        normalized = hex_text(parts[0], 28) + (_asset_name(parts[1]) if len(parts) == 2 else "")
        if normalized in assets:
            invalid()
        assets[normalized] = integer(quantity, 1)
    result = output(row.get("transaction_id"), row.get("output_index"), row.get("address"), value.get("coins"), assets)
    tx_out = result.output
    if row.get("datum_hash") is not None:
        expected = hex_text(row["datum_hash"], 32)
        if row.get("datum_type") == "hash":
            tx_out.datum = Datum.from_data_hash_hex(expected)
        elif row.get("datum_type") == "inline":
            tx_out.datum = inline_datum(obj(lookup(["datums", expected])).get("datum"), expected)
        else:
            invalid()
    elif row.get("datum_type") is not None:
        invalid()
    if row.get("script_hash") is not None:
        expected = hex_text(row["script_hash"], 28)
        script = obj(lookup(["scripts", expected]))
        tx_out.script_ref = script_bytes(script.get("language"), script.get("script"), expected)
    return result


def asset_quantity(utxo, unit):
    """Read a native asset quantity using the binding's lossless value view."""
    value = utxo.output.value.to_dict()
    if isinstance(value, int):
        return 0
    return value[1].get(bytes.fromhex(unit[:56]), {}).get(bytes.fromhex(unit[56:]), 0)


def ogmios_output(utxo):
    """Encode an additional input in Ogmios's flat UTxO dialect."""
    tx_out = utxo.output
    amount = tx_out.value.to_dict()
    value = {"ada": {"lovelace": integer(tx_out.value.coin)}}
    if not isinstance(amount, int):
        value.update({policy.hex(): {name.hex(): integer(quantity, 1) for name, quantity in names.items()}
                      for policy, names in amount[1].items()})
    result = {"transaction": {"id": hash_text(utxo.input.transaction_id)}, "index": utxo.input.index,
              "address": str(tx_out.address), "value": value}
    datum = tx_out.datum
    if datum is not None:
        inline = datum.get_inline_data()
        if inline is not None:
            result["datum"] = cbor(inline)
        else:
            result["datumHash"] = datum.data_hash_hex
    script = tx_out.script_ref
    if script is not None:
        language = int(script.language)
        if language == 0:
            result["script"] = {"language": "native", "cbor": cbor(script.to_native())}
        else:
            encoded = getattr(script, f"to_plutus_v{language}")()
            result["script"] = {"language": f"plutus:v{language}", "cbor": encoded.raw_bytes.hex()}
    return result
