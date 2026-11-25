"""HTTP provider for an existing Hydra Conway Head."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib

from ..common.network_magic import NetworkMagic
from ..errors import CardanoError
from ._http import Http, ProviderHttpError, confirm
from ._hydra import hydra_parameters, hydra_outputs
from ._outputs import asset_quantity
from ._remote import RemoteProvider
from ._values import address_text, asset_text, array, obj, hash_text, hex_text, integer, invalid, input_key, resolve_order, transaction


class HydraProvider(RemoteProvider):
    """Queries and L2 submissions for a running Head, not Head lifecycle control.

    Confirmation checks the latest signed snapshot's transaction list. Older
    transactions absent from that list cannot be rediscovered. UTxO presence is
    never proof of L2 confirmation: it can come from an L1 deposit. Rewards and
    remote script evaluation are unsupported; use a local evaluator for scripts.
    """

    def __init__(self, network: NetworkMagic, base_url: str, *, token: str | None = None,
                 timeout_ms: int = 30000, poll_interval_ms: int = 1000):
        super().__init__(network, poll_interval_ms)
        self._http = Http(base_url, token, timeout_ms)

    def get_parameters(self):
        """Return the Head's parameters, including its potentially zero fees."""
        return hydra_parameters(self._http.json(["protocol-parameters"]))

    def get_unspent_outputs(self, address):
        """Filter the confirmed Head snapshot by payment address."""
        expected = address_text(address)
        return [item for item in self._outputs() if str(item.output.address) == expected]

    def get_unspent_output_by_nft(self, asset_id):
        """Require one snapshot output holding exactly one unit of the asset."""
        unit = asset_text(asset_id)
        return self._nft([item for item in self._outputs() if asset_quantity(item, unit) > 0], unit)

    def resolve_unspent_outputs(self, tx_ins):
        """Resolve inputs in first-request order from the confirmed snapshot."""
        requested = list(tx_ins)
        keys = {input_key(item) for item in requested}
        return resolve_order(requested, [item for item in self._outputs() if input_key(item.input) in keys])

    def resolve_datum(self, datum_hash):
        """Find original inline datum bytes in the current confirmed snapshot."""
        expected = hash_text(datum_hash)
        snapshot = obj(self._http.json(["snapshot", "utxo"]))
        hydra_outputs(snapshot)
        for row in snapshot.values():
            if row.get("inlineDatumRaw") is not None:
                encoded = hex_text(row["inlineDatumRaw"])
                if hashlib.blake2b(bytes.fromhex(encoded), digest_size=32).hexdigest() == expected:
                    return encoded
        raise CardanoError("Datum is not available in the current Hydra snapshot")

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit on L2 once; a 202 acknowledgement is not confirmation."""
        expected = hash_text(transaction(tx_cbor_hex).id)
        status, raw = self._http.request(["transaction"], body={"type": "Tx ConwayEra", "description": "", "cborHex": hex_text(tx_cbor_hex)})
        reply = obj(raw)
        if status == 200 and reply.get("tag") == "SubmitTxConfirmed":
            integer(reply.get("snapshotNumber"))
        elif status != 202 or reply.get("tag") != "SubmitTxSubmitted":
            invalid()
        return expected

    def confirm_transaction(self, tx_id: str, timeout_ms: int | None = None) -> bool:
        """Poll the latest confirmed snapshot; this does not imply L1 settlement."""
        return confirm(hash_text(tx_id), timeout_ms, self._poll_interval, self._confirmed)

    def _confirmed(self, expected, remaining):
        try:
            reply = obj(self._http.json(["snapshot"], timeout_ms=remaining))
        except ProviderHttpError as error:
            if error.status == 404:
                return False
            raise
        if reply.get("tag") == "InitialSnapshot":
            return False
        if reply.get("tag") != "ConfirmedSnapshot":
            invalid()
        snapshot = obj(reply.get("snapshot"))
        integer(snapshot.get("number"))
        found = False
        for raw in array(snapshot.get("confirmed")):
            item = obj(raw)
            actual = hash_text(transaction(item.get("cborHex")).id)
            if "txId" in item and hash_text(item["txId"]) != actual:
                invalid()
            found = found or actual == expected
        return found

    def get_rewards_balance(self, reward_account):
        """Raise explicitly: Hydra Heads have no staking rewards."""
        raise NotImplementedError("Hydra Heads do not support staking rewards")

    def evaluate_transaction(self, tx_cbor_hex, additional_utxos=None):
        """Raise explicitly: configure a local evaluator for the Head's ledger."""
        raise NotImplementedError("Hydra has no remote evaluation endpoint; configure a local evaluator")

    def _outputs(self):
        return hydra_outputs(self._http.json(["snapshot", "utxo"]))
