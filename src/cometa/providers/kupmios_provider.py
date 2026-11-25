"""Kupo indexing paired with stateless Ogmios HTTP JSON-RPC."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from ..address import RewardAddress
from ..common.network_magic import NetworkMagic
from ._http import Http, confirm
from ._outputs import kupo_output
from ._remote import OgmiosProvider
from ._values import address_text, array, obj, asset_text, hash_text, hex_text, integer, invalid, input_key, resolve_order, datum_bytes, unique


class KupmiosProvider(OgmiosProvider):
    """Explicit Kupo/Ogmios endpoints on the same configured network.

    Kupo must index the requested addresses/assets and retain their datum, script
    and transaction history. Empty results describe that index, not the whole
    chain. Both endpoints accept independent optional bearer tokens.
    """

    def __init__(self, network: NetworkMagic, kupo_url: str, ogmios_url: str, *, kupo_token: str | None = None,
                 ogmios_token: str | None = None, timeout_ms: int = 30000, poll_interval_ms: int = 1000):
        super().__init__(network, poll_interval_ms, Http(ogmios_url, ogmios_token, timeout_ms))
        self._kupo = Http(kupo_url, kupo_token, timeout_ms)

    def get_unspent_outputs(self, address):
        """Return all indexed unspent outputs at the requested address."""
        text = address_text(address)
        outputs = self._outputs(text)
        if any(str(output.output.address) != text for output in outputs):
            invalid()
        return outputs

    def get_rewards_balance(self, reward_account):
        """Query rewards by the account's key or script credential."""
        account = RewardAddress.from_bech32(reward_account) if isinstance(reward_account, str) else reward_account
        credential = account.credential
        script = int(credential.type) == 1
        expected = credential.hash.to_hex()
        rows = array(self._rpc("queryLedgerState/rewardAccountSummaries", {"scripts" if script else "keys": [expected]}))
        if not rows:
            return 0
        if len(rows) != 1:
            invalid()
        row = obj(rows[0])
        if hex_text(row.get("credential"), 28) != expected or row.get("from") != ("script" if script else "verificationKey"):
            invalid()
        return integer(obj(obj(row.get("rewards")).get("ada")).get("lovelace"))

    def get_unspent_output_by_nft(self, asset_id):
        """Require one indexed output holding exactly one unit of the asset."""
        unit = asset_text(asset_id)
        return self._nft(self._outputs("*", {"policy_id": unit[:56], "asset_name": unit[56:]}), unit)

    def resolve_unspent_outputs(self, tx_ins):
        """Resolve indexed inputs in first-request order, omitting missing inputs."""
        requested = list(tx_ins)
        outputs = []
        for key in dict.fromkeys(input_key(item) for item in requested):
            tx_id, index = key.split("#")
            outputs.extend(self._outputs(f"{index}@{tx_id}"))
        return resolve_order(requested, outputs)

    def resolve_datum(self, datum_hash):
        """Return Kupo's original datum CBOR after verifying its hash."""
        expected = hash_text(datum_hash)
        return datum_bytes(obj(self._kupo.json(["datums", expected])).get("datum"), expected)

    def confirm_transaction(self, tx_id: str, timeout_ms: int | None = None) -> bool:
        """Wait for an indexed output; requires Kupo history for this transaction."""
        return confirm(hash_text(tx_id), timeout_ms, self._poll_interval, self._confirmed)

    def _confirmed(self, expected, remaining):
        rows = array(self._kupo.json(["matches", f"*@{expected}"], timeout_ms=remaining))
        for raw in rows:
            row = obj(raw)
            if hex_text(row.get("transaction_id"), 32) != expected:
                invalid()
            created = obj(row.get("created_at"))
            integer(created.get("slot_no"))
            hex_text(created.get("header_hash"), 32)
        return bool(rows)

    def _outputs(self, pattern, query=None):
        rows = array(self._kupo.json(["matches", pattern], {**(query or {}), "unspent": None}))
        return unique([kupo_output(row, self._kupo.json) for row in rows])
