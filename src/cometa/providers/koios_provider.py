"""Koios v1 provider with Ogmios protocol queries, evaluation and submission."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from ..address import RewardAddress
from ..common.network_magic import NetworkMagic
from ..errors import CardanoError
from ._http import Http, confirm
from ._outputs import koios_output
from ._remote import NETWORKS, OgmiosProvider
from ._values import address_text, array, obj, asset_text, hash_text, hex_text, integer, invalid, input_key, resolve_order, datum_bytes


class KoiosProvider(OgmiosProvider):
    """Koios's indexed queries and stateless Ogmios HTTP API.

    Queries are independent snapshots. Responses are bounded to 8 MiB, pagination
    to 10,000 pages, and submissions are never retried. ``token`` is optional.
    """

    def __init__(self, network: NetworkMagic, *, base_url: str | None = None, token: str | None = None,
                 timeout_ms: int = 30000, poll_interval_ms: int = 1000):
        if isinstance(network, bool) or network not in NETWORKS:
            raise ValueError("Unsupported provider network")
        prefix = "api" if network == NetworkMagic.MAINNET else NETWORKS[network]
        client = Http(base_url or f"https://{prefix}.koios.rest/api/v1", token, timeout_ms)
        super().__init__(network, poll_interval_ms, client, ["ogmios"])
        self._http = client

    def get_unspent_outputs(self, address):
        """Return indexed unspent outputs, validating their address and metadata."""
        text = address_text(address)
        outputs = self._outputs("address_utxos", {"_addresses": [text], "_extended": True})
        if any(str(output.output.address) != text for output in outputs):
            invalid()
        return outputs

    def get_rewards_balance(self, reward_account):
        """Return available staking rewards in lovelace; absent accounts return zero."""
        text = RewardAddress.from_bech32(reward_account).to_bech32() if isinstance(reward_account, str) else reward_account.to_bech32()
        rows = array(self._http.json(["account_info"], body={"_stake_addresses": [text]}))
        if not rows:
            return 0
        if len(rows) != 1 or obj(rows[0]).get("stake_address") != text:
            invalid()
        return integer(rows[0].get("rewards_available"))

    def get_unspent_output_by_nft(self, asset_id):
        """Require exactly one unspent output holding exactly one unit of the asset."""
        unit = asset_text(asset_id)
        return self._nft(self._outputs("asset_utxos", {"_asset_list": [[unit[:56], unit[56:]]], "_extended": True}), unit)

    def resolve_unspent_outputs(self, tx_ins):
        """Resolve inputs in first-request order, omitting missing or spent inputs."""
        requested = list(tx_ins)
        keys = list(dict.fromkeys(input_key(item) for item in requested))
        outputs = []
        for offset in range(0, len(keys), 100):
            outputs.extend(self._outputs("utxo_info", {"_utxo_refs": keys[offset:offset + 100], "_extended": True}))
        return resolve_order(requested, outputs)

    def resolve_datum(self, datum_hash):
        """Return original datum CBOR only after verifying the requested hash."""
        expected = hash_text(datum_hash)
        rows = array(self._http.json(["datum_info"], body={"_datum_hashes": [expected]}))
        if len(rows) != 1 or hex_text(obj(rows[0]).get("datum_hash"), 32) != expected:
            invalid()
        return datum_bytes(rows[0].get("bytes"), expected)

    def confirm_transaction(self, tx_id: str, timeout_ms: int | None = None) -> bool:
        """Poll for an indexed block confirmation within a total deadline."""
        return confirm(hash_text(tx_id), timeout_ms, self._poll_interval, self._confirmed)

    def _confirmed(self, expected, remaining):
        rows = array(self._http.json(["tx_status"], body={"_tx_hashes": [expected]}, timeout_ms=remaining))
        if not rows:
            return False
        if len(rows) != 1 or hex_text(obj(rows[0]).get("tx_hash"), 32) != expected:
            invalid()
        count = rows[0].get("num_confirmations")
        return count is not None and integer(count) > 0

    def _outputs(self, path, body):
        outputs, seen = [], set()
        for page in range(10000):
            rows = array(self._http.json([path], {"limit": "100", "offset": str(page * 100), "order": "tx_hash.asc,tx_index.asc"}, body))
            if len(rows) > 100:
                invalid()
            for row in rows:
                value = koios_output(row)
                key = input_key(value.input)
                if key in seen:
                    invalid()
                seen.add(key)
                if not row["is_spent"]:
                    outputs.append(value)
            if len(rows) < 100:
                return outputs
        raise CardanoError("Provider pagination limit exceeded")
