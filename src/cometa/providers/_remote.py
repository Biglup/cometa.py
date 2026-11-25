"""Common provider operations and Ogmios JSON-RPC validation."""
# Copyright 2026 Biglup Labs. SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod

from ..common import ExUnits
from ..common.network_magic import NetworkMagic
from ..witness_set import Redeemer, RedeemerTag
from ._http import milliseconds
from ._outputs import asset_quantity, ogmios_output
from ._protocol import parameters
from ._values import array, obj, integer, invalid, asset_text, hex_text, hash_text, transaction, unique

NETWORKS = {NetworkMagic.MAINNET: "mainnet", NetworkMagic.PREPROD: "preprod", NetworkMagic.PREVIEW: "preview"}


class RemoteProvider(ABC):
    """Network identity and asset filtering shared by the remote providers."""

    def __init__(self, network, poll_interval_ms):
        if isinstance(network, bool) or network not in NETWORKS:
            raise ValueError("Unsupported provider network")
        self._network = int(network)
        self._poll_interval = milliseconds(poll_interval_ms)

    def get_name(self) -> str:
        """Return the provider's stable human-readable name."""
        return type(self).__name__.removesuffix("Provider")

    def get_network_magic(self) -> int:
        """Return the explicitly configured network magic."""
        return self._network

    @abstractmethod
    def get_unspent_outputs(self, address):
        """Return all indexed unspent outputs at the payment address."""
        raise NotImplementedError

    def get_unspent_outputs_with_asset(self, address, asset_id):
        """Return address outputs containing a positive quantity of this asset."""
        unit = asset_text(asset_id)
        return [output for output in self.get_unspent_outputs(address) if asset_quantity(output, unit) > 0]

    @staticmethod
    def _nft(outputs, unit):
        if len(outputs) != 1 or asset_quantity(outputs[0], unit) != 1:
            raise ValueError("Expected exactly one NFT output")
        return outputs[0]


class OgmiosProvider(RemoteProvider, ABC):
    """Shared HTTP Ogmios operations; no acquired ledger state or retries."""

    def __init__(self, network, poll_interval_ms, node, rpc_path=()):
        super().__init__(network, poll_interval_ms)
        self._node = node
        self._rpc_path = rpc_path

    def _rpc(self, method, params=None):
        reply = obj(self._node.json(self._rpc_path, body={"jsonrpc": "2.0", "id": "cometa", "method": method, "params": params or {}}))
        if reply.get("jsonrpc") != "2.0" or reply.get("id") != "cometa" or reply.get("method", method) != method:
            invalid()
        if "error" in reply:
            from ..errors import CardanoError
            raise CardanoError("Ogmios rejected the request")
        if "result" not in reply:
            invalid()
        return reply["result"]

    def get_parameters(self):
        """Return a complete protocol snapshot, retaining exact rational prices."""
        return parameters(self._rpc("queryLedgerState/protocolParameters"))

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """Submit once and verify the returned ID against the original body hash."""
        encoded = hex_text(tx_cbor_hex)
        expected = hash_text(transaction(encoded).id)
        response = obj(self._rpc("submitTransaction", {"transaction": {"cbor": encoded}}))
        if hex_text(obj(response.get("transaction")).get("id"), 32) != expected:
            invalid()
        return expected

    def evaluate_transaction(self, tx_cbor_hex, additional_utxos=None):
        """Return all original redeemers with checked, purpose-matched budgets."""
        original = transaction(tx_cbor_hex)
        redeemers = list(original.witness_set.redeemers or [])
        additional = unique(list(additional_utxos or []))
        result = array(self._rpc("evaluateTransaction", {"transaction": {"cbor": hex_text(tx_cbor_hex)},
                                                        "additionalUtxo": [ogmios_output(item) for item in additional]}))
        return _budgets(redeemers, result)


def _budgets(redeemers, result):
    tags = {"spend": RedeemerTag.SPEND, "mint": RedeemerTag.MINT, "publish": RedeemerTag.CERTIFYING,
            "withdraw": RedeemerTag.REWARD, "vote": RedeemerTag.VOTING, "propose": RedeemerTag.PROPOSING}
    pending = {(item.tag, item.index): item for item in redeemers}
    if len(pending) != len(redeemers):
        invalid()
    evaluated = {}
    for raw in result:
        row = obj(raw)
        validator = obj(row.get("validator"))
        purpose = validator.get("purpose")
        if purpose not in tags:
            invalid()
        key = (tags[purpose], integer(validator.get("index")))
        if key not in pending:
            invalid()
        original = pending.pop(key)
        budget = obj(row.get("budget"))
        evaluated[key] = Redeemer.new(original.tag, original.index, original.data,
                                     ExUnits.new(integer(budget.get("memory")), integer(budget.get("cpu"))))
    if pending:
        invalid()
    return [evaluated[(item.tag, item.index)] for item in redeemers]
