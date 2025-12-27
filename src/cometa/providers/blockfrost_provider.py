"""
Copyright 2025 Biglup Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import annotations

import time
import json
from typing import Union, List, Optional, Any, Dict
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from ..protocol_params import Costmdls
from ..cbor import CborReader
from ..errors import CardanoError
from ..common.network_magic import NetworkMagic


def _network_magic_to_prefix(magic: NetworkMagic) -> str:
    """Convert network magic to Blockfrost URL prefix."""
    prefixes = {
        NetworkMagic.MAINNET: "cardano-mainnet",
        NetworkMagic.PREPROD: "cardano-preprod",
        NetworkMagic.PREVIEW: "cardano-preview",
        NetworkMagic.SANCHONET: "cardano-sanchonet",
    }
    return prefixes.get(magic, "unknown")


def _prepare_utxos_for_evaluation(utxos: List["Utxo"]) -> List:
    """Prepare UTXOs for the evaluation endpoint."""
    result = []
    for utxo in utxos:
        input_json = {
            "id": utxo.input.transaction_id.hex(),
            "index": utxo.input.index
        }

        output = utxo.output
        output_json = {
            "address": str(output.address),
            "value": {
                "ada": {
                    "lovelace": output.value.coin
                }
            }
        }

        assets = output.value.multi_asset
        if assets:
            for policy_id, asset_map in assets.items():
                pid_hex = policy_id.to_hex()
                if pid_hex not in output_json["value"]:
                    output_json["value"][pid_hex] = {}
                for asset_name, qty in asset_map.items():
                    name_hex = asset_name.to_hex()
                    output_json["value"][pid_hex][name_hex] = qty

        result.extend([input_json, output_json])

    return result


class BlockfrostProvider:
    """
    Provider implementation for the Blockfrost API.

    BlockfrostProvider enables interaction with the Cardano blockchain through
    the Blockfrost API service. It implements all provider methods for:
    - Fetching protocol parameters
    - Querying UTXOs
    - Resolving datums
    - Submitting and confirming transactions
    - Evaluating Plutus scripts
    """

    def __init__(
        self,
        network: NetworkMagic,
        project_id: str,
        base_url: Optional[str] = None,
    ):
        """
        Initialize the Blockfrost provider.

        Args:
            network: The Cardano network to connect to.
            project_id: Your Blockfrost project ID for authentication.
            base_url: Optional custom base URL (overrides network-based URL).
        """
        self._network = network
        self._project_id = project_id

        if base_url:
            self._base_url = base_url.rstrip("/") + "/"
        else:
            prefix = _network_magic_to_prefix(network)
            self._base_url = f"https://{prefix}.blockfrost.io/api/v0/"

    def _headers(self) -> Dict[str, str]:
        """
        Get headers for Blockfrost API requests.

        Returns:
            A dictionary containing the required HTTP headers for authentication.
        """
        return {
            "project_id": self._project_id,
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str) -> Any:
        """
        Make a GET request to the Blockfrost API.

        Args:
            endpoint: The API endpoint path (relative to base URL).

        Returns:
            The parsed JSON response, or None if the resource was not found (404).

        Raises:
            CardanoError: If the request fails or returns a non-404 error.
        """
        url = f"{self._base_url}{endpoint}"
        request = Request(url, headers=self._headers())

        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as http_err:
            if http_err.code == 404:
                return None
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            raise CardanoError(f"Blockfrost API error {http_err.code}: {body}") from http_err
        except URLError as url_err:
            raise CardanoError(f"Network error: {url_err.reason}") from url_err

    def _post(self, endpoint: str, data: bytes, content_type: str = "application/json") -> Any:
        """
        Make a POST request to the Blockfrost API.

        Args:
            endpoint: The API endpoint path (relative to base URL).
            data: The request body data as bytes.
            content_type: The Content-Type header value (default: "application/json").

        Returns:
            The parsed JSON response.

        Raises:
            CardanoError: If the request fails.
        """
        url = f"{self._base_url}{endpoint}"
        headers = self._headers()
        headers["Content-Type"] = content_type

        request = Request(url, data=data, headers=headers, method="POST")

        try:
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as http_err:
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            raise CardanoError(f"Blockfrost API error {http_err.code}: {body}") from http_err
        except URLError as url_err:
            raise CardanoError(f"Network error: {url_err.reason}") from url_err

    # -------------------------------------------------------------------------
    # Internal Helpers (Script Resolution & Parsing)
    # -------------------------------------------------------------------------

    def _get_script_ref(self, script_hash: str) -> Optional["Script"]:
        """
        Fetch and resolve a reference script by its hash.
        This handles both Plutus (CBOR) and Native (JSON) scripts.
        """
        from ..scripts import PlutusV1Script, PlutusV2Script, PlutusV3Script, NativeScript, Script
        from ..scripts.plutus_scripts import PlutusLanguageVersion

        meta_data = self._get(f"scripts/{script_hash}")
        if not meta_data or "type" not in meta_data:
            return None

        script_type = meta_data["type"]

        if script_type == "timelock":
            json_data = self._get(f"scripts/{script_hash}/json")
            if not json_data or "json" not in json_data:
                return None
            return Script.from_native(NativeScript.from_json(json_data["json"]))

        version_map = {
            "plutusV1": PlutusLanguageVersion.V1,
            "plutusV2": PlutusLanguageVersion.V2,
            "plutusV3": PlutusLanguageVersion.V3,
        }

        plutus_version = version_map.get(script_type)
        if plutus_version:
            cbor_data = self._get(f"scripts/{script_hash}/cbor")
            if not cbor_data or "cbor" not in cbor_data:
                return None

            cbor_bytes = bytes.fromhex(cbor_data["cbor"])

            if plutus_version == PlutusLanguageVersion.V1:
                return Script.from_plutus_v1(PlutusV1Script.new(cbor_bytes))

            if plutus_version == PlutusLanguageVersion.V2:
                return Script.from_plutus_v2(PlutusV2Script.new(cbor_bytes))

            if plutus_version == PlutusLanguageVersion.V3:
                return Script.from_plutus_v3(PlutusV3Script.new(cbor_bytes))

        return None

    # pylint: disable=too-many-locals,too-many-branches
    def _parse_utxo_json(self, address: str, utxo_data: Dict) -> "Utxo":
        """
        Parse a Blockfrost UTXO response dictionary into a Utxo object.
        This includes resolving Reference Scripts if present.
        """
        from ..common.utxo import Utxo
        from ..common.datum import Datum
        from ..transaction_body import TransactionInput, TransactionOutput, Value
        from ..address import Address

        tx_input = TransactionInput.from_hex(
            utxo_data["tx_hash"],
            utxo_data["output_index"]
        )

        lovelace = 0
        multi_asset_dict: Dict[bytes, Dict[bytes, int]] = {}

        for amount in utxo_data.get("amount", []):
            if amount["unit"] == "lovelace":
                lovelace = int(amount["quantity"])
            else:
                unit = amount["unit"]
                if len(unit) >= 56:
                    policy_id_hex = unit[:56]
                    asset_name_hex = unit[56:]

                    policy_id_bytes = bytes.fromhex(policy_id_hex)
                    asset_name_bytes = bytes.fromhex(asset_name_hex) if asset_name_hex else b""

                    if policy_id_bytes not in multi_asset_dict:
                        multi_asset_dict[policy_id_bytes] = {}
                    multi_asset_dict[policy_id_bytes][asset_name_bytes] = int(amount["quantity"])

        if multi_asset_dict:
            value = Value.from_dict([lovelace, multi_asset_dict])
        else:
            value = Value.from_coin(lovelace)

        addr = Address.from_string(address)
        tx_output = TransactionOutput.new(addr, lovelace)
        tx_output.value = value

        datum_hash = utxo_data.get("data_hash")
        inline_datum_cbor = utxo_data.get("inline_datum")

        if inline_datum_cbor:
            try:
                reader = CborReader.from_hex(inline_datum_cbor)
                datum = Datum.from_cbor(reader)
                tx_output.datum = datum
            except CardanoError:
                pass
        elif datum_hash:
            try:
                datum = Datum.from_data_hash_hex(datum_hash)
                tx_output.datum = datum
            except CardanoError:
                pass

        script_ref_hash = utxo_data.get("reference_script_hash")
        if script_ref_hash:
            try:
                script = self._get_script_ref(script_ref_hash)
                if script:
                    tx_output.script_ref = script
            except CardanoError:
                pass

        return Utxo.new(tx_input, tx_output)

    # -------------------------------------------------------------------------
    # Provider Protocol Implementation
    # -------------------------------------------------------------------------

    def get_name(self) -> str:
        """
        Get the provider name.

        Returns:
            The string "Blockfrost".

        Note:
            This method implements the provider protocol interface.
        """
        return "Blockfrost"

    def get_network_magic(self) -> int:
        """
        Get the network magic number.

        Returns:
            The network magic value as an integer.
        """
        return int(self._network)

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def get_parameters(self) -> "ProtocolParameters":
        """
        Retrieve the current protocol parameters from Blockfrost.

        Returns:
            The current ProtocolParameters.

        Raises:
            CardanoError: If the request fails.
        """
        from ..protocol_params import ProtocolParameters, ExUnitPrices
        from ..protocol_params.cost_model import CostModel
        from ..common import UnitInterval, ExUnits, ProtocolVersion
        from ..scripts.plutus_scripts import PlutusLanguageVersion

        data = self._get("epochs/latest/parameters")
        if data is None:
            raise CardanoError("Failed to fetch protocol parameters")

        if "message" in data:
            raise CardanoError(f"Blockfrost error: {data['message']}")

        params = ProtocolParameters.new()

        if data.get("min_fee_a") is not None:
            params.min_fee_a = int(data["min_fee_a"])
        if data.get("min_fee_b") is not None:
            params.min_fee_b = int(data["min_fee_b"])

        if data.get("max_block_size") is not None:
            params.max_block_body_size = int(data["max_block_size"])
        if data.get("max_tx_size") is not None:
            params.max_tx_size = int(data["max_tx_size"])
        if data.get("max_block_header_size") is not None:
            params.max_block_header_size = int(data["max_block_header_size"])

        if data.get("key_deposit") is not None:
            params.key_deposit = int(data["key_deposit"])
        if data.get("pool_deposit") is not None:
            params.pool_deposit = int(data["pool_deposit"])

        if data.get("e_max") is not None:
            params.max_epoch = int(data["e_max"])
        if data.get("n_opt") is not None:
            params.n_opt = int(data["n_opt"])
        if data.get("min_pool_cost") is not None:
            params.min_pool_cost = int(data["min_pool_cost"])

        if data.get("a0") is not None:
            params.pool_pledge_influence = UnitInterval.from_float(float(data["a0"]))
        if data.get("rho") is not None:
            params.expansion_rate = UnitInterval.from_float(float(data["rho"]))
        if data.get("tau") is not None:
            params.treasury_growth_rate = UnitInterval.from_float(float(data["tau"]))
        if data.get("decentralisation_param") is not None:
            params.decentralisation_param = UnitInterval.from_float(
                float(data["decentralisation_param"])
            )

        major = data.get("protocol_major_ver", 0)
        minor = data.get("protocol_minor_ver", 0)
        if major or minor:
            params.protocol_version = ProtocolVersion.new(int(major), int(minor))

        if data.get("coins_per_utxo_word") is not None:
            params.ada_per_utxo_byte = int(data["coins_per_utxo_word"])
        elif data.get("coins_per_utxo_size") is not None:
            params.ada_per_utxo_byte = int(data["coins_per_utxo_size"])

        if data.get("max_val_size") is not None:
            params.max_value_size = int(data["max_val_size"])
        if data.get("collateral_percent") is not None:
            params.collateral_percentage = int(data["collateral_percent"])
        if data.get("max_collateral_inputs") is not None:
            params.max_collateral_inputs = int(data["max_collateral_inputs"])

        max_tx_mem = data.get("max_tx_ex_mem")
        max_tx_steps = data.get("max_tx_ex_steps")
        if max_tx_mem is not None and max_tx_steps is not None:
            params.max_tx_ex_units = ExUnits.new(int(max_tx_mem), int(max_tx_steps))

        max_block_mem = data.get("max_block_ex_mem")
        max_block_steps = data.get("max_block_ex_steps")
        if max_block_mem is not None and max_block_steps is not None:
            params.max_block_ex_units = ExUnits.new(
                int(max_block_mem), int(max_block_steps)
            )

        price_mem = data.get("price_mem")
        price_step = data.get("price_step")
        if price_mem is not None and price_step is not None:
            mem_prices = UnitInterval.from_float(float(price_mem))
            step_prices = UnitInterval.from_float(float(price_step))
            params.execution_costs = ExUnitPrices.new(mem_prices, step_prices)

        if data.get("drep_deposit") is not None:
            params.drep_deposit = int(data["drep_deposit"])
        if data.get("drep_activity") is not None:
            params.drep_inactivity_period = int(data["drep_activity"])
        if data.get("gov_action_deposit") is not None:
            params.governance_action_deposit = int(data["gov_action_deposit"])
        if data.get("gov_action_lifetime") is not None:
            params.governance_action_validity_period = int(
                data["gov_action_lifetime"]
            )
        if data.get("committee_min_size") is not None:
            params.min_committee_size = int(data["committee_min_size"])
        if data.get("committee_max_term_length") is not None:
            params.committee_term_limit = int(data["committee_max_term_length"])

        ref_script_cost = data.get("min_fee_ref_script_cost_per_byte")
        if ref_script_cost is not None:
            params.ref_script_cost_per_byte = UnitInterval.from_float(
                float(ref_script_cost)
            )

        raw_models = data.get("cost_models_raw") or {}
        cost_models = Costmdls.new()

        if isinstance(raw_models, dict):
            for language_key, costs in raw_models.items():
                if not isinstance(costs, (list, tuple)):
                    continue

                key_norm = str(language_key).lower()

                if "v1" in key_norm:
                    lang_enum = PlutusLanguageVersion.V1
                elif "v2" in key_norm:
                    lang_enum = PlutusLanguageVersion.V2
                elif "v3" in key_norm:
                    lang_enum = PlutusLanguageVersion.V3
                else:
                    continue

                cost_ints = [int(c) for c in costs]
                model = CostModel.new(lang_enum, cost_ints)
                cost_models.insert(model)

        if cost_models:
            params.cost_models = cost_models

        return params

    def get_unspent_outputs(self, address: Union["Address", str]) -> List["Utxo"]:
        """
        Get all unspent transaction outputs for an address.

        Args:
            address: The payment address to query.

        Returns:
            A list of Utxo objects.
        """
        addr_str = str(address) if not isinstance(address, str) else address

        results = []
        page = 1
        max_page_count = 100

        while True:
            endpoint = f"addresses/{addr_str}/utxos?count={max_page_count}&page={page}"
            data = self._get(endpoint)

            if data is None:
                return []

            if isinstance(data, dict) and "message" in data:
                raise CardanoError(f"Blockfrost error: {data['message']}")

            for utxo_data in data:
                utxo = self._parse_utxo_json(addr_str, utxo_data)
                results.append(utxo)

            if len(data) < max_page_count:
                break
            page += 1

        return results

    def get_rewards_balance(self, reward_account: Union["RewardAddress", str]) -> int:
        """
        Get the staking rewards balance for a reward account.

        Args:
            reward_account: The reward address to query.

        Returns:
            The rewards balance in lovelace.
        """
        addr_str = str(reward_account) if not isinstance(reward_account, str) else reward_account

        data = self._get(f"accounts/{addr_str}")

        if data is None:
            return 0

        if isinstance(data, dict) and "message" in data:
            raise CardanoError(f"Blockfrost error: {data['message']}")

        return int(data.get("withdrawable_amount", 0))

    def get_unspent_outputs_with_asset(
        self, address: Union["Address", str], asset_id: Union["AssetId", str]
    ) -> List["Utxo"]:
        """
        Get UTXOs for an address that contain a specific asset.

        Args:
            address: The payment address to query.
            asset_id: The asset identifier to filter by.

        Returns:
            A list of Utxo objects containing the asset.
        """
        addr_str = str(address) if not isinstance(address, str) else address
        asset_str = str(asset_id) if not isinstance(asset_id, str) else asset_id

        results = []
        page = 1
        max_page_count = 100

        while True:
            endpoint = f"addresses/{addr_str}/utxos/{asset_str}?count={max_page_count}&page={page}"
            data = self._get(endpoint)

            if data is None:
                return []

            if isinstance(data, dict) and "message" in data:
                raise CardanoError(f"Blockfrost error: {data['message']}")

            for utxo_data in data:
                utxo = self._parse_utxo_json(addr_str, utxo_data)
                results.append(utxo)

            if len(data) < max_page_count:
                break
            page += 1

        return results

    def get_unspent_output_by_nft(self, asset_id: Union["AssetId", str]) -> "Utxo":
        """
        Get the UTXO containing a specific NFT.

        Args:
            asset_id: The NFT asset identifier.

        Returns:
            The Utxo containing the NFT.

        Raises:
            CardanoError: If the NFT is not found or held by multiple addresses/UTXOs.
        """
        asset_str = str(asset_id) if not isinstance(asset_id, str) else asset_id

        data = self._get(f"assets/{asset_str}/addresses")

        if data is None or len(data) == 0:
            raise CardanoError("NFT not found")

        if isinstance(data, dict) and "message" in data:
            raise CardanoError(f"Blockfrost error: {data['message']}")

        if len(data) > 1:
            raise CardanoError("NFT must be held by only one address")

        holder_address = data[0]["address"]
        utxos = self.get_unspent_outputs_with_asset(holder_address, asset_str)

        if len(utxos) != 1:
            raise CardanoError("NFT must be present in only one UTXO")

        return utxos[0]

    def resolve_unspent_outputs(
        self, tx_ins: Union["TransactionInputSet", List["TransactionInput"]]
    ) -> List["Utxo"]:
        """
        Resolve transaction inputs to their corresponding UTXOs.

        Args:
            tx_ins: The transaction inputs to resolve.

        Returns:
            A list of resolved Utxo objects.
        """
        from ..transaction_body import TransactionInputSet

        if isinstance(tx_ins, TransactionInputSet):
            inputs = list(tx_ins)
        else:
            inputs = tx_ins

        results = []

        for tx_in in inputs:
            tx_id = tx_in.transaction_id.hex()
            index = tx_in.index

            data = self._get(f"txs/{tx_id}/utxos")

            if data is None:
                continue

            if isinstance(data, dict) and "message" in data:
                raise CardanoError(f"Blockfrost error: {data['message']}")

            for output in data.get("outputs", []):
                if output["output_index"] == index:
                    output["tx_hash"] = tx_id
                    utxo = self._parse_utxo_json(output["address"], output)
                    results.append(utxo)
                    break

        return results

    def resolve_datum(self, datum_hash: Union["Blake2bHash", str]) -> str:
        """
        Resolve a datum by its hash.

        Args:
            datum_hash: The hash of the datum to resolve.

        Returns:
            The CBOR-encoded datum as a hex string.
        """
        hash_str = datum_hash.to_hex() if hasattr(datum_hash, "to_hex") else str(datum_hash)

        data = self._get(f"scripts/datum/{hash_str}/cbor")

        if data is None:
            raise CardanoError(f"Datum not found: {hash_str}")

        if isinstance(data, dict) and "message" in data:
            raise CardanoError(f"Blockfrost error: {data['message']}")

        return data.get("cbor", "")

    def confirm_transaction(self, tx_id: str, timeout_ms: Optional[int] = None) -> bool:
        """
        Wait for a transaction to be confirmed on-chain.

        Args:
            tx_id: The transaction ID (hex string).
            timeout_ms: Optional timeout in milliseconds.

        Returns:
            True if confirmed, False if timeout reached.
        """
        average_block_time = 20  # seconds

        def check_confirmation() -> bool:
            data = self._get(f"txs/{tx_id}/metadata/cbor")
            return data is not None and not (isinstance(data, dict) and "message" in data)

        if check_confirmation():
            return True

        if timeout_ms:
            start_time = time.time()
            timeout_sec = timeout_ms / 1000.0

            while (time.time() - start_time) < timeout_sec:
                time.sleep(average_block_time)
                if check_confirmation():
                    return True

        return False

    def submit_transaction(self, tx_cbor_hex: str) -> str:
        """
        Submit a signed transaction to the blockchain.

        Args:
            tx_cbor_hex: The CBOR-encoded transaction as a hex string.

        Returns:
            The transaction ID (hex string) of the submitted transaction.
        """
        tx_bytes = bytes.fromhex(tx_cbor_hex)

        url = f"{self._base_url}tx/submit"
        headers = {
            "project_id": self._project_id,
            "Content-Type": "application/cbor",
        }

        request = Request(url, data=tx_bytes, headers=headers, method="POST")

        try:
            with urlopen(request, timeout=60) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result if isinstance(result, str) else str(result)
        except HTTPError as http_err:
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            raise CardanoError(f"Failed to submit transaction: {body}") from http_err

    # pylint: disable=too-many-locals
    def evaluate_transaction(
            self,
            tx_cbor_hex: str,
            additional_utxos: Union["UtxoList", List["Utxo"], None] = None,
    ) -> List["Redeemer"]:
        """
        Evaluate a transaction to get execution units for Plutus scripts.

        Args:
            tx_cbor_hex: The CBOR-encoded transaction as a hex string.
            additional_utxos: Optional additional UTXOs for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.
        """
        from ..transaction import Transaction
        from ..witness_set import RedeemerTag
        from ..common.ex_units import ExUnits

        cbor_reader = CborReader.from_hex(tx_cbor_hex)
        parsed_tx = Transaction.from_cbor(cbor_reader)
        original_redeemers = parsed_tx.witness_set.redeemers

        redeemer_map = {}
        if original_redeemers is not None:
            for original_redeemer in original_redeemers:
                redeemer_map[(original_redeemer.tag, original_redeemer.index)] = original_redeemer

        payload: Dict[str, Any] = {"cbor": tx_cbor_hex}

        if additional_utxos:
            utxo_list = list(additional_utxos) if hasattr(additional_utxos, "__iter__") else [additional_utxos]
            payload["additionalUtxo"] = _prepare_utxos_for_evaluation(utxo_list)

        data = self._post(
            "utils/txs/evaluate/utxos",
            json.dumps(payload).encode("utf-8")
        )

        if isinstance(data, dict) and "message" in data:
            raise CardanoError(f"Blockfrost error: {data['message']}")

        if isinstance(data, dict) and "fault" in data:
            raise CardanoError(f"Evaluation fault: {data['fault']}")

        if not isinstance(data, dict) or "result" not in data:
            raise CardanoError(f"Unexpected evaluation response: {data}")

        result = data["result"]
        if "EvaluationResult" not in result:
            raise CardanoError(f"Evaluation failed: {result}")

        eval_result = result["EvaluationResult"]
        updated_redeemers = []

        for key, ex_units in eval_result.items():
            parts = key.split(":")
            if len(parts) != 2:
                continue

            purpose, index = parts[0], int(parts[1])

            tag_map = {
                "spend": RedeemerTag.SPEND,
                "mint": RedeemerTag.MINT,
                "certificate": RedeemerTag.CERTIFYING,
                "withdrawal": RedeemerTag.REWARD,
                "vote": RedeemerTag.VOTING,
                "propose": RedeemerTag.PROPOSING,
            }

            tag = tag_map.get(purpose)
            if tag is None:
                continue

            redeemer = redeemer_map.get((tag, index))

            if redeemer:
                units = ExUnits.new(int(ex_units["memory"]), int(ex_units["steps"]))
                redeemer.ex_units = units
                updated_redeemers.append(redeemer)

        return updated_redeemers
