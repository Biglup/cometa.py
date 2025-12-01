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

    Example:
        >>> from cometa import NetworkMagic
        >>> from cometa.providers import BlockfrostProvider, ProviderHandle
        >>>
        >>> provider = BlockfrostProvider(
        ...     network=NetworkMagic.PREPROD,
        ...     project_id="your_project_id"
        ... )
        >>> params = provider.get_parameters()
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
        """Get headers for Blockfrost API requests."""
        return {
            "project_id": self._project_id,
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str) -> Any:
        """Make a GET request to the Blockfrost API."""
        url = f"{self._base_url}{endpoint}"
        request = Request(url, headers=self._headers())

        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as http_err:
            if http_err.code == 404:
                return None
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            raise Exception(f"Blockfrost API error {http_err.code}: {body}") from http_err
        except URLError as url_err:
            raise Exception(f"Network error: {url_err.reason}") from url_err

    def _post(self, endpoint: str, data: bytes, content_type: str = "application/json") -> Any:
        """Make a POST request to the Blockfrost API."""
        url = f"{self._base_url}{endpoint}"
        headers = self._headers()
        headers["Content-Type"] = content_type

        request = Request(url, data=data, headers=headers, method="POST")

        try:
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as http_err:
            body = http_err.read().decode("utf-8") if http_err.fp else ""
            raise Exception(f"Blockfrost API error {http_err.code}: {body}") from http_err
        except URLError as url_err:
            raise Exception(f"Network error: {url_err.reason}") from url_err

    # -------------------------------------------------------------------------
    # Provider Protocol Implementation
    # -------------------------------------------------------------------------

    def get_name(self) -> str:  # pylint: disable=no-self-use
        """Get the provider name."""
        return "Blockfrost"

    def get_network_magic(self) -> int:
        """Get the network magic number."""
        return int(self._network)

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def get_parameters(self) -> "ProtocolParameters":
        """
        Retrieve the current protocol parameters from Blockfrost.

        Returns:
            The current ProtocolParameters.

        Raises:
            Exception: If the request fails.
        """
        from ..protocol_params import ProtocolParameters, ExUnitPrices
        from ..common import UnitInterval, ExUnits, ProtocolVersion

        data = self._get("epochs/latest/parameters")
        if data is None:
            raise Exception("Failed to fetch protocol parameters")

        if "message" in data:
            raise Exception(f"Blockfrost error: {data['message']}")

        # Build ProtocolParameters by setting individual properties
        params = ProtocolParameters.new()

        # Fee parameters
        if data.get("min_fee_a") is not None:
            params.min_fee_a = int(data["min_fee_a"])
        if data.get("min_fee_b") is not None:
            params.min_fee_b = int(data["min_fee_b"])

        # Size limits
        if data.get("max_block_size") is not None:
            params.max_block_body_size = int(data["max_block_size"])
        if data.get("max_tx_size") is not None:
            params.max_tx_size = int(data["max_tx_size"])
        if data.get("max_block_header_size") is not None:
            params.max_block_header_size = int(data["max_block_header_size"])

        # Deposit parameters
        if data.get("key_deposit") is not None:
            params.key_deposit = int(data["key_deposit"])
        if data.get("pool_deposit") is not None:
            params.pool_deposit = int(data["pool_deposit"])

        # Pool parameters
        if data.get("e_max") is not None:
            params.max_epoch = int(data["e_max"])
        if data.get("n_opt") is not None:
            params.n_opt = int(data["n_opt"])
        if data.get("min_pool_cost") is not None:
            params.min_pool_cost = int(data["min_pool_cost"])

        # Ratio parameters (as UnitInterval)
        if data.get("a0") is not None:
            params.pool_pledge_influence = UnitInterval.from_float(float(data["a0"]))
        if data.get("rho") is not None:
            params.expansion_rate = UnitInterval.from_float(float(data["rho"]))
        if data.get("tau") is not None:
            params.treasury_growth_rate = UnitInterval.from_float(float(data["tau"]))

        # Protocol version
        major = data.get("protocol_major_ver", 0)
        minor = data.get("protocol_minor_ver", 0)
        if major or minor:
            params.protocol_version = ProtocolVersion.new(int(major), int(minor))

        # UTXO parameters
        if data.get("coins_per_utxo_word") is not None:
            params.ada_per_utxo_byte = int(data["coins_per_utxo_word"])
        elif data.get("coins_per_utxo_size") is not None:
            params.ada_per_utxo_byte = int(data["coins_per_utxo_size"])

        # Plutus parameters
        if data.get("max_val_size") is not None:
            params.max_value_size = int(data["max_val_size"])
        if data.get("collateral_percent") is not None:
            params.collateral_percentage = int(data["collateral_percent"])
        if data.get("max_collateral_inputs") is not None:
            params.max_collateral_inputs = int(data["max_collateral_inputs"])

        # Execution units
        max_tx_mem = data.get("max_tx_ex_mem")
        max_tx_steps = data.get("max_tx_ex_steps")
        if max_tx_mem is not None and max_tx_steps is not None:
            params.max_tx_ex_units = ExUnits.new(int(max_tx_mem), int(max_tx_steps))

        max_block_mem = data.get("max_block_ex_mem")
        max_block_steps = data.get("max_block_ex_steps")
        if max_block_mem is not None and max_block_steps is not None:
            params.max_block_ex_units = ExUnits.new(int(max_block_mem), int(max_block_steps))

        # Execution costs (prices)
        price_mem = data.get("price_mem")
        price_step = data.get("price_step")
        if price_mem is not None and price_step is not None:
            mem_prices = UnitInterval.from_float(float(price_mem))
            step_prices = UnitInterval.from_float(float(price_step))
            params.execution_costs = ExUnitPrices.new(mem_prices, step_prices)

        # Governance parameters (Conway era)
        if data.get("drep_deposit") is not None:
            params.drep_deposit = int(data["drep_deposit"])
        if data.get("drep_activity") is not None:
            params.drep_inactivity_period = int(data["drep_activity"])
        if data.get("gov_action_deposit") is not None:
            params.governance_action_deposit = int(data["gov_action_deposit"])
        if data.get("gov_action_lifetime") is not None:
            params.governance_action_validity_period = int(data["gov_action_lifetime"])
        if data.get("committee_min_size") is not None:
            params.min_committee_size = int(data["committee_min_size"])
        if data.get("committee_max_term_length") is not None:
            params.committee_term_limit = int(data["committee_max_term_length"])

        # Reference script cost
        ref_script_cost = data.get("min_fee_ref_script_cost_per_byte")
        if ref_script_cost is not None:
            params.ref_script_cost_per_byte = UnitInterval.from_float(float(ref_script_cost))

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
                raise Exception(f"Blockfrost error: {data['message']}")

            for utxo_data in data:
                utxo = self._parse_utxo(addr_str, utxo_data)
                results.append(utxo)

            if len(data) < max_page_count:
                break
            page += 1

        return results

    # pylint: disable=too-many-locals,no-self-use
    def _parse_utxo(self, address: str, utxo_data: Dict) -> "Utxo":
        """Parse a Blockfrost UTXO response into a Utxo object."""
        from ..common.utxo import Utxo
        from ..common.datum import Datum
        from ..transaction_body import TransactionInput, TransactionOutput, Value
        from ..address import Address

        tx_input = TransactionInput.from_hex(
            utxo_data["tx_hash"],
            utxo_data["output_index"]
        )

        # Parse the value (lovelace and multi-assets)
        lovelace = 0
        multi_asset_dict: Dict[bytes, Dict[bytes, int]] = {}

        for amount in utxo_data.get("amount", []):
            if amount["unit"] == "lovelace":
                lovelace = int(amount["quantity"])
            else:
                # Native token: unit is policy_id + asset_name (both hex encoded)
                unit = amount["unit"]
                # Policy ID is always 56 hex chars (28 bytes)
                policy_id_hex = unit[:56]
                asset_name_hex = unit[56:]

                policy_id_bytes = bytes.fromhex(policy_id_hex)
                asset_name_bytes = bytes.fromhex(asset_name_hex) if asset_name_hex else b""

                if policy_id_bytes not in multi_asset_dict:
                    multi_asset_dict[policy_id_bytes] = {}
                multi_asset_dict[policy_id_bytes][asset_name_bytes] = int(amount["quantity"])

        # Create value with multi-assets if present
        if multi_asset_dict:
            value = Value.from_dict([lovelace, multi_asset_dict])
        else:
            value = Value.from_coin(lovelace)

        addr = Address.from_string(address)
        tx_output = TransactionOutput.new(addr, lovelace)
        tx_output.value = value

        # Handle datum if present
        datum_hash = utxo_data.get("data_hash")
        inline_datum = utxo_data.get("inline_datum")

        if inline_datum is not None:
            # Inline datum - need to convert JSON to PlutusData CBOR
            # Blockfrost returns inline_datum as JSON representation
            # For now, we'll try to get the CBOR from the datum endpoint if hash is available
            if datum_hash:
                try:
                    datum = Datum.from_data_hash_hex(datum_hash)
                    tx_output.datum = datum
                except Exception:  # pylint: disable=broad-except
                    pass  # If we can't parse datum, continue without it
        elif datum_hash:
            # Datum hash reference
            try:
                datum = Datum.from_data_hash_hex(datum_hash)
                tx_output.datum = datum
            except Exception:  # pylint: disable=broad-except
                pass  # If we can't parse datum, continue without it

        # Handle script reference if present
        script_ref = utxo_data.get("reference_script_hash")
        if script_ref:
            # Script references are more complex - would need to fetch the script
            # For now, we store the hash but don't resolve the full script
            pass

        return Utxo.new(tx_input, tx_output)

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
            raise Exception(f"Blockfrost error: {data['message']}")

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
                raise Exception(f"Blockfrost error: {data['message']}")

            for utxo_data in data:
                utxo = self._parse_utxo(addr_str, utxo_data)
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
            Exception: If the NFT is not found or held by multiple addresses/UTXOs.
        """
        asset_str = str(asset_id) if not isinstance(asset_id, str) else asset_id

        data = self._get(f"assets/{asset_str}/addresses")

        if data is None or len(data) == 0:
            raise Exception("NFT not found")

        if isinstance(data, dict) and "message" in data:
            raise Exception(f"Blockfrost error: {data['message']}")

        if len(data) > 1:
            raise Exception("NFT must be held by only one address")

        holder_address = data[0]["address"]
        utxos = self.get_unspent_outputs_with_asset(holder_address, asset_str)

        if len(utxos) != 1:
            raise Exception("NFT must be present in only one UTXO")

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
            tx_id = tx_in.id.to_hex()
            index = tx_in.index

            data = self._get(f"txs/{tx_id}/utxos")

            if data is None:
                continue

            if isinstance(data, dict) and "message" in data:
                raise Exception(f"Blockfrost error: {data['message']}")

            for output in data.get("outputs", []):
                if output["output_index"] == index:
                    output["tx_hash"] = tx_id
                    utxo = self._parse_utxo(output["address"], output)
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
            raise Exception(f"Datum not found: {hash_str}")

        if isinstance(data, dict) and "message" in data:
            raise Exception(f"Blockfrost error: {data['message']}")

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
            raise Exception(f"Failed to submit transaction: {body}") from http_err

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
        from ..witness_set import Redeemer, RedeemerTag
        from ..common.ex_units import ExUnits

        payload: Dict[str, Any] = {"cbor": tx_cbor_hex}

        if additional_utxos:
            # Convert UTXOs to Blockfrost format
            utxo_list = list(additional_utxos) if hasattr(additional_utxos, "__iter__") else [additional_utxos]
            payload["additionalUtxo"] = self._prepare_utxos_for_evaluation(utxo_list)

        data = self._post(
            "utils/txs/evaluate/utxos",
            json.dumps(payload).encode("utf-8")
        )

        if isinstance(data, dict) and "message" in data:
            raise Exception(f"Blockfrost error: {data['message']}")

        if isinstance(data, dict) and "fault" in data:
            raise Exception(f"Evaluation fault: {data['fault']}")

        if not isinstance(data, dict) or "result" not in data:
            raise Exception(f"Unexpected evaluation response: {data}")

        result = data["result"]
        if "EvaluationResult" not in result:
            raise Exception(f"Evaluation failed: {result}")

        eval_result = result["EvaluationResult"]
        redeemers = []

        for key, ex_units in eval_result.items():
            # Key format is "purpose:index" e.g., "spend:0"
            parts = key.split(":")
            if len(parts) != 2:
                continue

            purpose, index = parts[0], int(parts[1])

            # Map purpose to RedeemerTag
            tag_map = {
                "spend": RedeemerTag.SPEND,
                "mint": RedeemerTag.MINT,
                "cert": RedeemerTag.CERTIFYING,
                "reward": RedeemerTag.REWARD,
                "vote": RedeemerTag.VOTING,
                "propose": RedeemerTag.PROPOSING,
            }

            tag = tag_map.get(purpose)
            if tag is None:
                continue

            units = ExUnits.new(int(ex_units["memory"]), int(ex_units["steps"]))

            # Create a minimal redeemer with the execution units
            # The actual redeemer data would come from the transaction
            redeemer = Redeemer.new(tag, index, None, units)
            redeemers.append(redeemer)

        return redeemers

    def _prepare_utxos_for_evaluation(self, utxos: List["Utxo"]) -> List:  # pylint: disable=no-self-use
        """Prepare UTXOs for the evaluation endpoint."""
        result = []
        for utxo in utxos:
            input_json = {
                "id": utxo.input.id.to_hex(),
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

            result.extend([input_json, output_json])

        return result
