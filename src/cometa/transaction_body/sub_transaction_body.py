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

from typing import Optional, TYPE_CHECKING

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.network_id import NetworkId
from ..common.withdrawal_map import WithdrawalMap
from ..cryptography.blake2b_hash import Blake2bHash
from ..assets.multi_asset import MultiAsset
from ..certificates.certificate_set import CertificateSet
from ..proposal_procedures.proposal_procedure_set import ProposalProcedureSet
from ..voting_procedures.voting_procedures import VotingProcedures
from .transaction_input_set import TransactionInputSet
from .transaction_output_list import TransactionOutputList

if TYPE_CHECKING:
    from ..common import Credential
    from ..plutus_data import PlutusData
    from ..transaction import SubTransaction
    from .account_balance_interval import AccountBalanceInterval
    from ..certificates.certificate import Certificate, CertificateUnion


class SubTransactionBody:
    """Read the body of an independently signed Dijkstra sub-transaction."""

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("SubTransactionBody: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_sub_transaction_body_t**", self._ptr)
            lib.cardano_sub_transaction_body_unref(ptr_ptr)
            self._ptr = ffi.NULL

    @classmethod
    def from_cbor(cls, reader: CborReader) -> SubTransactionBody:
        """
        Deserializes a SubTransactionBody from CBOR data.

        Args:
            reader: A CborReader positioned at the transaction body data.

        Returns:
            A new SubTransactionBody deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.

        Note:
            The original CBOR encoding is cached internally to preserve
            the exact representation and avoid invalidating signatures
            when re-serializing.
        """
        out = ffi.new("cardano_sub_transaction_body_t**")
        err = lib.cardano_sub_transaction_body_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize SubTransactionBody from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the transaction body to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.

        Note:
            If this transaction body was created from CBOR, the cached
            original encoding is used to preserve the exact representation.
        """
        err = lib.cardano_sub_transaction_body_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize SubTransactionBody to CBOR (error code: {err})"
            )

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        After calling this, to_cbor will serialize the transaction body
        fresh rather than using the cached original encoding.
        """
        lib.cardano_sub_transaction_body_clear_cbor_cache(self._ptr)

    @property
    def inputs(self) -> TransactionInputSet:
        """
        The set of transaction inputs (UTXOs being spent).

        Returns:
            The TransactionInputSet containing all inputs.
        """
        ptr = lib.cardano_sub_transaction_body_get_inputs(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get inputs")
        return TransactionInputSet(ptr)

    @property
    def outputs(self) -> TransactionOutputList:
        """
        The list of transaction outputs.

        Returns:
            The TransactionOutputList containing all outputs.
        """
        ptr = lib.cardano_sub_transaction_body_get_outputs(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get outputs")
        return TransactionOutputList(ptr)

    @property
    def certificates(self) -> Optional[CertificateSet]:
        """
        The set of certificates included in the transaction.

        Returns:
            The CertificateSet if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_certificates(self._ptr)
        if ptr == ffi.NULL:
            return None
        return CertificateSet(ptr)

    @property
    def withdrawals(self) -> Optional[WithdrawalMap]:
        """
        The stake rewards withdrawals in this transaction.

        Returns:
            The WithdrawalMap if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_withdrawals(self._ptr)
        if ptr == ffi.NULL:
            return None
        return WithdrawalMap(ptr)

    @property
    def mint(self) -> Optional[MultiAsset]:
        """
        The multi-asset minting/burning operations.

        Returns:
            The MultiAsset representing minting operations, None if not present.
        """
        ptr = lib.cardano_sub_transaction_body_get_mint(self._ptr)
        if ptr == ffi.NULL:
            return None
        return MultiAsset(ptr)

    @property
    def script_data_hash(self) -> Optional[Blake2bHash]:
        """
        The hash of the script data (redeemers + datums + cost models).

        Returns:
            The script data hash if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_script_data_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)

    @property
    def network_id(self) -> Optional[NetworkId]:
        """
        The explicit network ID for this transaction.

        Returns:
            The NetworkId if set, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_network_id(self._ptr)
        if ptr == ffi.NULL:
            return None
        return NetworkId(ptr[0])

    @property
    def reference_inputs(self) -> Optional[TransactionInputSet]:
        """
        The reference inputs (read-only, not consumed).

        Returns:
            The TransactionInputSet of reference inputs, None if not present.
        """
        ptr = lib.cardano_sub_transaction_body_get_reference_inputs(self._ptr)
        if ptr == ffi.NULL:
            return None
        return TransactionInputSet(ptr)

    @property
    def voting_procedures(self) -> Optional[VotingProcedures]:
        """
        The voting procedures for governance actions.

        Returns:
            The VotingProcedures if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_voting_procedures(self._ptr)
        if ptr == ffi.NULL:
            return None
        return VotingProcedures(ptr)

    @property
    def proposal_procedures(self) -> Optional[ProposalProcedureSet]:
        """
        The proposal procedures for governance actions.

        Returns:
            The ProposalProcedureSet if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_proposal_procedures(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ProposalProcedureSet(ptr)

    @property
    def treasury_value(self) -> Optional[int]:
        """
        The treasury value for this transaction.

        Returns:
            The treasury value in lovelace, or None if not set.
        """
        ptr = lib.cardano_sub_transaction_body_get_treasury_value(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @property
    def donation(self) -> Optional[int]:
        """
        The donation amount to the treasury.

        Returns:
            The donation amount in lovelace, or None if not set.
        """
        ptr = lib.cardano_sub_transaction_body_get_donation(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])


    @property
    def guards(self) -> list[Credential]:
        """Return guards in a Python collection (Dijkstra)."""
        from ._dijkstra import read_guards
        return read_guards(lib.cardano_sub_transaction_body_get_guards(self._ptr))

    @property
    def required_top_level_guards(self) -> list[tuple[Credential, Optional[PlutusData]]]:
        """Return required top level guards in a Python collection (Dijkstra)."""
        from ._dijkstra import read_required_guards
        return read_required_guards(lib.cardano_sub_transaction_body_get_required_top_level_guards(self._ptr))

    @property
    def direct_deposits(self) -> dict[str, int]:
        """Return direct deposits in a Python collection (Dijkstra)."""
        from ._dijkstra import read_account_map
        return read_account_map(lib.cardano_sub_transaction_body_get_direct_deposits(self._ptr))

    @property
    def account_balance_intervals(self) -> dict[str, AccountBalanceInterval]:
        """Return account balance intervals in a Python collection (Dijkstra)."""
        from ._dijkstra import read_account_map
        return read_account_map(lib.cardano_sub_transaction_body_get_account_balance_intervals(self._ptr), intervals=True)


    @property
    def hash(self) -> Blake2bHash:
        """
        The Blake2b-256 hash of the transaction body.

        This hash is used for signing and uniquely identifies the transaction.

        Returns:
            The transaction body hash.
        """
        ptr = lib.cardano_sub_transaction_body_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction body hash")
        return Blake2bHash(ptr)


    @property
    def invalid_after(self) -> Optional[int]:
        """
        The TTL (time-to-live) slot number.

        The transaction is invalid if not included in a block by this slot.

        Returns:
            The TTL slot number, or None if not set.
        """
        ptr = lib.cardano_sub_transaction_body_get_invalid_after(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])


    @property
    def invalid_before(self) -> Optional[int]:
        """
        The validity start slot number.

        The transaction is invalid before this slot.

        Returns:
            The validity start slot number, or None if not set.
        """
        ptr = lib.cardano_sub_transaction_body_get_invalid_before(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])


    @property
    def aux_data_hash(self) -> Optional[Blake2bHash]:
        """
        The hash of the auxiliary data.

        Returns:
            The auxiliary data hash if present, None otherwise.
        """
        ptr = lib.cardano_sub_transaction_body_get_aux_data_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)
