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

from typing import Optional

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.network_id import NetworkId
from ..common.withdrawal_map import WithdrawalMap
from ..cryptography.blake2b_hash import Blake2bHash
from ..cryptography.blake2b_hash_set import Blake2bHashSet
from ..assets.multi_asset import MultiAsset
from ..certificates.certificate_set import CertificateSet
from ..proposal_procedures.proposal_procedure_set import ProposalProcedureSet
from ..protocol_params.update import Update
from ..voting_procedures.voting_procedures import VotingProcedures
from .transaction_input_set import TransactionInputSet
from .transaction_output_list import TransactionOutputList
from .transaction_output import TransactionOutput


class TransactionBody:
    """
    Represents the body of a Cardano transaction.

    The transaction body encapsulates the core details of a transaction including:
    - Inputs: The UTXOs being spent
    - Outputs: Where the funds are being sent
    - Fee: The transaction fee in lovelace
    - TTL: Optional time-to-live (slot number after which tx is invalid)
    - Various optional fields for certificates, withdrawals, minting, etc.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("TransactionBody: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_transaction_body_t**", self._ptr)
            lib.cardano_transaction_body_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TransactionBody:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"TransactionBody(fee={self.fee}, inputs={len(self.inputs)}, outputs={len(self.outputs)})"

    @classmethod
    def new(
        cls,
        inputs: TransactionInputSet,
        outputs: TransactionOutputList,
        fee: int,
        ttl: Optional[int] = None,
    ) -> TransactionBody:
        """
        Creates a new TransactionBody.

        Args:
            inputs: The set of transaction inputs (UTXOs being spent).
            outputs: The list of transaction outputs.
            fee: The transaction fee in lovelace.
            ttl: Optional time-to-live slot number.

        Returns:
            A new TransactionBody instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_transaction_body_t**")
        ttl_ptr = ffi.NULL
        if ttl is not None:
            ttl_ptr = ffi.new("uint64_t*", ttl)
        err = lib.cardano_transaction_body_new(
            inputs._ptr, outputs._ptr, fee, ttl_ptr, out
        )
        if err != 0:
            raise CardanoError(f"Failed to create TransactionBody (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TransactionBody:
        """
        Deserializes a TransactionBody from CBOR data.

        Args:
            reader: A CborReader positioned at the transaction body data.

        Returns:
            A new TransactionBody deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.

        Note:
            The original CBOR encoding is cached internally to preserve
            the exact representation and avoid invalidating signatures
            when re-serializing.
        """
        out = ffi.new("cardano_transaction_body_t**")
        err = lib.cardano_transaction_body_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TransactionBody from CBOR (error code: {err})"
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
        err = lib.cardano_transaction_body_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TransactionBody to CBOR (error code: {err})"
            )

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        After calling this, to_cbor will serialize the transaction body
        fresh rather than using the cached original encoding.
        """
        lib.cardano_transaction_body_clear_cbor_cache(self._ptr)

    @property
    def hash(self) -> Blake2bHash:
        """
        The Blake2b-256 hash of the transaction body.

        This hash is used for signing and uniquely identifies the transaction.

        Returns:
            The transaction body hash.
        """
        ptr = lib.cardano_transaction_body_get_hash(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get transaction body hash")
        return Blake2bHash(ptr)

    @property
    def inputs(self) -> TransactionInputSet:
        """
        The set of transaction inputs (UTXOs being spent).

        Returns:
            The TransactionInputSet containing all inputs.
        """
        ptr = lib.cardano_transaction_body_get_inputs(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get inputs")
        return TransactionInputSet(ptr)

    @inputs.setter
    def inputs(self, value: TransactionInputSet) -> None:
        """
        Sets the transaction inputs.

        Args:
            value: The TransactionInputSet to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_body_set_inputs(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set inputs (error code: {err})")

    @property
    def outputs(self) -> TransactionOutputList:
        """
        The list of transaction outputs.

        Returns:
            The TransactionOutputList containing all outputs.
        """
        ptr = lib.cardano_transaction_body_get_outputs(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get outputs")
        return TransactionOutputList(ptr)

    @outputs.setter
    def outputs(self, value: TransactionOutputList) -> None:
        """
        Sets the transaction outputs.

        Args:
            value: The TransactionOutputList to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_body_set_outputs(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set outputs (error code: {err})")

    @property
    def fee(self) -> int:
        """
        The transaction fee in lovelace.

        Returns:
            The fee amount.
        """
        return int(lib.cardano_transaction_body_get_fee(self._ptr))

    @fee.setter
    def fee(self, value: int) -> None:
        """
        Sets the transaction fee.

        Args:
            value: The fee amount in lovelace.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_transaction_body_set_fee(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set fee (error code: {err})")

    @property
    def invalid_after(self) -> Optional[int]:
        """
        The TTL (time-to-live) slot number.

        The transaction is invalid if not included in a block by this slot.

        Returns:
            The TTL slot number, or None if not set.
        """
        ptr = lib.cardano_transaction_body_get_invalid_after(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @invalid_after.setter
    def invalid_after(self, value: Optional[int]) -> None:
        """
        Sets the TTL (time-to-live) slot number.

        Args:
            value: The TTL slot number, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("uint64_t*", value)
        err = lib.cardano_transaction_body_set_invalid_after(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set invalid_after (error code: {err})")

    @property
    def invalid_before(self) -> Optional[int]:
        """
        The validity start slot number.

        The transaction is invalid before this slot.

        Returns:
            The validity start slot number, or None if not set.
        """
        ptr = lib.cardano_transaction_body_get_invalid_before(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @invalid_before.setter
    def invalid_before(self, value: Optional[int]) -> None:
        """
        Sets the validity start slot number.

        Args:
            value: The validity start slot number, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("uint64_t*", value)
        err = lib.cardano_transaction_body_set_invalid_before(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set invalid_before (error code: {err})")

    @property
    def certificates(self) -> Optional[CertificateSet]:
        """
        The set of certificates included in the transaction.

        Returns:
            The CertificateSet if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_certificates(self._ptr)
        if ptr == ffi.NULL:
            return None
        return CertificateSet(ptr)

    @certificates.setter
    def certificates(self, value: Optional[CertificateSet]) -> None:
        """
        Sets the certificates for this transaction.

        Args:
            value: The CertificateSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        cert_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_certificates(self._ptr, cert_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set certificates (error code: {err})")

    @property
    def withdrawals(self) -> Optional[WithdrawalMap]:
        """
        The stake rewards withdrawals in this transaction.

        Returns:
            The WithdrawalMap if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_withdrawals(self._ptr)
        if ptr == ffi.NULL:
            return None
        return WithdrawalMap(ptr)

    @withdrawals.setter
    def withdrawals(self, value: Optional[WithdrawalMap]) -> None:
        """
        Sets the withdrawals for this transaction.

        Args:
            value: The WithdrawalMap to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        withdrawal_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_withdrawals(self._ptr, withdrawal_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set withdrawals (error code: {err})")

    @property
    def update(self) -> Optional[Update]:
        """
        The protocol parameter update proposal.

        Returns:
            The Update if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_update(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Update(ptr)

    @update.setter
    def update(self, value: Optional[Update]) -> None:
        """
        Sets the protocol parameter update proposal.

        Args:
            value: The Update to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        update_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_update(self._ptr, update_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set update (error code: {err})")

    @property
    def aux_data_hash(self) -> Optional[Blake2bHash]:
        """
        The hash of the auxiliary data.

        Returns:
            The auxiliary data hash if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_aux_data_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)

    @aux_data_hash.setter
    def aux_data_hash(self, value: Optional[Blake2bHash]) -> None:
        """
        Sets the auxiliary data hash.

        Args:
            value: The Blake2bHash to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        hash_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_aux_data_hash(self._ptr, hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set aux_data_hash (error code: {err})")

    @property
    def mint(self) -> Optional[MultiAsset]:
        """
        The multi-asset minting/burning operations.

        Returns:
            The MultiAsset representing minting operations, None if not present.
        """
        ptr = lib.cardano_transaction_body_get_mint(self._ptr)
        if ptr == ffi.NULL:
            return None
        return MultiAsset(ptr)

    @mint.setter
    def mint(self, value: Optional[MultiAsset]) -> None:
        """
        Sets the minting operations.

        Args:
            value: The MultiAsset to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        mint_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_mint(self._ptr, mint_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set mint (error code: {err})")

    @property
    def script_data_hash(self) -> Optional[Blake2bHash]:
        """
        The hash of the script data (redeemers + datums + cost models).

        Returns:
            The script data hash if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_script_data_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHash(ptr)

    @script_data_hash.setter
    def script_data_hash(self, value: Optional[Blake2bHash]) -> None:
        """
        Sets the script data hash.

        Args:
            value: The Blake2bHash to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        hash_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_script_data_hash(self._ptr, hash_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set script_data_hash (error code: {err})")

    @property
    def collateral(self) -> Optional[TransactionInputSet]:
        """
        The collateral inputs for Plutus script execution.

        Returns:
            The TransactionInputSet of collateral inputs, None if not present.
        """
        ptr = lib.cardano_transaction_body_get_collateral(self._ptr)
        if ptr == ffi.NULL:
            return None
        return TransactionInputSet(ptr)

    @collateral.setter
    def collateral(self, value: Optional[TransactionInputSet]) -> None:
        """
        Sets the collateral inputs.

        Args:
            value: The TransactionInputSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        coll_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_collateral(self._ptr, coll_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set collateral (error code: {err})")

    @property
    def required_signers(self) -> Optional[Blake2bHashSet]:
        """
        The set of required signers (key hashes).

        Returns:
            The Blake2bHashSet of required signers, None if not present.
        """
        ptr = lib.cardano_transaction_body_get_required_signers(self._ptr)
        if ptr == ffi.NULL:
            return None
        return Blake2bHashSet(ptr)

    @required_signers.setter
    def required_signers(self, value: Optional[Blake2bHashSet]) -> None:
        """
        Sets the required signers.

        Args:
            value: The Blake2bHashSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        signers_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_required_signers(self._ptr, signers_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set required_signers (error code: {err})")

    @property
    def network_id(self) -> Optional[NetworkId]:
        """
        The explicit network ID for this transaction.

        Returns:
            The NetworkId if set, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_network_id(self._ptr)
        if ptr == ffi.NULL:
            return None
        return NetworkId(ptr[0])

    @network_id.setter
    def network_id(self, value: Optional[NetworkId]) -> None:
        """
        Sets the network ID.

        Args:
            value: The NetworkId to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("cardano_network_id_t*", value.value)
        err = lib.cardano_transaction_body_set_network_id(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set network_id (error code: {err})")

    @property
    def collateral_return(self) -> Optional[TransactionOutput]:
        """
        The collateral return output (change from collateral).

        Returns:
            The TransactionOutput for collateral return, None if not present.
        """
        ptr = lib.cardano_transaction_body_get_collateral_return(self._ptr)
        if ptr == ffi.NULL:
            return None
        return TransactionOutput(ptr)

    @collateral_return.setter
    def collateral_return(self, value: Optional[TransactionOutput]) -> None:
        """
        Sets the collateral return output.

        Args:
            value: The TransactionOutput to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        output_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_collateral_return(self._ptr, output_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set collateral_return (error code: {err})")

    @property
    def total_collateral(self) -> Optional[int]:
        """
        The total collateral amount in lovelace.

        Returns:
            The total collateral, or None if not set.
        """
        ptr = lib.cardano_transaction_body_get_total_collateral(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @total_collateral.setter
    def total_collateral(self, value: Optional[int]) -> None:
        """
        Sets the total collateral amount.

        Args:
            value: The total collateral in lovelace, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("uint64_t*", value)
        err = lib.cardano_transaction_body_set_total_collateral(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set total_collateral (error code: {err})")

    @property
    def reference_inputs(self) -> Optional[TransactionInputSet]:
        """
        The reference inputs (read-only, not consumed).

        Returns:
            The TransactionInputSet of reference inputs, None if not present.
        """
        ptr = lib.cardano_transaction_body_get_reference_inputs(self._ptr)
        if ptr == ffi.NULL:
            return None
        return TransactionInputSet(ptr)

    @reference_inputs.setter
    def reference_inputs(self, value: Optional[TransactionInputSet]) -> None:
        """
        Sets the reference inputs.

        Args:
            value: The TransactionInputSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        ref_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_reference_inputs(self._ptr, ref_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set reference_inputs (error code: {err})")

    @property
    def voting_procedures(self) -> Optional[VotingProcedures]:
        """
        The voting procedures for governance actions.

        Returns:
            The VotingProcedures if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_voting_procedures(self._ptr)
        if ptr == ffi.NULL:
            return None
        return VotingProcedures(ptr)

    @voting_procedures.setter
    def voting_procedures(self, value: Optional[VotingProcedures]) -> None:
        """
        Sets the voting procedures.

        Args:
            value: The VotingProcedures to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        voting_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_voting_procedures(self._ptr, voting_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set voting_procedures (error code: {err})")

    @property
    def proposal_procedures(self) -> Optional[ProposalProcedureSet]:
        """
        The proposal procedures for governance actions.

        Returns:
            The ProposalProcedureSet if present, None otherwise.
        """
        ptr = lib.cardano_transaction_body_get_proposal_procedures(self._ptr)
        if ptr == ffi.NULL:
            return None
        return ProposalProcedureSet(ptr)

    @proposal_procedures.setter
    def proposal_procedures(self, value: Optional[ProposalProcedureSet]) -> None:
        """
        Sets the proposal procedures.

        Args:
            value: The ProposalProcedureSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        proposal_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_transaction_body_set_proposal_procedure(self._ptr, proposal_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set proposal_procedures (error code: {err})")

    @property
    def treasury_value(self) -> Optional[int]:
        """
        The treasury value for this transaction.

        Returns:
            The treasury value in lovelace, or None if not set.
        """
        ptr = lib.cardano_transaction_body_get_treasury_value(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @treasury_value.setter
    def treasury_value(self, value: Optional[int]) -> None:
        """
        Sets the treasury value.

        Args:
            value: The treasury value in lovelace, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("uint64_t*", value)
        err = lib.cardano_transaction_body_set_treasury_value(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set treasury_value (error code: {err})")

    @property
    def donation(self) -> Optional[int]:
        """
        The donation amount to the treasury.

        Returns:
            The donation amount in lovelace, or None if not set.
        """
        ptr = lib.cardano_transaction_body_get_donation(self._ptr)
        if ptr == ffi.NULL:
            return None
        return int(ptr[0])

    @donation.setter
    def donation(self, value: Optional[int]) -> None:
        """
        Sets the donation amount.

        Args:
            value: The donation amount in lovelace, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        if value is None:
            val_ptr = ffi.NULL
        else:
            val_ptr = ffi.new("uint64_t*", value)
        err = lib.cardano_transaction_body_set_donation(self._ptr, val_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set donation (error code: {err})")
