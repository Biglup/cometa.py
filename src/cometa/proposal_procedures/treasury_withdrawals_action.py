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
from ..common.withdrawal_map import WithdrawalMap
from ..cryptography.blake2b_hash import Blake2bHash


class TreasuryWithdrawalsAction:
    """
    Represents a treasury withdrawals governance action.

    This action withdraws funds from the Cardano treasury to specified
    reward addresses. The guardrails policy hash can optionally be provided
    to ensure the withdrawal is validated against a guardrails script.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("TreasuryWithdrawalsAction: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_treasury_withdrawals_action_t**", self._ptr)
            lib.cardano_treasury_withdrawals_action_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> TreasuryWithdrawalsAction:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "TreasuryWithdrawalsAction(...)"

    @classmethod
    def new(
        cls,
        withdrawals: WithdrawalMap,
        policy_hash: Optional[Blake2bHash] = None,
    ) -> TreasuryWithdrawalsAction:
        """
        Creates a new treasury withdrawals action.

        Args:
            withdrawals: The withdrawal map specifying reward addresses and amounts.
            policy_hash: Optional guardrails policy hash.

        Returns:
            A new TreasuryWithdrawalsAction instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_treasury_withdrawals_action_t**")
        policy_ptr = policy_hash._ptr if policy_hash is not None else ffi.NULL
        err = lib.cardano_treasury_withdrawals_action_new(
            withdrawals._ptr, policy_ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create TreasuryWithdrawalsAction (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> TreasuryWithdrawalsAction:
        """
        Deserializes a TreasuryWithdrawalsAction from CBOR data.

        Args:
            reader: A CborReader positioned at the action data.

        Returns:
            A new TreasuryWithdrawalsAction deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_treasury_withdrawals_action_t**")
        err = lib.cardano_treasury_withdrawals_action_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize TreasuryWithdrawalsAction from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the action to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_treasury_withdrawals_action_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize TreasuryWithdrawalsAction to CBOR (error code: {err})"
            )

    @property
    def withdrawals(self) -> WithdrawalMap:
        """
        The withdrawal map specifying reward addresses and amounts.

        Returns:
            The WithdrawalMap.
        """
        ptr = lib.cardano_treasury_withdrawals_action_get_withdrawals(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get withdrawals")
        lib.cardano_withdrawal_map_ref(ptr)
        return WithdrawalMap(ptr)

    @withdrawals.setter
    def withdrawals(self, value: WithdrawalMap) -> None:
        """
        Sets the withdrawal map.

        Args:
            value: The WithdrawalMap to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_treasury_withdrawals_action_set_withdrawals(
            self._ptr, value._ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set withdrawals (error code: {err})")

    @property
    def policy_hash(self) -> Optional[Blake2bHash]:
        """
        The optional guardrails policy hash.

        Returns:
            The Blake2bHash if present, None otherwise.
        """
        ptr = lib.cardano_treasury_withdrawals_action_get_policy_hash(self._ptr)
        if ptr == ffi.NULL:
            return None
        lib.cardano_blake2b_hash_ref(ptr)
        return Blake2bHash(ptr)

    @policy_hash.setter
    def policy_hash(self, value: Optional[Blake2bHash]) -> None:
        """
        Sets the policy hash.

        Args:
            value: The Blake2bHash to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        policy_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_treasury_withdrawals_action_set_policy_hash(
            self._ptr, policy_ptr
        )
        if err != 0:
            raise CardanoError(f"Failed to set policy hash (error code: {err})")

    def to_cip116_json(self, writer: "JsonWriter") -> None:
        """
        Serializes this object to CIP-116 compliant JSON.

        Args:
            writer: The JsonWriter to write the JSON to.

        Raises:
            CardanoError: If serialization fails.
        """
        from ..json import JsonWriter
        if not isinstance(writer, JsonWriter):
            raise TypeError("writer must be a JsonWriter instance")
        err = lib.cardano_treasury_withdrawals_action_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
