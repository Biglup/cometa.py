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

from typing import Union

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from ..common.anchor import Anchor
from ..address.reward_address import RewardAddress
from .governance_action_type import GovernanceActionType
from .parameter_change_action import ParameterChangeAction
from .hard_fork_initiation_action import HardForkInitiationAction
from .treasury_withdrawals_action import TreasuryWithdrawalsAction
from .no_confidence_action import NoConfidenceAction
from .update_committee_action import UpdateCommitteeAction
from .new_constitution_action import NewConstitutionAction
from .info_action import InfoAction

GovernanceAction = Union[
    ParameterChangeAction,
    HardForkInitiationAction,
    TreasuryWithdrawalsAction,
    NoConfidenceAction,
    UpdateCommitteeAction,
    NewConstitutionAction,
    InfoAction,
]


class ProposalProcedure:
    """
    Represents a governance proposal procedure.

    This supports various types of governance actions as defined in CIP-1694.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("ProposalProcedure: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_proposal_procedure_t**", self._ptr)
            lib.cardano_proposal_procedure_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> ProposalProcedure:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"ProposalProcedure(type={self.action_type.name})"

    @classmethod
    def new_parameter_change_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: ParameterChangeAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for a parameter change action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The parameter change action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_parameter_change_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_hard_fork_initiation_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: HardForkInitiationAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for a hard fork initiation action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The hard fork initiation action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_hard_fork_initiation_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_treasury_withdrawals_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: TreasuryWithdrawalsAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for a treasury withdrawals action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The treasury withdrawals action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_treasury_withdrawals_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_no_confidence_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: NoConfidenceAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for a no confidence action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The no confidence action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_no_confidence_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_update_committee_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: UpdateCommitteeAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for an update committee action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The update committee action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_update_committee_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_constitution_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: NewConstitutionAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for a new constitution action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The new constitution action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_constitution_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def new_info_action(
        cls,
        deposit: int,
        reward_address: RewardAddress,
        anchor: Anchor,
        action: InfoAction,
    ) -> ProposalProcedure:
        """
        Creates a new proposal procedure for an info action.

        Args:
            deposit: The deposit required to submit the proposal.
            reward_address: The reward address for deposit return.
            anchor: The anchor with additional proposal information.
            action: The info action.

        Returns:
            A new ProposalProcedure instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_new_info_action(
            deposit, reward_address._ptr, anchor._ptr, action._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to create ProposalProcedure (error code: {err})"
            )
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> ProposalProcedure:
        """
        Deserializes a ProposalProcedure from CBOR data.

        Args:
            reader: A CborReader positioned at the proposal procedure data.

        Returns:
            A new ProposalProcedure deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_proposal_procedure_t**")
        err = lib.cardano_proposal_procedure_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize ProposalProcedure from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the proposal procedure to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_proposal_procedure_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize ProposalProcedure to CBOR (error code: {err})"
            )

    @property
    def action_type(self) -> GovernanceActionType:
        """
        The type of governance action.

        Returns:
            The GovernanceActionType.

        Raises:
            CardanoError: If retrieval fails.
        """
        type_out = ffi.new("cardano_governance_action_type_t*")
        err = lib.cardano_proposal_procedure_get_action_type(self._ptr, type_out)
        if err != 0:
            raise CardanoError(f"Failed to get action type (error code: {err})")
        return GovernanceActionType(type_out[0])

    @property
    def anchor(self) -> Anchor:
        """
        The anchor with proposal information.

        Returns:
            The Anchor.
        """
        ptr = lib.cardano_proposal_procedure_get_anchor(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get anchor")
        lib.cardano_anchor_ref(ptr)
        return Anchor(ptr)

    @anchor.setter
    def anchor(self, value: Anchor) -> None:
        """
        Sets the anchor.

        Args:
            value: The Anchor to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_proposal_procedure_set_anchor(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set anchor (error code: {err})")

    @property
    def reward_address(self) -> RewardAddress:
        """
        The reward address for deposit return.

        Returns:
            The RewardAddress.
        """
        ptr = lib.cardano_proposal_procedure_get_reward_address(self._ptr)
        if ptr == ffi.NULL:
            raise CardanoError("Failed to get reward address")
        lib.cardano_reward_address_ref(ptr)
        return RewardAddress(ptr)

    @reward_address.setter
    def reward_address(self, value: RewardAddress) -> None:
        """
        Sets the reward address.

        Args:
            value: The RewardAddress to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_proposal_procedure_set_reward_address(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set reward address (error code: {err})")

    @property
    def deposit(self) -> int:
        """
        The deposit amount in lovelace.

        Returns:
            The deposit amount.
        """
        return int(lib.cardano_proposal_procedure_get_deposit(self._ptr))

    @deposit.setter
    def deposit(self, value: int) -> None:
        """
        Sets the deposit amount.

        Args:
            value: The deposit amount in lovelace.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_proposal_procedure_set_deposit(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set deposit (error code: {err})")

    def to_parameter_change_action(self) -> ParameterChangeAction:
        """
        Converts to a ParameterChangeAction if applicable.

        Returns:
            The ParameterChangeAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_parameter_change_action_t**")
        err = lib.cardano_proposal_procedure_to_parameter_change_action(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to ParameterChangeAction (error code: {err})"
            )
        return ParameterChangeAction(out[0])

    def to_hard_fork_initiation_action(self) -> HardForkInitiationAction:
        """
        Converts to a HardForkInitiationAction if applicable.

        Returns:
            The HardForkInitiationAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_hard_fork_initiation_action_t**")
        err = lib.cardano_proposal_procedure_to_hard_fork_initiation_action(
            self._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to convert to HardForkInitiationAction (error code: {err})"
            )
        return HardForkInitiationAction(out[0])

    def to_treasury_withdrawals_action(self) -> TreasuryWithdrawalsAction:
        """
        Converts to a TreasuryWithdrawalsAction if applicable.

        Returns:
            The TreasuryWithdrawalsAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_treasury_withdrawals_action_t**")
        err = lib.cardano_proposal_procedure_to_treasury_withdrawals_action(
            self._ptr, out
        )
        if err != 0:
            raise CardanoError(
                f"Failed to convert to TreasuryWithdrawalsAction (error code: {err})"
            )
        return TreasuryWithdrawalsAction(out[0])

    def to_no_confidence_action(self) -> NoConfidenceAction:
        """
        Converts to a NoConfidenceAction if applicable.

        Returns:
            The NoConfidenceAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_no_confidence_action_t**")
        err = lib.cardano_proposal_procedure_to_no_confidence_action(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to NoConfidenceAction (error code: {err})"
            )
        return NoConfidenceAction(out[0])

    def to_update_committee_action(self) -> UpdateCommitteeAction:
        """
        Converts to an UpdateCommitteeAction if applicable.

        Returns:
            The UpdateCommitteeAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_update_committee_action_t**")
        err = lib.cardano_proposal_procedure_to_update_committee_action(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to UpdateCommitteeAction (error code: {err})"
            )
        return UpdateCommitteeAction(out[0])

    def to_constitution_action(self) -> NewConstitutionAction:
        """
        Converts to a NewConstitutionAction if applicable.

        Returns:
            The NewConstitutionAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_new_constitution_action_t**")
        err = lib.cardano_proposal_procedure_to_constitution_action(self._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to convert to NewConstitutionAction (error code: {err})"
            )
        return NewConstitutionAction(out[0])

    def to_info_action(self) -> InfoAction:
        """
        Converts to an InfoAction if applicable.

        Returns:
            The InfoAction.

        Raises:
            CardanoError: If conversion fails.
        """
        out = ffi.new("cardano_info_action_t**")
        err = lib.cardano_proposal_procedure_to_info_action(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to convert to InfoAction (error code: {err})")
        return InfoAction(out[0])

    def get_action(self) -> GovernanceAction:
        """
        Gets the underlying governance action based on action type.

        Returns:
            The specific governance action instance.

        Raises:
            CardanoError: If conversion fails.
        """
        action_type = self.action_type
        if action_type == GovernanceActionType.PARAMETER_CHANGE:
            return self.to_parameter_change_action()
        if action_type == GovernanceActionType.HARD_FORK_INITIATION:
            return self.to_hard_fork_initiation_action()
        if action_type == GovernanceActionType.TREASURY_WITHDRAWALS:
            return self.to_treasury_withdrawals_action()
        if action_type == GovernanceActionType.NO_CONFIDENCE:
            return self.to_no_confidence_action()
        if action_type == GovernanceActionType.UPDATE_COMMITTEE:
            return self.to_update_committee_action()
        if action_type == GovernanceActionType.NEW_CONSTITUTION:
            return self.to_constitution_action()
        if action_type == GovernanceActionType.INFO:
            return self.to_info_action()
        raise CardanoError(f"Unknown action type: {action_type}")

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
        err = lib.cardano_proposal_procedure_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
