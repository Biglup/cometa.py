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

from .._ffi import ffi, lib
from ..errors import CardanoError
from ..cbor.cbor_reader import CborReader
from ..cbor.cbor_writer import CborWriter
from .proposed_param_updates import ProposedParamUpdates


class Update:
    """
    Represents a protocol parameter update proposal.

    An Update consists of proposed parameter updates from genesis delegates
    and the epoch in which the update should be applied.

    This is part of the Shelley-era update mechanism.
    """

    def __init__(self, ptr) -> None:
        if ptr == ffi.NULL:
            raise CardanoError("Update: invalid handle")
        self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_update_t**", self._ptr)
            lib.cardano_update_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> Update:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return f"Update(epoch={self.epoch})"

    @classmethod
    def new(cls, epoch: int, proposed_updates: ProposedParamUpdates) -> Update:
        """
        Creates a new Update with the given epoch and proposed updates.

        Args:
            epoch: The epoch in which the update should be applied.
            proposed_updates: The proposed parameter updates from genesis delegates.

        Returns:
            A new Update instance.

        Raises:
            CardanoError: If creation fails.
        """
        out = ffi.new("cardano_update_t**")
        err = lib.cardano_update_new(epoch, proposed_updates._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to create Update (error code: {err})")
        return cls(out[0])

    @classmethod
    def from_cbor(cls, reader: CborReader) -> Update:
        """
        Deserializes Update from CBOR data.

        Args:
            reader: A CborReader positioned at the update data.

        Returns:
            A new Update deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_update_t**")
        err = lib.cardano_update_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to deserialize Update from CBOR (error code: {err})")
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the update to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_update_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize Update to CBOR (error code: {err})")

    @property
    def epoch(self) -> int:
        """
        The epoch in which the update should be applied.

        Returns:
            The target epoch number.
        """
        out = ffi.new("uint64_t*")
        err = lib.cardano_update_get_epoch(self._ptr, out)
        if err != 0:
            raise CardanoError(f"Failed to get epoch (error code: {err})")
        return int(out[0])

    @epoch.setter
    def epoch(self, value: int) -> None:
        """
        Sets the epoch in which the update should be applied.

        Args:
            value: The target epoch number.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_update_set_epoch(self._ptr, value)
        if err != 0:
            raise CardanoError(f"Failed to set epoch (error code: {err})")

    @property
    def proposed_parameters(self) -> ProposedParamUpdates:
        """
        The proposed parameter updates from genesis delegates.

        Returns:
            The ProposedParamUpdates containing the updates.
        """
        out = ffi.new("cardano_proposed_param_updates_t**")
        err = lib.cardano_update_get_proposed_parameters(self._ptr, out)
        if err != 0 or out[0] == ffi.NULL:
            raise CardanoError(f"Failed to get proposed parameters (error code: {err})")
        # Increment ref count since the C API returns a borrowed reference
        lib.cardano_proposed_param_updates_ref(out[0])
        return ProposedParamUpdates(out[0])

    @proposed_parameters.setter
    def proposed_parameters(self, value: ProposedParamUpdates) -> None:
        """
        Sets the proposed parameter updates.

        Args:
            value: The ProposedParamUpdates to set.

        Raises:
            CardanoError: If setting fails.
        """
        err = lib.cardano_update_set_proposed_parameters(self._ptr, value._ptr)
        if err != 0:
            raise CardanoError(f"Failed to set proposed parameters (error code: {err})")

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
        err = lib.cardano_update_to_cip116_json(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(f"Failed to serialize to CIP-116 JSON (error code: {err})")
