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
from .vkey_witness_set import VkeyWitnessSet
from .bootstrap_witness_set import BootstrapWitnessSet
from .native_script_set import NativeScriptSet
from .plutus_v1_script_set import PlutusV1ScriptSet
from .plutus_v2_script_set import PlutusV2ScriptSet
from .plutus_v3_script_set import PlutusV3ScriptSet
from .plutus_data_set import PlutusDataSet
from .redeemer_list import RedeemerList


class WitnessSet:
    """
    Represents a transaction witness set.

    A witness is a piece of information that allows you to efficiently verify
    the authenticity of a transaction (also known as proof).

    In Cardano, transactions have multiple types of authentication proofs,
    these can range from signatures for spending UTXOs, to scripts (with
    their arguments, datums and redeemers) for smart contract execution.

    The witness set contains:
    - VKey witnesses (public key + signature pairs)
    - Bootstrap witnesses (Byron era witnesses)
    - Native scripts
    - Plutus scripts (V1, V2, V3)
    - Plutus data (datums)
    - Redeemers
    """

    def __init__(self, ptr=None) -> None:
        if ptr is None:
            out = ffi.new("cardano_witness_set_t**")
            err = lib.cardano_witness_set_new(out)
            if err != 0:
                raise CardanoError(f"Failed to create WitnessSet (error code: {err})")
            self._ptr = out[0]
        else:
            if ptr == ffi.NULL:
                raise CardanoError("WitnessSet: invalid handle")
            self._ptr = ptr

    def __del__(self) -> None:
        if getattr(self, "_ptr", ffi.NULL) not in (None, ffi.NULL):
            ptr_ptr = ffi.new("cardano_witness_set_t**", self._ptr)
            lib.cardano_witness_set_unref(ptr_ptr)
            self._ptr = ffi.NULL

    def __enter__(self) -> WitnessSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        pass

    def __repr__(self) -> str:
        return "WitnessSet(...)"

    @classmethod
    def from_cbor(cls, reader: CborReader) -> WitnessSet:
        """
        Deserializes a WitnessSet from CBOR data.

        Args:
            reader: A CborReader positioned at the witness set data.

        Returns:
            A new WitnessSet deserialized from the CBOR data.

        Raises:
            CardanoError: If deserialization fails.
        """
        out = ffi.new("cardano_witness_set_t**")
        err = lib.cardano_witness_set_from_cbor(reader._ptr, out)
        if err != 0:
            raise CardanoError(
                f"Failed to deserialize WitnessSet from CBOR (error code: {err})"
            )
        return cls(out[0])

    def to_cbor(self, writer: CborWriter) -> None:
        """
        Serializes the witness set to CBOR format.

        Args:
            writer: A CborWriter to write the serialized data to.

        Raises:
            CardanoError: If serialization fails.
        """
        err = lib.cardano_witness_set_to_cbor(self._ptr, writer._ptr)
        if err != 0:
            raise CardanoError(
                f"Failed to serialize WitnessSet to CBOR (error code: {err})"
            )

    @property
    def vkeys(self) -> Optional[VkeyWitnessSet]:
        """
        The set of verification key witnesses.

        Returns:
            The VkeyWitnessSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_vkeys(self._ptr)
        if ptr == ffi.NULL:
            return None
        return VkeyWitnessSet(ptr)

    @vkeys.setter
    def vkeys(self, value: Optional[VkeyWitnessSet]) -> None:
        """
        Sets the verification key witnesses.

        Args:
            value: The VkeyWitnessSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        vkeys_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_vkeys(self._ptr, vkeys_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set vkeys (error code: {err})")

    @property
    def bootstrap(self) -> Optional[BootstrapWitnessSet]:
        """
        The set of bootstrap witnesses (Byron era).

        Returns:
            The BootstrapWitnessSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_bootstrap(self._ptr)
        if ptr == ffi.NULL:
            return None
        return BootstrapWitnessSet(ptr)

    @bootstrap.setter
    def bootstrap(self, value: Optional[BootstrapWitnessSet]) -> None:
        """
        Sets the bootstrap witnesses.

        Args:
            value: The BootstrapWitnessSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        bootstrap_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_bootstrap(self._ptr, bootstrap_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set bootstrap (error code: {err})")

    @property
    def native_scripts(self) -> Optional[NativeScriptSet]:
        """
        The set of native scripts.

        Returns:
            The NativeScriptSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_native_scripts(self._ptr)
        if ptr == ffi.NULL:
            return None
        return NativeScriptSet(ptr)

    @native_scripts.setter
    def native_scripts(self, value: Optional[NativeScriptSet]) -> None:
        """
        Sets the native scripts.

        Args:
            value: The NativeScriptSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        scripts_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_native_scripts(self._ptr, scripts_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set native_scripts (error code: {err})")

    @property
    def plutus_v1_scripts(self) -> Optional[PlutusV1ScriptSet]:
        """
        The set of Plutus V1 scripts.

        Returns:
            The PlutusV1ScriptSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_plutus_v1_scripts(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PlutusV1ScriptSet(ptr)

    @plutus_v1_scripts.setter
    def plutus_v1_scripts(self, value: Optional[PlutusV1ScriptSet]) -> None:
        """
        Sets the Plutus V1 scripts.

        Args:
            value: The PlutusV1ScriptSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        scripts_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_plutus_v1_scripts(self._ptr, scripts_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set plutus_v1_scripts (error code: {err})")

    @property
    def plutus_v2_scripts(self) -> Optional[PlutusV2ScriptSet]:
        """
        The set of Plutus V2 scripts.

        Returns:
            The PlutusV2ScriptSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_plutus_v2_scripts(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PlutusV2ScriptSet(ptr)

    @plutus_v2_scripts.setter
    def plutus_v2_scripts(self, value: Optional[PlutusV2ScriptSet]) -> None:
        """
        Sets the Plutus V2 scripts.

        Args:
            value: The PlutusV2ScriptSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        scripts_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_plutus_v2_scripts(self._ptr, scripts_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set plutus_v2_scripts (error code: {err})")

    @property
    def plutus_v3_scripts(self) -> Optional[PlutusV3ScriptSet]:
        """
        The set of Plutus V3 scripts.

        Returns:
            The PlutusV3ScriptSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_plutus_v3_scripts(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PlutusV3ScriptSet(ptr)

    @plutus_v3_scripts.setter
    def plutus_v3_scripts(self, value: Optional[PlutusV3ScriptSet]) -> None:
        """
        Sets the Plutus V3 scripts.

        Args:
            value: The PlutusV3ScriptSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        scripts_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_plutus_v3_scripts(self._ptr, scripts_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set plutus_v3_scripts (error code: {err})")

    @property
    def plutus_data(self) -> Optional[PlutusDataSet]:
        """
        The set of Plutus data (datums).

        Returns:
            The PlutusDataSet if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_plutus_data(self._ptr)
        if ptr == ffi.NULL:
            return None
        return PlutusDataSet(ptr)

    @plutus_data.setter
    def plutus_data(self, value: Optional[PlutusDataSet]) -> None:
        """
        Sets the Plutus data.

        Args:
            value: The PlutusDataSet to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        data_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_plutus_data(self._ptr, data_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set plutus_data (error code: {err})")

    @property
    def redeemers(self) -> Optional[RedeemerList]:
        """
        The list of redeemers.

        Returns:
            The RedeemerList if present, None otherwise.
        """
        ptr = lib.cardano_witness_set_get_redeemers(self._ptr)
        if ptr == ffi.NULL:
            return None
        return RedeemerList(ptr)

    @redeemers.setter
    def redeemers(self, value: Optional[RedeemerList]) -> None:
        """
        Sets the redeemers.

        Args:
            value: The RedeemerList to set, or None to clear.

        Raises:
            CardanoError: If setting fails.
        """
        redeemers_ptr = value._ptr if value is not None else ffi.NULL
        err = lib.cardano_witness_set_set_redeemers(self._ptr, redeemers_ptr)
        if err != 0:
            raise CardanoError(f"Failed to set redeemers (error code: {err})")

    def clear_cbor_cache(self) -> None:
        """
        Clears the cached CBOR representation.

        This is useful when you have modified the witness set after it was
        created from CBOR and you want to ensure that the next serialization
        reflects the current state rather than using the original cached CBOR.

        Warning:
            Clearing the CBOR cache may change the binary representation when
            serialized, which can alter the witness set and invalidate any
            existing signatures.
        """
        lib.cardano_witness_set_clear_cbor_cache(self._ptr)
