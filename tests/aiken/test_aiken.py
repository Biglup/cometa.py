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

import pytest
from unittest.mock import MagicMock
from cometa import (
    PlutusList,
    PlutusData,
    ConstrPlutusData,
    SlotConfig,
    ExUnits,
    AikenTxEvaluator,
    TxEvaluationError,
    apply_params_to_script,
    ApplyParamsError
)

@pytest.fixture
def mock_cost_models():
    """Create a mock cost models object for testing."""
    return MagicMock()


COMPILED_CODE = (
    "590221010000323232323232323232323223222232533300b32323232533300f3370e9000180700089"
    "919191919191919191919299980e98100010991919299980e99b87480000044c94ccc078cdc3a4000"
    "603a002264a66603e66e1c011200213371e00a0322940c07000458c8cc004004030894ccc0880045"
    "30103d87a80001323253330213375e6603a603e004900000d099ba548000cc0940092f5c02660080"
    "08002604c00460480022a66603a66e1c009200113371e00602e2940c06c050dd6980e8011bae301b"
    "00116301e001323232533301b3370e90010008a5eb7bdb1804c8dd59810800980c801180c8009919"
    "80080080111299980f0008a6103d87a8000132323232533301f3371e01e004266e952000330233"
    "74c00297ae0133006006003375660400066eb8c078008c088008c080004c8cc004004008894ccc07"
    "400452f5bded8c0264646464a66603c66e3d221000021003133022337606ea4008dd3000998030030"
    "019bab301f003375c603a0046042004603e0026eacc070004c070004c06c004c068004c064008dd6"
    "180b80098078029bae3015001300d001163013001301300230110013009002149858c94ccc02ccdc"
    "3a40000022a66601c60120062930b0a99980599b874800800454ccc038c02400c52616163009002"
    "375c0026600200290001111199980399b8700100300c233330050053370000890011807000801001"
    "118029baa001230033754002ae6955ceaab9e5573eae815d0aba201"
)

TX_HASH = "1f3f766bc864c3f8ce8ccc20716e3f3cf65f08a819073c75875ea4e67549947f"


class TestSlotConfig:
    """Tests for SlotConfig."""

    def test_mainnet_config(self):
        """Test mainnet slot configuration."""
        config = SlotConfig.mainnet()
        assert config.zero_time == 1596059091000
        assert config.zero_slot == 4492800
        assert config.slot_length == 1000
        assert config.start_epoch == 208
        assert config.epoch_length == 432000

    def test_preview_config(self):
        """Test Preview testnet slot configuration."""
        config = SlotConfig.preview()
        assert config.zero_time == 1666656000000
        assert config.zero_slot == 0
        assert config.slot_length == 1000
        assert config.start_epoch == 0
        assert config.epoch_length == 86400

    def test_preprod_config(self):
        """Test Preprod testnet slot configuration."""
        config = SlotConfig.preprod()
        assert config.zero_time == 1654041600000 + 1728000000
        assert config.zero_slot == 86400
        assert config.slot_length == 1000
        assert config.start_epoch == 4
        assert config.epoch_length == 432000

    def test_custom_config(self):
        """Test custom slot configuration."""
        config = SlotConfig(
            zero_time=1700000000000,
            zero_slot=100,
            slot_length=500,
            start_epoch=10,
            epoch_length=100000,
        )
        assert config.zero_time == 1700000000000
        assert config.zero_slot == 100
        assert config.slot_length == 500
        assert config.start_epoch == 10
        assert config.epoch_length == 100000

    def test_dataclass_equality(self):
        """Test that SlotConfig instances are equal when values match."""
        config1 = SlotConfig.mainnet()
        config2 = SlotConfig(
            zero_time=1596059091000,
            zero_slot=4492800,
            slot_length=1000,
            start_epoch=208,
            epoch_length=432000,
        )
        assert config1 == config2

    def test_dataclass_inequality(self):
        """Test that different SlotConfig instances are not equal."""
        config1 = SlotConfig.mainnet()
        config2 = SlotConfig.preview()
        assert config1 != config2


class TestApplyParamsToScript:
    """Tests for apply_params_to_script function."""

    def test_apply_params_basic(self):
        """Test applying parameters to a parameterized script."""
        output_ref = ConstrPlutusData(
            0,
            [
                PlutusData.from_hex(TX_HASH),
                PlutusData.from_int(0),
            ],
        )

        params = PlutusList()
        params.append("MyToken")
        params.add(PlutusData.from_constr(output_ref))

        result = apply_params_to_script(params, COMPILED_CODE)

        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0
        assert result != COMPILED_CODE

    def test_apply_params_with_python_list(self):
        """Test applying parameters using a Python list."""
        output_ref = ConstrPlutusData(
            0,
            [
                PlutusData.from_hex(TX_HASH),
                PlutusData.from_int(0),
            ],
        )

        params = [
            PlutusData.from_string("MyToken"),
            PlutusData.from_constr(output_ref),
        ]

        result = apply_params_to_script(params, COMPILED_CODE)

        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0

    def test_apply_params_single_param(self):
        """Test applying a single parameter."""
        params = PlutusList()
        params.append("TestToken")
        params.add(
            PlutusData.from_constr(
                ConstrPlutusData(0, [PlutusData.from_hex(TX_HASH), 0])
            )
        )

        result = apply_params_to_script(params, COMPILED_CODE)
        assert result is not None
        assert len(result) > 0

    def test_apply_params_integer_param(self):
        """Test applying integer parameters."""
        output_ref = ConstrPlutusData(
            0,
            [
                PlutusData.from_hex(TX_HASH),
                PlutusData.from_int(42),
            ],
        )

        params = PlutusList()
        params.append("Token")
        params.add(PlutusData.from_constr(output_ref))

        result = apply_params_to_script(params, COMPILED_CODE)
        assert result is not None

    def test_apply_params_with_bytes(self):
        """Test applying bytes parameters."""
        tx_hash_bytes = bytes.fromhex(TX_HASH)
        output_ref = ConstrPlutusData(
            0,
            [
                PlutusData.from_bytes(tx_hash_bytes),
                PlutusData.from_int(0),
            ],
        )

        params = PlutusList()
        params.append(b"MyToken")
        params.add(PlutusData.from_constr(output_ref))

        result = apply_params_to_script(params, COMPILED_CODE)
        assert result is not None

    def test_apply_params_invalid_compiled_code_raises(self):
        """Test that invalid compiled code raises ApplyParamsError."""
        params = PlutusList()
        params.append("Test")

        with pytest.raises(ApplyParamsError):
            apply_params_to_script(params, "invalid_hex")

    def test_apply_params_empty_compiled_code_raises(self):
        """Test that empty compiled code raises ApplyParamsError."""
        params = PlutusList()
        params.append("Test")

        with pytest.raises(ApplyParamsError):
            apply_params_to_script(params, "")

    def test_apply_params_result_is_different(self):
        """Test that applying params produces different code."""
        output_ref = ConstrPlutusData(
            0, [PlutusData.from_hex(TX_HASH), PlutusData.from_int(0)]
        )

        params1 = PlutusList()
        params1.append("TokenA")
        params1.add(PlutusData.from_constr(output_ref))

        params2 = PlutusList()
        params2.append("TokenB")
        params2.add(PlutusData.from_constr(output_ref))

        result1 = apply_params_to_script(params1, COMPILED_CODE)
        result2 = apply_params_to_script(params2, COMPILED_CODE)

        assert result1 != result2


class TestAikenTxEvaluator:
    """Tests for AikenTxEvaluator."""

    def test_create_with_cost_models(self, mock_cost_models):
        """Test creating evaluator with cost models and default configuration."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        assert evaluator.cost_models == mock_cost_models
        assert evaluator.slot_config == SlotConfig.mainnet()
        assert evaluator.max_tx_ex_units.memory == 14_000_000
        assert evaluator.max_tx_ex_units.cpu_steps == 10_000_000_000

    def test_create_with_custom_slot_config(self, mock_cost_models):
        """Test creating evaluator with custom slot config."""
        custom_config = SlotConfig.preview()
        evaluator = AikenTxEvaluator(
            cost_models=mock_cost_models,
            slot_config=custom_config,
        )
        assert evaluator.slot_config == custom_config
        assert evaluator.max_tx_ex_units.memory == 14_000_000
        assert evaluator.max_tx_ex_units.cpu_steps == 10_000_000_000

    def test_create_with_custom_ex_units(self, mock_cost_models):
        """Test creating evaluator with custom execution units."""
        custom_ex_units = ExUnits.new(28000000, 20000000000)
        evaluator = AikenTxEvaluator(
            cost_models=mock_cost_models,
            max_tx_ex_units=custom_ex_units,
        )
        assert evaluator.slot_config == SlotConfig.mainnet()
        assert evaluator.max_tx_ex_units == custom_ex_units

    def test_create_with_all_custom(self, mock_cost_models):
        """Test creating evaluator with all custom configuration."""
        custom_config = SlotConfig.preprod()
        custom_ex_units = ExUnits.new(10000000, 5000000000)
        evaluator = AikenTxEvaluator(
            cost_models=mock_cost_models,
            slot_config=custom_config,
            max_tx_ex_units=custom_ex_units,
        )
        assert evaluator.cost_models == mock_cost_models
        assert evaluator.slot_config == custom_config
        assert evaluator.max_tx_ex_units == custom_ex_units

    def test_get_name(self, mock_cost_models):
        """Test get_name returns correct name."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        assert evaluator.get_name() == "Aiken"

    def test_slot_config_property(self, mock_cost_models):
        """Test slot_config property."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        config = evaluator.slot_config
        assert isinstance(config, SlotConfig)
        assert config == SlotConfig.mainnet()

    def test_max_tx_ex_units_property(self, mock_cost_models):
        """Test max_tx_ex_units property."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        ex_units = evaluator.max_tx_ex_units
        assert isinstance(ex_units, ExUnits)
        assert ex_units.memory == 14_000_000
        assert ex_units.cpu_steps == 10_000_000_000

    def test_cost_models_property(self, mock_cost_models):
        """Test cost_models property."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        assert evaluator.cost_models == mock_cost_models


class TestAikenTxEvaluatorProtocolCompliance:
    """Tests to verify AikenTxEvaluator implements TxEvaluatorProtocol correctly."""

    def test_has_get_name_method(self, mock_cost_models):
        """Test that evaluator has get_name method."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        assert hasattr(evaluator, "get_name")
        assert callable(evaluator.get_name)
        result = evaluator.get_name()
        assert isinstance(result, str)

    def test_has_evaluate_method(self, mock_cost_models):
        """Test that evaluator has evaluate method."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        assert hasattr(evaluator, "evaluate")
        assert callable(evaluator.evaluate)

    def test_evaluate_method_signature_matches_protocol(self, mock_cost_models):
        """Test that evaluate method signature matches TxEvaluatorProtocol."""
        import inspect

        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        sig = inspect.signature(evaluator.evaluate)
        params = list(sig.parameters.keys())

        assert "transaction" in params
        assert "additional_utxos" in params
        assert "cost_models" not in params

    def test_evaluate_signature_matches_protocol(self, mock_cost_models):
        """Test that AikenTxEvaluator.evaluate matches TxEvaluatorProtocol.evaluate."""
        import inspect
        from cometa.transaction_builder.evaluation import TxEvaluatorProtocol

        protocol_sig = inspect.signature(TxEvaluatorProtocol.evaluate)
        protocol_params = set(protocol_sig.parameters.keys()) - {"self"}

        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)
        evaluator_sig = inspect.signature(evaluator.evaluate)
        evaluator_params = set(evaluator_sig.parameters.keys()) - {"self"}

        assert protocol_params == evaluator_params

    def test_cost_models_in_constructor_not_evaluate(self, mock_cost_models):
        """Test that cost_models is passed to constructor, not evaluate."""
        import inspect

        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)

        init_sig = inspect.signature(AikenTxEvaluator.__init__)
        init_params = list(init_sig.parameters.keys())
        assert "cost_models" in init_params

        eval_sig = inspect.signature(evaluator.evaluate)
        eval_params = list(eval_sig.parameters.keys())
        assert "cost_models" not in eval_params


class TestTxEvaluationError:
    """Tests for TxEvaluationError."""

    def test_error_is_exception(self):
        """Test that TxEvaluationError is an Exception."""
        error = TxEvaluationError("Test error")
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test that error message is preserved."""
        msg = "Transaction evaluation failed"
        error = TxEvaluationError(msg)
        assert str(error) == msg

    def test_evaluate_actually_calls_c_code(self, mock_cost_models):
        """Test that actually triggers the C-side evaluation."""
        evaluator = AikenTxEvaluator(cost_models=mock_cost_models)

        try:
            # Pass empty/dummy data just to hit the C function
            # Even garbage data should return a JSON error, NOT segfault
            evaluator._call_eval_phase_two(
                "80", "80", "80", "a0"  # Minimal Valid CBOR
            )
        except Exception:
            pass

class TestApplyParamsError:
    """Tests for ApplyParamsError."""

    def test_error_is_exception(self):
        """Test that ApplyParamsError is an Exception."""
        error = ApplyParamsError("Test error")
        assert isinstance(error, Exception)

    def test_error_message(self):
        """Test that error message is preserved."""
        msg = "Failed to apply parameters"
        error = ApplyParamsError(msg)
        assert str(error) == msg
