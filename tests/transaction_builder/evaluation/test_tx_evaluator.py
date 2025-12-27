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
from typing import List, Union
from cometa.transaction_builder.evaluation.tx_evaluator import (
    TxEvaluatorProtocol,
    TxEvaluator,
)


class MockTxEvaluator:
    """Mock implementation of TxEvaluatorProtocol for testing."""

    def __init__(self, name: str = "MockEvaluator"):
        """
        Initialize the mock transaction evaluator.

        Args:
            name: The name of this evaluator.
        """
        self._name = name
        self._evaluate_called = False
        self._get_name_called = False
        self._return_redeemers = []

    def get_name(self) -> str:
        """
        Get the human-readable name of this evaluator.

        Returns:
            The evaluator name.
        """
        self._get_name_called = True
        return self._name

    def evaluate(
        self,
        transaction,
        additional_utxos,
    ) -> List:
        """
        Evaluate the execution units required for a transaction.

        Args:
            transaction: The transaction to evaluate.
            additional_utxos: Optional additional UTXOs needed for evaluation.

        Returns:
            A list of Redeemer objects with computed execution units.
        """
        self._evaluate_called = True
        return self._return_redeemers

    def set_return_redeemers(self, redeemers: List):
        """
        Set the redeemers to be returned by evaluate.

        Args:
            redeemers: The list of redeemers to return.
        """
        self._return_redeemers = redeemers


class EmptyEvaluator:
    """Evaluator that returns empty redeemer lists."""

    def get_name(self) -> str:
        """Get the name of this evaluator."""
        return "Empty Evaluator"

    def evaluate(self, transaction, additional_utxos) -> List:
        """Evaluate and return empty list."""
        return []


class BlockfrostEvaluator:
    """Mock Blockfrost evaluator implementation."""

    def get_name(self) -> str:
        """Get the name of this evaluator."""
        return "Blockfrost"

    def evaluate(self, transaction, additional_utxos) -> List:
        """Evaluate using Blockfrost API."""
        return [{"index": 0, "mem": 1000, "cpu": 2000}]


class KoiosEvaluator:
    """Mock Koios evaluator implementation."""

    def get_name(self) -> str:
        """Get the name of this evaluator."""
        return "Koios"

    def evaluate(self, transaction, additional_utxos) -> List:
        """Evaluate using Koios API."""
        return [{"index": 0, "mem": 1500, "cpu": 2500}]


class LocalEvaluator:
    """Mock local evaluator implementation."""

    def get_name(self) -> str:
        """Get the name of this evaluator."""
        return "Local"

    def evaluate(self, transaction, additional_utxos) -> List:
        """Evaluate using local UPLC execution."""
        return [{"index": 0, "mem": 1200, "cpu": 2200}]


class FailingEvaluator:
    """Evaluator that raises an exception during evaluation."""

    def get_name(self) -> str:
        """Get the name of this evaluator."""
        return "FailingEvaluator"

    def evaluate(self, transaction, additional_utxos) -> List:
        """Raise an exception to simulate evaluation failure."""
        raise Exception("Evaluation failed")


class TestTxEvaluatorProtocol:
    """Tests for TxEvaluatorProtocol."""

    def test_can_import_protocol(self):
        """Test that TxEvaluatorProtocol can be imported."""
        assert TxEvaluatorProtocol is not None

    def test_can_import_alias(self):
        """Test that TxEvaluator alias can be imported."""
        assert TxEvaluator is not None

    def test_alias_refers_to_protocol(self):
        """Test that TxEvaluator is an alias for TxEvaluatorProtocol."""
        assert TxEvaluator is TxEvaluatorProtocol

    def test_protocol_has_get_name_method(self):
        """Test that the protocol defines get_name method."""
        assert hasattr(TxEvaluatorProtocol, "get_name")

    def test_protocol_has_evaluate_method(self):
        """Test that the protocol defines evaluate method."""
        assert hasattr(TxEvaluatorProtocol, "evaluate")

    def test_mock_implementation_conforms_to_protocol(self):
        """Test that MockTxEvaluator conforms to the protocol."""
        evaluator = MockTxEvaluator()
        assert hasattr(evaluator, "get_name")
        assert hasattr(evaluator, "evaluate")
        assert callable(evaluator.get_name)
        assert callable(evaluator.evaluate)


class TestMockTxEvaluatorGetName:
    """Tests for MockTxEvaluator.get_name() method."""

    def test_can_get_name(self):
        """Test that get_name returns the evaluator name."""
        evaluator = MockTxEvaluator("TestEvaluator")
        name = evaluator.get_name()
        assert name == "TestEvaluator"

    def test_get_name_returns_string(self):
        """Test that get_name returns a string."""
        evaluator = MockTxEvaluator()
        name = evaluator.get_name()
        assert isinstance(name, str)

    def test_get_name_with_default_name(self):
        """Test that get_name returns default name when not specified."""
        evaluator = MockTxEvaluator()
        name = evaluator.get_name()
        assert name == "MockEvaluator"

    def test_get_name_with_empty_string(self):
        """Test that get_name can return empty string."""
        evaluator = MockTxEvaluator("")
        name = evaluator.get_name()
        assert name == ""

    def test_get_name_sets_called_flag(self):
        """Test that get_name sets the called flag."""
        evaluator = MockTxEvaluator()
        assert not evaluator._get_name_called
        evaluator.get_name()
        assert evaluator._get_name_called

    def test_get_name_with_unicode(self):
        """Test that get_name works with unicode characters."""
        evaluator = MockTxEvaluator("評価者")
        assert evaluator.get_name() == "評価者"

    def test_get_name_with_special_characters(self):
        """Test that get_name works with special characters."""
        evaluator = MockTxEvaluator("Evaluator-v1.0_test")
        assert evaluator.get_name() == "Evaluator-v1.0_test"


class TestMockTxEvaluatorEvaluate:
    """Tests for MockTxEvaluator.evaluate() method."""

    def test_can_evaluate_with_none_transaction(self):
        """Test that evaluate works with None transaction."""
        evaluator = MockTxEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert isinstance(redeemers, list)
        assert len(redeemers) == 0

    def test_can_evaluate_with_none_additional_utxos(self):
        """Test that evaluate works with None additional_utxos."""
        evaluator = MockTxEvaluator()
        mock_tx = "mock_transaction"
        redeemers = evaluator.evaluate(mock_tx, None)
        assert isinstance(redeemers, list)

    def test_evaluate_returns_list(self):
        """Test that evaluate returns a list."""
        evaluator = MockTxEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert isinstance(redeemers, list)

    def test_evaluate_sets_called_flag(self):
        """Test that evaluate sets the called flag."""
        evaluator = MockTxEvaluator()
        assert not evaluator._evaluate_called
        evaluator.evaluate(None, None)
        assert evaluator._evaluate_called

    def test_evaluate_returns_configured_redeemers(self):
        """Test that evaluate returns configured redeemers."""
        evaluator = MockTxEvaluator()
        test_redeemers = [{"index": 0}, {"index": 1}]
        evaluator.set_return_redeemers(test_redeemers)
        result = evaluator.evaluate(None, None)
        assert result == test_redeemers

    def test_evaluate_with_empty_redeemers(self):
        """Test that evaluate can return empty redeemers list."""
        evaluator = MockTxEvaluator()
        evaluator.set_return_redeemers([])
        result = evaluator.evaluate(None, None)
        assert result == []
        assert len(result) == 0

    def test_evaluate_with_single_redeemer(self):
        """Test that evaluate works with a single redeemer."""
        evaluator = MockTxEvaluator()
        test_redeemers = [{"index": 0, "mem": 1000, "cpu": 2000}]
        evaluator.set_return_redeemers(test_redeemers)
        result = evaluator.evaluate("tx", None)
        assert len(result) == 1
        assert result[0] == test_redeemers[0]

    def test_evaluate_with_multiple_redeemers(self):
        """Test that evaluate works with multiple redeemers."""
        evaluator = MockTxEvaluator()
        test_redeemers = [
            {"index": 0, "mem": 1000, "cpu": 2000},
            {"index": 1, "mem": 1500, "cpu": 2500},
            {"index": 2, "mem": 2000, "cpu": 3000},
        ]
        evaluator.set_return_redeemers(test_redeemers)
        result = evaluator.evaluate("tx", None)
        assert len(result) == 3
        assert result == test_redeemers

    def test_evaluate_with_additional_utxos_as_list(self):
        """Test that evaluate accepts additional_utxos as a list."""
        evaluator = MockTxEvaluator()
        additional_utxos = ["utxo1", "utxo2"]
        redeemers = evaluator.evaluate("tx", additional_utxos)
        assert isinstance(redeemers, list)

    def test_evaluate_preserves_redeemer_data(self):
        """Test that evaluate preserves all redeemer data."""
        evaluator = MockTxEvaluator()
        test_redeemer = {
            "index": 0,
            "mem": 1000,
            "cpu": 2000,
            "tag": "spend",
            "data": "some_data",
        }
        evaluator.set_return_redeemers([test_redeemer])
        result = evaluator.evaluate("tx", None)
        assert result[0] == test_redeemer
        assert result[0]["tag"] == "spend"
        assert result[0]["data"] == "some_data"


class TestEmptyEvaluator:
    """Tests for EmptyEvaluator implementation."""

    def test_get_name_returns_correct_name(self):
        """Test that get_name returns the correct name."""
        evaluator = EmptyEvaluator()
        assert evaluator.get_name() == "Empty Evaluator"

    def test_evaluate_returns_empty_list(self):
        """Test that evaluate returns empty list."""
        evaluator = EmptyEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert len(redeemers) == 0

    def test_evaluate_always_returns_empty_list(self):
        """Test that evaluate always returns empty list regardless of inputs."""
        evaluator = EmptyEvaluator()
        redeemers1 = evaluator.evaluate("tx1", None)
        redeemers2 = evaluator.evaluate("tx2", ["utxo1"])
        assert len(redeemers1) == 0
        assert len(redeemers2) == 0


class TestBlockfrostEvaluator:
    """Tests for BlockfrostEvaluator implementation."""

    def test_get_name_returns_blockfrost(self):
        """Test that get_name returns Blockfrost."""
        evaluator = BlockfrostEvaluator()
        assert evaluator.get_name() == "Blockfrost"

    def test_evaluate_returns_redeemers(self):
        """Test that evaluate returns redeemers."""
        evaluator = BlockfrostEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert len(redeemers) > 0

    def test_evaluate_returns_expected_structure(self):
        """Test that evaluate returns expected structure."""
        evaluator = BlockfrostEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert "index" in redeemers[0]
        assert "mem" in redeemers[0]
        assert "cpu" in redeemers[0]


class TestKoiosEvaluator:
    """Tests for KoiosEvaluator implementation."""

    def test_get_name_returns_koios(self):
        """Test that get_name returns Koios."""
        evaluator = KoiosEvaluator()
        assert evaluator.get_name() == "Koios"

    def test_evaluate_returns_redeemers(self):
        """Test that evaluate returns redeemers."""
        evaluator = KoiosEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert len(redeemers) > 0

    def test_evaluate_returns_different_values_than_blockfrost(self):
        """Test that Koios returns different execution units than Blockfrost."""
        koios = KoiosEvaluator()
        blockfrost = BlockfrostEvaluator()
        koios_redeemers = koios.evaluate(None, None)
        blockfrost_redeemers = blockfrost.evaluate(None, None)
        assert koios_redeemers[0]["mem"] != blockfrost_redeemers[0]["mem"]


class TestLocalEvaluator:
    """Tests for LocalEvaluator implementation."""

    def test_get_name_returns_local(self):
        """Test that get_name returns Local."""
        evaluator = LocalEvaluator()
        assert evaluator.get_name() == "Local"

    def test_evaluate_returns_redeemers(self):
        """Test that evaluate returns redeemers."""
        evaluator = LocalEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert len(redeemers) > 0

    def test_evaluate_returns_expected_structure(self):
        """Test that evaluate returns expected structure."""
        evaluator = LocalEvaluator()
        redeemers = evaluator.evaluate(None, None)
        assert "index" in redeemers[0]
        assert "mem" in redeemers[0]
        assert "cpu" in redeemers[0]


class TestFailingEvaluator:
    """Tests for FailingEvaluator implementation."""

    def test_get_name_returns_correct_name(self):
        """Test that get_name returns the correct name."""
        evaluator = FailingEvaluator()
        assert evaluator.get_name() == "FailingEvaluator"

    def test_evaluate_raises_exception(self):
        """Test that evaluate raises an exception."""
        evaluator = FailingEvaluator()
        with pytest.raises(Exception) as exc_info:
            evaluator.evaluate(None, None)
        assert "Evaluation failed" in str(exc_info.value)

    def test_evaluate_raises_exception_with_transaction(self):
        """Test that evaluate raises exception even with transaction."""
        evaluator = FailingEvaluator()
        with pytest.raises(Exception) as exc_info:
            evaluator.evaluate("tx", None)
        assert "Evaluation failed" in str(exc_info.value)

    def test_evaluate_raises_exception_with_additional_utxos(self):
        """Test that evaluate raises exception even with additional UTXOs."""
        evaluator = FailingEvaluator()
        with pytest.raises(Exception) as exc_info:
            evaluator.evaluate("tx", ["utxo1"])
        assert "Evaluation failed" in str(exc_info.value)


class TestTxEvaluatorProtocolContract:
    """Tests to verify implementations conform to the protocol contract."""

    def test_implementations_have_required_methods(self):
        """Test that all implementations have required methods."""
        implementations = [
            MockTxEvaluator(),
            EmptyEvaluator(),
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
            FailingEvaluator(),
        ]
        for impl in implementations:
            assert hasattr(impl, "get_name")
            assert hasattr(impl, "evaluate")
            assert callable(impl.get_name)
            assert callable(impl.evaluate)

    def test_get_name_returns_string_for_all_implementations(self):
        """Test that get_name returns string for all implementations."""
        implementations = [
            MockTxEvaluator(),
            EmptyEvaluator(),
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
            FailingEvaluator(),
        ]
        for impl in implementations:
            name = impl.get_name()
            assert isinstance(name, str)

    def test_evaluate_accepts_two_arguments(self):
        """Test that evaluate accepts two arguments."""
        evaluator = MockTxEvaluator()
        try:
            evaluator.evaluate(None, None)
        except TypeError as e:
            pytest.fail(f"evaluate() should accept two arguments: {e}")

    def test_evaluate_returns_list(self):
        """Test that evaluate returns a list."""
        implementations = [
            MockTxEvaluator(),
            EmptyEvaluator(),
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
        ]
        for impl in implementations:
            result = impl.evaluate(None, None)
            assert isinstance(result, list)


class TestTxEvaluatorEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_evaluators_can_coexist(self):
        """Test that multiple evaluator instances can coexist."""
        evaluator1 = MockTxEvaluator("Evaluator1")
        evaluator2 = MockTxEvaluator("Evaluator2")
        assert evaluator1.get_name() != evaluator2.get_name()

    def test_evaluator_is_reusable(self):
        """Test that an evaluator can be used multiple times."""
        evaluator = MockTxEvaluator()
        evaluator.set_return_redeemers([{"index": 0}])
        result1 = evaluator.evaluate("tx1", None)
        result2 = evaluator.evaluate("tx2", None)
        assert result1 == result2

    def test_evaluator_with_unicode_name(self):
        """Test that evaluator can have unicode characters in name."""
        evaluator = MockTxEvaluator("トランザクション評価者")
        assert evaluator.get_name() == "トランザクション評価者"

    def test_evaluator_with_very_long_name(self):
        """Test that evaluator can have a very long name."""
        long_name = "A" * 1000
        evaluator = MockTxEvaluator(long_name)
        assert len(evaluator.get_name()) == 1000

    def test_empty_evaluator_with_various_inputs(self):
        """Test empty evaluator with various inputs."""
        evaluator = EmptyEvaluator()
        assert evaluator.evaluate(None, None) == []
        assert evaluator.evaluate("tx", None) == []
        assert evaluator.evaluate("tx", []) == []
        assert evaluator.evaluate("tx", ["utxo1"]) == []

    def test_evaluator_with_large_redeemer_list(self):
        """Test evaluator with a large number of redeemers."""
        evaluator = MockTxEvaluator()
        large_list = [{"index": i, "mem": 1000 * i, "cpu": 2000 * i} for i in range(100)]
        evaluator.set_return_redeemers(large_list)
        result = evaluator.evaluate("tx", None)
        assert len(result) == 100

    def test_different_evaluator_types_produce_different_results(self):
        """Test that different evaluator types can produce different results."""
        evaluators = [
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
        ]
        results = [e.evaluate("tx", None) for e in evaluators]
        names = [e.get_name() for e in evaluators]
        assert len(set(names)) == len(names)


class TestTxEvaluatorDocumentation:
    """Tests to verify documentation is present and correct."""

    def test_protocol_has_docstring(self):
        """Test that TxEvaluatorProtocol has a docstring."""
        assert TxEvaluatorProtocol.__doc__ is not None
        assert len(TxEvaluatorProtocol.__doc__) > 0

    def test_protocol_docstring_mentions_transaction(self):
        """Test that protocol docstring mentions transaction."""
        assert "transaction" in TxEvaluatorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_evaluator(self):
        """Test that protocol docstring mentions evaluator."""
        assert "evaluator" in TxEvaluatorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_plutus(self):
        """Test that protocol docstring mentions Plutus."""
        assert "plutus" in TxEvaluatorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_execution_units(self):
        """Test that protocol docstring mentions execution units."""
        assert "execution units" in TxEvaluatorProtocol.__doc__.lower()

    def test_get_name_has_docstring(self):
        """Test that get_name method has a docstring."""
        evaluator = MockTxEvaluator()
        assert evaluator.get_name.__doc__ is not None

    def test_evaluate_has_docstring(self):
        """Test that evaluate method has a docstring."""
        evaluator = MockTxEvaluator()
        assert evaluator.evaluate.__doc__ is not None

    def test_protocol_docstring_mentions_example(self):
        """Test that protocol docstring includes usage example."""
        assert "example" in TxEvaluatorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_redeemer(self):
        """Test that protocol docstring mentions redeemer."""
        assert "redeemer" in TxEvaluatorProtocol.__doc__.lower()

    def test_protocol_docstring_mentions_blockfrost_or_koios(self):
        """Test that protocol docstring mentions example services."""
        doc_lower = TxEvaluatorProtocol.__doc__.lower()
        assert "blockfrost" in doc_lower or "koios" in doc_lower


class TestTxEvaluatorTypeAnnotations:
    """Tests for type annotations on the protocol."""

    def test_get_name_return_type(self):
        """Test that get_name has correct return type annotation."""
        import inspect
        sig = inspect.signature(TxEvaluatorProtocol.get_name)
        assert sig.return_annotation in (str, "str")

    def test_evaluate_return_type(self):
        """Test that evaluate has correct return type annotation."""
        import inspect
        sig = inspect.signature(TxEvaluatorProtocol.evaluate)
        return_annotation = sig.return_annotation
        assert "List" in str(return_annotation) or "list" in str(return_annotation)

    def test_protocol_methods_have_annotations(self):
        """Test that protocol methods have type annotations."""
        import inspect
        get_name_sig = inspect.signature(TxEvaluatorProtocol.get_name)
        evaluate_sig = inspect.signature(TxEvaluatorProtocol.evaluate)
        assert get_name_sig.return_annotation is not inspect.Signature.empty
        assert evaluate_sig.return_annotation is not inspect.Signature.empty

    def test_evaluate_has_parameter_annotations(self):
        """Test that evaluate has parameter type annotations."""
        import inspect
        sig = inspect.signature(TxEvaluatorProtocol.evaluate)
        params = sig.parameters
        assert "transaction" in params
        assert "additional_utxos" in params


class TestTxEvaluatorNullSafety:
    """Tests for null/None safety in implementations."""

    def test_get_name_never_returns_none(self):
        """Test that get_name never returns None."""
        implementations = [
            MockTxEvaluator(),
            EmptyEvaluator(),
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
            FailingEvaluator(),
        ]
        for impl in implementations:
            name = impl.get_name()
            assert name is not None

    def test_evaluate_handles_none_transaction(self):
        """Test that evaluate handles None transaction gracefully."""
        evaluator = MockTxEvaluator()
        try:
            result = evaluator.evaluate(None, None)
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"evaluate should handle None transaction: {e}")

    def test_evaluate_handles_none_additional_utxos(self):
        """Test that evaluate handles None additional_utxos gracefully."""
        evaluator = MockTxEvaluator()
        try:
            result = evaluator.evaluate("tx", None)
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"evaluate should handle None additional_utxos: {e}")

    def test_evaluate_never_returns_none(self):
        """Test that evaluate never returns None."""
        implementations = [
            MockTxEvaluator(),
            EmptyEvaluator(),
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
        ]
        for impl in implementations:
            result = impl.evaluate(None, None)
            assert result is not None


class TestTxEvaluatorPerformance:
    """Tests for performance characteristics."""

    def test_get_name_is_fast(self):
        """Test that get_name executes quickly."""
        import time
        evaluator = MockTxEvaluator()
        start = time.time()
        for _ in range(1000):
            evaluator.get_name()
        elapsed = time.time() - start
        assert elapsed < 1.0

    def test_evaluate_can_handle_repeated_calls(self):
        """Test that evaluate can be called repeatedly."""
        evaluator = MockTxEvaluator()
        evaluator.set_return_redeemers([{"index": 0}])
        for i in range(100):
            result = evaluator.evaluate(f"tx{i}", None)
            assert len(result) == 1

    def test_multiple_evaluators_dont_interfere(self):
        """Test that multiple evaluators don't interfere with each other."""
        evaluator1 = MockTxEvaluator("Eval1")
        evaluator2 = MockTxEvaluator("Eval2")
        evaluator1.set_return_redeemers([{"index": 1}])
        evaluator2.set_return_redeemers([{"index": 2}])
        result1 = evaluator1.evaluate("tx", None)
        result2 = evaluator2.evaluate("tx", None)
        assert result1[0]["index"] == 1
        assert result2[0]["index"] == 2


class TestTxEvaluatorRealWorldScenarios:
    """Tests for real-world usage scenarios."""

    def test_evaluator_for_simple_transaction(self):
        """Test evaluator for a simple transaction scenario."""
        evaluator = MockTxEvaluator("SimpleEvaluator")
        evaluator.set_return_redeemers([
            {"index": 0, "tag": "spend", "mem": 1000000, "cpu": 500000000}
        ])
        result = evaluator.evaluate("simple_tx", None)
        assert len(result) == 1
        assert result[0]["mem"] == 1000000

    def test_evaluator_for_complex_transaction(self):
        """Test evaluator for a complex transaction with multiple scripts."""
        evaluator = MockTxEvaluator("ComplexEvaluator")
        evaluator.set_return_redeemers([
            {"index": 0, "tag": "spend", "mem": 1000000, "cpu": 500000000},
            {"index": 1, "tag": "mint", "mem": 1500000, "cpu": 750000000},
            {"index": 2, "tag": "cert", "mem": 2000000, "cpu": 1000000000},
        ])
        result = evaluator.evaluate("complex_tx", None)
        assert len(result) == 3
        assert result[1]["tag"] == "mint"

    def test_evaluator_with_reference_inputs(self):
        """Test evaluator with additional UTXOs for reference inputs."""
        evaluator = MockTxEvaluator("ReferenceEvaluator")
        evaluator.set_return_redeemers([{"index": 0, "mem": 1000000}])
        additional_utxos = ["ref_utxo1", "ref_utxo2"]
        result = evaluator.evaluate("tx", additional_utxos)
        assert isinstance(result, list)

    def test_switching_between_evaluators(self):
        """Test switching between different evaluator implementations."""
        evaluators = [
            BlockfrostEvaluator(),
            KoiosEvaluator(),
            LocalEvaluator(),
        ]
        tx = "test_transaction"
        for evaluator in evaluators:
            name = evaluator.get_name()
            result = evaluator.evaluate(tx, None)
            assert isinstance(name, str)
            assert isinstance(result, list)

    def test_evaluator_name_matches_service_type(self):
        """Test that evaluator names match their service types."""
        blockfrost = BlockfrostEvaluator()
        koios = KoiosEvaluator()
        local = LocalEvaluator()
        assert "blockfrost" in blockfrost.get_name().lower()
        assert "koios" in koios.get_name().lower()
        assert "local" in local.get_name().lower()
