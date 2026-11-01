"""Exercise the precompiled ABI cache in a fresh interpreter."""

import subprocess
import sys

from cometa._ffi_build import compile_all


def test_cached_recursive_callback_types_can_be_resolved_first(tmp_path):
    compile_all(str(tmp_path))
    script = '''
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("cometa._cardano_cffi", sys.argv[1])
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)
sys.modules["cometa._cardano_cffi"] = cache
from cometa._ffi import ffi
assert ffi is cache.ffi
for name in (
    "cardano_bip32_get_extended_account_public_key_func_t",
    "cardano_get_parameters_func_t",
    "cardano_coin_select_func_t",
    "cardano_tx_evaluate_func_t",
):
    assert ffi.typeof(name).kind == "function"
'''
    result = subprocess.run(
        [sys.executable, '-c', script, str(tmp_path / '_cardano_cffi.py')],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
