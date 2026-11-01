# Changelog

## 2.0.0rc2

- Upgrade bundled native libraries and CFFI declarations to cardano-c 2.0.0-rc.5.
- Include Dijkstra fields, nested witnesses and auxiliary data in transaction JSON inspection.

## 2.0.0rc1

- Upgrade all bundled platforms and CFFI declarations to cardano-c 2.0.0-rc.4.
- Use cardano-c's native Plutus evaluator in transaction builders. Remove the Aiken
  evaluator, FFI declarations and runtime binaries. Script parameter application
  remains available as `cometa.apply_params_to_script`.
- Add direct deposits, account balance intervals, key/script guards, native guard
  scripts, and signed sub-transaction building and batching. Expose the new body
  fields and sub-transaction signing through both software key handlers.
- Support standalone evaluation of a selected sub-transaction in a batch.
- Release native public-key and signature references after reading witness bytes.
- Prevent runtime CFFI parser deadlocks during garbage collection in source installs.
- Add `NativeTxEvaluator`, Plutus V4 scripts, script lists and witness sets.
- Accept deferred redeemer callbacks for inputs, minting, withdrawals, votes and
  certificates. Callbacks receive transaction and UTxO objects.
- Update coin selection for the new request/change-output interface. Native
  selectors now require a change address and protocol parameters; existing Python
  selectors retain their three-argument callback interface.
- Keep Python provider callbacks alive for provider-backed evaluators, preserve
  deferred callback exceptions, and safely truncate coin-selector error messages.
- Reject incompatible cardano-c 1.x system libraries before calling the 2.x ABI.
- Initialize recursive CFFI structures before cached callback types to prevent
  callback-type resolution from aborting the interpreter.
- Budget the example wallet's payment witness for script-only transactions.
- Fix platform wheel metadata and fail builds when a requested artifact fails.
  Linux x86-64/ARM64 wheels require glibc 2.33; macOS wheels require macOS 26.
- Remove ARMv6 debug information while preserving executable sections and exports.
  Precompiled CFFI declarations remain included for fast startup on small devices.
