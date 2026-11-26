# Changelog

## Unreleased

- Normalize omitted reference inputs to an empty collection when balancing, as required by native reference-script fee pricing.

- Upgrade native sources and CFFI declarations to cardano-c v2.0.0-rc.7, including CIP-172 created-output script sources from protocol 12.
- Add `TxBuilder.set_pool_state`, pool-aware signer discovery and balancing, and `PoolParams.requires_owner_witnesses`. Supply latest registered parameters, pending preferred over active; unknown pools remain conservative and pool deposits are unaffected.
- Expose protocol parameter 55 as `ref_inputs_cost_per_multi_asset_byte`, including optional updates.
- Align tests with native fixes: strict JSON, Base58 leading zeros, native-script threshold equality, rejection of zero PBKDF2 iterations, ledger fee sizing, and pool refunds at epoch boundaries.

- Add Koios, Kupmios (Kupo + Ogmios), and Hydra providers with exact wire decoding, bounded HTTP requests, and explicit confirmation semantics.
- Expose reference-script size limits, fee stride, and fee multiplier in protocol parameters.
- Fix Blockfrost inline datum and native reference-script decoding, preserve complete additional evaluation inputs, and reject incomplete or inconsistent execution budgets.

## 2.0.0rc3

- Bundle cardano-c 2.0.0-rc.6 on all supported platforms.
- **Breaking JSON change:** transaction inspection now emits all key and script credentials in `guards`, including Conway key-only guards. `required_signers` is no longer emitted in JSON. CBOR, signing, and Python's `required_signers` property are unchanged.

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
