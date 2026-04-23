# Upgrade Compatibility Classes

When using the `soroban-debug upgrade-check` command, the debugger runs deep analysis between the old and new WASM binaries. Instead of a binary valid/invalid report, it classifies the upgrade into three categories to help operators manage release risk.

## 🟢 Safe
- **Criteria:** No parameter signature changes, no removed functions, and identical behavior in test payloads.
- **Risk:** Minimal. Can be executed without breaking downstream callers.

## 🟡 Caution
- **Criteria:** Contains only non-breaking changes, like new functions or increased storage mappings without altering existing contract invariants. 
- **Risk:** Changes the surface area and expands interface footprint, so downstream indexers or dapps must be aware if they upgrade.

## 🔴 Breaking
- **Criteria:** Changing function parameters, dropping functions, return type mutation, or execution differences meaning outputs would wildly differ.
- **Risk:** High. Calling systems will fail if they don't adapt immediately to the API surface change.
