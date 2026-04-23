# Extension Telemetry & Privacy

The Soroban Debugger extension includes optional, opt-in telemetry to help maintainers identify and fix common launch failures and adapter crashes.

## Privacy First

Telemetry is **strictly opt-in**. No data is collected or transmitted unless you explicitly enable it in your VS Code settings.

## What We Collect

When enabled, the extension only collects limited data related to execution failures:

- **Error Types**: The category of the failure (e.g., `SPAWN_FAILURE`, `CONNECT_TIMEOUT`, `AUTH_FAILED`).
- **Error Messages**: The descriptive text of the error (redacted for secrets).
- **Execution Phase**: Where the failure occurred (e.g., during server launch, DAP handshake, or contract load).
- **VS Code Version & Extension Version**: To identify environment-specific bugs.

## What We NEVER Collect

- **Contract Code**: We never send your `.wasm` files or Rust source code.
- **Smart Contract Data**: We never send storage values, argument values, or execution traces.
- **Secrets**: Authentication tokens and private keys are automatically redacted from error messages before transmission.
- **Personal Information**: No filenames (outside of the extension itself), usernames, or machine identifiers are collected.

## How to Opt In

1. Open **Settings** in VS Code (`Cmd+,` or `Ctrl+,`).
2. Search for `Soroban Debugger: Telemetry Enabled`.
3. Check the box to enable failure reporting.

## Why Opt In?

By opting in, you help the maintainers discover:
- Which versions of the Soroban SDK cause compatibility issues.
- If the debugger fails to launch on certain operating systems.
- Common network configuration problems that can be automated away.

Thank you for helping us improve the Soroban development experience!
