# Soroban Debugger

[![CI](https://github.com/Timi16/soroban-debugger/actions/workflows/ci.yml/badge.svg)](https://github.com/Timi16/soroban-debugger/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Timi16/soroban-debugger/branch/main/graph/badge.svg)](https://codecov.io/gh/Timi16/soroban-debugger)
[![Latest Release](https://img.shields.io/github/v/release/Timi16/soroban-debugger?logo=github)](https://github.com/Timi16/soroban-debugger/releases)

A command-line debugger for Soroban smart contracts on the Stellar network. Debug your contracts interactively with breakpoints, step-through execution, state inspection, and budget tracking.

---

## Quick Start

### 1. Installation

#### Using Cargo (Recommended)
```bash
cargo install soroban-debugger
```

#### From Source
```bash
git clone https://github.com/Timi16/soroban-debugger.git
cd soroban-debugger
cargo install --path .
```

### 2. Your First Debug Run

Debug a contract by specifying the WASM file and function to execute:

```bash
soroban-debug run --contract token.wasm --function transfer --args '["Alice", "Bob", 100]'
```

For an interactive session with a terminal UI:
```bash
soroban-debug interactive --contract my_contract.wasm --function hello
```

---

## User Journeys

### 🛠️ Debugging Your First Contract
Learn how to execute functions, pass complex arguments, and use the interactive debugger.

- **Basic Execution**: Use the `run` command to execute functions and see results immediately.
- **Interactive Mode**: Use `interactive` for a step-by-step walkthrough with breakpoints.
- **REPL**: Use `repl` for repeated calls and exploration without restarting.
- **Complex Arguments**: Support for JSON-nested vectors, maps, and [typed annotations](#typed-annotations).

### 🔍 Source-Level Debugging
Debug your Rust code directly instead of raw WASM instructions.

- **Rust Source Mapping**: Automatically maps WASM offsets back to Rust lines using DWARF debug info.
- **Instruction Stepping**: Step into, over, or out of functions at the source level.
- **Source Map Caching**: Fast O(1) lookups for source locations after the first load.

See [Source-Level Debugging Guide](docs/source-level-debugging.md) for details.

### 🌐 Remote Debugging Sessions
Debug contracts running on remote servers or in CI environments.

- **Debug Server**: Start a `server` process to host a debugging session.
- **Remote Client**: Connect to a running server using the `remote` command.
- **Secure Connections**: Support for TLS and token-based authentication.

See [Remote Debugging Guide](docs/remote-debugging.md) for setup instructions.

### 📈 Analysis & Optimization
Analyze contract metadata, resource usage, and upgrade compatibility.

- **Inspection**: Use `inspect` to view contract functions and metadata without executing.
- **Profiling**: Use `profile` to find hotspots and budget-heavy execution paths.
- **Optimization**: Use `optimize` for automated gas and performance suggestions.
- **Upgrade Checks**: Use `upgrade-check` to ensure API compatibility between versions.

### 🤖 Regression & Automated Testing
Integrate debugging into your CI/CD pipeline and discover edge cases.

- **Scenarios**: Define multi-step integration tests in simple [TOML files](docs/tutorials/scenario-runner.md).
- **Batch Execution**: Run the same function with [multiple argument sets](docs/batch-execution.md) in parallel.
- **Symbolic Analysis**: Automatically explore input spaces to find panics and edge cases.
- **Test Generation**: Generate ready-to-run Rust unit tests from any debug session.

---

## Command Index

| Category | Commands |
| --- | --- |
| **Run & Debug** | `run`, `interactive`, `repl`, `tui`, `scenario`, `replay` |
| **Analyze & Compare** | `inspect`, `upgrade-check`, `optimize`, `profile`, `compare`, `symbolic`, `analyze` |
| **Remote & Server** | `server`, `remote` |
| **Utilities** | `completions`, `history-prune` |

> Use `soroban-debug <command> --help` for full flags and examples.

---

## Reference

### Supported Argument Types

The debugger supports passing typed arguments via the `--args` flag.

| JSON Value | Soroban Type | Example |
| --- | --- | --- |
| Number | `i128` | `10`, `-5` |
| String | `Symbol` | `"hello"` |
| Boolean | `Bool` | `true` |
| Array | `Vec<Val>` | `[1, 2, 3]` |
| Object | `Map` | `{"key": "value"}` |

#### Typed Annotations
For precise control, use `{"type": "...", "value": ...}`:
`u32`, `i32`, `u64`, `i64`, `u128`, `i128`, `bool`, `symbol`, `string`, `address`.

### Storage Filtering
Filter large storage outputs by key pattern:
```bash
soroban-debug run --contract token.wasm --function mint --storage-filter 'balance:*'
```
Supports `prefix*`, `re:<regex>`, and `exact_match`.

### Configuration File
Load default settings from `.soroban-debug.toml`:
```toml
[debug]
breakpoints = ["verify", "auth"]
[output]
show_events = true
```

---

## Troubleshooting

| Symptom | Likely Cause | Solution |
| --- | --- | --- |
| Request timed out | Slow host or low timeout | Increase `--timeout-ms` |
| Incompatible protocol | Build version mismatch | Reinstall client/server from same release |
| Auth failed | Token mismatch | Verify `--token` values match |

See [Remote Troubleshooting Guide](docs/remote-troubleshooting.md) for more.

---

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow.

## License
Licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).
