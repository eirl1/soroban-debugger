# Getting Started with Soroban Debugger

This guide will take you from zero to running your first interactive debug session with a Soroban smart contract.

## 1. Installation

You can install the Soroban Debugger using Cargo (Rust's package manager) or by downloading a pre-built binary.

### Option A: Install via Cargo (Recommended)

If you have Rust installed, you can install the debugger directly from source or from crates.io:

```bash
# Install from crates.io
cargo install soroban-debugger
```

### Option B: Download Pre-built Binaries

Download the latest binary for your operating system from the [GitHub Releases](https://github.com/Timi16/soroban-debugger/releases) page. Extract the archive and add the `soroban-debug` executable to your system's PATH.

---

## 2. Prepare a Simple Contract

To debug a contract, you first need to compile it to WebAssembly (WASM). If you don't have a contract ready, you can use the sample provided in this repository.

1.  **Navigate to a contract directory**:
    ```bash
    cd examples/sample_contract
    ```

2.  **Build the contract**:
    ```bash
    cargo build --target wasm32-unknown-unknown --release
    ```

The compiled WASM file will be located at:
`target/wasm32-unknown-unknown/release/sample_contract.wasm`

---

## 3. Run Your First Debug Session

Now, let's run a function in the contract using the debugger. We'll use the `run` command, which executes a function and displays the results.

Run the `expensive` function with an argument of `100`:

```bash
soroban-debug run \
  --contract target/wasm32-unknown-unknown/release/sample_contract.wasm \
  --function expensive \
  --args '[100]'
```

### Understanding the Output

When you run a command, the debugger provides a detailed summary:

- **Result**: The value returned by the function (e.g., `Ok(1234567)`).
- **Budget**: How much CPU and Memory the execution consumed.
- **Storage**: Any changes made to the contract's persistent storage.
- **Events**: Any events emitted during execution.

---

## 4. Interactive Debugging

If you want to step through the code instruction by instruction, use the `interactive` mode:

```bash
soroban-debug interactive --contract target/wasm32-unknown-unknown/release/sample_contract.wasm
```

Inside the interactive shell, you can use commands like:
- `s` (step): Execute the next instruction.
- `i` (inspect): View the current stack and local variables.
- `storage`: View the current contract storage.
- `q` (quit): Exit the debugger.

---

## Next Steps

- Explore [Source-Level Debugging](source-level-debugging.md) to map WASM back to your Rust code.
- Learn about [Time-Travel Debugging](remote-debugging.md) to step backward through execution.
- Check the [FAQ](faq.md) for troubleshooting common issues.

---

## Maintainers

For release readiness gates (CLI + extension + analyzer + benchmarks), follow:

- `docs/release-checklist.md`
