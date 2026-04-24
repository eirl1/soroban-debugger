# Soroban Debugger Starter Plugin

This is a template to help you quickly build your own plugins for the Soroban Debugger.

## Getting Started

1. Copy this directory to use as the base for your new plugin.
2. Rename the package in `Cargo.toml`.
3. Update the `plugin.toml` manifest with your plugin's details.
4. Update the `[capabilities]` section depending on whether you need to hook execution, provide custom CLI commands, or use formatters.

## Building

```bash
cargo build --release
```

## Installing

Create a directory for your plugin inside the debugger's plugin directory:

```bash
mkdir -p ~/.soroban-debug/plugins/starter-plugin
```

Copy the compiled dynamic library and the manifest (adjusting the library extension for your OS):

```bash
cp target/release/libsoroban_debug_starter_plugin.so ~/.soroban-debug/plugins/starter-plugin/
cp plugin.toml ~/.soroban-debug/plugins/starter-plugin/
```

## Running

Once installed, the Soroban Debugger will automatically discover and load your plugin on startup.
Because of the default trust policy, you may need to add it to your allowlist or run in local-only mode:

```bash
soroban-debug completions bash > /usr/local/etc/bash_completion.d/soroban-debug
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`.

#### Installation Instructions

**Bash:**

```bash
soroban-debug completions bash > /usr/local/etc/bash_completion.d/soroban-debug
```

**Zsh:**

```bash
soroban-debug completions zsh > /usr/local/share/zsh/site-functions/_soroban-debug
```

**Fish:**

```bash
soroban-debug completions fish > ~/.config/fish/completions/soroban-debug.fish
```

**PowerShell:**

```powershell
soroban-debug completions powershell >> $PROFILE
```

### Compare Command

Compare two execution trace JSON files side-by-side to identify
differences and regressions in storage, budget, return values, and
execution flow:

```bash
soroban-debug compare <TRACE_A> <TRACE_B> [OPTIONS]

Options:
  -o, --output <FILE>       Output file for the comparison report (default: stdout)
```

Example:

```bash
# Compare two saved execution traces
soroban-debug compare examples/trace_a.json examples/trace_b.json

# Save report to a file
soroban-debug compare baseline.json new.json --output diff_report.txt
```

See [`doc/compare.md`](https://github.com/Timi16/soroban-debugger/blob/main/docs/doc/compare.md) for the full trace JSON format reference
and a regression testing workflow guide.

## Examples

### Example 1: Debug a Token Transfer

```bash
soroban-debug run \
  --contract token.wasm \
  --function transfer \
  --args '["user1", "user2", 100]'
```

### Example 1a: Debug with Map Arguments

Pass JSON objects as Map arguments:

```bash
# Flat map argument
soroban-debug run \
  --contract token.wasm \
  --function update_user \
  --args '{"user":"ABC","balance":1000}'

# Nested map argument
soroban-debug run \
  --contract token.wasm \
  --function update_user \
  --args '{"user":"ABC","balance":1000,"metadata":{"verified":true,"level":"premium"}}'

# Mixed-type values in map
soroban-debug run \
  --contract dao.wasm \
  --function create_proposal \
  --args '{"title":"Proposal 1","votes":42,"active":true,"tags":["important","urgent"]}'
```

Output:

```
> Debugger started
> Paused at: transfer
> Args: from=user1, to=user2, amount=100

(debug) s
> Executing: get_balance(user1)
> Storage: balances[user1] = 500

(debug) s
> Executing: set_balance(user1, 400)

(debug) storage
Storage:
  balances[user1] = 400
  balances[user2] = 100

(debug) c
> Execution completed
> Result: Ok(())
```

### Example 2: Set Breakpoints

```bash
soroban-debug run \
  --contract dao.wasm \
  --function execute \
  --breakpoint verify_signature \
  --breakpoint update_state
```

### Example 3: Initial Storage State

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

For more scenarios, see the Troubleshooting Index, Full FAQ and Remote Troubleshooting Guide.

---

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow.

## License
Licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).
