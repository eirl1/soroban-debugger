# Symbolic Analysis Budgets

The `symbolic` command now supports deterministic exploration budgets so you can tune analysis depth for local debugging and CI.

## Preset profiles

Use `--profile` to start from a preset:

- `fast`: small budget for quick feedback
- `balanced`: default budget for everyday use
- `deep`: larger budget for more exhaustive exploration

Example:

```bash
soroban-debug symbolic \
  --contract ./target/wasm32-unknown-unknown/release/my_contract.wasm \
  --function transfer \
  --profile balanced
```

## Explicit caps

Override any preset dimension with explicit flags:

```bash
soroban-debug symbolic \
  --contract ./target/wasm32-unknown-unknown/release/my_contract.wasm \
  --function transfer \
  --profile fast \
  --input-combination-cap 128 \
  --path-cap 64 \
  --timeout 20
```

Flags:

- `--input-combination-cap`: maximum number of generated input combinations
- `--path-cap`: maximum number of generated inputs to execute
- `--timeout`: overall symbolic-analysis timeout in seconds

## Truncation metadata

Symbolic reports now explain whether exploration was truncated by:

- input combination cap
- path exploration cap
- timeout

Generated scenario TOML files include a `[metadata]` section with the applied budget and truncation reasons, which is useful for CI artifacts and reproducible investigations.

## JSON schema

Machine-readable symbolic reports are emitted with `--format json` and use the shared command envelope:

```json
{
  "schema_version": "1.0.0",
  "command": "symbolic",
  "status": "success",
  "result": {},
  "error": null
}
```

The current symbolic report schema is `tests/schemas/symbolic_output.json` and expects envelope `schema_version` `1.0.0`. The `result.metadata` object includes the applied seed or replay token, optional `storage_seed`, budget caps, truncation flags, truncation reasons, and coverage metadata so CI consumers can detect partial exploration and suggest raising `--input-combination-cap`, `--path-cap`, or `--timeout` when needed.
