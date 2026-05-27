# Trace compatibility

The `replay` command consumes execution-trace JSON files produced by the
debugger. To avoid confusing failures deep in execution, `replay` validates the
trace **before** running it (see `validate_trace_schema` in
`src/compare/trace.rs`, issue #1288).

## Supported schema versions

`SUPPORTED_TRACE_VERSIONS = [1]`.

A trace MAY carry a top-level `"version"` integer:

- **absent** — treated as the current schema (backward-compatible with traces
  captured before versioning).
- **present and supported** — replayed normally.
- **present and unsupported** — rejected with a clear error suggesting you
  re-capture the trace with a matching debugger version or migrate the file.

## Required fields

A trace must be a JSON **object** and contain enough to replay:

- a non-empty **`call_sequence`** array, **or**
- a non-empty **`function`** string.

Otherwise it is rejected as malformed before execution begins.

## Full shape

The complete structure is defined by `ExecutionTrace` in
`src/compare/trace.rs` (`label`, `contract`, `function`, `args`, `storage`,
`budget`, `return_value`, `call_sequence`, `events`). Unknown fields are ignored
on load, so additive changes are backward-compatible; removing or repurposing a
field, or changing replay semantics, warrants bumping `SUPPORTED_TRACE_VERSIONS`.
