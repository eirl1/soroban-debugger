# Design: Why the debugger uses `soroban-env-host` directly

_Backlog item: I-016 (Section B — Architecture and Design Docs)._

## Decision

The debugger drives contract execution through **`soroban-env-host`** (the
Soroban environment **Host**) directly — see `src/runtime/executor.rs`,
`src/runtime/invoker.rs`, and `src/runtime/mocking.rs` — rather than through the
higher-level `soroban-sdk` contract-authoring abstractions.

## Context

`soroban-sdk` is designed for **writing** contracts: it hides the host behind
ergonomic types (`Env`, `Symbol`, `Val`, generated client bindings) and is
optimized for compiling *to* WASM. A debugger has the opposite needs — it must
**observe and control** an already-compiled contract as the host executes it.

## Why direct host access

The debugger's core features map onto host-level capabilities that the SDK
intentionally abstracts away:

| Debugger capability | Requires | SDK exposes it? |
| --- | --- | --- |
| Instruction-level stepping / instrumentation (`src/runtime/instrumentation.rs`, `src/inspector/instructions.rs`) | Hooking the host's execution loop | No |
| Budget / metering inspection (`src/inspector/budget.rs`) | `Host` budget internals | No |
| Storage & footprint inspection (`src/inspector/storage.rs`, `storage::Footprint`) | Host storage + footprint | No |
| Event & auth capture (`src/inspector/events.rs`, `src/inspector/auth.rs`) | Host event/auth recording | Partially, not introspectably |
| Deterministic replay (`src/compare/trace.rs`, replay command) | Pinning host state/seed and re-running | No |
| Mocking host functions (`src/runtime/mocking.rs`) | `ContractFunctionSet` on the host | No |

Going through the SDK would mean re-implementing or scraping these out of an
abstraction that exists precisely to hide them — adding a translation layer with
no upside for a tool that already operates at the host boundary.

## Trade-offs

- **Cost:** `soroban-env-host` is a lower-level, faster-moving dependency; its
  API is less stable across protocol versions than the SDK surface. The
  `src/protocol.rs` module and the pinned host version localize that churn.
- **Benefit:** full fidelity to actual on-chain execution semantics (budget,
  storage, events, auth) and the fine-grained control the debugger/inspectors
  and replay/optimize features depend on.

## Alternatives considered

1. **Build on `soroban-sdk`** — rejected: the SDK hides exactly the host
   internals the debugger must surface; instruction/budget/storage inspection
   would not be expressible.
2. **Fork or vendor a thin host shim** — rejected as premature: `protocol.rs`
   plus a pinned `soroban-env-host` already isolate version churn without the
   maintenance burden of a fork.

## Consequences

New execution/inspection features should continue to build on the `Host`
directly via `src/runtime/`. Protocol-version sensitivity is concentrated in
`src/protocol.rs` and the `soroban-env-host` pin in `Cargo.toml`; upgrades
should be validated there first.
