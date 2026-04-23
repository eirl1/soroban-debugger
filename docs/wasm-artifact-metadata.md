# WASM Artifact Metadata

`inspect` now reports lightweight artifact metadata inferred directly from the
WASM file before execution starts.

## What It Surfaces

- Whether DWARF-style debug sections such as `.debug_info` or `.debug_line`
  are embedded.
- Whether the standard WASM `name` section is present.
- Producers metadata from the standard `producers` custom section.
- Heuristic build hints such as:
  - `debug-like`
  - `release-with-debug-info`
  - `release-with-symbol-names`
  - `stripped-release-like`
- Optimization hints, including an explicit signal when `wasm-opt` appears in
  the producers metadata.
- Package hints when recoverable from module names and producers entries.

## Why This Helps

This gives users a quick read on whether a contract artifact is likely to:

- support source-level debugging well,
- have been stripped or heavily optimized,
- retain symbol names,
- include recognizable toolchain or SDK markers.

## Heuristic Nature

These fields are best-effort hints, not guarantees.

- A contract can be optimized and still retain debug info.
- A `name` section can survive release builds.
- Missing debug sections usually limit source-level debugging, but do not make
  execution invalid.
- Producers metadata depends on the toolchain and may be absent entirely.

## JSON Output

When you run:

```bash
soroban-debug inspect --contract path/to/contract.wasm --format json
```

the versioned JSON envelope now includes an additive `artifact_metadata` field
under `result`.

## Pretty Output

Pretty `inspect` output now includes an `Artifact metadata:` block showing the
same build and debug hints in a human-readable summary.
