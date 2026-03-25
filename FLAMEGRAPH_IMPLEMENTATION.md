# Flame Graph Export Feature (#501)

## Overview

This implementation adds flame graph export capability to the `soroban-debug profile` command, allowing developers to generate interactive performance visualization artifacts alongside traditional hotspot reports.

## Changes Made

### 1. New Dependencies

- **inferno (0.11)**: Rust library for flame graph rendering and SVG generation

### 2. New Module: `src/profiler/flamegraph.rs`

Implements `FlameGraphGenerator` with the following capabilities:

- **`from_report()`**: Converts OptimizationReport into flame graph stack format
  - Creates stacks for each function based on total CPU instructions
  - Generates sub-stacks for operations and storage accesses
  - Normalizes counts for proper visualization

- **`to_collapsed_stack_format()`**: Converts stacks to collapsed format (text-based intermediate)
  - Standard format compatible with Flamegraph tools
  - `function;operation;detail count` format

- **`generate_svg()`**: Renders SVG flame graph directly
  - 1200x800 default dimensions (customizable)
  - 12pt default font size
  - Full interactive SVG output

- **`write_collapsed_stack_file()`**: Exports intermediate format to file
- **`write_svg_file()`**: Exports rendered SVG to file

### 3. Extended `ProfileArgs` CLI Options

Added four new options to `src/cli/args.rs`:

```rust
--flamegraph <FLAMEGRAPH>              // Path to SVG output
--flamegraph-stacks <STACKS>           // Path to collapsed stack format output
--flamegraph-width <WIDTH>             // SVG width (default: 1200)
--flamegraph-height <HEIGHT>           // SVG height (default: 800)
```

### 4. Updated Profile Command

Modified `src/cli/commands.rs::profile()` to:

- Generate flame graphs after analysis when `--flamegraph` flag is provided
- Export collapsed stack format when `--flamegraph-stacks` flag is provided
- Support both formats simultaneously
- Log output paths for user confirmation

### 5. Comprehensive Tests

Created `tests/cli/flamegraph_tests.rs` with:

- `test_profile_flamegraph_svg_export`: Validates SVG generation
- `test_profile_flamegraph_stacks_export`: Validates collapsed format export
- `test_profile_flamegraph_both_exports`: Validates simultaneous export
- `test_profile_flamegraph_custom_dimensions`: Validates custom size parameters

### 6. Unit Tests in Flamegraph Module

- Stack generation from mock reports
- Collapsed format formatting
- File output operations

### 7. Updated Documentation

Updated `man/man1/soroban-debug-profile.1` with:

- New flame graph options in SYNOPSIS
- Detailed descriptions for each new parameter
- Extended DESCRIPTION section noting visualization capability

## Usage Examples

### Export SVG Flame Graph

```bash
soroban-debug profile \
  --contract contract.wasm \
  --function init \
  --flamegraph profile.svg
```

### Export Collapsed Stack Format (Flamegraph-compatible)

```bash
soroban-debug profile \
  --contract contract.wasm \
  --function main \
  --flamegraph-stacks profile.stacks
```

### Custom Dimensions

```bash
soroban-debug profile \
  --contract contract.wasm \
  --function execute \
  --flamegraph profile.svg \
  --flamegraph-width 1600 \
  --flamegraph-height 1000
```

### Combined Report and Visualization

```bash
soroban-debug profile \
  --contract contract.wasm \
  --function transfer \
  --output report.md \
  --flamegraph profile.svg \
  --flamegraph-stacks profile.stacks
```

## Technical Details

### Stack Format

Flame graphs are generated from:

- **Function-level stacks**: Each function gets a stack proportional to its CPU cost
- **Operation stacks**: Expensive operations appear as sub-stacks under their function
- **Storage access stacks**: Storage operations tracked as separate branches

### Data Normalization

- Uses CPU instructions as primary metric
- Normalizes to reasonable sampling counts for visualization
- Handles edge cases (zero costs, single samples)

### Flamegraph Format Compatibility

- Collapsed stack format is compatible with:
  - `flamegraph-rs` tools
  - Firefox Profiler import
  - Other standard flamegraph viewers

## Code Quality

- **Minimal comments**: Code is self-documenting through clear naming
- **Zero redundancy**: Reuses existing report structures
- **Optimized**: Efficient stack generation and formatting
- **Well-tested**: Unit and integration tests included

## Acceptance Criteria Met

✅ Profile emits flame graph artifacts (SVG)
✅ Profile emits intermediate format (collapsed stacks)
✅ Tests added for new functionality
✅ User-facing documentation updated (man page, args help)
✅ Optional feature (doesn't affect existing workflow)
