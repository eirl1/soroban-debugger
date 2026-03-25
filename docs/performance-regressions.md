# Benchmark regression policy (CI)

This repository runs Criterion benchmarks in CI and compares pull request results against a rolling baseline captured from the default branch (`main`).

## What happens in CI

- **On `push` to `main`:**
  - Run `cargo bench --benches`
  - Record results into `.bench/baseline.json`
  - Save the baseline via GitHub Actions cache and upload it as an artifact

- **On pull requests:**
  - Restore the latest available `.bench/baseline.json` from cache (generated on `main`)
  - Run `cargo bench --benches`
  - Compare current results to baseline with **pass / warn / fail** thresholds
  - Emit a Markdown summary into the GitHub Actions step summary and annotations for top regressions

## Tunable thresholds (defaults)

The CI workflow uses these environment variables:

- `BENCH_WARN_PCT` (default: `10`) – mark benchmark as **Warn** when slowdown is ≥ this percent
- `BENCH_FAIL_PCT` (default: `20`) – mark benchmark as **Fail** when slowdown is ≥ this percent

## Noise control knobs

Criterion sampling parameters are also set in CI and can be tuned if the job is too noisy or too slow:

- `BENCH_SAMPLE_SIZE` (default: `20`)
- `BENCH_MEASUREMENT_TIME` (default: `5`)
- `BENCH_WARMUP_TIME` (default: `2`)

## Local usage

Record a baseline:

```bash
cargo bench --benches -- --noplot
cargo run --bin bench-regression -- record --criterion target/criterion --out .bench/baseline.json
```

Compare current results against a baseline:

```bash
cargo bench --benches -- --noplot
cargo run --bin bench-regression -- compare --baseline .bench/baseline.json --criterion target/criterion
```

