#!/usr/bin/env bash
# Runs the benchmark regression gate without mutating the caller's checkout.
# It benchmarks the current tree, benchmarks a baseline ref in a temporary
# detached worktree, and compares the saved Criterion baselines with critcmp.
#
# Usage:
#   bash scripts/check_benchmark_regressions.sh
#
# Optional environment variables:
#   BASELINE_REF            Git ref to benchmark as the baseline.
#   BENCHMARK_THRESHOLD     critcmp percentage threshold (default: 10).
#   CURRENT_BASELINE_NAME   Criterion baseline name for the current tree.
#   BASELINE_NAME           Criterion baseline name for the baseline ref.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHMARK_THRESHOLD="${BENCHMARK_THRESHOLD:-10}"
CURRENT_BASELINE_NAME="${CURRENT_BASELINE_NAME:-new}"
BASELINE_NAME="${BASELINE_NAME:-base}"

if [ -z "${BASELINE_REF:-}" ]; then
    if git -C "$REPO_ROOT" rev-parse --verify --quiet refs/remotes/origin/main >/dev/null; then
        BASELINE_REF="origin/main"
    else
        BASELINE_REF="main"
    fi
fi

TEMP_DIR="$(mktemp -d)"
WORKTREE_DIR="$TEMP_DIR/baseline-worktree"
BENCH_TARGET_DIR="$TEMP_DIR/cargo-target"
CRITCMP_ROOT="$TEMP_DIR/critcmp-root"
WORKTREE_ADDED=0

cleanup() {
    if [ "$WORKTREE_ADDED" -eq 1 ]; then
        git -C "$REPO_ROOT" worktree remove --force "$WORKTREE_DIR" >/dev/null 2>&1 || true
    fi
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

if ! command -v critcmp >/dev/null 2>&1; then
    echo "critcmp is required but was not found on PATH."
    echo "Install it with: cargo install critcmp --version 0.1.7"
    exit 2
fi

echo "Preparing baseline worktree for $BASELINE_REF..."
git -C "$REPO_ROOT" worktree add --detach "$WORKTREE_DIR" "$BASELINE_REF"
WORKTREE_ADDED=1

echo "Running benchmarks for the current checkout..."
(
    cd "$REPO_ROOT"
    CARGO_TARGET_DIR="$BENCH_TARGET_DIR" cargo bench -- --save-baseline "$CURRENT_BASELINE_NAME" --noplot
)

echo "Running benchmarks for the baseline checkout..."
(
    cd "$WORKTREE_DIR"
    CARGO_TARGET_DIR="$BENCH_TARGET_DIR" cargo bench -- --save-baseline "$BASELINE_NAME" --noplot
)

mkdir -p "$CRITCMP_ROOT/target"

if [ ! -d "$BENCH_TARGET_DIR/criterion" ]; then
    echo "Criterion output was not produced under $BENCH_TARGET_DIR/criterion."
    exit 2
fi

cp -R "$BENCH_TARGET_DIR/criterion" "$CRITCMP_ROOT/target/criterion"

echo "Comparing baselines with critcmp (threshold: ${BENCHMARK_THRESHOLD}%)..."
(
    cd "$CRITCMP_ROOT"

    set +e
    output="$(critcmp "$BASELINE_NAME" "$CURRENT_BASELINE_NAME" --threshold "$BENCHMARK_THRESHOLD" 2>&1)"
    status=$?
    set -e

    echo "$output"

    if [ "$status" -eq 0 ]; then
        exit 0
    fi

    if echo "$output" | grep -Fq "no benchmark comparisons to show"; then
        echo "No overlapping benchmark IDs between '$BASELINE_NAME' and '$CURRENT_BASELINE_NAME'; skipping regression gate."
        exit 0
    fi

    exit "$status"
)
