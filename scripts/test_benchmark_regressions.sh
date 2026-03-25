#!/usr/bin/env bash
# Lightweight behavioral test for scripts/check_benchmark_regressions.sh.
# Uses a temporary git repo plus fake cargo/critcmp binaries to verify that
# the baseline run happens from a detached worktree rather than by checking
# out another branch in-place.

set -euo pipefail

SOURCE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check_benchmark_regressions.sh"
TEST_ROOT="$(mktemp -d)"
REPO_ROOT="$TEST_ROOT/repo"
BIN_DIR="$TEST_ROOT/bin"
LOG_FILE="$TEST_ROOT/invocations.log"

cleanup() {
    rm -rf "$TEST_ROOT"
}

trap cleanup EXIT

mkdir -p "$REPO_ROOT/scripts" "$BIN_DIR"
cp "$SOURCE_SCRIPT" "$REPO_ROOT/scripts/check_benchmark_regressions.sh"
chmod +x "$REPO_ROOT/scripts/check_benchmark_regressions.sh"

git init -b main "$REPO_ROOT" >/dev/null
git -C "$REPO_ROOT" config user.name "Codex Test"
git -C "$REPO_ROOT" config user.email "codex@example.com"

cat > "$REPO_ROOT/branch.txt" <<'EOF'
main
EOF
git -C "$REPO_ROOT" add branch.txt scripts/check_benchmark_regressions.sh
git -C "$REPO_ROOT" commit -m "main branch" >/dev/null

git -C "$REPO_ROOT" checkout -b feature >/dev/null
cat > "$REPO_ROOT/branch.txt" <<'EOF'
feature
EOF
git -C "$REPO_ROOT" add branch.txt
git -C "$REPO_ROOT" commit -m "feature branch" >/dev/null

cat > "$BIN_DIR/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

baseline=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
    if [ "${args[$i]}" = "--save-baseline" ]; then
        baseline="${args[$((i + 1))]}"
        break
    fi
done

if [ -z "$baseline" ]; then
    echo "missing --save-baseline" >&2
    exit 1
fi

branch_value="$(cat branch.txt)"
printf 'cargo|%s|%s\n' "$baseline" "$PWD|$branch_value" >> "$LOG_FILE"
mkdir -p "$CARGO_TARGET_DIR/criterion/fake/$baseline"
printf '%s\n' "$branch_value" > "$CARGO_TARGET_DIR/criterion/fake/$baseline/source.txt"
EOF
chmod +x "$BIN_DIR/cargo"

cat > "$BIN_DIR/critcmp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'critcmp|%s\n' "$PWD" >> "$LOG_FILE"
test -f "$PWD/target/criterion/fake/base/source.txt"
test -f "$PWD/target/criterion/fake/new/source.txt"
printf 'comparison ok\n'
EOF
chmod +x "$BIN_DIR/critcmp"

export PATH="$BIN_DIR:$PATH"
export LOG_FILE

bash "$REPO_ROOT/scripts/check_benchmark_regressions.sh" >/dev/null

current_branch="$(git -C "$REPO_ROOT" branch --show-current)"
if [ "$current_branch" != "feature" ]; then
    echo "expected to remain on feature branch, got $current_branch" >&2
    exit 1
fi

if ! grep -Fq "cargo|new|$REPO_ROOT|feature" "$LOG_FILE"; then
    echo "expected current benchmark run to happen in the feature checkout" >&2
    cat "$LOG_FILE" >&2
    exit 1
fi

if ! grep -Eq "cargo\|base\|.*/baseline-worktree\|main" "$LOG_FILE"; then
    echo "expected baseline benchmark run to happen in a separate baseline worktree" >&2
    cat "$LOG_FILE" >&2
    exit 1
fi

if ! grep -Eq "critcmp\|.*/critcmp-root" "$LOG_FILE"; then
    echo "expected critcmp to run from the isolated comparison root" >&2
    cat "$LOG_FILE" >&2
    exit 1
fi

echo "benchmark regression script uses an isolated baseline worktree"
