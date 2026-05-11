#!/usr/bin/env bash
# Phase 7.5.0 verification harness.
#
# Runs the gates that Phase 7.5.0 closure depends on, with per-stage
# output captured to discrete files under `out/` so any failure is
# narrow-debuggable. Stages run in order; each stage's exit code is
# captured, but later stages still run so we get the full picture in
# one pass rather than only seeing the first failure.
#
# Stages:
#  1. vdf-tests        — direct test of the new adamant-crypto::vdf module
#  2. crypto-clippy    — clippy on adamant-crypto alone (fast targeted gate)
#  3. workspace-clippy — clippy across workspace, warnings as errors
#  4. fmt              — cargo fmt --check across workspace
#  5. workspace-tests  — cargo test --workspace --lib --bins --tests
#                         (excludes doctests; adamant-halo2 has pre-existing
#                         vendored doctest failures unrelated to Phase 7.5.0)
#  6. audit            — tools/workspace-audit/audit.py --strict
#  7. no-sui           — tests/no_sui_in_production_deps
#  8. no-halo2         — tests/no_upstream_halo2_in_production_deps
#
# Output convention:
#  - out/<stage>.log: full captured stdout+stderr for that stage.
#  - out/<stage>.exit: numeric exit code.
#  - out/SUMMARY.txt: end-of-run consolidated status table.
#
# Re-run with `tools/phase-7-5-0-debug/verify.sh` from any working
# directory; the script `cd`s to the repo root itself.

set -u

# Locate repo root (this script lives at tools/phase-7-5-0-debug/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

OUT="$SCRIPT_DIR/out"
mkdir -p "$OUT"
rm -f "$OUT"/*.log "$OUT"/*.exit "$OUT/SUMMARY.txt"

declare -A RESULTS

run_stage() {
    local name="$1"
    shift
    local cmd=("$@")

    echo "===================================================="
    echo "[stage] $name"
    echo "[cmd]   ${cmd[*]}"
    echo "===================================================="

    "${cmd[@]}" >"$OUT/$name.log" 2>&1
    local rc=$?
    echo "$rc" >"$OUT/$name.exit"
    RESULTS[$name]=$rc

    if [ "$rc" -eq 0 ]; then
        echo "[ok]    $name"
    else
        echo "[FAIL]  $name (exit $rc) — see $OUT/$name.log"
        echo
        echo "--- last 40 lines of $name.log ---"
        tail -40 "$OUT/$name.log"
        echo "--- end ---"
    fi
    echo
}

run_stage vdf-tests \
    cargo test -p adamant-crypto vdf --quiet

run_stage crypto-clippy \
    cargo clippy -p adamant-crypto -- -D warnings

run_stage workspace-clippy \
    cargo clippy --workspace --all-targets -- -D warnings

run_stage fmt \
    cargo fmt --all -- --check

run_stage workspace-tests \
    cargo test --workspace --lib --bins --tests --quiet

run_stage audit \
    python tools/workspace-audit/audit.py --strict

run_stage no-sui \
    cargo test --workspace --test no_sui_in_production_deps --quiet

run_stage no-halo2 \
    cargo test --workspace --test no_upstream_halo2_in_production_deps --quiet

# Build SUMMARY.txt
{
    echo "Phase 7.5.0 verification summary"
    echo "Repo root: $REPO_ROOT"
    echo "Timestamp: $(date -Iseconds 2>/dev/null || date)"
    echo
    printf "%-22s %s\n" "stage" "result"
    printf "%-22s %s\n" "---------------------" "------"
    local_overall=0
    for stage in vdf-tests crypto-clippy workspace-clippy fmt workspace-tests audit no-sui no-halo2; do
        rc="${RESULTS[$stage]}"
        if [ "$rc" -eq 0 ]; then
            status="ok"
        else
            status="FAIL (exit $rc)"
            local_overall=1
        fi
        printf "%-22s %s\n" "$stage" "$status"
    done
    echo
    if [ "$local_overall" -eq 0 ]; then
        echo "Overall: ALL GATES PASS"
    else
        echo "Overall: FAILURES PRESENT — inspect failing stage logs under $OUT/"
    fi
} | tee "$OUT/SUMMARY.txt"

# Exit with non-zero if any stage failed.
for stage in vdf-tests crypto-clippy workspace-clippy fmt workspace-tests audit no-sui no-halo2; do
    if [ "${RESULTS[$stage]}" -ne 0 ]; then
        exit 1
    fi
done
exit 0
