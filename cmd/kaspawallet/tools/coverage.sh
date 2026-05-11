#!/bin/bash
#
# Cargo coverage helper for the kaspawallet crate (Phase 1 spec
# sec.6.12.2). Runs `cargo llvm-cov` against the workspace, scoped
# to the kaspawallet crate, and emits both an lcov artifact the
# Validator attaches to the closure report and a summary the gate
# script greps. Exits non-zero when either threshold is missed.
#
# Tooling install (one-time):
#   cargo install cargo-llvm-cov
#   rustup component add llvm-tools-preview
#
# Spec thresholds (see sec.6.12.2):
#   - Line coverage: >= 85%
#   - Branch coverage: >= 80%
#
# Coverage exclusions (per spec):
#   - cmd/kaspawallet/src/main.rs: thin clap dispatch -- excluded.
#   - tonic-generated proto modules under daemon/pb.rs (resolved
#     via OUT_DIR include): excluded by default since cargo-llvm-cov
#     sees them as `OUT_DIR/...` paths outside the crate's source
#     tree; no extra config needed.
#   - #[cfg(test)] code: trivially covered.

set -euo pipefail

LINE_THRESHOLD="${LINE_COVERAGE_THRESHOLD:-85}"
BRANCH_THRESHOLD="${BRANCH_COVERAGE_THRESHOLD:-80}"

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$WORKSPACE_ROOT"

LCOV_OUT="${COVERAGE_LCOV_OUT:-target/llvm-cov/kaspawallet.lcov}"
mkdir -p "$(dirname "$LCOV_OUT")"

echo "kaspawallet coverage: lcov -> $LCOV_OUT"
cargo llvm-cov \
    --package kaspawallet \
    --tests \
    --ignore-filename-regex '(/main\.rs$|/target/.*/build/.*/out/)' \
    --lcov \
    --output-path "$LCOV_OUT"

echo "kaspawallet coverage summary:"
SUMMARY="$(cargo llvm-cov \
    --package kaspawallet \
    --tests \
    --ignore-filename-regex '(/main\.rs$|/target/.*/build/.*/out/)' \
    --summary-only)"
echo "$SUMMARY"

# Parse the summary's TOTAL line. Format example (cargo-llvm-cov 0.6.x):
#   Filename                     Regions    Missed Regions   Cover    Functions   Missed Functions   Cover   Lines   Missed Lines   Cover   Branches   Missed Branches   Cover
#   ...
#   TOTAL                        ...                          XX.XX%          ...                    XX.XX%   ...                   XX.XX%   ...                         XX.XX%
TOTAL_LINE="$(printf '%s\n' "$SUMMARY" | awk '$1 == "TOTAL" { print }')"
if [ -z "$TOTAL_LINE" ]; then
    echo "ERROR: could not locate TOTAL row in cargo-llvm-cov summary" >&2
    exit 1
fi

# Strip percent signs and pull the line/branch coverage numbers.
LINE_COV="$(printf '%s\n' "$TOTAL_LINE" | awk '{ for (i=1;i<=NF;i++) if ($i ~ /%$/) cov[++c]=$i; print cov[3] }' | tr -d '%')"
BRANCH_COV="$(printf '%s\n' "$TOTAL_LINE" | awk '{ for (i=1;i<=NF;i++) if ($i ~ /%$/) cov[++c]=$i; print cov[4] }' | tr -d '%')"

if [ -z "$LINE_COV" ] || [ -z "$BRANCH_COV" ]; then
    echo "ERROR: could not parse line/branch coverage from TOTAL row: $TOTAL_LINE" >&2
    exit 1
fi

echo
printf 'Line coverage:    %s%% (threshold %s%%)\n' "$LINE_COV" "$LINE_THRESHOLD"
printf 'Branch coverage:  %s%% (threshold %s%%)\n' "$BRANCH_COV" "$BRANCH_THRESHOLD"

fail=0
if awk -v cov="$LINE_COV" -v thr="$LINE_THRESHOLD" 'BEGIN { exit (cov+0 < thr+0) ? 0 : 1 }'; then
    echo "FAIL: line coverage $LINE_COV% below threshold $LINE_THRESHOLD%" >&2
    fail=1
fi
if awk -v cov="$BRANCH_COV" -v thr="$BRANCH_THRESHOLD" 'BEGIN { exit (cov+0 < thr+0) ? 0 : 1 }'; then
    echo "FAIL: branch coverage $BRANCH_COV% below threshold $BRANCH_THRESHOLD%" >&2
    fail=1
fi

exit "$fail"
