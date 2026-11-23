#!/usr/bin/env bash
#
# Tests that the workflows still say what the CI map and the rulesets rely on
# (tests/lib/ci_wiring.py holds the checks and lists what each one protects).
#
# Two parts: the real tree must pass, and each rule must fail when its subject
# is broken. The second part is what makes the first one worth reading: a check
# that has never been seen to fail may be checking nothing.

set -euo pipefail

# The helpers are Python; keep their bytecode out of the tree being tested.
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
check() {
	if [[ "$2" == "$3" ]]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"
		fail=1
	fi
}

# A copy of the files the checks read, so a case can break one without touching the tree.
fresh_copy() {
	rm -rf "$WORK/tree"
	mkdir -p "$WORK/tree/.github" "$WORK/tree/tests"
	cp -r "$ROOT/.github/workflows" "$WORK/tree/.github/workflows"
	cp "$ROOT/.github/ci-map.json" "$ROOT/.github/required-checks.json" "$WORK/tree/.github/"
	cp -r "$ROOT/tests/lib" "$WORK/tree/tests/lib"
}

# finding: runs the checks on the copy and prints the first finding, or "none".
finding() {
	local out rc=0
	out="$(python3 "$WORK/tree/tests/lib/ci_wiring.py" 2>&1)" || rc=$?
	if [[ "$rc" -eq 0 ]]; then echo none; else printf '%s\n' "$out" | head -n 1; fi
}

fresh_copy
check "the real workflows satisfy every rule" "none" "$(finding)"

fresh_copy
sed -i 's/^  workflow-lint:$/  lint-workflows:/' "$WORK/tree/.github/workflows/ci.yml"
check "renaming a job a ruleset requires is caught" \
	"required check on develop is emitted by no workflow: 'workflow-lint / workflow-lint'" "$(finding)"

fresh_copy
sed -i 's/needs\.decide\.outputs\.audit/needs.decide.outputs.nothing/' "$WORK/tree/.github/workflows/ci.yml"
out="$(finding)"
check "a suite the workflow stops reading is caught" "suite 'audit' of the map is never read as needs.decide.outputs.audit in ci.yml" "$out"

fresh_copy
python3 - "$WORK/tree/.github/ci-map.json" << 'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["suites"]["docs"] = ["docs/**"]
json.dump(m, open(sys.argv[1], "w"))
PY
check "a suite added to the map but not to ci.yml is caught" "suite 'docs' of the map is never read as needs.decide.outputs.docs in ci.yml" "$(finding)"

fresh_copy
sed -i "0,/if: \${{ inputs.run != 'false' }}/s//if: \${{ true }}/" "$WORK/tree/.github/workflows/reusable-rust-ci.yml"
check "a reusable job that ignores the verdict is caught" \
	"reusable-rust-ci.yml: job 'lint' takes the run input but its \`if\` does not test it" "$(finding)"

fresh_copy
sed -i 's/^      test-command: .*$/      test-command: ""/' "$WORK/tree/.github/workflows/ci.yml"
check "emptying test-command, which would skip a required check, is caught" \
	"ci.yml: the shell suite is called without test-command, so shell / test would skip and report success" "$(finding)"

fresh_copy
sed -i 's/^      coverage-threshold: .*$/      coverage-threshold: 0/' "$WORK/tree/.github/workflows/ci.yml"
check "a zero coverage threshold, which would skip a required check, is caught" \
	"ci.yml: the Rust suite is called without a positive coverage-threshold, so rust / Coverage would skip and report success" "$(finding)"

fresh_copy
sed -i 's/^  pull_request:$/  pull_request_target:/' "$WORK/tree/.github/workflows/ci.yml"
out="$(finding)"
check "a ci.yml that no longer runs on pull requests loses its checks" "required check on develop is emitted by no workflow: 'rust / Format & lint'" "$out"

exit "$fail"
