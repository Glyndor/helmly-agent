#!/usr/bin/env bash
# Helpers shared by the wiring tests (ci-wiring.test.sh and ci-wiring-release.test.sh).
#
# `ci_wiring.py` reads the workflows, the actions, the map and the list of required
# checks from the tree it sits in. Each case here makes a fresh copy of those files, breaks
# one of them and asserts which finding comes back, so that the checks are seen to fail.
# Source it from a test; it sets ROOT, WORK, `fail` and an exit trap.

# shellcheck disable=SC2034 # fail is read by the sourcing test
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
	cp -r "$ROOT/.github/actions" "$WORK/tree/.github/actions"
	cp "$ROOT/.github/ci-map.json" "$ROOT/.github/required-checks.json" "$WORK/tree/.github/"
	cp -r "$ROOT/tests/lib" "$WORK/tree/tests/lib"
}

# finding: runs the checks on the copy and prints the first finding, or "none".
finding() {
	local out rc=0
	out="$(python3 "$WORK/tree/tests/lib/ci_wiring.py" 2>&1)" || rc=$?
	if [[ "$rc" -eq 0 ]]; then echo none; else printf '%s\n' "$out" | head -n 1; fi
}


# sabotage <file> <old> <new>: replace the first occurrence in the copy, failing loudly if absent.
sabotage() {
	python3 - "$WORK/tree/.github/workflows/$1" "$2" "$3" << 'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if old not in text:
	sys.exit("sabotage target not found: " + old)
open(path, "w").write(text.replace(old, new, 1))
PY
}
# caught <name> <expected substring>: the checks print the substring somewhere
caught() {
	local out rc=0
	out="$(python3 "$WORK/tree/tests/lib/ci_wiring.py" 2>&1)" || rc=$?
	if [[ "$rc" -ne 0 ]] && grep -qF -- "$2" <<< "$out"; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       expected a finding containing: %s\n       got (exit %s): %s\n' "$1" "$2" "$rc" "$(head -n 3 <<< "$out")"
		fail=1
	fi
}

