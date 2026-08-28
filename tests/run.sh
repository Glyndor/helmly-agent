#!/usr/bin/env bash
#
# Runs every shell test. CI calls this rather than naming one file, so a
# new tests/*.test.sh is picked up by existing, not by remembering to add
# it to a workflow input. #167 wired shell-ci at one named file and
# the next test added was already invisible to CI before this existed.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
found=0
for t in tests/*.test.sh; do
	found=$((found + 1))
	printf '\n== %s\n' "$t"
	if bash "$t"; then :; else fail=1; fi
done

# A runner that finds nothing must not report success. That is the same
# skipped-check-reports-Success shape shell-ci's own `test` job had.
if [[ "$found" -eq 0 ]]; then
	echo "no tests/*.test.sh found; refusing to report success" >&2
	exit 1
fi

printf '\n%s suite(s) run\n' "$found"
exit "$fail"
