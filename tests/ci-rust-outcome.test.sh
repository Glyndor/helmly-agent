#!/usr/bin/env bash
#
# Tests for the `outcome` job of reusable-rust-ci.yml.
#
# The caller of that workflow sees one result, and a skipped job counts as passed, so a
# condition made false by mistake (`&& false` on the coverage job) would leave the caller
# green with no test run at all. `outcome` always runs and fails unless the jobs the inputs
# select ran and succeeded. Its text is taken from the workflow and run with the results
# every combination can give, asserting the verdict.

set -euo pipefail
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

python3 -I - "$ROOT/.github/workflows/reusable-rust-ci.yml" "$WORK/outcome.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["jobs"]["outcome"]["steps"][0]["run"])
PY

# outcome <run> <threshold> <lint> <test> <coverage>: exit code of the job
outcome() {
	local rc=0
	env RUN="$1" THRESHOLD="$2" LINT="$3" TEST="$4" COVERAGE="$5" bash "$WORK/outcome.sh" > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}

check "with a threshold: lint and coverage succeeded, test skipped: green" "0" "$(outcome true 45 success skipped success)"
check "with a threshold: coverage skipped, as an '&& false' would leave it: red" "1" "$(outcome true 45 success skipped skipped)"
grep -q "coverage ended 'skipped' and should have ended 'success'" "$WORK/out" && r=said || r=silent
check "and it says which job did not run" "said" "$r"
check "with a threshold: coverage failed: red" "1" "$(outcome true 45 success skipped failure)"
check "with a threshold: test ran as well as coverage: red" "1" "$(outcome true 45 success success success)"
check "with a threshold: lint failed: red" "1" "$(outcome true 45 failure skipped skipped)"
check "with a threshold: lint skipped: red" "1" "$(outcome true 45 skipped skipped success)"
check "without a threshold: lint and test succeeded, coverage skipped: green" "0" "$(outcome true 0 success success skipped)"
check "without a threshold: test skipped: red" "1" "$(outcome true 0 success skipped skipped)"
check "without a threshold: coverage ran: red" "1" "$(outcome true 0 success success success)"
check "with the plan's verdict false everything is skipped: green" "0" "$(outcome false 45 skipped skipped skipped)"
check "with the plan's verdict false a job that ran: red" "1" "$(outcome false 45 success skipped skipped)"
check "an empty plan verdict is a run: nothing skipped passes" "1" "$(outcome '' 45 skipped skipped skipped)"
check "an empty plan verdict with the jobs done: green" "0" "$(outcome '' 45 success skipped success)"
check "a cancelled job: red" "1" "$(outcome true 45 success skipped cancelled)"
check "a threshold that is not a number is read as none: test must run" "1" "$(outcome true abc success skipped success)"

exit "$fail"
