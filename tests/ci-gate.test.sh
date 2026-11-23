#!/usr/bin/env bash
#
# Tests for the `ci-gate` job of ci.yml, the one check the rulesets require
# besides the DCO check.
#
# GitHub counts a skipped required check as passed, so the gate is the only
# thing standing between "a suite did not run" and a green pull request. Its
# text is taken from the workflow and run as written, once per situation, and
# each case asserts the verdict (exit code) and not merely that something was
# printed:
#
#   - every suite succeeded                                  green
#   - a suite skipped because the plan said so               green
#   - the plan failed                                        red, whatever else
#   - a suite skipped while the plan said it should run      red (a gate before
#     it failed, or the plan came back empty)
#   - a suite failed or was cancelled                        red
#   - DCO did not succeed on a pull request                  red; on a push, where
#     it is skipped by design, it does not matter

set -euo pipefail

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

python3 - "$ROOT/.github/workflows/ci.yml" "$WORK/gate.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
steps = doc["jobs"]["ci-gate"]["steps"]
open(sys.argv[2], "w").write(steps[0]["run"])
PY

# gate <var=value>...: exit code of the gate with every suite green on a pull
# request, except for the assignments given.
gate() {
	local rc=0
	env EVENT=pull_request BASE_REF=develop DECIDE=success DCO=success WORKFLOW_LINT=success SHELL_SUITE=success RUST=success AUDIT=success STRUCTURE=success PINS=success \
		PLAN_WORKFLOWS=true PLAN_SHELL=true PLAN_RUST=true "$@" bash "$WORK/gate.sh" > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}

check "every suite succeeded: green" "0" "$(gate)"
check "a suite skipped because the plan said false: green" "0" "$(gate RUST=skipped PLAN_RUST=false)"
check "every suite skipped by the plan: green" "0" "$(gate RUST=skipped PLAN_RUST=false SHELL_SUITE=skipped PLAN_SHELL=false WORKFLOW_LINT=skipped PLAN_WORKFLOWS=false)"

check "the plan failed: red" "1" "$(gate DECIDE=failure PLAN_RUST= PLAN_SHELL= PLAN_WORKFLOWS=)"
grep -q "the plan job ended 'failure'" "$WORK/out" && r=found || r=missing
check "the red says the plan failed" "found" "$r"
check "the plan failed but every suite is green: still red" "1" "$(gate DECIDE=failure)"
check "the plan was cancelled: red" "1" "$(gate DECIDE=cancelled)"
check "the plan was skipped: red" "1" "$(gate DECIDE=skipped)"

check "a suite skipped while the plan said true: red" "1" "$(gate RUST=skipped)"
grep -q "rust was skipped but the plan did not say it could be (plan: 'true')" "$WORK/out" && r=found || r=missing
check "the red names the suite and the plan" "found" "$r"
check "the audit skipped, which no plan can excuse: red" "1" "$(gate AUDIT=skipped)"
check "the audit skipped although every other suite was skipped by the plan: red" "1" "$(gate AUDIT=skipped RUST=skipped PLAN_RUST=false)"
check "a suite skipped by a failed gate before it, plan true: red" "1" "$(gate SHELL_SUITE=skipped WORKFLOW_LINT=failure)"
check "a suite that failed: red" "1" "$(gate SHELL_SUITE=failure)"
check "a suite that failed although the plan said false: red" "1" "$(gate RUST=failure PLAN_RUST=false)"
check "the audit failing: red" "1" "$(gate AUDIT=failure)"
check "the structure check failing: red" "1" "$(gate STRUCTURE=failure)"
check "the structure check skipped, which no plan can excuse: red" "1" "$(gate STRUCTURE=skipped)"
check "the pins check failing: red" "1" "$(gate PINS=failure)"
check "the pins check skipped, which no plan can excuse: red" "1" "$(gate PINS=skipped)"
check "the pins check cancelled: red" "1" "$(gate PINS=cancelled)"
check "the pins check skipped on a push, still no plan to excuse it: red" "1" "$(gate EVENT=push DCO=skipped PINS=skipped)"
check "the structure check skipped on a push, still no plan to excuse it: red" "1" "$(gate EVENT=push DCO=skipped STRUCTURE=skipped)"
check "a suite that was cancelled: red" "1" "$(gate AUDIT=cancelled)"

check "DCO failed on a pull request: red" "1" "$(gate DCO=failure)"
check "DCO skipped on a pull request: red" "1" "$(gate DCO=skipped)"
check "DCO skipped on a push, where it does not run: green" "0" "$(gate EVENT=push DCO=skipped)"

# The table is what a person reads when the gate is red: every job with its
# result and plan, the plan of a skipped suite visible.
gate RUST=skipped PLAN_RUST=false > /dev/null
grep -q '^rust  *skipped  *false$' "$WORK/out" && r=found || r=missing
check "the gate prints the rust row with its result and plan" "found" "$r"
grep -q '^audit  *success  *-$' "$WORK/out" && r=found || r=missing
check "the gate prints the audit row" "found" "$r"

# The name of the gate depends on the base, and `==` in an expression ignores case, so
# the gate itself checks the base exactly before it approves.
check "a pull request into main passes" "0" "$(gate BASE_REF=main)"
check "a pull request whose base is Develop, which an expression would read as develop, fails" "1" "$(gate BASE_REF=Develop)"
grep -q "neither develop nor main" "$WORK/out" && r=found || r=missing
check "and says why" "found" "$r"
check "a pull request whose base is Main fails" "1" "$(gate BASE_REF=Main)"
check "a pull request stacked on the branch of another one fails" "1" "$(gate BASE_REF=topic/other)"
check "an empty base on a pull request fails" "1" "$(gate BASE_REF=)"
check "a push has no base and passes" "0" "$(gate EVENT=push DCO=skipped BASE_REF=)"

# --- the job of the Rust workflow that gives its caller the one result ---------------------------
# The caller of reusable-rust-ci.yml sees one result, and a skipped job counts as passed, so a
# condition made false by mistake (`&& false` on the coverage job) would leave the caller green
# with no test run at all. `outcome` always runs and fails unless the jobs the inputs select
# ran and succeeded. Its text is taken from the workflow and run with the results every
# combination can give, asserting the verdict.
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
