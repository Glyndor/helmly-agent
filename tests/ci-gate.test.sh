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
	env EVENT=pull_request DECIDE=success DCO=success WORKFLOW_LINT=success SHELL_SUITE=success RUST=success AUDIT=success \
		PLAN_WORKFLOWS=true PLAN_SHELL=true PLAN_RUST=true PLAN_AUDIT=true "$@" bash "$WORK/gate.sh" > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}

check "every suite succeeded: green" "0" "$(gate)"
check "a suite skipped because the plan said false: green" "0" "$(gate RUST=skipped PLAN_RUST=false)"
check "every suite skipped by the plan: green" "0" "$(gate RUST=skipped PLAN_RUST=false SHELL_SUITE=skipped PLAN_SHELL=false AUDIT=skipped PLAN_AUDIT=false WORKFLOW_LINT=skipped PLAN_WORKFLOWS=false)"

check "the plan failed: red" "1" "$(gate DECIDE=failure PLAN_RUST= PLAN_SHELL= PLAN_AUDIT= PLAN_WORKFLOWS=)"
grep -q "the plan job ended 'failure'" "$WORK/out" && r=found || r=missing
check "the red says the plan failed" "found" "$r"
check "the plan failed but every suite is green: still red" "1" "$(gate DECIDE=failure)"
check "the plan was cancelled: red" "1" "$(gate DECIDE=cancelled)"
check "the plan was skipped: red" "1" "$(gate DECIDE=skipped)"

check "a suite skipped while the plan said true: red" "1" "$(gate RUST=skipped)"
grep -q "rust was skipped but the plan did not say it could be (plan: 'true')" "$WORK/out" && r=found || r=missing
check "the red names the suite and the plan" "found" "$r"
check "a suite skipped with an empty plan: red" "1" "$(gate AUDIT=skipped PLAN_AUDIT=)"
check "a suite skipped by a failed gate before it, plan true: red" "1" "$(gate SHELL_SUITE=skipped WORKFLOW_LINT=failure)"
check "a suite that failed: red" "1" "$(gate SHELL_SUITE=failure)"
check "a suite that failed although the plan said false: red" "1" "$(gate RUST=failure PLAN_RUST=false)"
check "a suite that was cancelled: red" "1" "$(gate AUDIT=cancelled)"

check "DCO failed on a pull request: red" "1" "$(gate DCO=failure)"
check "DCO skipped on a pull request: red" "1" "$(gate DCO=skipped)"
check "DCO skipped on a push, where it does not run: green" "0" "$(gate EVENT=push DCO=skipped)"

exit "$fail"
