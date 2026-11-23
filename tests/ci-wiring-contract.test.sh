#!/usr/bin/env bash
#
# Tests that the execution contract of the CI is pinned by equality
# (tests/lib/ci_wiring_contract.py): every property that changes how a suite runs, and a
# property the contract does not know is a finding. Each case breaks one in a copy of the
# workflows and asserts the finding that comes back.

# shellcheck disable=SC2016,SC1091,SC2154 # the text sabotaged below is literal workflow text, `${{ ... }}` included; the helpers are sourced from lib/ (linted there as its own file) and set `fail`
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

source "$(dirname "${BASH_SOURCE[0]}")/lib/wiring.sh"

# case_in <file> <description> <expected> <old> <new>: break one workflow or action file
case_in() {
	fresh_copy
	python3 - "$WORK/tree/$1" "$4" "$5" << 'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if old not in text:
	sys.exit("sabotage target not found: " + old)
open(path, "w").write(text.replace(old, new, 1))
PY
	caught "$2" "$3"
}
W=.github/workflows
A=.github/actions/cargo-audit/action.yml

fresh_copy
check "the contract holds on the real tree" "none" "$(finding)"

# --- continue-on-error -------------------------------------------------------------------
case_in $W/ci.yml "continue-on-error on the step of the gate is caught" "sets continue-on-error" \
	'      - name: Every suite passed, or the plan said it had nothing to check' '      - continue-on-error: true
        name: Every suite passed, or the plan said it had nothing to check'
case_in $W/ci.yml "continue-on-error on a suite job is caught" "sets continue-on-error" \
	'  workflow-lint:
    needs: [decide]' '  workflow-lint:
    continue-on-error: true
    needs: [decide]'
case_in $W/reusable-rust-ci.yml "continue-on-error on the coverage job is caught" "sets continue-on-error" \
	'  coverage:
    name: Coverage' '  coverage:
    continue-on-error: true
    name: Coverage'
case_in $A "continue-on-error on a step of the audit action is caught" "sets continue-on-error" \
	'    - name: cargo deny' '    - continue-on-error: true
      name: cargo deny'

# --- defaults and shell ------------------------------------------------------------------
case_in $W/ci.yml "a shell that exits at once, set as a default of a job, is caught" "sets defaults that are not the pinned ones" \
	'  audit:
    runs-on: ubuntu-latest' "  audit:
    defaults:
      run:
        shell: \"bash -c 'exit 0' {0}\"
    runs-on: ubuntu-latest"
case_in $W/reusable-shell-ci.yml "a shell default added to the shell suite is caught" "sets defaults that are not the pinned ones" \
	'      run:
        working-directory: ${{ inputs.working-directory }}
    env:
      SEVERITY' "      run:
        shell: \"bash -c 'exit 0' {0}\"
        working-directory: \${{ inputs.working-directory }}
    env:
      SEVERITY"
case_in $W/reusable-rust-ci.yml "a shell on a step is caught" "sets a shell on a step" \
	'      - name: rustfmt' "      - shell: \"bash -c 'exit 0' {0}\"
        name: rustfmt"
case_in $A "a shell other than bash on a step of the audit action is caught" "must run with shell: bash exactly" \
	'      shell: bash
      run: cargo deny check' "      shell: \"bash -c 'exit 0' {0}\"
      run: cargo deny check"

# --- the plan reads the base, not the pull request -------------------------------------------
case_in $W/ci.yml "BASE_SHA tied to the head of the pull request is caught" "BASE_SHA is the base of the pull request, not its head" \
	'BASE_SHA: ${{ github.event.pull_request.base.sha }}' 'BASE_SHA: ${{ github.event.pull_request.head.sha }}'
case_in $W/ci.yml "HEAD_SHA tied to the base is caught" "the plan step must take the base and head commits" \
	'HEAD_SHA: ${{ github.event.pull_request.head.sha }}' 'HEAD_SHA: ${{ github.event.pull_request.base.sha }}'
case_in $W/ci.yml "an output of the plan tied to another suite is caught" "the outputs of decide are not exactly the verdict of each suite" \
	'      rust: ${{ steps.decide.outputs.rust }}' '      rust: ${{ steps.decide.outputs.shell }}'
case_in $W/ci.yml "a condition added to a step is caught" "has a step with a condition" \
	'      - name: Read the paths this change touched against the map' "      - if: \${{ true }}
        name: Read the paths this change touched against the map"
case_in $W/ci.yml "a job condition that is not the pinned one is caught" "the condition of job 'shell' is not the pinned one" \
	'  shell:
    needs: [decide]
    if: ${{ !cancelled() }}' '  shell:
    needs: [decide]
    if: ${{ !cancelled() && false }}'

# --- the audit action --------------------------------------------------------------------
case_in $A "an '&& false' on the audit step is caught" "step 'cargo audit' must have exactly the pinned condition and command" \
	"      if: \${{ inputs.lockfile == '' }}
      # \`--deny" "      if: \${{ inputs.lockfile == '' && false }}
      # \`--deny"
case_in $A "an '&& false' on the deny step is caught" "step 'cargo deny' must have exactly the pinned condition and command" \
	"    - name: cargo deny
      if: \${{ inputs.lockfile == '' }}" "    - name: cargo deny
      if: \${{ inputs.lockfile == '' && false }}"
case_in $A "a deny command that ignores its result is caught" "step 'cargo deny' must have exactly the pinned condition and command" \
	'run: cargo deny check' 'run: cargo deny check || true'
case_in $A "an install step made conditional is caught" "must always run" \
	'    - name: Install cargo-audit and cargo-deny' "    - name: Install cargo-audit and cargo-deny
      if: \${{ false }}"
case_in $A "an extra step in the audit action is caught" "is not part of the contract" \
	'    - name: cargo deny' '    - name: Something else
      shell: bash
      run: echo hello

    - name: cargo deny'

# --- the Rust reusable workflow --------------------------------------------------------------
case_in $W/reusable-rust-ci.yml "an '&& false' on the coverage job is caught" "the condition of job 'coverage' is not the pinned one" \
	"    if: \${{ inputs.run != 'false' && inputs.coverage-threshold > 0 }}" "    if: \${{ inputs.run != 'false' && inputs.coverage-threshold > 0 && false }}"
case_in $W/reusable-rust-ci.yml "an '&& false' on the test job is caught" "the condition of job 'test' is not the pinned one" \
	"    if: \${{ inputs.run != 'false' && inputs.coverage-threshold == 0 }}" "    if: \${{ inputs.run != 'false' && inputs.coverage-threshold == 0 && false }}"
case_in $W/reusable-rust-ci.yml "an outcome that stops running always is caught" "the condition of job 'outcome' is not the pinned one" \
	'    name: Outcome
    needs: [lint, test, coverage]
    if: ${{ always() }}' '    name: Outcome
    needs: [lint, test, coverage]
    if: ${{ success() }}'
case_in $W/reusable-rust-ci.yml "an outcome that reads another result is caught" "outcome must wait for lint, test and coverage and read exactly" \
	'      COVERAGE: ${{ needs.coverage.result }}' '      COVERAGE: ${{ needs.lint.result }}'
case_in $W/reusable-rust-ci.yml "an outcome that no longer requires coverage is caught" "outcome no longer requires" \
	'want coverage "$COVERAGE" success' 'want coverage "$COVERAGE" skipped'

# --- security results are not cancelled -----------------------------------------------------------
case_in $W/ci.yml "a gate workflow that cancels the run in progress is caught" "must not sit in a concurrency group that cancels the run in progress" \
	'  cancel-in-progress: false' "  cancel-in-progress: \${{ github.event_name == 'pull_request' }}"
case_in $W/codeql.yml "an analysis that a newer run cancels is caught" "must not sit in a concurrency group that cancels the run in progress" \
	'  cancel-in-progress: false' "  cancel-in-progress: \${{ github.event_name == 'pull_request' }}"
case_in $W/audit.yml "a scheduled audit that stops at the first failing branch is caught" "must use fail-fast: false" \
	'      fail-fast: false' '      fail-fast: true'

# --- the enumerators and the index of names ----------------------------------------------------------
fresh_copy
cat > "$WORK/tree/$W/extra.yaml" << 'YAML'
name: extra
on: [pull_request]
permissions: write-all
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML
caught "the permissions of a workflow with the .yaml suffix are checked" "extra.yaml: the token can write to Actions at workflow level"

case_in $W/codeql.yml "a job named like a required check in another case is caught" "produced by more than one workflow or event" \
	'jobs:
  analyze:' 'jobs:
  impostor:
    name: CI-Gate
    runs-on: ubuntu-latest
    steps:
      - run: echo hi

  analyze:'

exit "$fail"
