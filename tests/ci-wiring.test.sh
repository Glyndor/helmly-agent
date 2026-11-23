#!/usr/bin/env bash
#
# Tests that the workflows still say what the CI map and the rulesets rely on
# (tests/lib/ci_wiring.py holds the checks and lists what each one protects).
#
# Two parts: the real tree must pass, and each rule must fail when its subject
# is broken. The second part is what makes the first one worth reading: a check
# that has never been seen to fail may be checking nothing.

# shellcheck disable=SC2016 # the text sabotaged below is literal workflow text, `${{ ... }}` included
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
sed -i 's/^    name: ci-gate$/    name: gate/' "$WORK/tree/.github/workflows/ci.yml"
check "renaming a job a ruleset requires is caught" \
	"required check on develop is emitted by no workflow: 'ci-gate'" "$(finding)"

fresh_copy
sed -i "s/^    if: \${{ always() }}$/    if: \${{ success() }}/" "$WORK/tree/.github/workflows/ci.yml"
check "a ci-gate that does not run always is caught" \
	"ci.yml: ci-gate must run \`if: \${{ always() }}\`, or a skipped gate reports success" "$(finding)"

fresh_copy
sed -i 's/^    needs: \[decide, dco, workflow-lint, shell, rust, audit\]$/    needs: [decide, dco, workflow-lint, shell, rust]/' "$WORK/tree/.github/workflows/ci.yml"
check "a job that ci-gate no longer judges is caught" "ci.yml: ci-gate does not need 'audit', so its result is not judged" "$(finding)"

fresh_copy
sed -i 's/needs\.decide\.outputs\.workflows/needs.decide.outputs.nothing/' "$WORK/tree/.github/workflows/ci.yml"
out="$(finding)"
check "a suite the workflow stops reading is caught" "suite 'workflows' of the map is never read as needs.decide.outputs.workflows in ci.yml" "$out"

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
check "a ci.yml that no longer runs on pull requests loses its checks" "required check on develop is emitted by no workflow: 'ci-gate'" "$out"

# --- the exact shape: each sabotage below passes a check that only counts names -------
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

fresh_copy
sabotage ci.yml 'run: ${{ needs.decide.outputs.rust }}' 'run: ${{ needs.decide.outputs.shell }}'
caught "the shell verdict handed to the Rust suite is caught" "job 'rust' must pass \`run: \${{ needs.decide.outputs.rust }}\`"

fresh_copy
sabotage ci.yml 'run: ${{ needs.decide.outputs.shell }}' 'run: ${{ needs.decide.outputs.rust }}'
caught "the Rust verdict handed to the shell suite is caught" "job 'shell' must pass \`run: \${{ needs.decide.outputs.shell }}\`"

fresh_copy
sabotage ci.yml 'run: ${{ needs.decide.outputs.rust }}' "run: 'false'"
caught "a literal false handed to the Rust suite is caught" "job 'rust' must pass"

fresh_copy
sabotage ci.yml 'PLAN_RUST: ${{ needs.decide.outputs.rust }}' 'PLAN_RUST: ${{ needs.decide.outputs.shell }}'
caught "the plans of rust and shell crossed in ci-gate are caught" "the env of ci-gate is not the exact pairing"

fresh_copy
sabotage ci.yml 'RUST: ${{ needs.rust.result }}' 'RUST: ${{ needs.audit.result }}'
caught "the Rust result read from the audit job is caught" "the env of ci-gate is not the exact pairing"

fresh_copy
sabotage ci.yml '2>/dev/null; then
              all "the base commit has no decision script yet"' '2>/dev/null; then
              all "the base commit has no decision script yet"'
sabotage ci.yml 'if ! git show "$BASE_SHA:.github/scripts/ci/decide.py" > "$tmp/decide.py" 2>/dev/null; then' 'if ! cp .github/scripts/ci/decide.py "$tmp/decide.py"; then'
caught "reading decide.py from the checkout instead of the base is caught" "line about the script or the map that is not one of the known ones"

fresh_copy
sabotage ci.yml 'if ! git show "$BASE_SHA:.github/ci-map.json" > "$tmp/ci-map.json" 2>/dev/null; then' 'if ! cp .github/ci-map.json "$tmp/ci-map.json"; then'
caught "reading the map from the checkout instead of the base is caught" "line about the script or the map that is not one of the known ones"

fresh_copy
sabotage ci.yml '            from="$BASE_SHA"; to="$HEAD_SHA"; range="$from...$to"
' '            from="$BASE_SHA"; to="$HEAD_SHA"; range="$from...$to"
            cp .github/scripts/ci/decide.py .github/ci-map.json "$tmp/"
'
caught "a second copy from the checkout inside the pull request branch is caught" "must contain exactly once: cp .github/scripts/ci/decide.py"

fresh_copy
sabotage ci.yml '      run: ${{ needs.decide.outputs.workflows }}' '      run: ${{ needs.decide.outputs.workflows }}
      tooling-isolation: false'
caught "tooling-isolation: false passed to the workflow lint is caught" "job 'workflow-lint' passes ['tooling-isolation']"

fresh_copy
sabotage ci.yml '      test-command: ./tests/run.sh' '      test-command: ./tests/run.sh
      severity: error'
caught "severity: error passed to the shell suite is caught" "job 'shell' passes ['severity']"

fresh_copy
sabotage ci.yml '      apt-packages: python3-cryptography' '      apt-packages: python3-cryptography
      check-exec-bit: false'
caught "check-exec-bit: false passed to the shell suite is caught" "job 'shell' passes ['check-exec-bit']"

fresh_copy
sabotage ci.yml 'test-command: ./tests/run.sh' 'test-command: true'
caught "a test-command that runs nothing is caught" "job 'shell' must pass test-command: './tests/run.sh'"

fresh_copy
sabotage ci.yml 'coverage-threshold: 45' 'coverage-threshold: 40'
caught "lowering the coverage threshold is caught" "the ratchet never goes down"

fresh_copy
python3 - "$WORK/tree/.github/workflows/ci.yml" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read() + "\n  halt:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"
open(p, "w").write(s)
PY
caught "an extra job named halt that ci-gate does not judge is caught" "ci-gate does not need 'halt'"

fresh_copy
sabotage ci.yml '  audit:
    runs-on: ubuntu-latest' '  audit:
    if: ${{ false }}
    runs-on: ubuntu-latest'
caught "a condition on the audit job is caught" "the audit job has a condition or a dependency"

fresh_copy
sabotage ci.yml "printf '%s=true\n' rust shell workflows" "printf '%s=true\n' rust shell"
caught "a fallback that forgets a suite is caught" "the fallback of the plan step answers for"

exit "$fail"
