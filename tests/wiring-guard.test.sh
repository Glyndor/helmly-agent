#!/usr/bin/env bash
#
# Tests for the guard of the base (wiring-guard.yml): the wiring validator that the base
# holds runs on the `.github` of a pull request, brought in as files, and the pull request
# cannot change what judges it.
#
# The two steps of the workflow are taken out of it and run in a checkout of a stand-in
# base, against a stand-in origin that serves `refs/pull/<n>/merge`. A change that weakens
# a workflow must stay red whatever else it ships: a validator of its own, relaxed tables,
# planted modules, links, attributes. Then the workflow is broken in a copy, one way at a
# time, to see that the contract that pins it notices.

# shellcheck disable=SC2016,SC1091,SC2154 # the text sabotaged below is literal workflow text; the helpers are sourced from lib/ (linted there as its own file) and set `fail`
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

source "$(dirname "${BASH_SOURCE[0]}")/lib/wiring.sh"

G=(git -c user.email=t@example.invalid -c user.name=t -c commit.gpgsign=false)
W=.github/workflows

python3 -I - "$ROOT/$W/wiring-guard.yml" "$WORK/fetch.sh" "$WORK/validate.sh" << 'PY'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["wiring-guard"]["steps"]
open(sys.argv[2], "w").write(steps[1]["run"])
open(sys.argv[3], "w").write(steps[2]["run"])
PY

# The stand-in origin: the real .github on main, and pull request refs made over it.
ORIGIN="$WORK/origin"
mkdir -p "$ORIGIN"
git -C "$ORIGIN" init -q -b main
cp -r "$ROOT/.github" "$ORIGIN/.github"
mkdir -p "$ORIGIN/tests"
echo "the readme" > "$ORIGIN/README.md"
git -C "$ORIGIN" add -A
"${G[@]}" -C "$ORIGIN" commit -q -m base

# The stand-in base checkout: the validator of the base (real) next to a clone of the origin.
BASE="$WORK/base"
mkdir -p "$BASE/tests"
cp -r "$ROOT/tests/lib" "$BASE/tests/lib"
rm -rf "$BASE/tests/lib/__pycache__"
git -C "$BASE" init -q -b main
git -C "$BASE" remote add origin "$ORIGIN"

# pr <number> <shell commands run inside a checkout of the origin>: a pull request ref
pr() {
	local number="$1"
	shift
	git -C "$ORIGIN" checkout -q -B "pr$number" main
	(cd "$ORIGIN" && eval "$*")
	git -c advice.addEmbeddedRepo=false -C "$ORIGIN" add -A 2> /dev/null
	"${G[@]}" -C "$ORIGIN" commit -q --allow-empty -m "change $number"
	git -C "$ORIGIN" update-ref "refs/pull/$number/merge" HEAD
	git -C "$ORIGIN" checkout -q main 2> /dev/null
	rm -rf "$ORIGIN/.github/sub"
	git -C "$ORIGIN" clean -ffdxq
}
# guard <event> <number or commit>: exit code of the two steps, output in $WORK/out
guard() {
	local event="$1" what="$2" rc=0 temp="$WORK/temp$RANDOM"
	mkdir -p "$temp"
	rm -rf "$BASE/.git/refs/wiring-guard"
	(
		cd "$BASE"
		export RUNNER_TEMP="$temp" EVENT="$event" PR_NUMBER="" GROUP_SHA=""
		if [[ "$event" == merge_group ]]; then GROUP_SHA="$what"; else PR_NUMBER="$what"; fi
		bash "$WORK/fetch.sh" && CI_WIRING_TREE="$temp/change" bash "$WORK/validate.sh"
	) > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}
said() { if grep -qF -- "$1" "$WORK/out"; then echo said; else echo "silent: $(head -n 3 "$WORK/out" | tr '\n' ' ')"; fi; }

WEAKEN="python3 -I -c \"import re,pathlib; p=pathlib.Path('.github/workflows/ci.yml'); t=p.read_text(); n=t.replace('      - name: Every suite passed, or the plan said it had nothing to check', '      - continue-on-error: true\n        name: Every suite passed, or the plan said it had nothing to check',1); assert n!=t; p.write_text(n)\""

pr 1 ':'
check "a change that touches nothing passes" "0" "$(guard pull_request_target 1)"

pr 2 "$WEAKEN"
check "a change that adds continue-on-error to the gate is red" "0" "$([[ "$(guard pull_request_target 2)" != 0 ]] && echo 0 || echo 1)"
check "and the finding is the one the contract gives" "said" "$(said "sets continue-on-error")"

# The change ships a validator of its own that passes everything, and the weakened workflow.
pr 3 "$WEAKEN
mkdir -p tests/lib
printf 'import sys\nsys.exit(0)\n' > tests/lib/ci_wiring.py
printf 'def check_contract(findings):\n    return\n' > tests/lib/ci_wiring_contract.py"
check "a change that brings its own validator that passes everything is still red" "0" "$([[ "$(guard pull_request_target 3)" != 0 ]] && echo 0 || echo 1)"
check "and it is the base's validator that said so" "said" "$(said "sets continue-on-error")"

# The tables of the contract relaxed in the change: the weakened workflow now passes THAT copy.
cp "$ROOT/tests/lib/ci_wiring_contract.py" "$WORK/relaxed_contract.py"
python3 -I - "$WORK/relaxed_contract.py" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
n = s.replace('if "continue-on-error" in node:', "if False:")
assert n != s
open(p, "w").write(n)
PY
pr 4 "$WEAKEN
mkdir -p tests/lib
cp '$WORK/relaxed_contract.py' tests/lib/ci_wiring_contract.py"
check "a change whose contract tables were relaxed to let its own change through is still red" "0" "$([[ "$(guard pull_request_target 4)" != 0 ]] && echo 0 || echo 1)"
check "because the table of the base rules" "said" "$(said "sets continue-on-error")"
# The same change judged by its own copy of the contract, to show that the relaxed copy would have passed it.
rm -rf "$WORK/own" && mkdir -p "$WORK/own/tests" && cp -r "$ROOT/tests/lib" "$WORK/own/tests/lib" && cp "$WORK/relaxed_contract.py" "$WORK/own/tests/lib/ci_wiring_contract.py"
rc=0
(cd "$ORIGIN" && git checkout -q pr4 && CI_WIRING_TREE="$ORIGIN" python3 -I "$WORK/own/tests/lib/ci_wiring.py" > /dev/null 2>&1) || rc=$?
git -C "$ORIGIN" checkout -q main
check "(the relaxed copy of the contract does accept that change, which is why it is not read)" "0" "$rc"

# Modules planted next to the files that are read must not be imported.
pr 5 "for m in yaml sitecustomize usercustomize json; do printf 'import pathlib\npathlib.Path(\"$WORK/planted\").touch()\n' > .github/\$m.py; done
mkdir -p .github/scripts/ci && printf 'import pathlib\npathlib.Path(\"$WORK/planted\").touch()\n' > .github/scripts/ci/yaml.py"
rm -f "$WORK/planted"
check "a change that plants modules under .github is judged on its workflows alone" "0" "$(guard pull_request_target 5)"
[[ -e "$WORK/planted" ]] && r=ran || r=never-ran
check "and none of the planted modules ran" "never-ran" "$r"

# Links and submodules under .github are refused before anything is validated.
pr 6 'ln -s /etc/passwd .github/passwd'
check "a link under .github is refused" "0" "$([[ "$(guard pull_request_target 6)" != 0 ]] && echo 0 || echo 1)"
check "and the finding says it is not a regular file" "said" "$(said "is not a regular file")"
pr 7 'mkdir .github/sub && git -C .github/sub init -q && git -c user.email=t@example.invalid -c user.name=t -C .github/sub commit -q --allow-empty -m s' 
check "a submodule under .github is refused" "0" "$([[ "$(guard pull_request_target 7)" != 0 ]] && echo 0 || echo 1)"

# Attributes of the change must not hide a file from the copy that is read.
pr 8 "$WEAKEN
printf '.github/workflows/ci.yml export-ignore\n.github/** export-subst\n' > .gitattributes"
check "export-ignore and export-subst in the change do not hide the weakened workflow" "0" "$([[ "$(guard pull_request_target 8)" != 0 ]] && echo 0 || echo 1)"
check "the weakened workflow is found all the same" "said" "$(said "sets continue-on-error")"

# A file over the limit.
pr 9 'head -c 3000000 /dev/zero | tr "\0" "a" > .github/big.md'
check "a file over the size limit is refused" "0" "$([[ "$(guard pull_request_target 9)" != 0 ]] && echo 0 || echo 1)"

# The event and what it carries.
check "a number that is not a number is refused and nothing runs" "0" "$([[ "$(guard pull_request_target '7; touch '"$WORK"'/injected')" != 0 ]] && echo 0 || echo 1)"
[[ -e "$WORK/injected" ]] && r=ran || r=never-ran
check "(and what followed the number did not run)" "never-ran" "$r"
check "a pull request that has no merge ref is refused" "0" "$([[ "$(guard pull_request_target 99)" != 0 ]] && echo 0 || echo 1)"
check "an event the guard does not judge is refused" "0" "$([[ "$(guard push 1)" != 0 ]] && echo 0 || echo 1)"
sha2="$(git -C "$ORIGIN" rev-parse refs/pull/2/merge)"
check "a merge group commit with the weakened workflow is red" "0" "$([[ "$(guard merge_group "$sha2")" != 0 ]] && echo 0 || echo 1)"
sha1="$(git -C "$ORIGIN" rev-parse refs/pull/1/merge)"
check "a merge group commit that changes nothing passes" "0" "$(guard merge_group "$sha1")"
check "a merge group value that is not a commit is refused" "0" "$([[ "$(guard merge_group main)" != 0 ]] && echo 0 || echo 1)"

# --- the contract pins the workflow itself ----------------------------------------------------
case_in() { # case_in <description> <expected> <old> <new>
	fresh_copy
	python3 - "$WORK/tree/$W/wiring-guard.yml" "$3" "$4" << 'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if old not in text:
	sys.exit("sabotage target not found: " + old)
open(path, "w").write(text.replace(old, new, 1))
PY
	caught "$1" "$2"
}
fresh_copy
check "the contract holds on the real guard" "none" "$(finding)"
case_in "a guard that also runs on pull_request is caught" "must run on pull_request_target and merge_group and on nothing else" \
	'  merge_group:' '  merge_group:
  pull_request:'
case_in "a guard open to every base is caught" "must be limited to the bases develop and main" \
	'    branches: [develop, main]' '    branches: ["**"]'
case_in "a guard with a write token is caught" "the workflow must hold contents: read and nothing more" \
	'permissions:
  contents: read

# A security' 'permissions:
  contents: write

# A security'
case_in "a job with a write token is caught" "the job holds contents: read" \
	'    permissions:
      contents: read
    steps:' '    permissions:
      contents: write
    steps:'
case_in "a checkout of the head of the change is caught" "the first step must check out the base only" \
	'ref: ${{ github.event.merge_group.base_sha || github.sha }}' 'ref: ${{ github.event.pull_request.head.sha }}'
case_in "a checkout that keeps the credentials is caught" "the first step must check out the base only" \
	'persist-credentials: false' 'persist-credentials: true'
case_in "a validator run without -I is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'run: python3 -I tests/lib/ci_wiring.py' 'run: python3 tests/lib/ci_wiring.py'
case_in "a validator of the change is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'run: python3 -I tests/lib/ci_wiring.py' 'run: python3 -I "$RUNNER_TEMP/change/tests/lib/ci_wiring.py"'
case_in "a tree that is not the one the extractor wrote is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'CI_WIRING_TREE: ${{ runner.temp }}/change' 'CI_WIRING_TREE: ${{ github.workspace }}'
case_in "an extraction with git archive is caught" "the second step must have exactly one line: python3 -I tests/lib/ci_wiring_extract.py" \
	'python3 -I tests/lib/ci_wiring_extract.py refs/wiring-guard/change "$RUNNER_TEMP/change"' 'git archive refs/wiring-guard/change | tar -x -C "$RUNNER_TEMP/change"'
case_in "a number taken from the title is caught" "the second step must take the event, the number and the commit of the group from exactly their own expressions" \
	'PR_NUMBER: ${{ github.event.pull_request.number }}' 'PR_NUMBER: ${{ github.event.pull_request.title }}'
case_in "a step that runs a script of the change is caught" "the job has three steps" \
	'      - name: Validate it with the validator of the base' '      - run: bash "$RUNNER_TEMP/change/.github/scripts/x.sh"

      - name: Validate it with the validator of the base'
case_in "a secret named in the guard is caught" "no secret may be named here" \
	'          PR_NUMBER: ${{ github.event.pull_request.number }}' '          PR_NUMBER: ${{ github.event.pull_request.number }}
          TOKEN: ${{ secrets.X }}'
case_in "a guard that a newer run cancels is caught" "a security result is not cancelled by a newer run" \
	'  cancel-in-progress: false' '  cancel-in-progress: true'
case_in "a number that is no longer checked is caught" "the second step must have exactly one line: [[ \"\$PR_NUMBER\"" \
	'              [[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "::error::the number of the pull request is not a number"; exit 1; }
' ''

exit "$fail"
