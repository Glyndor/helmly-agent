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

# pr <number> <shell commands run inside a checkout of the origin>: the head of a pull request
# and its merge ref, as GitHub makes it: a commit of the head's tree whose parents are the base and the head.
pr() {
	local number="$1" head merge
	shift
	git -C "$ORIGIN" checkout -q -B "pr$number" main
	(cd "$ORIGIN" && eval "$*")
	git -c advice.addEmbeddedRepo=false -C "$ORIGIN" add -A 2> /dev/null
	"${G[@]}" -C "$ORIGIN" commit -q --allow-empty -m "change $number"
	head="$(git -C "$ORIGIN" rev-parse HEAD)"
	merge="$("${G[@]}" -C "$ORIGIN" commit-tree "$head^{tree}" -p main -p "$head" -m "merge $number")"
	git -C "$ORIGIN" update-ref "refs/pull/$number/merge" "$merge"
	echo "$head" > "$WORK/head$number"
	git -C "$ORIGIN" checkout -q main 2> /dev/null
	rm -rf "$ORIGIN/.github/sub"
	git -C "$ORIGIN" clean -ffdxq
}
# guard <event> <number> [head sha]: exit code of the two steps, output in $WORK/out
guard() {
	local event="$1" number="$2" head="${3:-}" rc=0 temp="$WORK/temp$RANDOM"
	if [[ "$head" == EMPTY ]]; then head=""; elif [[ -z "$head" ]]; then head="$(cat "$WORK/head$number" 2> /dev/null || echo 0123456789012345678901234567890123456789)"; fi
	mkdir -p "$temp"
	rm -rf "$BASE/.git/refs/wiring-guard"
	(
		cd "$BASE"
		export RUNNER_TEMP="$temp" EVENT="$event" PR_NUMBER="$number" HEAD_SHA="$head"
		bash "$WORK/fetch.sh" && CI_WIRING_TREE="$temp/change" bash "$WORK/validate.sh"
	) > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}
red() { [[ "$1" != 0 ]] && echo red || echo "green($1)"; } # red <exit code>
said() { if grep -qF -- "$1" "$WORK/out"; then echo said; else echo "silent: $(head -n 3 "$WORK/out" | tr '\n' ' ')"; fi; }

WEAKEN="python3 -I -c \"import re,pathlib; p=pathlib.Path('.github/workflows/ci.yml'); t=p.read_text(); n=t.replace('      - name: Every suite passed, or the plan said it had nothing to check', '      - continue-on-error: true\n        name: Every suite passed, or the plan said it had nothing to check',1); assert n!=t; p.write_text(n)\""

pr 1 ':'
check "a change that touches nothing passes" "0" "$(guard pull_request_target 1)"

pr 2 "$WEAKEN"
check "a change that adds continue-on-error to the gate is red" "red" "$(red "$(guard pull_request_target 2)")"
check "and the finding is the one the contract gives" "said" "$(said "sets continue-on-error")"

# The change ships a validator of its own that passes everything, and the weakened workflow.
pr 3 "$WEAKEN
mkdir -p tests/lib
printf 'import sys\nsys.exit(0)\n' > tests/lib/ci_wiring.py
printf 'def check_contract(findings):\n    return\n' > tests/lib/ci_wiring_contract.py"
check "a change that brings its own validator that passes everything is still red" "red" "$(red "$(guard pull_request_target 3)")"
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
check "a change whose contract tables were relaxed to let its own change through is still red" "red" "$(red "$(guard pull_request_target 4)")"
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
check "a link under .github is refused" "red" "$(red "$(guard pull_request_target 6)")"
check "and the finding says it is not a regular file" "said" "$(said "is not a regular file")"
pr 7 'mkdir .github/sub && git -C .github/sub init -q && git -c user.email=t@example.invalid -c user.name=t -C .github/sub commit -q --allow-empty -m s'
check "a submodule under .github is refused" "red" "$(red "$(guard pull_request_target 7)")"

# Attributes of the change must not hide a file from the copy that is read.
pr 8 "$WEAKEN
printf '.github/workflows/ci.yml export-ignore\n.github/** export-subst\n' > .gitattributes"
check "export-ignore and export-subst in the change do not hide the weakened workflow" "red" "$(red "$(guard pull_request_target 8)")"
check "the weakened workflow is found all the same" "said" "$(said "sets continue-on-error")"

pr 9 'head -c 3000000 /dev/zero | tr "\0" "a" > .github/big.md'
check "a file over the size limit is refused" "red" "$(red "$(guard pull_request_target 9)")"

# A name that is not UTF-8 would collide with another once its bytes were replaced.
pr 10 "printf x > \$'.github/a\\xffb' && printf y > \$'.github/a\\xfeb'"
check "two names that are not UTF-8, which a lossy decoding would make one, are refused" "red" "$(red "$(guard pull_request_target 10)")"
check "and the finding says the name is not valid UTF-8" "said" "$(said "is not valid UTF-8")"

# An entry written twice: a tree object made by hand with the same name twice.
git -C "$ORIGIN" checkout -q -B pr11 main
blob="$(printf 'one' | git -C "$ORIGIN" hash-object -w --stdin)"
blob2="$(printf 'two' | git -C "$ORIGIN" hash-object -w --stdin)"
inner="$(printf '100644 dup.md\0%b100644 dup.md\0%b' "$(printf '%s' "$blob" | sed 's/../\\x&/g')" "$(printf '%s' "$blob2" | sed 's/../\\x&/g')" | git -C "$ORIGIN" hash-object -w -t tree --literally --stdin)"
outer="$(printf '40000 .github\0%b' "$(printf '%s' "$inner" | sed 's/../\\x&/g')" | git -C "$ORIGIN" hash-object -w -t tree --literally --stdin)"
dupcommit="$("${G[@]}" -C "$ORIGIN" commit-tree "$outer" -p main -m dup)"
dupmerge="$("${G[@]}" -C "$ORIGIN" commit-tree "$outer" -p main -p "$dupcommit" -m "merge 11")"
git -C "$ORIGIN" update-ref refs/pull/11/merge "$dupmerge"
echo "$dupcommit" > "$WORK/head11"
git -C "$ORIGIN" checkout -q main 2> /dev/null
check "an entry that appears twice in the tree is refused, not the last one kept" "red" "$(red "$(guard pull_request_target 11)")"
check "and the finding says it appears twice" "said" "$(said "appears twice")"

# --- the merge ref has to be the one of the head of the event --------------------------------------
check "a merge ref that is behind the head: the head of the event is another commit, so it is refused" "red" "$(red "$(guard pull_request_target 1 "$(cat "$WORK/head2")")")"
check "and the finding says the merge ref holds another head" "said" "$(said "the merge ref holds")"
git -C "$ORIGIN" update-ref refs/pull/12/merge "$(git -C "$ORIGIN" rev-parse refs/pull/2/merge)"
check "a merge ref that GitHub has not remade yet (it still holds an older change) is refused" "red" "$(red "$(guard pull_request_target 12 "$(cat "$WORK/head1")")")"
git -C "$ORIGIN" update-ref refs/pull/13/merge "$(git -C "$ORIGIN" rev-parse main)"
check "a merge ref that is not a merge, with one parent, is refused" "red" "$(red "$(guard pull_request_target 13 "$(cat "$WORK/head1")")")"
check "and the finding says it holds no head" "said" "$(said "holds no head")"
check "a head of the event that is not a commit is refused" "red" "$(red "$(guard pull_request_target 1 not-a-commit)")"
check "an empty head is refused" "red" "$(red "$(guard pull_request_target 1 EMPTY)")"
check "a head with upper case digits is refused" "red" "$(red "$(guard pull_request_target 1 "$(tr 'a-f' 'A-F' < "$WORK/head1")")")"

# The event and what it carries.
check "a number that is not a number is refused and nothing runs" "red" "$(red "$(guard pull_request_target '7; touch '"$WORK"'/injected')")"
[[ -e "$WORK/injected" ]] && r=ran || r=never-ran
check "(and what followed the number did not run)" "never-ran" "$r"
check "a pull request that has no merge ref is refused" "red" "$(red "$(guard pull_request_target 99)")"
check "an event the guard does not judge is refused" "red" "$(red "$(guard push 1)")"
check "so is a merge group, which this repository has none of" "red" "$(red "$(guard merge_group 1)")"

# --- the contract pins the workflow itself ----------------------------------------------------
case_in() { # case_in <file> <description> <expected> <old> <new>
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
GW=$W/wiring-guard.yml
fresh_copy
check "the contract holds on the real guard" "none" "$(finding)"
fresh_copy
rm "$WORK/tree/$GW"
caught "a guard that is deleted is a finding, not a pass" "wiring-guard.yml is missing"
case_in $GW "a guard that also runs in a merge queue is caught" "the \`on\` block must be exactly pull_request_target" \
	'    types: [opened, synchronize, reopened]' '    types: [opened, synchronize, reopened]
  merge_group:'
case_in $GW "a guard that also runs on edited is caught" "the \`on\` block must be exactly pull_request_target" \
	'types: [opened, synchronize, reopened]' 'types: [opened, synchronize, reopened, edited]'
case_in $GW "a guard open to every base is caught" "the \`on\` block must be exactly pull_request_target" \
	'    branches: [develop, main]' '    branches: ["**"]'
case_in $GW "a guard with a write token is caught" "the workflow must hold contents: read and nothing more" \
	'permissions:
  contents: read

# A security' 'permissions:
  contents: write

# A security'
case_in $GW "a job with a write token is caught" "the job holds contents: read" \
	'    permissions:
      contents: read
    steps:' '    permissions:
      contents: write
    steps:'
case_in $GW "a checkout of the head of the change is caught" "the first step must check out the base only" \
	'        with:
          persist-credentials: false' '        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false'
case_in $GW "a checkout that keeps the credentials is caught" "the first step must check out the base only" \
	'persist-credentials: false' 'persist-credentials: true'
case_in $GW "a runner other than the pinned one is caught" "the job runs on ubuntu-latest" \
	'    runs-on: ubuntu-latest' '    runs-on: self-hosted'
case_in $GW "a concurrency group of another kind is caught" "the concurrency must be the group of the pull request" \
	'  group: wiring-guard-${{ github.event.pull_request.number }}' '  group: wiring-guard'
case_in $GW "a guard that a newer run cancels is caught" "the concurrency must be the group of the pull request, and never cancel" \
	'  cancel-in-progress: false' '  cancel-in-progress: true'
case_in $GW "a validator run without -I is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'run: python3 -I tests/lib/ci_wiring.py' 'run: python3 tests/lib/ci_wiring.py'
case_in $GW "a validator of the change is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'run: python3 -I tests/lib/ci_wiring.py' 'run: python3 -I "$RUNNER_TEMP/change/tests/lib/ci_wiring.py"'
case_in $GW "a tree that is not the one the extractor wrote is caught" "the third step must run python3 -I tests/lib/ci_wiring.py of the base" \
	'CI_WIRING_TREE: ${{ runner.temp }}/change' 'CI_WIRING_TREE: ${{ github.workspace }}'
case_in $GW "an extraction with git archive is caught" "the second step must be, word for word" \
	'python3 -I tests/lib/ci_wiring_extract.py refs/wiring-guard/change "$RUNNER_TEMP/change"' 'git archive refs/wiring-guard/change | tar -x -C "$RUNNER_TEMP/change"'
case_in $GW "a number taken from the title is caught" "the second step must take the event, the number and the head from exactly their own expressions" \
	'PR_NUMBER: ${{ github.event.pull_request.number }}' 'PR_NUMBER: ${{ github.event.pull_request.title }}'
case_in $GW "a head taken from the base is caught" "the second step must take the event, the number and the head from exactly their own expressions" \
	'HEAD_SHA: ${{ github.event.pull_request.head.sha }}' 'HEAD_SHA: ${{ github.event.pull_request.base.sha }}'
case_in $GW "a head that is no longer passed is caught" "the second step must take the event, the number and the head from exactly their own expressions" \
	'          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
' ''
case_in $GW "a check of the head of the merge ref that is gone is caught" "the second step must be, word for word" \
	'          [ "$merged_head" = "$HEAD_SHA" ] || { echo "::error::the merge ref holds ${merged_head:-no head}, not the head of the pull request ($HEAD_SHA); run it again once GitHub has made it"; exit 1; }
' ''
case_in $GW "a check of the head that compares the first parent is caught" "the second step must be, word for word" \
	'sed -n 2p)' 'sed -n 1p)'
case_in $GW "an added line in the second step, with nothing a list of words would know, is caught" "the second step must be, word for word" \
	'          mkdir "$RUNNER_TEMP/change"' '          true
          mkdir "$RUNNER_TEMP/change"'
case_in $GW "a number that is no longer checked is caught" "the second step must be, word for word" \
	'          [[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "::error::the number of the pull request is not a number"; exit 1; }
' ''
case_in $GW "a step that runs a script of the change is caught" "the job has three steps" \
	'      - name: Validate it with the validator of the base' '      - run: bash "$RUNNER_TEMP/change/.github/scripts/x.sh"

      - name: Validate it with the validator of the base'
case_in $GW "an expression inside a run is caught" "no run may hold an expression" \
	'        run: python3 -I tests/lib/ci_wiring.py' '        run: python3 -I tests/lib/ci_wiring.py ${{ github.event.pull_request.title }}'
case_in $GW "a secret named in an expression is caught" "no secret may be named here" \
	'          PR_NUMBER: ${{ github.event.pull_request.number }}' '          PR_NUMBER: ${{ github.event.pull_request.number }}
          TOKEN: ${{ format("{0}", secrets.X) }}'
case_in $GW "a secret reached through an expression with no dot is caught" "no secret may be named here" \
	'          EVENT: ${{ github.event_name }}' "          EVENT: \${{ toJSON(secrets) }}"
case_in $GW "a name that does not follow the base is caught" "the check is named by the base" \
	'    name: ${{ github.event.pull_request.base.ref' '    name: wiring-guard${{ github.event.pull_request.base.ref'
# another workflow
case_in $W/codeql.yml "another workflow triggered by pull_request_target is caught" "a workflow triggered by pull_request_target runs with the token of the base" \
	'on:' 'on:
  pull_request_target:
    branches: [develop]'
case_in $W/codeql.yml "another workflow whose job carries the name of the guard is caught" "carries the name of the guard's check" \
	'jobs:
  analyze:' 'jobs:
  impostor:
    name: Wiring-Guard (main)
    runs-on: ubuntu-latest
    steps:
      - run: echo hi

  analyze:'

# --- a required name is produced once, by pull_request_target as by pull_request ----------------
req() { # req <json>: the required checks of the copy
	fresh_copy
	printf '%s\n' "$1" > "$WORK/tree/.github/required-checks.json"
}
req '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring-guard"], "main": ["ci-gate (main)", "develop-only", "wiring-guard (main)"]}'
check "a guard required on develop and on main, with a name for each base, holds" "none" "$(finding)"
req '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring-guard"], "main": ["ci-gate (main)", "develop-only", "wiring-guard"]}'
caught "the same guard name required on both bases is caught" "a check name is required on both develop and main"
req '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring-guard (main)"], "main": ["ci-gate (main)", "develop-only"]}'
caught "the name of the main guard required on develop is caught: it is not produced for that base" "required check on develop is emitted by no workflow: 'wiring-guard (main)'"
req '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring guard"], "main": ["ci-gate (main)", "develop-only"]}'
caught "a required name that no workflow produces is caught" "emitted by no workflow: 'wiring guard'"
fresh_copy
printf '%s\n' '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring-guard"], "main": ["ci-gate (main)", "develop-only"]}' > "$WORK/tree/.github/required-checks.json"
python3 - "$WORK/tree/$W/ci.yml" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
n = s.replace("  decide:\n", "  wiring-guard:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n\n  decide:\n", 1)
assert n != s
open(p, "w").write(n)
PY
caught "a second producer of a required guard name, on the pull_request event, is caught" "required check 'wiring-guard' on develop is produced by more than one workflow or event"
fresh_copy
printf '%s\n' '{"develop": ["ci-gate", "dco / Signed-off-by present on every commit", "wiring-guard"], "main": ["ci-gate (main)", "develop-only"]}' > "$WORK/tree/.github/required-checks.json"
rm "$WORK/tree/$GW"
caught "a required guard name with no guard is caught as produced by nobody" "required check on develop is emitted by no workflow: 'wiring-guard'"

exit "$fail"
