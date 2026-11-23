#!/usr/bin/env bash
#
# Tests for .github/workflows/main-guard.yml: a pull request into main must come from
# `develop` of this repository. A fork can have a branch called `develop`, so the name of
# the branch is not enough and the head repository has to be this one.
#
# The step is taken out of the workflow and run with each head the guard has to tell apart;
# then the wiring check that pins the comparison is shown to fail when the comparison goes.

# shellcheck disable=SC2016,SC1091,SC2154 # the text sabotaged below is literal workflow text; the helpers are sourced from lib/ (linted there as its own file) and set `fail`
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

source "$(dirname "${BASH_SOURCE[0]}")/lib/wiring.sh"

python3 -I - "$ROOT/.github/workflows/main-guard.yml" "$WORK/guard.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["jobs"]["develop-only"]["steps"][-1]["run"])
PY

# guard <head ref> <head repository> <this repository>: exit code of the step
guard() {
	local rc=0
	env HEAD_REF="$1" HEAD_REPO="$2" THIS_REPO="$3" bash "$WORK/guard.sh" > /dev/null 2>&1 || rc=$?
	echo "$rc"
}
check "develop of this repository passes" "0" "$(guard develop Glyndor/helmly-agent Glyndor/helmly-agent)"
check "a branch called develop in a fork is refused" "1" "$(guard develop someone/helmly-agent Glyndor/helmly-agent)"
check "a fork with the same name under another owner is refused" "1" "$(guard develop Glyndor-fork/helmly-agent Glyndor/helmly-agent)"
check "another branch of this repository is refused" "1" "$(guard feature/x Glyndor/helmly-agent Glyndor/helmly-agent)"
check "a branch named Develop is refused: the comparison tells case apart" "1" "$(guard Develop Glyndor/helmly-agent Glyndor/helmly-agent)"
check "a repository named like this one in another case is refused" "1" "$(guard develop glyndor/helmly-agent Glyndor/helmly-agent)"
check "an empty head repository (a deleted fork) is refused" "1" "$(guard develop '' Glyndor/helmly-agent)"
check "an empty head branch is refused" "1" "$(guard '' Glyndor/helmly-agent Glyndor/helmly-agent)"

case_in() { # case_in <description> <expected> <old> <new>
	fresh_copy
	python3 - "$WORK/tree/.github/workflows/main-guard.yml" "$3" "$4" << 'PY'
import sys
path, old, new = sys.argv[1:4]
text = open(path).read()
if old not in text:
	sys.exit("sabotage target not found: " + old)
open(path, "w").write(text.replace(old, new, 1))
PY
	caught "$1" "$2"
}
M="main-guard.yml: develop-only must compare the head repository with this repository"
case_in "a guard that drops the repository comparison is caught" "$M" \
	'if [ "$HEAD_REF" != "develop" ] || [ "$HEAD_REPO" != "$THIS_REPO" ]; then' 'if [ "$HEAD_REF" != "develop" ]; then'
case_in "a guard that reads the head repository from the wrong field is caught" "$M" \
	'HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}' 'HEAD_REPO: ${{ github.event.pull_request.base.repo.full_name }}'
case_in "a guard that compares this repository with itself is caught" "$M" \
	'THIS_REPO: ${{ github.repository }}' 'THIS_REPO: ${{ github.event.pull_request.head.repo.full_name }}'
case_in "a guard that lets either condition through is caught" "$M" \
	'if [ "$HEAD_REF" != "develop" ] || [ "$HEAD_REPO" != "$THIS_REPO" ]; then' 'if [ "$HEAD_REF" != "develop" ] && [ "$HEAD_REPO" != "$THIS_REPO" ]; then'

exit "$fail"
