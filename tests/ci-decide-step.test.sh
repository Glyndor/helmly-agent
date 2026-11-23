#!/usr/bin/env bash
#
# Tests for the `decide` step of ci.yml, the glue that turns a diff into the
# plan. The step's own text is extracted from the workflow and run in a
# throwaway repository whose first commit is the base and whose second is the
# change, with the environment GitHub would give it. What is asserted is the
# plan it writes to GITHUB_OUTPUT, including every way it has to fail open.

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

python3 - "$ROOT/.github/workflows/ci.yml" "$WORK/step.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
step = [s for s in doc["jobs"]["decide"]["steps"] if s.get("id") == "decide"][0]
open(sys.argv[2], "w").write(step["run"])
PY

git_() { git -C "$1" -c user.email=t@example.invalid -c user.name=t "${@:2}"; }

# mkrepo <name> <with-script yes|no>: a repository whose HEAD is the base
mkrepo() {
	local d="$WORK/$1"
	mkdir -p "$d/.github/scripts/ci" "$d/internal"
	git init -q "$d"
	if [[ "$2" == yes ]]; then
		cp "$ROOT/.github/scripts/ci/decide.py" "$d/.github/scripts/ci/decide.py"
		cp "$ROOT/.github/ci-map.json" "$d/.github/ci-map.json"
	fi
	echo base > "$d/README.md"
	echo base > "$d/internal/main.rs"
	git_ "$d" add -A
	git_ "$d" commit -q -m base
}
# plan <name> <event> <base-ref>: the plan written for HEAD against HEAD~1, as "rust=.. shell=.. workflows=.."
plan() {
	local d="$WORK/$1" out="$WORK/$1.out"
	: > "$out"
	git_ "$d" add -A
	git_ "$d" commit -q -m change
	(cd "$d" && env RUNNER_TEMP="$WORK/tmp-$1" GITHUB_OUTPUT="$out" EVENT="$2" BASE_REF="$3" \
		BASE_SHA="$(git rev-parse HEAD~1)" HEAD_SHA="$(git rev-parse HEAD)" \
		BEFORE_SHA="${4:-$(git rev-parse HEAD~1)}" AFTER_SHA="$(git rev-parse HEAD)" bash "$WORK/step.sh" > "$WORK/$1.log" 2>&1)
	sort "$out" | tr '\n' ' ' | sed 's/ $//'
}
ALL_TRUE="rust=true shell=true workflows=true"
ALL_FALSE="rust=false shell=false workflows=false"

mkrepo a yes
echo changed > "$WORK/a/README.md"
check "a documentation-only pull request into develop runs no suite" "$ALL_FALSE" "$(plan a pull_request develop)"

mkrepo b yes
echo changed > "$WORK/b/internal/main.rs"
check "a source change runs the Rust suite and not the shell suite" "rust=true shell=false workflows=false" "$(plan b pull_request develop)"

mkrepo c yes
echo changed > "$WORK/c/README.md"
check "a pull request into main runs every suite, even for a documentation change" "$ALL_TRUE" "$(plan c pull_request main)"
grep -q 'into main runs every suite' "$WORK/c.log" && r=said || r=silent
check "and says why" "said" "$r"

mkrepo d no
echo changed > "$WORK/d/README.md"
check "a base without the decision script runs every suite" "$ALL_TRUE" "$(plan d pull_request develop)"

mkrepo e yes
echo changed > "$WORK/e/README.md"
check "a push to develop reads its own diff" "$ALL_FALSE" "$(plan e push develop)"

mkrepo f yes
echo changed > "$WORK/f/internal/main.rs"
check "a push whose before commit is the all-zero value runs every suite" "$ALL_TRUE" "$(plan f push develop 0000000000000000000000000000000000000000)"

mkrepo g yes
echo changed > "$WORK/g/README.md"
check "an event with no diff to read runs every suite" "$ALL_TRUE" "$(plan g workflow_dispatch develop)"

# A pull request that replaces the decision script with one that always answers
# "false" must not be judged by it: the base's copy runs, and a change to the script is
# a path the map says reruns everything.
mkrepo h yes
printf '#!/usr/bin/env python3\nimport sys\nfor n in ("rust","shell","workflows"):\n    print(n + "=false")\n' > "$WORK/h/.github/scripts/ci/decide.py"
echo changed > "$WORK/h/internal/main.rs"
check "a pull request that swaps the decision script is judged by the base's copy" "$ALL_TRUE" "$(plan h pull_request develop)"

# The same for the map.
mkrepo i yes
python3 - "$WORK/i/.github/ci-map.json" << 'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["no-suite"].append("internal/**")
json.dump(m, open(sys.argv[1], "w"))
PY
echo changed > "$WORK/i/internal/main.rs"
check "a pull request that moves the sources to no-suite is judged by the base's map" "$ALL_TRUE" "$(plan i pull_request develop)"

exit "$fail"
