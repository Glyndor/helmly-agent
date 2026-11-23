#!/usr/bin/env bash
#
# Tests for .github/scripts/ci/structure.py and its exceptions file.
#
# The script judges the tracked files of the repository it runs in, so each case
# builds a throwaway repository. What matters is which finding comes back: the
# script has several, and a bare "failed" is satisfied by the wrong one.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/.github/scripts/ci/structure.py"
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

# repo <name>: a fresh repository at $WORK/<name>
repo() {
	rm -rf "${WORK:?}/$1"
	mkdir -p "$WORK/$1"
	git -C "$WORK/$1" init -q
	echo '{"files": {}, "folders": {}}' > "$WORK/$1/exceptions.json"
}
lines() { # lines <n> <file>: n code lines
	yes 'x=1' 2> /dev/null | head -n "$1" > "$2" || true
}
# verdict <repo>: the first finding with the repository path removed, or "ok"
verdict() {
	local out rc=0
	git -C "$WORK/$1" add -A
	out="$(cd "$WORK/$1" && python3 "$SCRIPT" --exceptions exceptions.json 2>&1)" || rc=$?
	if [[ "$rc" -eq 0 ]]; then echo ok; else printf '%s\n' "$out" | head -n 1 | sed 's/^::error:://'; fi
}

repo a
lines 500 "$WORK/a/big.sh"
check "a file of exactly 500 code lines fits" "ok" "$(verdict a)"

repo b
lines 501 "$WORK/b/big.sh"
check "a file of 501 code lines is over the limit" "file big.sh has 501, over the limit of 500; split it, or list it in the exceptions file with a ceiling and a reason" "$(verdict b)"

repo c
{ lines 500 "$WORK/c/f.sh"; for _ in $(seq 400); do echo '# a comment'; echo; done >> "$WORK/c/f.sh"; }
check "comment and blank lines do not count" "ok" "$(verdict c)"

repo d
lines 501 "$WORK/d/big.sh"
echo '{"files": {"big.sh": {"ceiling": 510, "reason": "one installer file"}}, "folders": {}}' > "$WORK/d/exceptions.json"
check "a listed file within its ceiling fits" "ok" "$(verdict d)"
lines 511 "$WORK/d/big.sh"
check "a listed file past its ceiling fails" "file big.sh has 511, over its ceiling of 510" "$(verdict d)"
lines 100 "$WORK/d/big.sh"
check "an exception for a file back under the limit is stale" "the exception for big.sh is stale: it has 100, within the limit of 500; remove the entry" "$(verdict d)"
lines 530 "$WORK/d/big.sh"
echo '{"files": {"big.sh": {"ceiling": 600, "reason": "one installer file"}}, "folders": {}}' > "$WORK/d/exceptions.json"
check "a ceiling far above the real number must be lowered" "the ceiling of big.sh is 600 but it has 530; lower the ceiling to 530" "$(verdict d)"
echo '{"files": {"big.sh": {"ceiling": 540}}, "folders": {}}' > "$WORK/d/exceptions.json"
check "an exception with no reason is refused" "the exception for big.sh needs an integer ceiling and a written reason" "$(verdict d)"
echo '{"files": {"gone.sh": {"ceiling": 540, "reason": "x"}}, "folders": {}}' > "$WORK/d/exceptions.json"
lines 10 "$WORK/d/big.sh"
check "an exception for a file that is not tracked is refused" "the exception for gone.sh names a file that is not tracked; remove the entry" "$(verdict d)"

repo e
mkdir "$WORK/e/dir"
for i in $(seq 20); do : > "$WORK/e/dir/f$i.txt"; done
check "a folder of 20 files fits" "ok" "$(verdict e)"
: > "$WORK/e/dir/f21.txt"
check "a folder of 21 files is over the limit" "folder dir has 21, over the limit of 20; split it, or list it in the exceptions file with a ceiling and a reason" "$(verdict e)"

repo f
mkdir -p "$WORK/f/.github/workflows" "$WORK/f/.sqlx" "$WORK/f/pkg/testdata"
for i in $(seq 25); do : > "$WORK/f/.github/workflows/w$i.yml"; : > "$WORK/f/.sqlx/q$i.json"; : > "$WORK/f/pkg/testdata/t$i"; done
check "the workflows folder, .sqlx and testdata are not counted" "ok" "$(verdict f)"

repo g
rc=0
(cd "$WORK/g" && python3 "$SCRIPT" --exceptions missing.json > /dev/null 2>&1) || rc=$?
check "an unreadable exceptions file is exit 2" "2" "$rc"

# --- the real tree ---------------------------------------------------------------
rc=0
(cd "$ROOT" && python3 "$SCRIPT" --exceptions .github/structure.json > "$WORK/real.out" 2>&1) || rc=$?
check "the repository fits its own limits" "0" "$rc"
sed 's/^/       /' "$WORK/real.out" | grep -v 'tracked files fit' || true

# --- the step of ci.yml that runs it ------------------------------------------------
# The step has no plan, and judges a pull request with the base commit's copy of
# the script and the exceptions AND the tree's, both of which must pass. Its text
# is extracted from the workflow and run in a throwaway repository whose first
# commit is the base and whose second is the pull request.
python3 - "$ROOT/.github/workflows/ci.yml" "$WORK/step.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["jobs"]["structure"]["steps"][-1]["run"])
PY

# pr_repo <name>: a repository whose HEAD is the base, with the real script and empty exceptions
pr_repo() {
	repo "$1"
	mkdir -p "$WORK/$1/.github/scripts/ci"
	cp "$SCRIPT" "$WORK/$1/.github/scripts/ci/structure.py"
	echo '{"files": {}, "folders": {}}' > "$WORK/$1/.github/structure.json"
	rm -f "$WORK/$1/exceptions.json"
	git -C "$WORK/$1" add -A
	git -C "$WORK/$1" -c user.email=t@example.invalid -c user.name=t commit -q -m base
}
# judge <name> <event>: exit code of the step with HEAD as the pull request
judge() {
	local rc=0 base="${3:-}"
	git -C "$WORK/$1" add -A
	git -C "$WORK/$1" -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m change
	(cd "$WORK/$1" && env RUNNER_TEMP="$WORK/tmp-$1" EVENT="$2" BASE_SHA="${base:-$(git rev-parse HEAD~1)}" bash "$WORK/step.sh" > "$WORK/$1.out" 2>&1) || rc=$?
	echo "$rc"
}

pr_repo h
mkdir "$WORK/h/docs"
echo 'x' > "$WORK/h/docs/a.md"
check "a pull request that fits is green" "0" "$(judge h pull_request)"
grep -q "judged with the base commit's script" "$WORK/h.out" && r=both || r=one
grep -q "judged with this tree's script" "$WORK/h.out" && r="$r+tree" || r="$r+none"
check "it was judged with both copies" "both+tree" "$r"

pr_repo i
for n in $(seq 21); do : > "$WORK/i/doc$n.md"; done
check "a pull request that only adds documents and overfills the root folder is red" "1" "$(judge i pull_request)"
grep -q 'folder . has' "$WORK/i.out" && r=found || r=missing
check "and the folder finding is the reason" "found" "$r"

pr_repo j
lines 501 "$WORK/j/big.sh"
check "a pull request that adds a file of 501 code lines is red" "1" "$(judge j pull_request)"
grep -q 'file big.sh has 501' "$WORK/j.out" && r=found || r=missing
check "and the file finding is the reason" "found" "$r"

# A pull request that only deletes the exception of a file that is still too long:
# the base's exceptions judge it green, the tree's judge it red, and the step is red.
pr_repo k
lines 600 "$WORK/k/big.sh"
echo '{"files": {"big.sh": {"ceiling": 600, "reason": "the installer"}}, "folders": {}}' > "$WORK/k/.github/structure.json"
git -C "$WORK/k" add -A
git -C "$WORK/k" -c user.email=t@example.invalid -c user.name=t commit -q -m "base with an exception"
echo '{"files": {}, "folders": {}}' > "$WORK/k/.github/structure.json"
check "a pull request that only deletes an exception still needed is red (the tree's copy catches it)" "1" "$(judge k pull_request)"

# And the other way round: a pull request that raises its own limit is judged by the base too.
pr_repo l
lines 501 "$WORK/l/big.sh"
echo '{"files": {"big.sh": {"ceiling": 510, "reason": "added by the same change"}}, "folders": {}}' > "$WORK/l/.github/structure.json"
check "a pull request that adds its own exception is red (the base's copy catches it)" "1" "$(judge l pull_request)"

# A base without the check yet: the tree's copy judges alone.
repo m
mkdir -p "$WORK/m/.github/scripts/ci"
git -C "$WORK/m" -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m base
cp "$SCRIPT" "$WORK/m/.github/scripts/ci/structure.py"
echo '{"files": {}, "folders": {}}' > "$WORK/m/.github/structure.json"
rm -f "$WORK/m/exceptions.json"
check "a base with no check yet: the change that introduces it is judged by its own copy and passes" "0" "$(judge m pull_request)"
grep -q 'no structure check yet' "$WORK/m.out" && r=found || r=missing
check "the notice says so" "found" "$r"

repo m2
mkdir -p "$WORK/m2/.github/scripts/ci"
git -C "$WORK/m2" -c user.email=t@example.invalid -c user.name=t commit -q --allow-empty -m base
cp "$SCRIPT" "$WORK/m2/.github/scripts/ci/structure.py"
echo '{"files": {}, "folders": {}}' > "$WORK/m2/.github/structure.json"
rm -f "$WORK/m2/exceptions.json"
lines 501 "$WORK/m2/big.sh"
check "and with no base copy its own copy still turns a long file red" "1" "$(judge m2 pull_request)"

pr_repo n
lines 501 "$WORK/n/big.sh"
check "on a push the tree's copy judges alone and a long file is red" "1" "$(judge n push)"

# --- a change to an exception is judged against the base's number, not its own -----------
# A folder the base does not list is judged with the default of the base, 20.
pr_repo o
for n in $(seq 21); do : > "$WORK/o/doc$n.md"; done
echo '{"files": {}, "folders": {".": {"ceiling": 21, "reason": "added by the same change"}}}' > "$WORK/o/.github/structure.json"
check "a new folder past 20 files that lists itself is red: the base's default judges it" "1" "$(judge o pull_request)"
grep -q 'folder . has 21' "$WORK/o.out" && r=found || r=missing
check "and it is the base's copy that says so" "found" "$r"

# A folder the base lists at 25 cannot take a sixth file by raising its own ceiling.
pr_repo p
mkdir "$WORK/p/dir"
for n in $(seq 25); do : > "$WORK/p/dir/doc$n.md"; done
echo '{"files": {}, "folders": {"dir": {"ceiling": 25, "reason": "the base allows 25"}}}' > "$WORK/p/.github/structure.json"
git -C "$WORK/p" add -A
git -C "$WORK/p" -c user.email=t@example.invalid -c user.name=t commit -q -m "base with a folder exception"
for n in 26 27 28; do : > "$WORK/p/dir/doc$n.md"; done
echo '{"files": {}, "folders": {"dir": {"ceiling": 28, "reason": "raised by the same change"}}}' > "$WORK/p/.github/structure.json"
check "a listed folder that raises its own ceiling and grows is red" "1" "$(judge p pull_request)"
grep -q 'folder dir has 28, over its ceiling of 25' "$WORK/p.out" && r=found || r=missing
check "and the finding names the ceiling of the base" "found" "$r"

# A file the base lists at 600 lines: the change that makes it shorter, and lowers its own
# ceiling to match, is the change the exceptions exist to ask for, and must not be red.
pr_repo q
lines 600 "$WORK/q/big.sh"
echo '{"files": {"big.sh": {"ceiling": 600, "reason": "the installer"}}, "folders": {}}' > "$WORK/q/.github/structure.json"
git -C "$WORK/q" add -A
git -C "$WORK/q" -c user.email=t@example.invalid -c user.name=t commit -q -m "base with an exception"
lines 540 "$WORK/q/big.sh"
echo '{"files": {"big.sh": {"ceiling": 540, "reason": "the installer"}}, "folders": {}}' > "$WORK/q/.github/structure.json"
check "a file that shrinks by 60 lines and lowers its ceiling is green" "0" "$(judge q pull_request)"

pr_repo r
lines 600 "$WORK/r/big.sh"
echo '{"files": {"big.sh": {"ceiling": 600, "reason": "the installer"}}, "folders": {}}' > "$WORK/r/.github/structure.json"
git -C "$WORK/r" add -A
git -C "$WORK/r" -c user.email=t@example.invalid -c user.name=t commit -q -m "base with an exception"
lines 480 "$WORK/r/big.sh"
echo '{"files": {}, "folders": {}}' > "$WORK/r/.github/structure.json"
check "a file that shrinks under the limit and drops its exception is green" "0" "$(judge r pull_request)"

# A base commit that cannot be read is not a base without the check: the step fails, and
# runs nothing, instead of judging with the tree's copy alone.
pr_repo s
lines 10 "$WORK/s/ok.sh"
check "a base commit that cannot be read is red, not 'no check yet'" "1" "$(judge s pull_request 0000000000000000000000000000000000000000)"
grep -q 'cannot be read' "$WORK/s.out" && r=said || r=silent
check "and the step says the base commit cannot be read" "said" "$r"

exit "$fail"
