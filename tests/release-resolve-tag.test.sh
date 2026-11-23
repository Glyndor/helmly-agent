#!/usr/bin/env bash
#
# Tests for .github/scripts/release/resolve-tag.sh, which turns the tag of a release run
# into the commit it points at and requires that commit to be the one expected.
#
# The run of a release is started by a tag or by hand with a typed name. A bare name can
# be a branch, so what must hold is that only refs/tags/<tag> counts: a branch called like
# a version, with no tag, fails; a tag that points elsewhere fails; a tag that moved after
# it was verified fails when it is asked again with the commit that was verified. Each case
# runs in a throwaway repository with its own origin.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/.github/scripts/release/resolve-tag.sh"
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

g() { git -C "$1" -c user.email=t@example.invalid -c user.name=t -c tag.gpgsign=false -c commit.gpgsign=false "${@:2}"; }

# repo <name>: an origin and a clone of it with two commits on main, returns nothing
repo() {
	local d="$WORK/$1"
	rm -rf "$d"
	mkdir -p "$d"
	git init -q --bare "$d/origin.git"
	git init -q "$d/run"
	g "$d/run" remote add origin "file://$d/origin.git"
	echo one > "$d/run/f"
	g "$d/run" add -A
	g "$d/run" commit -q -m one
	g "$d/run" branch -M main
	echo two > "$d/run/f"
	g "$d/run" commit -q -am two
	g "$d/run" push -q origin main
}
head_of() { git -C "$WORK/$1/run" rev-parse "${2:-HEAD}"; }
# resolve <repo> <tag> <expected>: "<exit code> <stdout>" of the script run in the clone
resolve() {
	local rc=0 out
	out="$(cd "$WORK/$1/run" && bash "$SCRIPT" "$2" "$3" 2> "$WORK/$1.err")" || rc=$?
	echo "$rc $out"
}

repo a
g "$WORK/a/run" tag v2.0.2
g "$WORK/a/run" push -q origin v2.0.2
sha="$(head_of a)"
check "a tag at the expected commit resolves to that commit" "0 $sha" "$(resolve a v2.0.2 "$sha")"

repo b
g "$WORK/b/run" tag -a v2.0.2 -m release
g "$WORK/b/run" push -q origin v2.0.2
sha="$(head_of b)"
check "an annotated tag is peeled to its commit" "0 $sha" "$(resolve b v2.0.2 "$sha")"

# A run started by hand from a BRANCH called like a version, with no tag at all.
repo c
g "$WORK/c/run" branch v2.0.2
g "$WORK/c/run" push -q origin v2.0.2
sha="$(head_of c v2.0.2)"
check "a branch called v2.0.2 does not pass for the tag" "1 " "$(resolve c v2.0.2 "$sha")"
grep -q 'there is no tag v2.0.2' "$WORK/c.err" && r=said || r=silent
check "and the refusal says there is no tag" "said" "$r"

# Both exist: the tag decides, not the branch.
repo d
first="$(head_of d HEAD~1)"
second="$(head_of d)"
g "$WORK/d/run" tag v2.0.2 "$first"
g "$WORK/d/run" push -q origin v2.0.2
g "$WORK/d/run" branch v2.0.2x
check "the tag is the commit the tag names, whatever the branch" "0 $first" "$(resolve d v2.0.2 "$first")"
check "a tag that points elsewhere than the expected commit is refused" "1 " "$(resolve d v2.0.2 "$second")"
grep -q 'not at' "$WORK/d.err" && r=said || r=silent
check "and the refusal names both commits" "said" "$r"

# The tag is moved after verification: asked again with the verified commit, it fails.
repo e
g "$WORK/e/run" tag v2.0.2
g "$WORK/e/run" push -q origin v2.0.2
verified="$(head_of e)"
earlier="$(head_of e HEAD~1)"
check "before the move the tag still points at the verified commit" "0 $verified" "$(resolve e v2.0.2 "$verified")"
g "$WORK/e/run" tag -f v2.0.2 "$earlier" > /dev/null
g "$WORK/e/run" push -q -f origin refs/tags/v2.0.2
git -C "$WORK/e/run" tag -d v2.0.2 > /dev/null
check "after the tag moved, the verified commit no longer matches" "1 " "$(resolve e v2.0.2 "$verified")"

repo f
sha="$(head_of f)"
for bad in v2 v2.0 v2.0.2.1 V2.0.2 v2.0.2-rc1; do
	g "$WORK/f/run" tag "$bad"
	g "$WORK/f/run" push -q origin "refs/tags/$bad"
done
for bad in v2 v2.0 v2.0.2.1 V2.0.2 v2.0.2-rc1 "v2.0.2;x" "" main; do
	check "the tag '$bad' is refused by its shape even when it exists" "1 " "$(resolve f "$bad" "$sha")"
done
check "an expected commit that is not a full id is refused" "1 " "$(resolve a v2.0.2 abc123)"
check "an expected commit with a newline is refused" "1 " "$(resolve a v2.0.2 "$(printf '%s\nextra' "$sha")")"

exit "$fail"
