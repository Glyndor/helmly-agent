#!/usr/bin/env bash
#
# Tests for .github/scripts/ci/pins.py, which judges the value of every pin that the
# wiring contract leaves alone so that pull requests of Dependabot can pass.
#
# The tags are asked of local repositories: `--remote-prefix` points the script at
# $WORK/remote/, where each <owner>/<repo> is a small git repository made here. The
# production step never passes that option (the wiring check pins it).
#
# Two directions: a bump of a pin of the kind Dependabot makes passes, and each way of
# changing a pin to something that was not released fails with its own finding.
#
# The last part runs the step of ci.yml that calls the script, with stand-ins for the two
# copies, to see which one runs first and what the step does when the base cannot be read.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/.github/scripts/ci/pins.py"
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

G=(git -c user.email=t@example.invalid -c user.name=t -c commit.gpgsign=false -c tag.gpgsign=false)
REMOTE="$WORK/remote"

# remote_repo <owner/repo>: a repository with two commits, c1 and c2, in $WORK/<name>.sha
remote_repo() {
	local dir="$REMOTE/$1"
	mkdir -p "$dir"
	git -C "$dir" init -q
	echo 1 > "$dir/f"
	git -C "$dir" add f
	"${G[@]}" -C "$dir" commit -q -m c1
	git -C "$dir" rev-parse HEAD > "$WORK/${1//\//-}.c1"
	echo 2 > "$dir/f"
	"${G[@]}" -C "$dir" commit -q -am c2
	git -C "$dir" rev-parse HEAD > "$WORK/${1//\//-}.c2"
}
sha() { cat "$WORK/${1//\//-}.$2"; } # sha <owner/repo> <c1|c2>

remote_repo actions/checkout
remote_repo actions/cache
remote_repo github/codeql-action
remote_repo evil/checkout
# checkout: v1.2.3 is a lightweight tag at c1, v1.3.0 an annotated one at c2, v1.0.0 at c1
"${G[@]}" -C "$REMOTE/actions/checkout" tag v1.2.3 "$(sha actions/checkout c1)"
"${G[@]}" -C "$REMOTE/actions/checkout" tag v1.0.0 "$(sha actions/checkout c1)"
"${G[@]}" -C "$REMOTE/actions/checkout" tag -a v1.3.0 -m "release" "$(sha actions/checkout c2)"
git -C "$REMOTE/actions/checkout" rev-parse "refs/tags/v1.3.0" > "$WORK/checkout.tagobject"
"${G[@]}" -C "$REMOTE/actions/cache" tag v2.0.0 "$(sha actions/cache c1)"
"${G[@]}" -C "$REMOTE/github/codeql-action" tag v4.1.0 "$(sha github/codeql-action c1)"
"${G[@]}" -C "$REMOTE/evil/checkout" tag v1.2.3 "$(sha evil/checkout c1)"

CO1="$(sha actions/checkout c1)"
CO2="$(sha actions/checkout c2)"
CA="$(sha actions/cache c1)"
CQ="$(sha github/codeql-action c1)"

# tree <name> <workflow text>: a repository whose base commit has the real script and the given workflow
tree() {
	rm -rf "${WORK:?}/$1"
	mkdir -p "$WORK/$1/.github/workflows"
	git -C "$WORK/$1" init -q
	printf '%s\n' "$2" > "$WORK/$1/.github/workflows/w.yml"
	git -C "$WORK/$1" add -A
	"${G[@]}" -C "$WORK/$1" commit -q -m base
}
# change <name> <workflow text>: the pull request, one commit over the base
change() {
	printf '%s\n' "$2" > "$WORK/$1/.github/workflows/w.yml"
	git -C "$WORK/$1" add -A
	"${G[@]}" -C "$WORK/$1" commit -q --allow-empty -m change
}
# run <name> [args]: exit code, and the findings, with the repository path removed
run() {
	local name="$1" rc=0
	shift
	(cd "$WORK/$name" && python3 -I "$SCRIPT" --remote-prefix "$REMOTE/" "$@" > "$WORK/$name.out" 2>&1) || rc=$?
	echo "$rc"
}
said() {
	if grep -qF -- "$2" "$WORK/$1.out"; then echo said; else echo "silent: $(head -n 2 "$WORK/$1.out" | tr "\n" " ")"; fi
}

wf() { # wf <uses lines...>: a workflow with those steps
	printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
	for u in "$@"; do printf '      - uses: %s\n' "$u"; done
}
BASE_WF="$(wf "actions/checkout@$CO1 # v1.2.3")"

tree a "$BASE_WF"
check "a pin that is the commit of its tag passes" "0" "$(run a)"

tree b "$(wf "actions/checkout@$CO2 # v1.3.0")"
check "an annotated tag is judged by its commit, not by the tag object" "0" "$(run b)"
tree b2 "$(wf "actions/checkout@$(cat "$WORK/checkout.tagobject") # v1.3.0")"
check "the SHA of the tag object of an annotated tag is not the commit: red" "1" "$(run b2)"
check "and it says which commit the tag points at" "said" "$(said b2 "is not the commit of actions/checkout v1.3.0")"

# A commit of the same repository that no tag of that version points at (a fork's commit is reachable the same way).
tree c "$(wf "actions/checkout@$CO2 # v1.2.3")"
check "another commit of the same repository, with the version of a real tag: red" "1" "$(run c)"
tree c2 "$(wf "actions/checkout@0123456789abcdef0123456789abcdef01234567 # v1.2.3")"
check "a SHA that no repository has: red" "1" "$(run c2)"

# --- what a reference is allowed to be --------------------------------------------------
tree d "$(wf "evil/checkout@$(sha evil/checkout c1) # v1.2.3")"
check "an owner outside the allowed list is refused even when its tag matches" "1" "$(run d)"
check "and the finding is the owner" "said" "$(said d "is not from an allowed owner")"
tree d2 "$(wf "actions/checkout@v1.2.3")"
check "a tag in place of a SHA is refused" "1" "$(run d2)"
tree d2b "$(wf "actions/checkout@v1.2.3 # v1.2.3")"
check "a tag in place of a SHA with the comment of that very version is red" "1" "$(run d2b)"
check "and it is refused for what it is" "said" "$(said d2b "is not pinned to a SHA of 40 hex digits")"
tree d3 "$(wf "actions/checkout@main")"
check "a branch in place of a SHA is refused" "1" "$(run d3)"
tree d4 "$(wf "actions/checkout@${CO1:0:12} # v1.2.3")"
check "an abbreviated SHA is refused" "1" "$(run d4)"
tree d5 "$(wf "actions/checkout@$CO1")"
check "a pin with no version comment is refused" "1" "$(run d5)"
tree d6 "$(wf "actions/checkout@$CO1 # v1.2")"
check "a version with two numbers is refused" "1" "$(run d6)"
tree d7 "$(wf "actions/checkout@$CO1 # 1.2.3")"
check "a version with no v is refused" "1" "$(run d7)"
tree d8 "$(wf "actions/checkout@$CO1 # v1.2.3-rc1")"
check "a pre-release version is refused" "1" "$(run d8)"
tree d9 "$(wf "actions/checkout@\${{ github.sha }} # v1.2.3")"
check "an expression in place of the pin is refused" "1" "$(run d9)"
tree d10 "$(wf "actions/checkout@$CO1 # v9.9.9")"
check "a version whose tag does not exist is refused, not skipped" "1" "$(run d10)"
check "and the finding says the tag does not exist" "said" "$(said d10 "the tag v9.9.9 does not exist")"
tree d11 "$(wf "./.github/actions/local" "actions/checkout@$CO1 # v1.2.3")"
check "a local action is not a pin and is not judged" "0" "$(run d11)"

# --- fail closed ---------------------------------------------------------------------
tree e "$BASE_WF"
rc=0
(cd "$WORK/e" && python3 -I "$SCRIPT" --remote-prefix "$WORK/nowhere/" > "$WORK/e.out" 2>&1) || rc=$?
check "a remote that cannot be asked is a failure, not a pass" "1" "$rc"
check "and it says it could not ask" "said" "$(said e "cannot ask for the tag")"
# A local git setting that rewrites the address must not reach the question.
tree e2 "$BASE_WF"
git -C "$WORK/e2" config "url.$WORK/nowhere/.insteadOf" "$REMOTE/"
check "a rewrite of the URL in the repository's own configuration does not change the answer" "0" "$(run e2)"

# --- one pair per repository ---------------------------------------------------------
tree f "$(wf "actions/checkout@$CO1 # v1.2.3" "actions/checkout@$CO2 # v1.3.0")"
check "two pairs for one action in the tree: red" "1" "$(run f)"
check "and the finding is the pair" "said" "$(said f "is pinned to more than one (SHA, version)")"
mkdir -p "$WORK/f2/.github/actions/x" "$WORK/f2/.github/workflows"
tree f2 "$BASE_WF"
mkdir -p "$WORK/f2/.github/actions/x"
printf 'name: x\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@%s # v1.3.0\n' "$CO2" > "$WORK/f2/.github/actions/x/action.yml"
check "a second pair in a composite action is found as well" "1" "$(run f2)"
tree f3 "$(wf "github/codeql-action/init@$CQ # v4.1.0" "github/codeql-action/analyze@$CQ # v4.1.0")"
check "two actions of one repository with the same pair are one pair" "0" "$(run f3)"

# --- Dependabot: a bump passes, a step back does not ---------------------------------------
tree g "$BASE_WF"
base_sha="$(git -C "$WORK/g" rev-parse HEAD)"
change g "$(wf "actions/checkout@$CO2 # v1.3.0")"
check "a bump of the SHA and the version together passes, against the base" "0" "$(run g --base "$base_sha")"
tree g2 "$(wf "actions/checkout@$CO2 # v1.3.0")"
base_sha="$(git -C "$WORK/g2" rev-parse HEAD)"
change g2 "$BASE_WF"
check "going back to an older real version is refused: lowering needs a decision" "1" "$(run g2 --base "$base_sha")"
check "and the finding names the two versions" "said" "$(said g2 "goes from v1.3.0 to v1.2.3")"
tree g3 "$BASE_WF"
base_sha="$(git -C "$WORK/g3" rev-parse HEAD)"
change g3 "$(wf "actions/checkout@$CO1 # v1.2.3" "actions/cache@$CA # v2.0.0")"
check "a new action that the base did not have passes" "0" "$(run g3 --base "$base_sha")"
tree g4 "$BASE_WF"
change g4 "$(wf "actions/checkout@$CO1 # v1.2.3")"
check "a base commit that cannot be read is a failure" "1" "$(run g4 --base 0000000000000000000000000000000000000000)"
check "and it says the commit cannot be read" "said" "$(said g4 "cannot be read")"
mkdir -p "$WORK/g5"
git -C "$WORK/g5" init -q
"${G[@]}" -C "$WORK/g5" commit -q --allow-empty -m base
base_sha="$(git -C "$WORK/g5" rev-parse HEAD)"
mkdir -p "$WORK/g5/.github/workflows"
wf "actions/checkout@$CO1 # v1.2.3" > "$WORK/g5/.github/workflows/w.yml"
check "a base that has no workflows yet is an absent file, not a failure" "0" "$(run g5 --base "$base_sha")"

# --- images ------------------------------------------------------------------------
IMG='name: w
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    container: ubuntu@sha256:0000000000000000000000000000000000000000000000000000000000000000
    steps:
      - run: echo'
tree h "$IMG"
check "an image by digest from a repository outside the allowed list is refused" "1" "$(run h)"
tree h2 "${IMG/ubuntu@sha256:*/ubuntu:22.04}"
check "an image by tag is refused" "1" "$(run h2)"
tree h3 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    services:\n      db:\n        image: postgres:16\n    steps:\n      - run: echo\n')"
check "a service image is read as well" "1" "$(run h3)"
tree h4 "$(wf 'docker://alpine:3.20')"
check "a docker:// reference is an image and is judged as one" "1" "$(run h4)"
tree h5 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    container:\n      image: ubuntu:22.04\n    steps:\n      - run: echo\n')"
check "the image inside a container mapping is read" "1" "$(run h5)"

# --- the YAML, as GitHub reads it ------------------------------------------------------------
tree i "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - { uses: evil/checkout@%s } # v1.2.3\n' "$(sha evil/checkout c1)")"
check "a reference in flow style is read" "1" "$(run i)"
tree i2 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@%s # v1.2.3\n        uses: evil/checkout@%s # v1.2.3\n' "$CO1" "$(sha evil/checkout c1)")"
check "a key repeated in a step is judged both times" "1" "$(run i2)"
tree i3 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - "uses": "evil/checkout@%s" # v1.2.3\n' "$(sha evil/checkout c1)")"
check "quoted keys and values are read" "1" "$(run i3)"
tree i4 "$(printf 'name: w\non: push\njobs:\n  j:\n    uses: evil/checkout/.github/workflows/x.yml@%s # v1.2.3\n' "$(sha evil/checkout c1)")"
check "a reusable workflow called from a job is judged like an action" "1" "$(run i4)"
tree i5 "$(printf 'name: w\njobs: [\n')"
check "a file that is not YAML is a failure" "1" "$(run i5)"
tree i6 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: [actions/checkout]\n')"
check "a reference that is not a plain string is a failure" "1" "$(run i6)"
tree i7 "$BASE_WF"
printf 'name: x\nruns:\n  using: composite\n  steps:\n    - uses: evil/checkout@%s # v1.2.3\n' "$(sha evil/checkout c1)" > "$WORK/i7/.github/ext.yaml"
check "a .yaml file under .github is read as well" "1" "$(run i7)"
tree i8 "$BASE_WF"
ln -s w.yml "$WORK/i8/.github/workflows/link.yml"
check "a workflow that is a link is refused" "1" "$(run i8)"
tree i9 "$(printf 'name: w\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: "actions/checkout@%s" # v1.2.3\n' "$CO1")"
check "the comment after a quoted value is the version comment" "0" "$(run i9)"

# --- the real tree against the real remote is run by CI itself; here, only that it reads ---------------
rc=0
(cd "$ROOT" && python3 -I "$SCRIPT" --remote-prefix "$WORK/nowhere/" > "$WORK/real.out" 2>&1) || rc=$?
check "the real tree is read and every reference is judged (the question fails here: no network is used)" "1" "$rc"
grep -c "cannot ask for the tag" "$WORK/real.out" | { read -r n; [[ "$n" -ge 3 ]] && r=many || r=few; check "and every distinct pin is asked" "many" "$r"; }

# --- the step of ci.yml that runs the script -------------------------------------------------
python3 -I - "$ROOT/.github/workflows/ci.yml" "$WORK/step.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["jobs"]["pins"]["steps"][-1]["run"])
PY

STUB_BASE='import os, sys
open(os.environ["LOG"], "a").write("base " + " ".join(sys.argv[1:]) + "\n")
sys.exit(int(os.environ.get("BASE_RC", "0")))'
STUB_TREE='import os, sys
open(os.environ["LOG"], "a").write("tree " + " ".join(sys.argv[1:]) + "\n")
sys.exit(int(os.environ.get("TREE_RC", "0")))'

# pr_repo <name> <base has the script: yes|no>: HEAD~1 is the base, HEAD the pull request
pr_repo() {
	rm -rf "${WORK:?}/$1"
	mkdir -p "$WORK/$1/.github/scripts/ci"
	git -C "$WORK/$1" init -q
	if [[ "$2" == yes ]]; then printf '%s\n' "$STUB_BASE" > "$WORK/$1/.github/scripts/ci/pins.py"; else : > "$WORK/$1/keep"; fi
	git -C "$WORK/$1" add -A
	"${G[@]}" -C "$WORK/$1" commit -q -m base
	printf '%s\n' "$STUB_TREE" > "$WORK/$1/.github/scripts/ci/pins.py"
	git -C "$WORK/$1" add -A
	"${G[@]}" -C "$WORK/$1" commit -q -m change
}
# step <name> <event> <base sha> [VAR=value...]: exit code and the log, on one line
step() {
	local name="$1" event="$2" base="$3" rc=0
	shift 3
	: > "$WORK/$name.log"
	(cd "$WORK/$name" && env RUNNER_TEMP="$WORK" EVENT="$event" BASE_SHA="$base" LOG="$WORK/$name.log" "$@" bash "$WORK/step.sh" > "$WORK/$name.out" 2>&1) || rc=$?
	echo "$rc:$(tr '\n' '|' < "$WORK/$name.log")"
}

pr_repo a yes
BASE="$(git -C "$WORK/a" rev-parse HEAD~1)"
check "both copies green: green, the base's first and with the base commit" "0:base --base $BASE|tree --base $BASE|" "$(step a pull_request "$BASE")"
check "the base's copy red and the tree's green: red, and the tree's copy still ran" "1:base --base $BASE|tree --base $BASE|" "$(step a pull_request "$BASE" BASE_RC=1)"
check "the tree's copy red and the base's green: red" "1:base --base $BASE|tree --base $BASE|" "$(step a pull_request "$BASE" TREE_RC=1)"
check "on a push only the tree's copy runs, with no base" "0:tree |" "$(step a push "")"
check "on a push the tree's copy red is red" "1:tree |" "$(step a push "" TREE_RC=1)"

pr_repo b no
BASE="$(git -C "$WORK/b" rev-parse HEAD~1)"
check "a readable base with no script: the tree's copy judges alone, and it is said" "0:tree --base $BASE|" "$(step b pull_request "$BASE")"
grep -q 'no pins check yet' "$WORK/b.out" && r=said || r=silent
check "the notice says so" "said" "$r"
check "a readable base with no script and the tree's copy red is red" "1:tree --base $BASE|" "$(step b pull_request "$BASE" TREE_RC=1)"

pr_repo c yes
check "a base commit that cannot be read is red and runs nothing, not read as 'no check yet'" "1:" "$(step c pull_request 0000000000000000000000000000000000000000)"
grep -q 'cannot be read' "$WORK/c.out" && r=said || r=silent
check "and it says the commit cannot be read" "said" "$r"
check "an empty base commit on a pull request is red and runs nothing" "1:" "$(step c pull_request "")"

# A base whose script is listed but cannot be shown: a tree object kept without its blob.
pr_repo d yes
BASE="$(git -C "$WORK/d" rev-parse HEAD~1)"
blob="$(git -C "$WORK/d" rev-parse "$BASE:.github/scripts/ci/pins.py")"
rm -f "$WORK/d/.git/objects/${blob:0:2}/${blob:2}"
if git -C "$WORK/d" cat-file -e "$blob" 2> /dev/null; then
	echo "FAIL the blob could not be removed, so the case cannot run"; fail=1
else
	check "a script listed by the base and that cannot be shown is red, not 'no check yet'" "1:" "$(step d pull_request "$BASE")"
fi

exit "$fail"
