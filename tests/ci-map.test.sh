#!/usr/bin/env bash
#
# Tests for the CI map (.github/ci-map.json) and the script that reads it
# (.github/scripts/ci/decide.py).
#
# The map answers "which suites does this change have anything to check in".
# It has to be right in both directions, and each direction has its own test:
#
#   - A file no suite covers must fail. Otherwise a new directory is merged
#     with nothing ever running for it. (--audit-map: "unclaimed".)
#   - A suite must not run for a change that cannot concern it. Otherwise the
#     map only moves the cost around. (The per-suite cases below, and the
#     "dead pattern" finding for a pattern that matches nothing.)
#
# Each case asserts WHICH answer came back. The script fails open, so a bare
# "ran something" is satisfied by exactly the failure the test is looking for.

set -euo pipefail

# The helpers are Python; keep their bytecode out of the tree being tested.
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DECIDE="$ROOT/.github/scripts/ci/decide.py"
MAP="$ROOT/.github/ci-map.json"
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

# decide <map> <path>...: prints the suites that would run, sorted, on one line.
decide() {
	local map="$1"
	shift
	printf '%s\n' "$@" | python3 "$DECIDE" --map "$map" 2> /dev/null | sed -n 's/=true$//p' | sort | tr '\n' ' ' | sed 's/ $//'
}
all_suites="audit rust shell workflows"

# --- the real map against the real tree -----------------------------------------
tracked="$WORK/tracked"
git -C "$ROOT" ls-files -z --cached --others --exclude-standard > "$tracked"
rc=0
python3 "$DECIDE" --map "$MAP" --audit-map < "$tracked" > "$WORK/audit.out" 2>&1 || rc=$?
check "the map claims every tracked path and has no dead pattern" "0" "$rc"
sed 's/^/       /' "$WORK/audit.out" | grep -v '^       ci-map:' || true

# --- per suite: a change to that suite's own files runs it and no other ------------
check "a source file runs the Rust suite only" "rust" "$(decide "$MAP" internal/main.rs)"
check "a migration runs the Rust suite only" "rust" "$(decide "$MAP" migrations/009_rename_nftables_chains.sql)"
check "the installer runs the shell suite only" "shell" "$(decide "$MAP" setup-agent.sh)"
check "a shell test runs the shell suite only" "shell" "$(decide "$MAP" tests/run.sh)"
check "a workflow file runs the workflow lint and the shell suite, which holds the wiring tests" "shell workflows" "$(decide "$MAP" .github/workflows/release.yml)"
check "the audit policy runs only the audit" "audit" "$(decide "$MAP" deny.toml)"
check "the lockfile runs the audit and the Rust suite" "audit rust" "$(decide "$MAP" Cargo.lock)"

# --- what watches the CI cannot be left unwatched ---------------------------------
# The wiring tests live in the shell suite. Every path that can change what the
# workflows or the rulesets say must run that suite (directly or by rerunning
# everything), or a change to the CI is merged with the test that guards it unrun.
for path in .github/workflows/release.yml .github/workflows/codeql.yml .github/workflows/freshness.yml \
	.github/workflows/reusable-rust-ci.yml .github/workflows/ci.yml .github/ci-map.json .github/required-checks.json \
	.github/scripts/ci/decide.py .github/scripts/ci/cancel/others.sh .github/actions/cargo-audit/action.yml \
	tests/lib/ci_wiring.py tests/ci-wiring.test.sh; do
	case " $(decide "$MAP" "$path") " in
		*" shell "*) r=runs-the-shell-suite ;;
		*) r="does-not-run-the-shell-suite" ;;
	esac
	check "a change to $path runs the shell suite, where the wiring tests are" "runs-the-shell-suite" "$r"
done

# --- nothing to check ------------------------------------------------------------
check "the README runs nothing" "" "$(decide "$MAP" README.md)"
check "a document under docs/ runs nothing" "" "$(decide "$MAP" docs/security-architecture.md)"
check "documents plus licence plus editor config run nothing" "" "$(decide "$MAP" CONTRIBUTING.md LICENSE .editorconfig)"
check "paths of two suites run both" "rust shell" "$(decide "$MAP" internal/main.rs tests/run.sh)"
check "the order of the paths does not change the answer" "rust shell" "$(decide "$MAP" tests/run.sh internal/main.rs)"
check "a mix of a document and a source file runs the source file's suite" "rust" "$(decide "$MAP" README.md internal/server.rs)"

# --- fail open -------------------------------------------------------------------
check "a path the map does not know runs everything" "$all_suites" "$(decide "$MAP" brand-new-directory/file.txt)"
check "an empty change set runs everything" "$all_suites" "$(decide "$MAP")"
check "a change to the map itself runs everything" "$all_suites" "$(decide "$MAP" .github/ci-map.json)"
check "a change to the decision script runs everything" "$all_suites" "$(decide "$MAP" .github/scripts/ci/decide.py)"
check "a change to ci.yml runs everything" "$all_suites" "$(decide "$MAP" .github/workflows/ci.yml)"

rc=0
printf 'README.md\n' | python3 "$DECIDE" --map "$WORK/does-not-exist.json" > /dev/null 2>&1 || rc=$?
check "an unreadable map is exit 2, which the workflow reads as run everything" "2" "$rc"
printf '{"suites": {"rust": []}}' > "$WORK/empty-suite.json"
rc=0
printf 'README.md\n' | python3 "$DECIDE" --map "$WORK/empty-suite.json" > /dev/null 2>&1 || rc=$?
check "a suite with no pattern is refused, exit 2" "2" "$rc"
printf '{"suites": {"rust": ["../etc/**"]}}' > "$WORK/escape.json"
rc=0
printf 'README.md\n' | python3 "$DECIDE" --map "$WORK/escape.json" > /dev/null 2>&1 || rc=$?
check "a pattern that climbs out of the tree is refused, exit 2" "2" "$rc"

# NUL-separated input is what the workflow sends: a name with a newline must not split.
rc=0
printf 'a\nb.md\0' | python3 "$DECIDE" --map "$MAP" > /dev/null 2>&1 || rc=$?
check "a path containing a line break is refused, exit 2" "2" "$rc"

# --- the audit finds each way the map can be wrong ----------------------------------
audit_finding() { # audit_finding <map> <tracked-file>: first finding, or "none"
	python3 "$DECIDE" --map "$1" --audit-map < "$2" 2> /dev/null | sed -n 's/^::error:://p' | head -n 1 | cut -d: -f1 | sed 's/^$/none/' || true
}
tracked_plus="$WORK/tracked-plus"
{
	cat "$tracked"
	printf 'brand-new-directory/file.txt\0'
} > "$tracked_plus"
check "a tracked file no suite covers is reported as unclaimed" "unclaimed" "$(audit_finding "$MAP" "$tracked_plus")"

python3 - "$MAP" "$WORK/dead.json" << 'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["suites"]["rust"].append("nothing-like-this/**")
json.dump(m, open(sys.argv[2], "w"))
PY
check "a pattern matching no tracked path is reported as dead" "dead pattern" "$(audit_finding "$WORK/dead.json" "$tracked")"

python3 - "$MAP" "$WORK/contradiction.json" << 'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["no-suite"].append("internal/**")
json.dump(m, open(sys.argv[2], "w"))
PY
check "a path declared no-suite and claimed by a suite is a contradiction" "contradiction" "$(audit_finding "$WORK/contradiction.json" "$tracked")"

python3 - "$MAP" "$WORK/narrow.json" << 'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["suites"]["rust"] = [p for p in m["suites"]["rust"] if p != "internal/**"]
json.dump(m, open(sys.argv[2], "w"))
PY
check "dropping a suite's pattern leaves its files unclaimed" "unclaimed" "$(audit_finding "$WORK/narrow.json" "$tracked")"

exit "$fail"
