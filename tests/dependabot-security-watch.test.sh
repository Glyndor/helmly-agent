#!/usr/bin/env bash
#
# Tests for .github/scripts/dependabot_security_watch.py.
#
# The watcher exists to make one silent state loud: a Dependabot security
# update opened against `main`, where `main-guard` refuses it for good. Each
# case below pins one decision it makes, and each asserts WHICH exit code came
# back, because the script has three and a bare "non-zero" would be satisfied
# by the wrong one (2 means "could not read the input", which is a failure of
# the watcher, never a clean bill of health).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/.github/scripts/dependabot_security_watch.py"
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

# run_watch <name> <json>: prints "<exit code>" and leaves the output in $WORK/<name>.out
run_watch() {
	local name="$1" json="$2" rc=0
	printf '%s' "$json" > "$WORK/$name.json"
	python3 "$SCRIPT" --now 2026-11-22T12:00:00Z "$WORK/$name.json" > "$WORK/$name.out" 2> "$WORK/$name.err" || rc=$?
	echo "$rc"
}

stuck='[{"number":7,"title":"bump a crate","author":{"login":"app/dependabot"},"headRefName":"dependabot/cargo/x","createdAt":"2026-11-20T12:00:00Z"}]'
check "a Dependabot pull request against main is reported, exit 1" "1" "$(run_watch stuck "$stuck")"
grep -q '::error::#7 stuck against main for 2 days' "$WORK/stuck.out" && r=found || r=missing
check "the report names the number and the age in days" "found" "$r"

old_shape='[{"number":8,"title":"t","author":{"login":"dependabot[bot]"},"headRefName":"dependabot/cargo/y","createdAt":"2026-11-22T12:00:00Z"}]'
check "the older user-shaped login is also Dependabot" "1" "$(run_watch oldshape "$old_shape")"

release='[{"number":9,"title":"release","author":{"login":"dependabot[bot]"},"headRefName":"develop","createdAt":"2026-11-22T12:00:00Z"}]'
check "a Dependabot pull request whose head is develop is a release, not stuck" "0" "$(run_watch release "$release")"

human='[{"number":10,"title":"human","author":{"login":"somebody"},"headRefName":"feature/x","createdAt":"2026-11-22T12:00:00Z"}]'
check "a pull request by a person is not reported" "0" "$(run_watch human "$human")"

lookalike='[{"number":11,"title":"t","author":{"login":"dependabot-fake"},"headRefName":"x","createdAt":"2026-11-22T12:00:00Z"}]'
check "a login that only resembles Dependabot is not Dependabot" "0" "$(run_watch lookalike "$lookalike")"

check "an empty listing is clean" "0" "$(run_watch empty '[]')"
check "input that is not JSON is exit 2, not a clean bill of health" "2" "$(run_watch garbage 'not json')"
check "a JSON object instead of a list is exit 2" "2" "$(run_watch notlist '{"number":1}')"
check "an entry without a number is exit 2, not a smaller report" "2" "$(run_watch nonumber '[{"title":"x"}]')"

rc=0
python3 "$SCRIPT" "$WORK/does-not-exist.json" > /dev/null 2>&1 || rc=$?
check "a missing input file is exit 2" "2" "$rc"

two='[{"number":1,"title":"a","author":{"login":"app/dependabot"},"headRefName":"d/a","createdAt":"2026-11-22T12:00:00Z"},{"number":2,"title":"b","author":{"login":"somebody"},"headRefName":"f","createdAt":"2026-11-22T12:00:00Z"},{"number":3,"title":"c","author":{"login":"app/dependabot"},"headRefName":"d/c","createdAt":"bad-date"}]'
run_watch two "$two" > /dev/null
check "two stuck out of three are counted" "2" "$(grep -c '^::error::' "$WORK/two.out")"
grep -q 'stuck against main for ? days: c' "$WORK/two.out" && r=found || r=missing
check "an unreadable date does not drop the pull request" "found" "$r"

exit "$fail"
