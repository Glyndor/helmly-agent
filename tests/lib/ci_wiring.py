#!/usr/bin/env python3
"""Check that the workflows still say what the CI map and the rulesets rely on.

Run by tests/ci-wiring.test.sh. Each finding is one line on stdout; the exit
status is the number of findings capped at 1, and 2 when a file cannot be read.

What it holds in place:

1. Every check the rulesets require (`.github/required-checks.json`, a copy of
   the two rulesets) is emitted by some workflow under exactly that name. A job
   renamed for tidiness leaves the ruleset waiting on a name nobody emits, and
   every pull request blocks with no explanation.
2. Every suite in `.github/ci-map.json` is consumed by `ci.yml` as
   `needs.decide.outputs.<suite>`, and `ci.yml` consumes no output the map does
   not define: a suite nobody reads is a suite that always runs or never does.
3. Every job of a reusable workflow that takes the `run` input carries
   `inputs.run != 'false'` in its `if`, so a `false` verdict skips all of it and
   a missing verdict (the empty string) skips none of it.
4. `ci-gate`, the check a pull request must pass besides DCO, runs always,
   needs every other job of ci.yml, and carries the event in its name unless the
   event is a pull request. Each required check is produced by one workflow on
   one event: the push run of develop and the promotion pull request into main
   share a commit, and a gate named alike would let the first satisfy the second.
5. The workflows are read with a real YAML parser that refuses a key twice
   (GitHub keeps the last of two and says nothing), through one enumerator that
   lists `.yml` and `.yaml` at any depth, and composite actions are listed the
   same way. A workflow below `.github/workflows` is a finding: GitHub never
   runs it. A security tool is never restored from a cache.
6. No job checks out a ref other than the event's. The weekly audit of develop and
   main takes exactly two files of each out of git, runs nothing of them and
   uses no cache.
7. The exact shape of how ci.yml feeds each suite and how ci-gate reads it back,
   the closed list of inputs each reusable workflow takes, and the lines of the
   plan step that name the script or the map, which a pull request must read
   from its base commit.
7. No job can write to Actions, judged on EFFECTIVE permissions (a job inherits
   its workflow's, and `write-all` counts), and every workflow declares its
   permissions. Nothing here cancels or starts runs: the other workflows of a
   commit are security analyses and are never cancelled.
   The dependency audit has no plan, so no functional failure leaves a
   commit without it, and each suite job starts even when the plan failed
   (`!cancelled()`) and skips only on an explicit `false`.
8. No `run:` text interpolates `github.event.*` or `github.head_ref`; they
   enter through `env:`.
9. The two inputs that can turn a required job off by being emptied are not
   empty in ci.yml: `test-command` of the shell suite and `coverage-threshold`
   of the Rust suite. A skipped required check reports success."""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ci_wiring_ci import *  # noqa: E402,F403
from ci_wiring_core import *  # noqa: E402,F403
from ci_wiring_names import *  # noqa: E402,F403
from ci_wiring_release import *  # noqa: E402,F403


def main() -> int:
	findings: list = []
	try:
		check_required(findings)
		check_layout(findings)
		check_names(findings)
		check_foreign_refs(findings)
		check_release(findings)
		check_scheduled_audit(findings)
		check_suites_consumed(findings)
		check_reusables_honour_run(findings)
		check_triggers(findings)
		check_gate(findings)
		check_bases(findings)
		check_write_token(findings)
		check_suite_jobs_start(findings)
		check_tests_run_once(findings)
		check_event_values_via_env(findings)
		check_switches(findings)
		check_shape(findings)
	except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
		print(f"cannot read the workflows: {exc!r}")
		return 2
	for finding in findings:
		print(finding)
	return 1 if findings else 0


if __name__ == "__main__":
	sys.exit(main())
