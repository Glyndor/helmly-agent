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
4. `ci-gate`, the one check the rulesets require besides DCO, runs always and
   needs every other job of ci.yml.
5. The two inputs that can turn a required job off by being emptied are not
   empty in ci.yml: `test-command` of the shell suite and `coverage-threshold`
   of the Rust suite. A skipped required check reports success.
"""

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def load_yaml(path: Path) -> dict:
	with open(path, encoding="utf-8") as fh:
		data = yaml.safe_load(fh)
	if not isinstance(data, dict):
		raise ValueError(f"{path} is not a mapping")
	return data


def emitted_checks() -> set:
	"""Names that workflows run on a pull request emit, as a ruleset spells them.

	Only workflows with a pull_request trigger count: a job of the weekly audit
	is also called `audit` and must not satisfy the ruleset for the pull request
	one. A reusable workflow counts only through the job that calls it.
	"""
	names = set()
	for path in sorted(WORKFLOWS.glob("*.yml")):
		doc = load_yaml(path)
		# YAML 1.1 reads the key `on` as the boolean True.
		trigger = doc.get("on", doc.get(True)) or {}
		if "pull_request" not in trigger:
			continue
		jobs = doc.get("jobs") or {}
		for job_id, job in jobs.items():
			caller = job.get("name", job_id)
			uses = job.get("uses", "")
			if uses.startswith("./.github/workflows/"):
				inner = load_yaml(ROOT / uses[2:]).get("jobs") or {}
				for inner_id, inner_job in inner.items():
					names.add(f"{caller} / {inner_job.get('name', inner_id)}")
			else:
				names.add(str(caller))
	return names


def check_required(findings: list) -> None:
	required = json.loads((ROOT / ".github" / "required-checks.json").read_text(encoding="utf-8"))
	emitted = emitted_checks()
	for branch, names in required.items():
		for name in names:
			if name not in emitted:
				findings.append(f"required check on {branch} is emitted by no workflow: {name!r}")


def check_suites_consumed(findings: list) -> None:
	cmap = json.loads((ROOT / ".github" / "ci-map.json").read_text(encoding="utf-8"))
	text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
	used = set(re.findall(r"needs\.decide\.outputs\.([a-z][a-z0-9-]*)", text))
	declared = set(load_yaml(WORKFLOWS / "ci.yml")["jobs"]["decide"].get("outputs", {}))
	for suite in cmap["suites"]:
		if suite not in used:
			findings.append(f"suite {suite!r} of the map is never read as needs.decide.outputs.{suite} in ci.yml")
		if suite not in declared:
			findings.append(f"suite {suite!r} of the map is not an output of the decide job in ci.yml")
	for name in sorted(used | declared):
		if name not in cmap["suites"]:
			findings.append(f"ci.yml reads the output {name!r}, which the map does not define as a suite")


def check_reusables_honour_run(findings: list) -> None:
	for path in sorted(WORKFLOWS.glob("reusable-*.yml")):
		doc = load_yaml(path)
		# YAML 1.1 reads the key `on` as the boolean True.
		trigger = doc.get("on", doc.get(True)) or {}
		inputs = (trigger.get("workflow_call") or {}).get("inputs") or {}
		if "run" not in inputs:
			continue
		for job_id, job in (doc.get("jobs") or {}).items():
			if "inputs.run != 'false'" not in str(job.get("if", "")):
				findings.append(f"{path.name}: job {job_id!r} takes the run input but its `if` does not test it")


def check_switches(findings: list) -> None:
	jobs = load_yaml(WORKFLOWS / "ci.yml")["jobs"]
	if not str((jobs.get("shell", {}).get("with") or {}).get("test-command", "")).strip():
		findings.append("ci.yml: the shell suite is called without test-command, so shell / test would skip and report success")
	threshold = (jobs.get("rust", {}).get("with") or {}).get("coverage-threshold", 0)
	if not isinstance(threshold, (int, float)) or threshold <= 0:
		findings.append("ci.yml: the Rust suite is called without a positive coverage-threshold, so rust / Coverage would skip and report success")


def check_gate(findings: list) -> None:
	"""`ci-gate` runs always and sees every other job of ci.yml."""
	jobs = load_yaml(WORKFLOWS / "ci.yml")["jobs"]
	gate = jobs.get("ci-gate")
	if gate is None:
		findings.append("ci.yml has no ci-gate job")
		return
	if str(gate.get("if", "")).replace(" ", "") != "${{always()}}":
		findings.append("ci.yml: ci-gate must run `if: ${{ always() }}`, or a skipped gate reports success")
	needs = set(gate.get("needs") or [])
	for job_id in jobs:
		if job_id == "ci-gate":
			continue
		if job_id not in needs:
			findings.append(f"ci.yml: ci-gate does not need {job_id!r}, so its result is not judged")


# The exact shape of how ci.yml feeds each suite and how ci-gate reads it back.
# A pair crossed by hand (rust given the plan of shell, rust's result read from
# the audit job) passes every check that only counts names, so the pairs are
# written here and compared whole.
SUITE_JOBS = {"workflow-lint": "workflows", "shell": "shell", "rust": "rust"}
GATE_RESULTS = {
	"DECIDE": "decide",
	"DCO": "dco",
	"WORKFLOW_LINT": "workflow-lint",
	"SHELL_SUITE": "shell",
	"RUST": "rust",
	"AUDIT": "audit",
}
GATE_PLANS = {"PLAN_WORKFLOWS": "workflows", "PLAN_SHELL": "shell", "PLAN_RUST": "rust"}
# The only entries ci.yml may pass to each reusable workflow. Anything else, a
# `tooling-isolation: false` or a `severity: error`, quietly changes what a
# required check looks at.
CALL_INPUTS = {
	"workflow-lint": {"run"},
	"shell": {"run", "test-command", "apt-packages"},
	"rust": {"run", "coverage-threshold"},
}
CALL_VALUES = {
	("shell", "test-command"): "./tests/run.sh",
	("shell", "apt-packages"): "python3-cryptography",
}
MIN_COVERAGE = 45
# Every line of the plan step that names the script or the map, word for word.
DECIDE_PATH_LINES = [
	'if ! git show "$BASE_SHA:.github/scripts/ci/decide.py" > "$tmp/decide.py" 2>/dev/null; then',
	'if ! git show "$BASE_SHA:.github/ci-map.json" > "$tmp/ci-map.json" 2>/dev/null; then',
	'cp .github/scripts/ci/decide.py .github/ci-map.json "$tmp/"',
	'out="$(python3 "$tmp/decide.py" --map "$tmp/ci-map.json" < "$tmp/changed")" || all "the decision script failed"',
]


def check_shape(findings: list) -> None:
	jobs = load_yaml(WORKFLOWS / "ci.yml")["jobs"]
	for job_id, suite in SUITE_JOBS.items():
		job = jobs.get(job_id, {})
		with_ = job.get("with") or {}
		if with_.get("run") != "${{ needs.decide.outputs." + suite + " }}":
			findings.append(f"ci.yml: job {job_id!r} must pass `run: ${{{{ needs.decide.outputs.{suite} }}}}`, the verdict of its own suite")
		extra = set(with_) - CALL_INPUTS[job_id]
		if extra:
			findings.append(f"ci.yml: job {job_id!r} passes {sorted(extra)} to its reusable workflow, which may take only {sorted(CALL_INPUTS[job_id])}")
		for (name, key), value in CALL_VALUES.items():
			if name == job_id and with_.get(key) != value:
				findings.append(f"ci.yml: job {job_id!r} must pass {key}: {value!r}")
	threshold = (jobs.get("rust", {}).get("with") or {}).get("coverage-threshold", 0)
	if not isinstance(threshold, int) or threshold < MIN_COVERAGE:
		findings.append(f"ci.yml: the coverage threshold must be an integer of at least {MIN_COVERAGE}, the ratchet never goes down")
	expected = {"EVENT": "${{ github.event_name }}"}
	expected.update({var: "${{ needs." + job + ".result }}" for var, job in GATE_RESULTS.items()})
	expected.update({var: "${{ needs.decide.outputs." + suite + " }}" for var, suite in GATE_PLANS.items()})
	if (jobs.get("ci-gate", {}).get("env") or {}) != expected:
		findings.append("ci.yml: the env of ci-gate is not the exact pairing of each result and each plan with its own job and suite")
	audit = jobs.get("audit", {})
	if "if" in audit or "needs" in audit:
		findings.append("ci.yml: the audit job has a condition or a dependency; it runs on every pull request and push, with no plan")
	steps = jobs.get("decide", {}).get("steps") or []
	run = "\n".join(str(step.get("run", "")) for step in steps)
	lines = [line.strip() for line in run.splitlines()]
	for line in lines:
		if (".github/scripts/ci/" in line or ".github/ci-map.json" in line) and line not in DECIDE_PATH_LINES:
			findings.append(f"ci.yml: the plan step has a line about the script or the map that is not one of the known ones: {line!r}")
	for line in DECIDE_PATH_LINES:
		if lines.count(line) != 1:
			findings.append(f"ci.yml: the plan step must contain exactly once: {line}")
	try:
		push_branch = lines.index('elif [ "$EVENT" = push ]; then')
		end = lines.index("else", push_branch)
		if not push_branch < lines.index(DECIDE_PATH_LINES[2]) < end:
			findings.append("ci.yml: the plan step reads the script from the checkout outside the push branch")
	except ValueError:
		findings.append("ci.yml: the plan step lost its push branch")
	printed = set()
	for line in lines:
		if line.startswith("printf '%s=true\\n'"):
			printed = set(line.split("true\\n'", 1)[1].split(">>", 1)[0].split())
	cmap = json.loads((ROOT / ".github" / "ci-map.json").read_text(encoding="utf-8"))
	if printed != set(cmap["suites"]):
		findings.append(f"ci.yml: the fallback of the plan step answers for {sorted(printed)} and the map has {sorted(cmap['suites'])}")


def main() -> int:
	findings: list = []
	try:
		check_required(findings)
		check_suites_consumed(findings)
		check_reusables_honour_run(findings)
		check_gate(findings)
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
