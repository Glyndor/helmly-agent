"""Rules about ci.yml: the plan, the gate, the shape of each suite call, the triggers and the token."""

import json
import re
import sys
from pathlib import Path

import yaml

from ci_wiring_core import *  # noqa: F403


def check_suites_consumed(findings: list) -> None:
	cmap = json.loads((ROOT / ".github" / "ci-map.json").read_text(encoding="utf-8"))
	used = set()
	for text in strings(load_yaml(WORKFLOWS / "ci.yml")):
		used.update(re.findall(r"needs\.decide\.outputs\.([a-z][a-z0-9-]*)", text))
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
	for path in workflow_files():
		if not path.name.startswith("reusable-"):
			continue
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


def check_triggers(findings: list) -> None:
	"""The events that rerun a pull request, and the guard against a fork's `develop`.

	ci.yml reruns on opened, synchronize and reopened only. `edited` would rerun the
	whole CI and cancel the one in flight each time a title or body is corrected; it
	is not needed because the gate is named by base branch, so a retargeted pull
	request has no check of the name its new ruleset requires until a run exists.
	main-guard is cheap and also reruns on `edited`.
	"""
	for name, expected in (("ci.yml", {"opened", "synchronize", "reopened"}), ("main-guard.yml", {"opened", "synchronize", "reopened", "edited"})):
		doc = load_yaml(WORKFLOWS / name)
		on = doc.get("on", doc.get(True)) or {}
		types = set(((on.get("pull_request") or {}).get("types")) or [])
		if types != expected:
			findings.append(f"{name}: pull_request types must be exactly {sorted(expected)}, not {sorted(types)}")
	guard = load_yaml(WORKFLOWS / "main-guard.yml")["jobs"].get("develop-only", {})
	steps = guard.get("steps") or [{}]
	env = steps[-1].get("env") or {}
	run = str(steps[-1].get("run", ""))
	if env.get("HEAD_REPO") != "${{ github.event.pull_request.head.repo.full_name }}" or env.get("THIS_REPO") != "${{ github.repository }}" or '"$HEAD_REPO" != "$THIS_REPO"' not in run:
		findings.append("main-guard.yml: develop-only must compare the head repository with this repository, since a fork can have a branch called develop")


def check_gate(findings: list) -> None:
	"""`ci-gate` runs always and sees every other job of ci.yml."""
	jobs = load_yaml(WORKFLOWS / "ci.yml")["jobs"]
	if (jobs.get("ci-gate") or {}).get("name") != GATE_NAME:
		findings.append("ci.yml: ci-gate must carry the known name expression, which gives it a different name for each event and for a base of main")
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
	"STRUCTURE": "structure",
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
	'out="$(python3 -I "$tmp/decide.py" --map "$tmp/ci-map.json" < "$tmp/changed")" || all "the decision script failed"',
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
	structure = jobs.get("structure", {})
	if set(structure.get("needs") or []) != {"dco", "workflow-lint", "shell"} or "outputs.structure" in str(structure.get("if", "")):
		findings.append("ci.yml: the structure job must wait for the three cheap gates and have no plan of its own")
	step = (structure.get("steps") or [{}, {}])[-1]
	run = str(step.get("run", ""))
	for needle in ('git show "$BASE_SHA:.github/scripts/ci/structure.py"', 'git show "$BASE_SHA:.github/structure.json"', 'python3 .github/scripts/ci/structure.py --exceptions .github/structure.json || bad=1', 'python3 "$tmp/structure.py" --exceptions "$tmp/structure.json" || bad=1'):
		if needle not in run:
			findings.append(f"ci.yml: the structure step must judge with both copies, and is missing: {needle}")
	steps = jobs.get("decide", {}).get("steps") or []
	run = "\n".join(str(step.get("run", "")) for step in steps)
	lines = [line.strip() for line in run.splitlines()]
	for line in lines:
		if (".github/scripts/ci/" in line or ".github/ci-map.json" in line) and line not in DECIDE_PATH_LINES:
			findings.append(f"ci.yml: the plan step has a line about the script or the map that is not one of the known ones: {line!r}")
	for line in DECIDE_PATH_LINES:
		if lines.count(line) != 1:
			findings.append(f"ci.yml: the plan step must contain exactly once: {line}")
	plan_env = (steps[-1].get("env") or {}) if steps else {}
	if lines.count('if [ "$BASE_REF" = main ]; then') != 1 or plan_env.get("BASE_REF") != "${{ github.event.pull_request.base.ref }}":
		findings.append("ci.yml: the plan step must answer `true` for every suite when the pull request's base is main")
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


def actions_permission(perms: object) -> str:
	"""`write`, `read` or `none` for the `actions` scope of a permissions value."""
	if perms == "write-all":
		return "write"
	if perms == "read-all":
		return "read"
	if isinstance(perms, dict):
		return str(perms.get("actions", "none"))
	return "none"


def check_write_token(findings: list) -> None:
	"""No job writes to Actions: nothing in this repository cancels or starts runs."""
	for path in sorted(WORKFLOWS.glob("*.yml")):
		doc = load_yaml(path)
		if "permissions" not in doc:
			findings.append(f"{path.name}: declares no top-level permissions, so its token is whatever the repository default is")
		if actions_permission(doc.get("permissions")) == "write":
			findings.append(f"{path.name}: the token can write to Actions at workflow level")
		for job_id, job in (doc.get("jobs") or {}).items():
			effective = job["permissions"] if "permissions" in job else doc.get("permissions")
			if actions_permission(effective) == "write":
				findings.append(f"{path.name}: job {job_id!r} can write to Actions")


def check_tests_run_once(findings: list) -> None:
	"""The Rust suite builds and runs the tests once: Test only without a threshold, Coverage after lint."""
	jobs = load_yaml(WORKFLOWS / "reusable-rust-ci.yml")["jobs"]
	if "inputs.coverage-threshold == 0" not in str(jobs.get("test", {}).get("if", "")):
		findings.append("reusable-rust-ci.yml: the Test job must run only when there is no coverage threshold, or the suite is built and run twice")
	if jobs.get("coverage", {}).get("needs") != "lint":
		findings.append("reusable-rust-ci.yml: Coverage must need only the lint job, which is the cheap gate before the one build of the tests")
	if jobs.get("test", {}).get("needs") != "lint":
		findings.append("reusable-rust-ci.yml: Test must need the lint job")


def check_suite_jobs_start(findings: list) -> None:
	"""Each suite job starts even if the plan failed, and skips only on an explicit `false`."""
	jobs = load_yaml(WORKFLOWS / "ci.yml")["jobs"]
	for job_id in ("workflow-lint", "shell", "rust"):
		condition = str(jobs.get(job_id, {}).get("if", ""))
		if "!cancelled()" not in condition:
			findings.append(f"ci.yml: job {job_id!r} has no `!cancelled()` in its `if`, so a failed plan would leave it skipped and green")
		if "== 'true'" in condition:
			findings.append(f"ci.yml: job {job_id!r} runs only on an explicit true; a missing plan must run it")


def check_event_values_via_env(findings: list) -> None:
	for path in sorted(WORKFLOWS.glob("*.yml")):
		for job_id, job in (load_yaml(path).get("jobs") or {}).items():
			for step in job.get("steps") or []:
				if re.search(r"\$\{\{\s*(?:github\.event\.|github\.head_ref)", str(step.get("run", ""))):
					findings.append(f"{path.name}: job {job_id!r} puts a github.event value inside run:, not env:")
