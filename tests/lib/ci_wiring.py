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
"""

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class StrictLoader(yaml.SafeLoader):
	"""A safe YAML loader that refuses a mapping with the same key twice.

	GitHub keeps the last of two equal keys and says nothing, so a reader that
	keeps the first (or a regular expression that sees both) validates a file
	other than the one that runs.
	"""


def _no_duplicate_keys(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
	seen = set()
	for key_node, _ in node.value:
		key = loader.construct_object(key_node, deep=deep)
		if key in seen:
			raise ValueError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
		seen.add(key)
	return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


def workflow_files() -> list:
	"""Every workflow file, with both suffixes and at any depth.

	GitHub runs only the top level of .github/workflows, so a file deeper down
	is reported by check_layout. The one enumerator, so that what the validator
	compares is what GitHub could run: a file this does not list is never checked.
	"""
	return sorted(p for p in WORKFLOWS.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml"))


def action_files() -> list:
	return sorted(p for p in (ROOT / ".github").rglob("action.y*ml") if p.is_file() and p.name in ("action.yml", "action.yaml"))


def load_yaml(path: Path) -> dict:
	with open(path, encoding="utf-8") as fh:
		data = yaml.load(fh, Loader=StrictLoader)  # noqa: S506 (a safe subclass)
	if not isinstance(data, dict):
		raise ValueError(f"{path} is not a mapping")
	return data


PR_ONLY = "${{ github.event_name == 'pull_request' }}"
# The one `name:` expression ci.yml uses, with what it resolves to for each
# event and base branch. Every other `name:` with an expression is a finding
# unless it is a matrix name this file can expand.
GATE_NAME = (
	"${{ github.event_name == 'pull_request' && (github.event.pull_request.base.ref == 'main' && 'ci-gate (main)' || 'ci-gate')"
	" || format('ci-gate ({0})', github.event_name) }}"
)
MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def triggers(doc: dict) -> dict:
	"""event -> the base branches it is limited to ('*' for no limit). The key `on` is the boolean True in YAML 1.1."""
	on = doc.get("on", doc.get(True)) or {}
	if isinstance(on, str):
		return {on: ["*"]}
	if isinstance(on, list):
		return {event: ["*"] for event in on}
	found = {}
	for event, config in on.items():
		branches = ["*"]
		if event == "pull_request" and isinstance(config, dict) and config.get("branches"):
			branches = list(config["branches"])
		found[event] = branches
	return found


def expand_name(raw: str, job: dict, event: str, base: str) -> list:
	"""The names a job's check carries, or [] when the expression cannot be resolved."""
	if "${{" not in raw:
		return [raw]
	if raw == GATE_NAME:
		if event == "pull_request":
			return ["ci-gate (main)" if base == "main" else "ci-gate"]
		return [f"ci-gate ({event})"]
	matrix = ((job.get("strategy") or {}).get("matrix")) or {}
	keys = set(MATRIX_REF.findall(raw))
	if not keys or "${{" in MATRIX_REF.sub("", raw) or not isinstance(matrix, dict):
		return []
	axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
	if any(not isinstance(v, list) for v in axes.values()) or (isinstance(matrix.get("include"), str)):
		return []
	combos = [dict()] if axes else []
	for key, values in axes.items():
		combos = [dict(c, **{key: v}) for c in combos for v in values]
	combos += [dict(c) for c in (matrix.get("include") or []) if isinstance(c, dict)]
	names = []
	for combo in combos:
		if not keys <= set(combo):
			return []
		names.append(MATRIX_REF.sub(lambda m: str(combo[m.group(1)]), raw))
	return names


def emitted(path_name: str, job_id: str, job: dict, event: str, base: str, prefix: str, problems: list) -> list:
	"""Names one job makes appear for one event, a skipped job included.

	A job whose `if` is false still reports its check, and GitHub counts a
	skipped check as passed, so a skipped job is not "emitting nothing". A skipped
	caller of a reusable workflow reports its own name and none of the inner ones.
	"""
	raw = str(job.get("name", job_id))
	names = expand_name(raw, job, event, base)
	if not names:
		problems.append(f"{path_name}: job {job_id!r} has a name with an expression this validator cannot resolve: {raw!r}")
		names = [raw]
	callers = [prefix + n for n in names]
	uses = str(job.get("uses", ""))
	skipped_here = str(job.get("if", "")).strip() == PR_ONLY and event != "pull_request"
	if uses.startswith("./.github/workflows/") and not skipped_here:
		out = []
		inner_doc = load_yaml(ROOT / uses[2:])
		for inner_id, inner_job in (inner_doc.get("jobs") or {}).items():
			for caller in callers:
				out += emitted(uses, inner_id, inner_job, event, base, caller + " / ", problems)
		return out
	if uses and not uses.startswith("./"):
		problems.append(f"{path_name}: job {job_id!r} calls the remote workflow {uses!r}, whose check names this validator cannot see; callers: {callers}")
	return callers


def producers() -> tuple:
	"""(check name -> set of (workflow, event, base branch), problems found while resolving names)."""
	found: dict = {}
	problems: list = []
	for path in workflow_files():
		doc = load_yaml(path)
		for event, bases in triggers(doc).items():
			if event == "workflow_call":
				continue
			for base in bases:
				for job_id, job in (doc.get("jobs") or {}).items():
					for name in emitted(path.name, job_id, job, event, base, "", problems):
						found.setdefault(name, set()).add((path.name, event, base))
	return found, sorted(set(problems))


def check_required(findings: list) -> None:
	"""Each required check is produced by exactly one workflow and one event, for the base it guards.

	The push run of develop and the promotion pull request into main share a
	commit, and a skipped job still reports its name and counts as passed, so a name
	two events (or two bases with different plans) share lets one result satisfy
	the other's requirement. Jobs with an `if` that skips them are counted.
	"""
	required = json.loads((ROOT / ".github" / "required-checks.json").read_text(encoding="utf-8"))
	made, _ = producers()
	for branch, names in required.items():
		for name in names:
			relevant = {(wf, ev) for wf, ev, base in made.get(name, set()) if ev != "pull_request" or base in (branch, "*")}
			if not any(ev == "pull_request" for _, ev in relevant):
				findings.append(f"required check on {branch} is emitted by no workflow: {name!r}")
			elif len(relevant) > 1:
				findings.append(f"required check {name!r} on {branch} is produced by more than one workflow or event: {sorted(relevant)}")
	names_by_branch = {name: branch for branch, names in required.items() for name in names}
	if len(names_by_branch) != sum(len(names) for names in required.values()):
		findings.append("a check name is required on both develop and main; the two bases carry different plans, so each ruleset needs its own name")


# A tag checkout in the release workflow is the ref of the event itself (a pushed
# tag, or the tag a dispatch names), and tags are protected by their own ruleset.
EVENT_REF = "${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}"
SCHEDULED_BRANCHES = ["main", "develop"]
SCHEDULED_GIT_LINES = [
	'git show "origin/${BRANCH}:Cargo.lock" > "$dir/Cargo.lock"',
	'git show "origin/${BRANCH}:.cargo/audit.toml" > "$dir/.cargo/audit.toml"',
]


def check_foreign_refs(findings: list) -> None:
	"""No job checks out a ref other than the event's.

	A checkout of another ref brings code of that ref into a job that may hold the
	privileges of the event, and CodeQL calls it actions/cache-poisoning/
	poisonable-step. The weekly audit of develop and main takes two files out of git
	instead (see check_scheduled_audit).
	"""
	for path in workflow_files():
		for job_id, job in (load_yaml(path).get("jobs") or {}).items():
			for step in job.get("steps") or []:
				if str(step.get("uses", "")).startswith("actions/checkout") and (step.get("with") or {}).get("ref") not in (None, EVENT_REF):
					findings.append(f"{path.name}: job {job_id!r} fetches another ref with a checkout; take the files it needs out of git as data")


def check_scheduled_audit(findings: list) -> None:
	"""The weekly audit of another branch reads a lockfile and a config out of git, and runs nothing of that branch."""
	job = (load_yaml(WORKFLOWS / "audit.yml").get("jobs") or {}).get("audit") or {}
	steps = job.get("steps") or []
	where = "audit.yml: job 'audit'"
	if ((job.get("strategy") or {}).get("matrix") or {}).get("branch") != SCHEDULED_BRANCHES:
		findings.append(f"{where} must audit exactly the fixed branches {SCHEDULED_BRANCHES}")
	checkouts = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout")]
	if len(checkouts) != 1 or "ref" in (checkouts[0].get("with") or {}):
		findings.append(f"{where} must have exactly one checkout, the event's own, with no ref")
	for step in steps:
		uses = str(step.get("uses", ""))
		if uses.startswith("actions/cache") or uses.startswith("actions/setup-") or "cache" in (step.get("with") or {}):
			findings.append(f"{where} uses a cache ({uses or step.get('name')}); a scheduled job installs clean")
		if uses.startswith("./") and uses != "./.github/actions/cargo-audit":
			findings.append(f"{where} runs a local action other than the audit action: {uses}")
		if uses == "./.github/actions/cargo-audit" and set(step.get("with") or {}) != {"lockfile"}:
			findings.append(f"{where} must call the audit action with the lockfile input and nothing else")
	runs = [str(step.get("run", "")) for step in steps if "run" in step]
	if any("${{" in run for run in runs):
		findings.append(f"{where} puts an expression inside run:; the branch name reaches the shell through env")
	lines = [line.strip() for run in runs for line in run.splitlines() if "git show" in line]
	if lines != SCHEDULED_GIT_LINES:
		findings.append(f"{where} must take out of git exactly the lockfile and the audit configuration, and these lines: {SCHEDULED_GIT_LINES}")
	if any("cargo-deny" in run or "cargo deny" in run for run in runs):
		findings.append(f"{where} must not run cargo-deny, which reads the manifests of the tree")


def check_names(findings: list) -> None:
	"""Fail closed on names: an expression this file cannot resolve could equal a required name."""
	_, problems = producers()
	findings.extend(problems)


def check_layout(findings: list) -> None:
	"""GitHub runs only the top level of .github/workflows, and only workflows with a trigger."""
	for path in workflow_files():
		if path.parent != WORKFLOWS:
			findings.append(f"{path.relative_to(ROOT)}: GitHub never runs a workflow below .github/workflows, and a validator would compare it as if it ran")
	for path in action_files():
		doc = load_yaml(path)
		for step in (doc.get("runs") or {}).get("steps") or []:
			if str(step.get("uses", "")).startswith("actions/cache"):
				findings.append(f"{path.relative_to(ROOT)}: a security tool is downloaded and checked on every run, never restored from a cache")
	for path in workflow_files():
		doc = load_yaml(path)
		for job_id, job in (doc.get("jobs") or {}).items():
			is_audit = job_id == "audit" or any(
				str(step.get("uses", "")) == "./.github/actions/cargo-audit" for step in job.get("steps") or []
			)
			if is_audit and any(str(step.get("uses", "")).startswith("actions/cache") for step in job.get("steps") or []):
				findings.append(f"{path.name}: job {job_id!r} restores a cache next to a security tool")


def strings(node: object):
	"""Every string of a parsed document, keys and values."""
	if isinstance(node, str):
		yield node
	elif isinstance(node, dict):
		for key, value in node.items():
			yield from strings(key)
			yield from strings(value)
	elif isinstance(node, list):
		for item in node:
			yield from strings(item)


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
def main() -> int:
	findings: list = []
	try:
		check_required(findings)
		check_layout(findings)
		check_names(findings)
		check_foreign_refs(findings)
		check_scheduled_audit(findings)
		check_suites_consumed(findings)
		check_reusables_honour_run(findings)
		check_triggers(findings)
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
