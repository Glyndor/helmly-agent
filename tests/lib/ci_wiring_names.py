"""Rules about check names: what each ruleset requires is produced once, by one event, and no name is left unresolved."""

import json
import re
import sys
from pathlib import Path

import yaml

from ci_wiring_core import *  # noqa: F403
from ci_wiring_core import _no_duplicate_keys  # noqa: F401


# The events that run for a pull request, with the base it is aimed at. A required name must be
# produced by one of them, once, and by no other workflow.
PR_EVENTS = ("pull_request", "pull_request_target")


def check_required(findings: list) -> None:
	"""Each required check is produced by exactly one workflow and one event, for the base it guards.

	The push run of develop and the promotion pull request into main share a
	commit, and a skipped job still reports its name and counts as passed, so a name
	two events (or two bases with different plans) share lets one result satisfy
	the other's requirement. Jobs with an `if` that skips them are counted.
	"""
	required = json.loads((ROOT / ".github" / "required-checks.json").read_text(encoding="utf-8"))
	made = {}
	for name, who in producers()[0].items():
		# GitHub does not tell names apart by case, so neither does the index.
		made.setdefault(name.lower(), set()).update(who)
	for branch, names in required.items():
		for name in names:
			relevant = {(wf, ev) for wf, ev, base in made.get(name.lower(), set()) if ev not in PR_EVENTS or base in (branch, "*")}
			if not any(ev in PR_EVENTS for _, ev in relevant):
				findings.append(f"required check on {branch} is emitted by no workflow: {name!r}")
			elif len(relevant) > 1:
				findings.append(f"required check {name!r} on {branch} is produced by more than one workflow or event: {sorted(relevant)}")
	names_by_branch = {name: branch for branch, names in required.items() for name in names}
	if len(names_by_branch) != sum(len(names) for names in required.values()):
		findings.append("a check name is required on both develop and main; the two bases carry different plans, so each ruleset needs its own name")


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
