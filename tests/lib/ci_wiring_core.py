"""Loading and naming: the strict YAML reader, the one enumerator of workflows and actions, and the check names each job produces."""

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
