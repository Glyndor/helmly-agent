"""Rules about the release workflow and the weekly audit of another branch."""

import json
import re
import sys
from pathlib import Path

import yaml

from ci_wiring_core import *  # noqa: F403


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
				if str(step.get("uses", "")).startswith("actions/checkout") and "ref" in (step.get("with") or {}):
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


RELEASE_SIGN_RUN = (
	'bash "$GITHUB_WORKSPACE/.github/scripts/release/sign-artifacts.sh" '
	'"$RUNNER_TEMP/artifacts" "$RUNNER_TEMP/installers" "$RUNNER_TEMP/release"'
)


RELEASE_TAG_SHAPE = "^v[0-9]+\\.[0-9]+\\.[0-9]+$"


RELEASE_TAG_SOURCES = ("inputs.tag", "github.ref_name", "github.event.inputs")


SECRET_IN_EXPRESSION = re.compile(r"\$\{\{[^}]*\bsecrets\.(?!GITHUB_TOKEN\b)")
RELEASE_ORIGIN_GUARD = "push:refs/tags/v* | workflow_dispatch:refs/tags/v* | workflow_dispatch:refs/heads/main) ;;"


def check_secret_environments(findings: list) -> None:
	"""Every job that names a secret declares an environment, and the signing key sits in `release` only.

	`workflow_dispatch` lets whoever can push a branch start the workflow on it with their
	own scripts, and a condition in the file is theirs to edit. The environment, whose
	policy lives in the repository settings, is what limits the refs that can read the
	secret. A rehearsal reads none and so uses none.
	"""
	for path in workflow_files():
		for job_id, job in (load_yaml(path).get("jobs") or {}).items():
			named = bool(SECRET_IN_EXPRESSION.search("\n".join(strings(job)))) or "secrets" in job
			if named and not job.get("environment"):
				findings.append(f"{path.name}: job {job_id!r} names a secret and declares no environment")
	jobs = load_yaml(WORKFLOWS / "release.yml").get("jobs") or {}
	for job_id, job in jobs.items():
		has_key = "GLYNDOR_RELEASE_ED25519_KEY" in "\n".join(strings(job)) and "secrets." in "\n".join(strings(job))
		if job_id == "release":
			if job.get("environment") != "release":
				findings.append("release.yml: the job that signs must declare `environment: release`, exactly")
			first = (job.get("steps") or [{}])[0]
			if "uses" in first or RELEASE_ORIGIN_GUARD not in str(first.get("run", "")) or "secrets." in "\n".join(strings(first)):
				findings.append("release.yml: the first step of the signing job must be the secretless check of the event and the ref")
		elif "environment" in job and has_key:
			findings.append(f"release.yml: job {job_id!r} reads the key and is not the signing job")
		elif "environment" in job:
			findings.append(f"release.yml: job {job_id!r} declares an environment; only the signing job does, a rehearsal has none")


def check_release(findings: list) -> None:
	"""The release workflow: the tag is validated once, the key is read in one job, artifacts are data.

	Rules: no cache; no checkout of a ref (every job runs at the commit of the run, and a
	run that publishes must be at the tagged commit); the tag leaves `verify` as an output
	and no other job reads the event for it; only `release` can publish and read the
	secret, and a rehearsal signs with a key made in its own job; the artifacts are
	downloaded by name into a folder each under the runner's temp directory; the signing
	script is the one called, never sign.py; the signer's library comes from hashes; every
	Python of a step runs isolated.
	"""
	check_secret_environments(findings)
	doc = load_yaml(WORKFLOWS / "release.yml")
	jobs = doc.get("jobs") or {}
	where = "release.yml"
	text_of = lambda job: "\n".join(strings(job))  # noqa: E731
	for job_id, job in jobs.items():
		for step in job.get("steps") or []:
			uses = str(step.get("uses", ""))
			if uses.startswith("actions/cache"):
				findings.append(f"{where}: job {job_id!r} uses a cache; a release is built from nothing but the commit")
			if uses.startswith("actions/checkout") and "ref" in (step.get("with") or {}):
				findings.append(f"{where}: job {job_id!r} checks out a ref; every job runs at the commit of the run")
	verify = jobs.get("verify") or {}
	if (verify.get("outputs") or {}).get("tag") != "${{ steps.tag.outputs.tag }}":
		findings.append(f"{where}: verify must output the tag it validated, from the step with id `tag`")
	if (verify.get("outputs") or {}).get("sha") != "${{ inputs.dry_run && github.sha || steps.commit.outputs.sha }}":
		findings.append(f"{where}: verify must output the commit the tag resolved to, from the step with id `commit`, and fall back to the run's commit for a rehearsal only")
	commit_steps = [step for step in verify.get("steps") or [] if step.get("id") == "commit"]
	commit_lines = [line.strip() for line in str((commit_steps or [{}])[0].get("run", "")).splitlines()]
	if (
		len(commit_steps) != 1
		or commit_lines.count('sha="$(bash .github/scripts/release/resolve-tag.sh "$TAG" "$RUN_SHA")"') != 1
		or commit_lines.count('[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::the tag did not resolve to a commit"; exit 1; }') != 1
		or commit_lines.count('echo "sha=$sha" >> "$GITHUB_OUTPUT"') != 1
		or any("$(" in line for line in commit_lines if line.startswith("echo"))
	):
		findings.append(f"{where}: the step with id `commit` must assign the output of resolve-tag.sh first, check it is 40 hex digits, and only then write it (a command substitution inside echo hides its exit status)")
	release_text = "\n".join(str(s.get("run", "")) for s in (jobs.get("release") or {}).get("steps") or [])
	if '[[ "$VERIFIED_SHA" =~ ^[0-9a-f]{40}$ ]]' not in release_text:
		findings.append(f"{where}: the release job must refuse a verified commit that is not 40 hex digits")
	tag_steps = [step for step in verify.get("steps") or [] if step.get("id") == "tag"]
	if len(tag_steps) != 1 or RELEASE_TAG_SHAPE not in str(tag_steps[0].get("run", "")):
		findings.append(f"{where}: the step with id `tag` must check the tag against {RELEASE_TAG_SHAPE}")
	for job_id, job in jobs.items():
		if job_id != "verify" and any(source in text_of(job) for source in RELEASE_TAG_SOURCES):
			findings.append(f"{where}: job {job_id!r} reads the tag from the event; it takes it from needs.verify.outputs.tag")
	# every job depends on verify, directly or through another job
	def reaches_verify(job_id: str, seen: frozenset = frozenset()) -> bool:
		needs = jobs[job_id].get("needs") or []
		needs = [needs] if isinstance(needs, str) else needs
		return "verify" in needs or any(n not in seen and reaches_verify(n, seen | {job_id}) for n in needs)
	for job_id in jobs:
		if job_id != "verify" and not reaches_verify(job_id):
			findings.append(f"{where}: job {job_id!r} does not depend on verify, so it could run on a tag that was never validated")
	release = jobs.get("release") or {}
	dry = jobs.get("sign-dry-run") or {}
	build = jobs.get("build") or {}
	if str(release.get("if", "")).replace(" ", "") != "${{!inputs.dry_run}}":
		findings.append(f"{where}: release must run only when dry_run is not set")
	if str(dry.get("if", "")).replace(" ", "") != "${{inputs.dry_run}}":
		findings.append(f"{where}: the rehearsal must run only when dry_run is set")
	for job_id, job in jobs.items():
		if "secrets." in text_of(job) and job_id != "release":
			findings.append(f"{where}: job {job_id!r} reads a secret; only release signs with the release key")
		if (job.get("permissions") or {}).get("contents") == "write" and job_id != "release":
			findings.append(f"{where}: job {job_id!r} can write to the repository; only release publishes")
	if text_of(release).count("secrets.GLYNDOR_RELEASE_ED25519_KEY") != 1:
		findings.append(f"{where}: release must read the release key exactly once, in the signing step")
	if "add-mask" not in text_of(dry) or "throwaway" not in text_of(dry):
		findings.append(f"{where}: the rehearsal must make a masked throwaway key in its own job")
	for job_id in ("release", "sign-dry-run", "attest"):
		job = jobs.get(job_id) or {}
		downloads = [step.get("with") or {} for step in job.get("steps") or [] if str(step.get("uses", "")).startswith("actions/download-artifact")]
		expected = [{"name": f"agent-{arch}", "path": f"${{{{ runner.temp }}}}/artifacts/{arch}"} for arch in ("x86_64", "arm64")]
		if downloads != expected:
			findings.append(f"{where}: job {job_id!r} must download exactly the two named artifacts, one folder each under runner.temp/artifacts, merged into nothing")
		if job_id == "attest":
			continue
		sign = [step for step in job.get("steps") or [] if step.get("name") == "Sign"]
		if len(sign) != 1 or str(sign[0].get("run", "")).strip() != RELEASE_SIGN_RUN:
			findings.append(f"{where}: job {job_id!r} must sign by running the signing script on the three directories and nothing else")
		elif (sign[0].get("env") or {}).get("SIGN_PYTHON") != "${{ runner.temp }}/signvenv/bin/python":
			findings.append(f"{where}: job {job_id!r} must run the signer with the interpreter of the venv")
	for job_id, job in jobs.items():
		for step in job.get("steps") or []:
			run = str(step.get("run", ""))
			for line in run.splitlines():
				code = line.strip()
				if "sign.py" in code and "sign-artifacts" not in code and "verify" not in code:
					findings.append(f"{where}: job {job_id!r} calls sign.py itself: {code!r}")
				if "pip install" in code and not ("--require-hashes" in code and "--only-binary=:all:" in code and "sign-requirements.txt" in code):
					findings.append(f"{where}: job {job_id!r} installs a library without hashes on one line: {code!r}")
				for match in re.finditer(r"(?:python3?|signvenv/bin/python)\"?\s+(\S+)", code):
					if code.startswith("#"):
						continue
					if match.group(1) not in ("-I", "-m", "-"):
						findings.append(f"{where}: job {job_id!r} runs Python without -I: {code!r}")
	rel_runs = [str(step.get("run", "")) for step in release.get("steps") or []]
	if not any('resolve-tag.sh "$TAG" "$VERIFIED_SHA"' in run for run in rel_runs) or sum('resolve-tag.sh' in run for run in rel_runs) < 2:
		findings.append(f"{where}: release must check the tag against the verified commit before it signs and again before it publishes")
	if not any('"$RUN_SHA" = "$VERIFIED_SHA"' in run for run in rel_runs):
		findings.append(f"{where}: release must check that the run is at the commit verify resolved")
	create = [run for run in rel_runs if "gh release create" in run]
	if len(create) != 1 or "--verify-tag" not in create[0] or "--target" in create[0]:
		findings.append(f"{where}: the release is created with --verify-tag and without --target, so it never makes a tag of its own")
	order = [step.get("name", "") for step in release.get("steps") or []]
	if "The tag still points at the commit that was verified" not in order or order.index("The tag still points at the commit that was verified") > order.index("Create GitHub Release"):
		findings.append(f"{where}: the tag must be checked again right before the release is created")
	attest = jobs.get("attest") or {}
	if str(attest.get("if", "")).replace(" ", "") != "${{!inputs.dry_run}}":
		findings.append(f"{where}: attest must not run in a rehearsal")
	if "release" in jobs and "attest" not in ((release.get("needs") or []) if isinstance(release.get("needs"), list) else [release.get("needs")]):
		findings.append(f"{where}: release must wait for the attestation")
	for job_id, job in jobs.items():
		perms = job.get("permissions") or {}
		for scope in ("id-token", "attestations", "packages"):
			if perms.get(scope) == "write" and job_id != "attest":
				findings.append(f"{where}: job {job_id!r} holds {scope}: write; only attest, which compiles nothing, does")
	if (build.get("permissions") or {}) != {"contents": "read"}:
		findings.append(f"{where}: build compiles and installs tools, so it holds only contents: read")
	if jobs.get("sign-dry-run", {}).get("permissions"):
		findings.append(f"{where}: the rehearsal must get no permissions of its own")
	for step in attest.get("steps") or []:
		if str(step.get("uses", "")).startswith("actions/checkout") or "cargo" in str(step.get("run", "")):
			findings.append(f"{where}: attest must only download, check and attest; it does not check out or build")
	if "cargo install cross --locked --version" not in text_of(build):
		findings.append(f"{where}: cross must be installed at a pinned version")
