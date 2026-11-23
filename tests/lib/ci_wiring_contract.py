"""The execution contract: everything that changes how a suite runs is pinned by equality.

A test that looks for the command in a step accepts `echo 'the command'`, and a check
of a name accepts a changed condition. So the properties that change execution are fixed
here exactly, and a property this file does not know is a finding: `continue-on-error`
(a failing step that leaves the job green), `defaults` and `shell` (a shell that exits
without reading the script), the whole `if` of each job and step, the environment that ties
the plan's commits to their expression, the outputs of the plan, the conditions and commands
of the audit action, the conditions of the reusable Rust workflow, whose caller reads
only one result in which a skipped job counts as passed, and the database the Rust tests run
against, without which the authentication tests skip themselves.
"""

import re

from ci_wiring_core import *  # noqa: F403

CI_JOB_IFS = {
	"dco": "${{ github.event_name == 'pull_request' }}",
	"workflow-lint": "${{ !cancelled() }}",
	"shell": "${{ !cancelled() }}",
	"rust": "${{ !cancelled() && (github.event_name != 'pull_request' || (needs.dco.result != 'failure' && needs.workflow-lint.result != 'failure' && needs.shell.result != 'failure')) }}",
	"structure": "${{ !cancelled() && (github.event_name != 'pull_request' || (needs.dco.result != 'failure' && needs.workflow-lint.result != 'failure' && needs.shell.result != 'failure')) }}",
	"pins": "${{ !cancelled() && (github.event_name != 'pull_request' || (needs.dco.result != 'failure' && needs.workflow-lint.result != 'failure' && needs.shell.result != 'failure')) }}",
	"ci-gate": "${{ always() }}",
}
CI_JOBS_WITHOUT_IF = {"decide", "audit"}
PLAN_ENV = {
	"EVENT": "${{ github.event_name }}",
	"BASE_REF": "${{ github.event.pull_request.base.ref }}",
	"BASE_SHA": "${{ github.event.pull_request.base.sha }}",
	"HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
	"BEFORE_SHA": "${{ github.event.before }}",
	"AFTER_SHA": "${{ github.sha }}",
}
PLAN_OUTPUTS = {
	"rust": "${{ steps.decide.outputs.rust }}",
	"shell": "${{ steps.decide.outputs.shell }}",
	"workflows": "${{ steps.decide.outputs.workflows }}",
}
RUST_JOB_IFS = {
	"lint": "${{ inputs.run != 'false' }}",
	"test": "${{ inputs.run != 'false' && inputs.coverage-threshold == 0 }}",
	"coverage": "${{ inputs.run != 'false' && inputs.coverage-threshold > 0 }}",
	"outcome": "${{ always() }}",
	"msrv-gate": "${{ inputs.run != 'false' }}",
	"extra-platforms-gate": "${{ inputs.run != 'false' }}",
}
OUTCOME_ENV = {
	"RUN": "${{ inputs.run }}",
	"THRESHOLD": "${{ inputs.coverage-threshold }}",
	"LINT": "${{ needs.lint.result }}",
	"TEST": "${{ needs.test.result }}",
	"COVERAGE": "${{ needs.coverage.result }}",
}
# The database service of the jobs that run the Rust tests. The image is the official one at
# the major the installer runs, by digest; the tests migrate the database themselves and
# fail under CI when there is none (internal/auth/test_db.rs), so the variables are pinned
# whole and `CI` may not be set by hand.
POSTGRES_IMAGE = re.compile(r"^postgres:18@sha256:[0-9a-f]{64}$")
POSTGRES_ENV = {"POSTGRES_PASSWORD": "postgres", "POSTGRES_DB": "helmly_test"}
DATABASE_JOB_ENV = {
	"DATABASE_URL": "postgres://postgres:postgres@localhost:5432/helmly_test",
	"SQLX_OFFLINE": "true",
}
DATABASE_JOBS = ("test", "coverage")
# The steps of the audit action that run a tool, and the condition and command of each.
AUDIT_STEPS = {
	"Install the toolchain": ("${{ inputs.lockfile == '' }}", "rustup toolchain install"),
	"cargo audit": ("${{ inputs.lockfile == '' }}", "cargo audit --deny warnings"),
	"cargo deny": ("${{ inputs.lockfile == '' }}", "cargo deny check"),
}
AUDIT_LOCKFILE_STEP = "cargo audit, on a lockfile alone"
AUDIT_LOCKFILE_IF = "${{ inputs.lockfile != '' }}"
AUDIT_LOCKFILE_LAST = 'cargo-audit audit --deny warnings --file "$LOCKFILE"'


# The only defaults any workflow sets, by file and job (None for the workflow level). The
# working directory a reusable shell workflow scans, and bash for a workflow that only
# reads an API; any other `defaults`, a shell above all, is a finding.
ALLOWED_DEFAULTS = {
	("reusable-shell-ci.yml", "shellcheck"): {"run": {"working-directory": "${{ inputs.working-directory }}"}},
	("reusable-shell-ci.yml", "test"): {"run": {"working-directory": "${{ inputs.working-directory }}"}},
	("reusable-dependabot-freshness.yml", None): {"run": {"shell": "bash"}},
}


def _walk_jobs(doc: dict):
	for job_id, job in (doc.get("jobs") or {}).items():
		yield job_id, job
		for step in job.get("steps") or []:
			yield f"{job_id}/step", step


def check_no_continue_on_error(findings: list) -> None:
	for path in workflow_files() + action_files():
		doc = load_yaml(path)
		nodes = list(_walk_jobs(doc)) if "jobs" in doc else [(f"step {s.get('name')}", s) for s in (doc.get("runs") or {}).get("steps") or []]
		for where, node in nodes:
			if "continue-on-error" in node:
				findings.append(f"{path.name}: {where!r} sets continue-on-error, which leaves a job green when its script fails")


def check_defaults_and_shell(findings: list) -> None:
	for path in workflow_files():
		doc = load_yaml(path)
		if "defaults" in doc and doc["defaults"] != ALLOWED_DEFAULTS.get((path.name, None)):
			findings.append(f"{path.name}: sets defaults at workflow level that are not the pinned ones; a shell that exits at once leaves every step green")
		for job_id, job in (doc.get("jobs") or {}).items():
			if "defaults" in job and job["defaults"] != ALLOWED_DEFAULTS.get((path.name, job_id)):
				findings.append(f"{path.name}: job {job_id!r} sets defaults that are not the pinned ones; a shell that exits at once leaves its steps green")
			for step in job.get("steps") or []:
				if "shell" in step:
					findings.append(f"{path.name}: job {job_id!r} sets a shell on a step; the runner's own shell reads the script")
	for path in action_files():
		for step in (load_yaml(path).get("runs") or {}).get("steps") or []:
			if "run" in step and step.get("shell") != "bash":
				findings.append(f"{path.name}: step {step.get('name')!r} must run with shell: bash exactly")


def check_ci_contract(findings: list) -> None:
	ci = load_yaml(WORKFLOWS / "ci.yml")
	jobs = ci.get("jobs") or {}
	for job_id, job in jobs.items():
		expected = CI_JOB_IFS.get(job_id)
		if job_id in CI_JOBS_WITHOUT_IF:
			if "if" in job:
				findings.append(f"ci.yml: job {job_id!r} carries a condition; it has none")
		elif expected is None:
			findings.append(f"ci.yml: job {job_id!r} is not part of the contract")
		elif job.get("if") != expected:
			findings.append(f"ci.yml: the condition of job {job_id!r} is not the pinned one")
		for step in job.get("steps") or []:
			if "if" in step:
				findings.append(f"ci.yml: job {job_id!r} has a step with a condition; none is expected")
	decide = jobs.get("decide") or {}
	if decide.get("outputs") != PLAN_OUTPUTS:
		findings.append("ci.yml: the outputs of decide are not exactly the verdict of each suite")
	plan_steps = [step for step in decide.get("steps") or [] if step.get("id") == "decide"]
	if len(plan_steps) != 1 or plan_steps[0].get("env") != PLAN_ENV:
		findings.append("ci.yml: the plan step must take the base and head commits from exactly their own expressions (BASE_SHA is the base of the pull request, not its head)")


PINS_STEP_LINES = (
	'git cat-file -e "$BASE_SHA^{commit}" || { echo "::error::the base commit cannot be read"; exit 1; }',
	'listing="$(git ls-tree "$BASE_SHA" -- .github/scripts/ci/pins.py)" || { echo "::error::the base commit cannot be listed"; exit 1; }',
	'git show "$BASE_SHA:.github/scripts/ci/pins.py" > "$tmp/pins.py" || { echo "::error::the base copy of the script cannot be read"; exit 1; }',
	'python3 -I "$tmp/pins.py" --base "$BASE_SHA" || bad=1',
	'python3 -I .github/scripts/ci/pins.py --base "$BASE_SHA" || bad=1',
	'python3 -I .github/scripts/ci/pins.py || bad=1',
)


def check_pins_job(findings: list) -> None:
	"""The pins job judges with the base's script first and runs on everything, with no plan.

	The value of an action's pin is judged by `pins.py`, and the gate must count its result, or
	taking the SHA out of the contract is a step back. The base's copy runs before anything of
	the tree, with `python3 -I`, and a base commit that cannot be read is a failure, not an
	absent check.
	"""
	jobs = load_yaml(WORKFLOWS / "ci.yml").get("jobs") or {}
	pins = jobs.get("pins") or {}
	if set(pins.get("needs") or []) != {"dco", "workflow-lint", "shell"} or "outputs." in str(pins.get("if", "")):
		findings.append("ci.yml: the pins job must wait for the three cheap gates and have no plan of its own")
	if "pins" not in set((jobs.get("ci-gate") or {}).get("needs") or []):
		findings.append("ci.yml: ci-gate must need the pins job, or the value of a pin counts for nothing when merging")
	steps = pins.get("steps") or [{}]
	run = [line.strip() for line in str(steps[-1].get("run", "")).splitlines()]
	for needle in PINS_STEP_LINES:
		if run.count(needle) != 1:
			findings.append(f"ci.yml: the pins step must have exactly one line: {needle}")
	if all(line in run for line in PINS_STEP_LINES[3:5]) and run.index(PINS_STEP_LINES[3]) > run.index(PINS_STEP_LINES[4]):
		findings.append("ci.yml: the pins step must run the base's script before this tree's")
	if any("--remote-prefix" in line for line in run):
		findings.append("ci.yml: the pins step must not name another place to ask for tags")
	env = steps[-1].get("env") or {}
	if env != {"EVENT": "${{ github.event_name }}", "BASE_SHA": "${{ github.event.pull_request.base.sha }}"}:
		findings.append("ci.yml: the pins step must take the event and the base commit from exactly their own expressions")


def check_rust_contract(findings: list) -> None:
	jobs = load_yaml(WORKFLOWS / "reusable-rust-ci.yml").get("jobs") or {}
	for job_id, expected in RUST_JOB_IFS.items():
		if (jobs.get(job_id) or {}).get("if") != expected:
			findings.append(f"reusable-rust-ci.yml: the condition of job {job_id!r} is not the pinned one")
	for job_id in jobs:
		if job_id not in RUST_JOB_IFS:
			findings.append(f"reusable-rust-ci.yml: job {job_id!r} is not part of the contract")
	outcome = jobs.get("outcome") or {}
	if outcome.get("needs") != ["lint", "test", "coverage"] or outcome.get("env") != OUTCOME_ENV:
		findings.append("reusable-rust-ci.yml: outcome must wait for lint, test and coverage and read exactly their results and the inputs")
	text = "\n".join(str(step.get("run", "")) for step in outcome.get("steps") or [])
	for needle in ('want lint "$LINT" success', 'want test "$TEST" skipped', 'want coverage "$COVERAGE" success', 'want test "$TEST" success', 'want coverage "$COVERAGE" skipped'):
		if needle not in text:
			findings.append(f"reusable-rust-ci.yml: outcome no longer requires: {needle}")


def _env_blocks(node):
	"""Every mapping found under an `env` key, at any depth."""
	if isinstance(node, dict):
		for key, value in node.items():
			if key == "env" and isinstance(value, dict):
				yield value
			yield from _env_blocks(value)
	elif isinstance(node, list):
		for item in node:
			yield from _env_blocks(item)


def check_rust_database(findings: list) -> None:
	"""The jobs that run the Rust tests have the same pinned PostgreSQL, and nothing turns `CI` off."""
	doc = load_yaml(WORKFLOWS / "reusable-rust-ci.yml")
	jobs = doc.get("jobs") or {}
	images = set()
	for job_id in DATABASE_JOBS:
		job = jobs.get(job_id) or {}
		services = job.get("services") or {}
		postgres = services.get("postgres") or {}
		if set(services) != {"postgres"}:
			findings.append(f"reusable-rust-ci.yml: job {job_id!r} must have the postgres service and no other")
		image = str(postgres.get("image", ""))
		images.add(image)
		if not POSTGRES_IMAGE.match(image):
			findings.append(f"reusable-rust-ci.yml: the postgres service of job {job_id!r} must be postgres:18 pinned by digest")
		if postgres.get("env") != POSTGRES_ENV:
			findings.append(f"reusable-rust-ci.yml: the postgres service of job {job_id!r} must set exactly {sorted(POSTGRES_ENV)}")
		if job.get("env") != DATABASE_JOB_ENV:
			findings.append(f"reusable-rust-ci.yml: job {job_id!r} must set exactly DATABASE_URL and SQLX_OFFLINE, as pinned")
	if len(images) > 1:
		findings.append("reusable-rust-ci.yml: the test and coverage jobs must use the same postgres image")
	if any("CI" in block for block in _env_blocks(doc)):
		findings.append("reusable-rust-ci.yml: sets CI by hand; the runner sets it, and a false value would let the database tests skip")


def check_audit_action(findings: list) -> None:
	steps = (load_yaml(ROOT / ".github" / "actions" / "cargo-audit" / "action.yml").get("runs") or {}).get("steps") or []
	seen = set()
	for step in steps:
		name = step.get("name", "")
		if name in AUDIT_STEPS:
			seen.add(name)
			condition, command = AUDIT_STEPS[name]
			if step.get("if") != condition or str(step.get("run", "")).strip() != command:
				findings.append(f"cargo-audit/action.yml: step {name!r} must have exactly the pinned condition and command")
		elif name == AUDIT_LOCKFILE_STEP:
			seen.add(name)
			if step.get("if") != AUDIT_LOCKFILE_IF or AUDIT_LOCKFILE_LAST not in str(step.get("run", "")):
				findings.append(f"cargo-audit/action.yml: step {name!r} must have exactly the pinned condition and command")
		elif name.startswith("Install cargo-audit"):
			seen.add(name)
			if "if" in step:
				findings.append(f"cargo-audit/action.yml: step {name!r} must always run")
		else:
			findings.append(f"cargo-audit/action.yml: step {name!r} is not part of the contract")
	if len(seen) != len(AUDIT_STEPS) + 2:
		findings.append("cargo-audit/action.yml: a step of the contract is missing")


CANCEL_ON_PULL_REQUEST = "${{ github.event_name == 'pull_request' }}"
CONCURRENCY = {
	"ci.yml": {"group": "ci-${{ github.event.pull_request.number || github.sha }}", "cancel-in-progress": CANCEL_ON_PULL_REQUEST},
	"codeql.yml": {
		"group": "codeql-${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
		"cancel-in-progress": CANCEL_ON_PULL_REQUEST,
	},
}


def check_security_concurrency(findings: list) -> None:
	"""A newer run of the same pull request cancels the older one, and nothing else cancels a run.

	The new run has to pass by itself, so the old one is of no use. What must not happen is a
	push to develop or main, or the weekly run, being cancelled by another run: those groups
	are by commit or by run, and `cancel-in-progress` is on only for a pull request. The groups
	and the condition are pinned whole. The weekly audit never cancels, and one branch failing
	it hides no other.
	"""
	for name, expected in CONCURRENCY.items():
		if load_yaml(WORKFLOWS / name).get("concurrency") != expected:
			findings.append(f"{name}: the concurrency must be the pinned group, cancelling only a run of the same pull request (cancel-in-progress: {CANCEL_ON_PULL_REQUEST})")
	if (load_yaml(WORKFLOWS / "audit.yml").get("concurrency") or {}).get("cancel-in-progress") not in (None, False):
		findings.append("audit.yml: the weekly audit must not sit in a concurrency group that cancels the run in progress")
	matrix = (((load_yaml(WORKFLOWS / "audit.yml").get("jobs") or {}).get("audit") or {}).get("strategy") or {})
	if matrix.get("fail-fast") is not False:
		findings.append("audit.yml: the audit of each branch must use fail-fast: false")


def check_contract(findings: list) -> None:
	check_no_continue_on_error(findings)
	check_defaults_and_shell(findings)
	check_ci_contract(findings)
	check_pins_job(findings)
	check_rust_contract(findings)
	check_rust_database(findings)
	check_audit_action(findings)
	check_security_concurrency(findings)
